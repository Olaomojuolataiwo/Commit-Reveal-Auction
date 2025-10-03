// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title SealedBidAuction (single-auction instance)
/// @notice Commit–Reveal sealed-bid auction supporting ETH or ERC20 bids.
///         - Commit phase: bidders submit a commitment hash + deposit.
///         - Reveal phase: bidders reveal (amount + nonce) and must transfer the bid amount to contract.
///         - Finalize: can be called after reveal window to choose winner, slash unrevealed deposits, and allow withdrawals.
/// @dev Designed for clarity and on-chain testing. Use AuctionManager/factory to deploy multiple auctions.
interface IERC20Minimal {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

abstract contract ReentrancyGuard {
    uint256 private _status;

    constructor() {
        _status = 1;
    }

    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

contract SealedBidAuction is ReentrancyGuard {
    // --- Immutable configuration set at deploy ---
    address public immutable creator; // deployer / auction creator
    address public immutable beneficiary; // where winner funds & slashed deposits go
    address public immutable paymentToken; // address(0) => native ETH, else ERC20 token
    uint256 public immutable commitEndBlock; // inclusive: last block allowed for commit
    uint256 public immutable revealEndBlock; // inclusive: last block allowed for reveal
    uint256 public immutable depositAmount; // deposit required at commit

    // --- Auction state ---
    mapping(address => bytes32) public commitments; // bidder => commitment hash
    mapping(address => bool) public revealed; // bidder => revealed flag
    mapping(address => uint256) public revealedBid; // bidder => bid amount (collected at reveal)
    mapping(address => uint256) public deposits; // bidder => deposit amount (non-zero after commit)
    address[] public bidders; // list of bidders (for slashing iteration in finalize)

    bool public finalized;
    address public winner;
    uint256 public winningBid;
    uint256 public winningRevealBlock; // tie-breaker: earlier revealBlock wins

    // --- Events ---
    event BidCommitted(address indexed bidder);
    event BidRevealed(address indexed bidder, uint256 amount);
    event AuctionFinalized(address indexed winner, uint256 winningBid);
    event Withdrawn(address indexed bidder, uint256 amount);
    event DepositSlashed(address indexed bidder, uint256 amount);

    // --- Modifiers ---
    modifier onlyDuringCommit() {
        require(block.number <= commitEndBlock, "not commit phase");
        _;
    }

    modifier onlyDuringReveal() {
        require(block.number > commitEndBlock && block.number <= revealEndBlock, "not reveal phase");
        _;
    }

    modifier onlyAfterRevealWindow() {
        require(block.number > revealEndBlock, "reveal window open");
        _;
    }

    /// @param _creator deployer / creator address
    /// @param _beneficiary recipient of winning bid and slashed deposits
    /// @param _paymentToken address(0) for ETH, otherwise ERC20 token address
    /// @param _commitEndBlock inclusive last commit block
    /// @param _revealEndBlock inclusive last reveal block
    /// @param _depositAmount deposit (in paymentToken units or wei)
    constructor(
        address _creator,
        address _beneficiary,
        address _paymentToken,
        uint256 _commitEndBlock,
        uint256 _revealEndBlock,
        uint256 _depositAmount
    ) {
        require(_creator != address(0), "zero creator");
        require(_beneficiary != address(0), "zero beneficiary");
        require(_commitEndBlock < _revealEndBlock, "invalid windows");
        creator = _creator;
        beneficiary = _beneficiary;
        paymentToken = _paymentToken;
        commitEndBlock = _commitEndBlock;
        revealEndBlock = _revealEndBlock;
        depositAmount = _depositAmount;
    }

    // ----------------------
    // Commit phase
    // ----------------------
    /// @notice Submit a commitment hash and a deposit to participate.
    /// @param _commitment keccak256(abi.encodePacked(uint256 amount, address bidder, bytes32 nonce))
    /// @dev deposit must be sent in ETH when paymentToken == address(0), otherwise caller must approve depositAmount to this contract.
    function commit(bytes32 _commitment) external payable onlyDuringCommit {
        require(_commitment != bytes32(0), "empty commitment");
        require(commitments[msg.sender] == bytes32(0), "already committed");

        if (paymentToken == address(0)) {
            // Native ETH deposit
            require(msg.value == depositAmount, "deposit mismatch");
        } else {
            require(msg.value == 0, "no native expected");
            // transfer depositAmount from bidder -> this contract
            bool ok = IERC20Minimal(paymentToken).transferFrom(msg.sender, address(this), depositAmount);
            require(ok, "deposit token transfer failed");
        }

        commitments[msg.sender] = _commitment;
        deposits[msg.sender] = depositAmount;
        bidders.push(msg.sender);

        emit BidCommitted(msg.sender);
    }

    // ----------------------
    // Reveal phase
    // ----------------------
    /// @notice Reveal bid and supply bid funds (either via msg.value for ETH or transferFrom for ERC20)
    /// @param amount bid amount (in wei or token smallest unit)
    /// @param nonce secret nonce used to construct the commitment
    function reveal(uint256 amount, bytes32 nonce) external payable onlyDuringReveal nonReentrant {
        bytes32 comm = commitments[msg.sender];
        require(comm != bytes32(0), "no commit");
        require(!revealed[msg.sender], "already revealed");

        // Recreate the commitment: keep ordering and types consistent with client-side preimage
        bytes32 expected = keccak256(abi.encodePacked(amount, msg.sender, nonce));
        require(expected == comm, "commitment mismatch");

        // Collect the bid funds now: either msg.value == amount for ETH, or ERC20 transferFrom
        if (paymentToken == address(0)) {
            require(msg.value == amount, "must send bid amount in ETH");
        } else {
            require(msg.value == 0, "no native ETH allowed for token auction");
            bool ok = IERC20Minimal(paymentToken).transferFrom(msg.sender, address(this), amount);
            require(ok, "token bid transfer failed");
        }

        // Record revealed bid & mark revealed
        revealed[msg.sender] = true;
        revealedBid[msg.sender] = amount;

        // Compare vs current highest; tie-breaker: earlier reveal wins (lower reveal block)
        uint256 rBlock = block.number;
        if (amount > winningBid) {
            winningBid = amount;
            winner = msg.sender;
            winningRevealBlock = rBlock;
        } else if (amount == winningBid) {
            // tie-breaker: earlier reveal block wins
            if (rBlock < winningRevealBlock) {
                winner = msg.sender;
                winningRevealBlock = rBlock;
            }
        }

        emit BidRevealed(msg.sender, amount);
    }

    // ----------------------
    // Finalize (after reveal window)
    // ----------------------
    /// @notice Finalize auction: slash unrevealed deposits, transfer winner's bid to beneficiary, allow refunds via withdraw().
    function finalize() external onlyAfterRevealWindow nonReentrant {
        require(!finalized, "already finalized");
        finalized = true;

        // Slash deposits of unrevealed bidders to beneficiary
        for (uint256 i = 0; i < bidders.length; i++) {
            address b = bidders[i];
            if (!revealed[b] && deposits[b] > 0) {
                uint256 amt = deposits[b];
                deposits[b] = 0;
                if (paymentToken == address(0)) {
                    // send ETH to beneficiary
                    (bool sent,) = beneficiary.call{value: amt}("");
                    require(sent, "slash transfer failed");
                } else {
                    bool ok = IERC20Minimal(paymentToken).transfer(beneficiary, amt);
                    require(ok, "slash token transfer failed");
                }
                emit DepositSlashed(b, amt);
            }
        }

        // Transfer winner's bid to beneficiary (if any)
        if (winner != address(0) && revealedBid[winner] > 0) {
            uint256 pay = revealedBid[winner];
            revealedBid[winner] = 0; // zero out to prevent double-withdraw
            if (paymentToken == address(0)) {
                (bool sent,) = beneficiary.call{value: pay}("");
                require(sent, "payout failed");
            } else {
                bool ok = IERC20Minimal(paymentToken).transfer(beneficiary, pay);
                require(ok, "payout token failed");
            }
        }

        emit AuctionFinalized(winner, winningBid);
    }

    // ----------------------
    // Withdrawals (after finalize)
    // ----------------------
    /// @notice Non-winning revealed bidders can withdraw their bid & deposit refunds.
    function withdraw() external nonReentrant {
        require(finalized, "not finalized");

        // Only revealed bidders who are not the winner have refundable bid + deposit
        require(revealed[msg.sender], "not revealed");
        require(msg.sender != winner, "winner cannot withdraw (funds already paid)");

        uint256 refundBid = revealedBid[msg.sender];
        uint256 refundDep = deposits[msg.sender];

        require(refundBid > 0 || refundDep > 0, "nothing to withdraw");

        // zero out first
        revealedBid[msg.sender] = 0;
        deposits[msg.sender] = 0;

        uint256 totalRefund = refundBid + refundDep;

        if (paymentToken == address(0)) {
            (bool sent,) = msg.sender.call{value: totalRefund}("");
            require(sent, "withdraw ETH failed");
        } else {
            bool ok = IERC20Minimal(paymentToken).transfer(msg.sender, totalRefund);
            require(ok, "withdraw token failed");
        }

        emit Withdrawn(msg.sender, totalRefund);
    }

    // ----------------------
    // View helpers
    // ----------------------
    function getBidders() external view returns (address[] memory) {
        return bidders;
    }

    // Allow contract to receive ETH (only used for safety; primary ETH flow uses msg.value on commit/reveal)
    receive() external payable {}
}
