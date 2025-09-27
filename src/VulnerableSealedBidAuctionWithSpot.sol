// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./utils/Interfaces.sol";

/// @title VulnerableSealedBidAuctionWithSpot
/// @dev Vulnerable variant: winner selection uses `effectiveBid = amount * price / 1e18` read at reveal().
contract VulnerableSealedBidAuctionWithSpot is ReentrancyGuard {
    // --- Immutable configuration set at deploy ---
    address public immutable creator;
    address public immutable beneficiary;
    address public immutable paymentToken; // address(0) => native ETH
    uint256 public immutable commitEndBlock; // inclusive
    uint256 public immutable revealEndBlock; // inclusive
    uint256 public immutable depositAmount;
    address public immutable priceSource; // oracle/DEX mock address (provides price with 18 decimals)

    // --- Auction state ---
    mapping(address => bytes32) public commitments;
    mapping(address => bool) public revealed;
    mapping(address => uint256) public revealedBid;           // nominal amount revealed
    mapping(address => uint256) public revealedEffectiveBid; // amount * price / 1e18
    mapping(address => uint256) public priceObservedAtReveal; // price observed during reveal
    mapping(address => uint256) public deposits;
    address[] public bidders;

    bool public finalized;
    address public winner;
    uint256 public winningBid; // nominal winning bid (amount)
    uint256 public winningEffectiveBid; // effective metric used for selection
    uint256 public winningRevealBlock;

    // --- Events ---
    event BidCommitted(address indexed bidder);
    event BidRevealed(address indexed bidder, uint256 amount);
    /// optional visibility aid for tests: emits observed price & effectiveBid (does NOT include nonce)
    event PriceObserved(address indexed bidder, uint256 price, uint256 effectiveBid);
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
    /// @param _priceSource price oracle / DEX mock that returns price scaled by 1e18
    constructor(
        address _creator,
        address _beneficiary,
        address _paymentToken,
        uint256 _commitEndBlock,
        uint256 _revealEndBlock,
        uint256 _depositAmount,
        address _priceSource
    ) {
        require(_creator != address(0), "zero creator");
        require(_beneficiary != address(0), "zero beneficiary");
        require(_commitEndBlock < _revealEndBlock, "invalid windows");
        require(_priceSource != address(0), "zero price source");

        creator = _creator;
        beneficiary = _beneficiary;
        paymentToken = _paymentToken;
        commitEndBlock = _commitEndBlock;
        revealEndBlock = _revealEndBlock;
        depositAmount = _depositAmount;
        priceSource = _priceSource;
    }

    // ----------------------
    // Commit phase
    // ----------------------
    /// @notice Submit a commitment hash and a deposit to participate.
    /// @param _commitment keccak256(abi.encodePacked(uint256 amount, address bidder, bytes32 nonce))
    function commit(bytes32 _commitment) external payable onlyDuringCommit {
        require(_commitment != bytes32(0), "empty commitment");
        require(commitments[msg.sender] == bytes32(0), "already committed");

        if (paymentToken == address(0)) {
            require(msg.value == depositAmount, "deposit mismatch");
        } else {
            require(msg.value == 0, "no native expected");
            bool ok = IERC20Minimal(paymentToken).transferFrom(msg.sender, address(this), depositAmount);
            require(ok, "deposit token transfer failed");
        }

        commitments[msg.sender] = _commitment;
        deposits[msg.sender] = depositAmount;
        bidders.push(msg.sender);

        emit BidCommitted(msg.sender);
    }

    // ----------------------
    // Reveal phase (vulnerable)
    // ----------------------
    /// @notice Reveal bid and supply bid funds. Reads spot price at reveal and uses it to compute effectiveBid.
    /// @param amount bid amount (in wei or token smallest unit)
    /// @param nonce secret nonce used to construct the commitment
    function reveal(uint256 amount, bytes32 nonce) external payable onlyDuringReveal nonReentrant {
        bytes32 comm = commitments[msg.sender];
        require(comm != bytes32(0), "no commit");
        require(!revealed[msg.sender], "already revealed");

        bytes32 expected = keccak256(abi.encodePacked(amount, msg.sender, nonce));
        require(expected == comm, "commitment mismatch");

        // Collect bid funds
        if (paymentToken == address(0)) {
            require(msg.value == amount, "must send bid amount in ETH");
        } else {
            require(msg.value == 0, "no native ETH allowed for token auction");
            bool ok = IERC20Minimal(paymentToken).transferFrom(msg.sender, address(this), amount);
            require(ok, "token bid transfer failed");
        }

        // Read spot price at reveal time (vulnerable point)
        uint256 price = IPriceOracle(priceSource).getPrice(); // price scaled by 1e18
        // Compute effective bid metric (normalized)
        uint256 effective = mulDiv(amount, price, 1e18);

        // Record revealed values
        revealed[msg.sender] = true;
        revealedBid[msg.sender] = amount;
        revealedEffectiveBid[msg.sender] = effective;
        priceObservedAtReveal[msg.sender] = price;

        // Compare vs current highest using effective metric
        uint256 rBlock = block.number;
        if (effective > winningEffectiveBid) {
            // update selection
            winningEffectiveBid = effective;
            winningBid = amount; // keep nominal winning bid for payout
            winner = msg.sender;
            winningRevealBlock = rBlock;
        } else if (effective == winningEffectiveBid) {
            // tie-breaker: earlier reveal block wins
            if (rBlock < winningRevealBlock) {
                winner = msg.sender;
                winningRevealBlock = rBlock;
                winningBid = amount;
            }
        }

        emit BidRevealed(msg.sender, amount);
        emit PriceObserved(msg.sender, price, effective);
    }

    // ----------------------
    // Finalize (after reveal window)
    // ----------------------
    /// @notice Finalize auction: slash unrevealed deposits, transfer winner's nominal bid to beneficiary.
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
                    (bool sent, ) = beneficiary.call{value: amt}("");
                    require(sent, "slash transfer failed");
                } else {
                    bool ok = IERC20Minimal(paymentToken).transfer(beneficiary, amt);
                    require(ok, "slash token transfer failed");
                }
                emit DepositSlashed(b, amt);
            }
        }

        // Transfer winner's nominal bid to beneficiary (if any)
        if (winner != address(0) && revealedBid[winner] > 0) {
            uint256 pay = revealedBid[winner];
            revealedBid[winner] = 0; // zero out to prevent double-withdraw
            if (paymentToken == address(0)) {
                (bool sent, ) = beneficiary.call{value: pay}("");
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
    function withdraw() external nonReentrant {
        require(finalized, "not finalized");
        require(revealed[msg.sender], "not revealed");
        require(msg.sender != winner, "winner cannot withdraw (funds already paid)");

        uint256 refundBid = revealedBid[msg.sender];
        uint256 refundDep = deposits[msg.sender];
        require(refundBid > 0 || refundDep > 0, "nothing to withdraw");

        revealedBid[msg.sender] = 0;
        deposits[msg.sender] = 0;

        uint256 totalRefund = refundBid + refundDep;

        if (paymentToken == address(0)) {
            (bool sent, ) = msg.sender.call{value: totalRefund}("");
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
    function getPriceAtReveal(address bidder) external view returns (uint256) {
        return priceObservedAtReveal[bidder];
    }
    function getRevealedEffectiveBid(address bidder) external view returns (uint256) {
        return revealedEffectiveBid[bidder];
    }

    // ----------------------
    // Internal utilities
    // ----------------------
    /// @dev safe mulDiv to avoid intermediate overflow for (a * b) / denom
    function mulDiv(uint256 a, uint256 b, uint256 denom) internal pure returns (uint256) {
        // simple check: since solidity 0.8 has overflow checks, use unchecked for intermediate mul if necessary
        // but keep simple: (a * b) / denom with 512-bit not required for typical auction numbers in tests
        // Use unchecked for small gas saving
        unchecked {
            return (a * b) / denom;
        }
    }

    // Allow contract to receive ETH (safety)
    receive() external payable {}
}

/// @notice Simple DEX/Price mock that exposes setPrice(). Price scaled by 1e18.
contract PriceSourceMock is IPriceOracle {
    uint256 private price; // scaled by 1e18
    address public owner;

    event PriceSet(uint256 price);

    constructor(uint256 _initialPrice) {
        price = _initialPrice;
        owner = msg.sender;
        emit PriceSet(_initialPrice);
    }

    /// @notice Set the spot price (attacker in tests will call this to manipulate)
    function setPrice(uint256 _p) external {
        // no access control to allow attacker manipulation in tests
        price = _p;
        emit PriceSet(_p);
    }

    function getPrice() external view override returns (uint256) {
        return price;
    }
}
