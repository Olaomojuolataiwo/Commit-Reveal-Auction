// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal ERC20 interface used by the auctions (mock token)
interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title VulnerableAuction
/// @notice Demonstrates bad patterns: linear scans, push-style refunds (unsafe), no per-address caps.
/// Designed so finalize() does unbounded work and attempts push-transfers (ERC20).
contract VulnerableAuction {
    IERC20Minimal public token;

    uint256 public auctionCounter;

    struct Commit {
        address bidder;
        bytes32 commitHash;
    }

    struct AuctionData {
        uint256 id;
        Commit[] commits;
        mapping(address => uint256) revealed; // revealed bid amount (token units)
        bool finalized;
    }

    mapping(uint256 => AuctionData) internal auctions;

    event AuctionCreated(uint256 indexed id);
    event CommitCreated(uint256 indexed auctionId, address indexed bidder);
    event Revealed(uint256 indexed auctionId, address indexed bidder, uint256 amount);
    event Finalized(uint256 indexed auctionId);

    constructor(address tokenAddress) {
        require(tokenAddress != address(0), "token required");
        token = IERC20Minimal(tokenAddress);
    }

    /// @notice create a new auction ID
    function newAuction() external returns (uint256) {
        auctionCounter++;
        uint256 id = auctionCounter;
        AuctionData storage a = auctions[id];
        a.id = id;
        emit AuctionCreated(id);
        return id;
    }

    /// @notice Commit with an optional ERC20 deposit amount parameter (vulnerable allows many commits per address)
    /// @dev This version keeps a deposit parameter to easily craft test cases; in real deployment you'd fix this
    function commit(uint256 auctionId, bytes32 commitHash, uint256 depositAmount) external {
        // if deposit is non-zero, pull ERC20 from sender
        if (depositAmount > 0) {
            require(token.transferFrom(msg.sender, address(this), depositAmount), "deposit transferFrom failed");
        }
        AuctionData storage a = auctions[auctionId];
        a.commits.push(Commit({ bidder: msg.sender, commitHash: commitHash }));
        emit CommitCreated(auctionId, msg.sender);
    }

    /// @notice Reveal looks up the commit by scanning the commits array linearly (gas-inefficient)
    function reveal(uint256 auctionId, uint256 bidAmount, bytes32 salt) external {
        AuctionData storage a = auctions[auctionId];
        bytes32 expected = keccak256(abi.encodePacked(bidAmount, salt));
        // naive linear scan
        for (uint256 i = 0; i < a.commits.length; ++i) {
            Commit storage c = a.commits[i];
            if (c.bidder == msg.sender && c.commitHash == expected) {
                a.revealed[msg.sender] = bidAmount;
                emit Revealed(auctionId, msg.sender, bidAmount);
                return;
            }
        }
        revert("no matching commit found");
    }

    /// @notice Vulnerable finalize: computes winner naively and then *pushes* refunds (ERC20) to every bidder.
    /// This push pattern can be griefed by a malicious recipient contract (revert on token transfer, gas burn, reentrancy).
    function finalize(uint256 auctionId) external {
        AuctionData storage a = auctions[auctionId];
        require(!a.finalized, "already finalized");

        // determine winner naively
        uint256 highest = 0;
        address winner = address(0);
        for (uint256 i = 0; i < a.commits.length; ++i) {
            address bidder = a.commits[i].bidder;
            uint256 b = a.revealed[bidder];
            if (b > highest) {
                highest = b;
                winner = bidder;
            }
        }

        // Push refunds to every bidder (dangerous)
        for (uint256 i = 0; i < a.commits.length; ++i) {
            address recipient = a.commits[i].bidder;
            uint256 refundAmount = a.revealed[recipient];
            if (refundAmount > 0) {
                // If recipient is a malicious contract that reverts on transfer or burns gas, this will revert / be expensive
                require(token.transfer(recipient, refundAmount), "refund transfer failed");
            }
        }

        a.finalized = true;
        emit Finalized(auctionId);
    }

    /// @notice helper getter for number of commits (for off-chain checks)
    function commitCount(uint256 auctionId) external view returns (uint256) {
        return auctions[auctionId].commits.length;
    }

    /// @notice view revealed bid for an address
    function revealedBid(uint256 auctionId, address who) external view returns (uint256) {
        return auctions[auctionId].revealed[who];
    }
}
