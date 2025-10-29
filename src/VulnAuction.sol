// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/ISimpleAuction.sol";

/// @notice VulnAuction is intentionally vulnerable for demonstration:
/// it records reveals but DOES NOT enforce requiredConfirmations at finalize time.
/// As a result, finalizeWithCandidates can conclude immediately after reveal and
/// will consider short-lived reveals — making it exploitable via reorgs.
contract VulnAuction is ISimpleAuction {
    struct Reveal {
        bytes32 commitHash;
        bool revealed;
        uint256 amount;
        uint256 revealBlock;
    }

    uint256 private immutable _requiredConfirmations; // exposed but ignored in finalize
    mapping(uint256 => mapping(address => Reveal)) public reveals;
    mapping(uint256 => bool) private _finalized;
    mapping(uint256 => address) private _winner;

    event Committed(uint256 indexed auctionId, address indexed bidder, bytes32 commitHash);
    event Revealed(uint256 indexed auctionId, address indexed bidder, uint256 amount, uint256 revealBlock);
    event Finalized(uint256 indexed auctionId, address indexed winner);

    constructor(uint256 requiredConfirmations_) {
        _requiredConfirmations = requiredConfirmations_;
    }

    function requiredConfirmations() external view returns (uint256) {
        return _requiredConfirmations;
    }

    function commit(uint256 auctionId, bytes32 commitHash) external {
        reveals[auctionId][msg.sender].commitHash = commitHash;
        emit Committed(auctionId, msg.sender, commitHash);
    }

    function reveal(uint256 auctionId, uint256 amount, bytes32 salt) external {
        Reveal storage r = reveals[auctionId][msg.sender];
        require(r.commitHash != bytes32(0), "NoCommit");
        require(!r.revealed, "AlreadyRevealed");
        bytes32 expected = keccak256(abi.encodePacked(amount, salt));
        require(expected == r.commitHash, "CommitMismatch");

        r.revealed = true;
        r.amount = amount;
        r.revealBlock = block.number; // recorded, but not used correctly by finalize
        emit Revealed(auctionId, msg.sender, amount, r.revealBlock);
    }

    /// @notice Vulnerable finalize: considers any revealed bids immediately, ignoring confirmations.
    /// This makes it possible for an attacker to reveal, have that reveal included in a short-lived block,
    /// and have the auction finalized before reorg can be resolved.
    function finalizeWithCandidates(uint256 auctionId, address[] calldata candidates) external {
        require(!_finalized[auctionId], "AlreadyFinalized");

        address best;
        uint256 bestAmount;
        bool anyReveal = false;

        for (uint256 i = 0; i < candidates.length; i++) {
            address bidder = candidates[i];
            Reveal storage r = reveals[auctionId][bidder];
            if (!r.revealed) continue;

            // VULNERABILITY: no confirmation check — immediately accepts revealed bids
            anyReveal = true;
            if (r.amount > bestAmount) {
                bestAmount = r.amount;
                best = bidder;
            }
        }

        require(anyReveal, "NoReveals");

        _finalized[auctionId] = true;
        _winner[auctionId] = best;
        emit Finalized(auctionId, best);
    }

    // ---- View helpers ----
    function isFinalized(uint256 auctionId) external view returns (bool) {
        return _finalized[auctionId];
    }

    function winnerOf(uint256 auctionId) external view returns (address) {
        return _winner[auctionId];
    }

    function revealBlock(uint256 auctionId, address bidder) external view returns (uint256) {
        return reveals[auctionId][bidder].revealBlock;
    }

    function debugHash(uint256 amount, bytes32 salt) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(amount, salt));
    }

}
