// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal auction interface used by the reorg tests.
/// The test harness will call these functions on both the secure and vuln implementations.
interface ISimpleAuction {
    function commit(uint256 auctionId, bytes32 commitHash) external;
    function reveal(uint256 auctionId, uint256 amount, bytes32 salt) external;

    /// A finalize function which accepts an explicit candidate list for simplicity in tests.
    /// Many real auctions compute bidders internally; tests will pass known addresses to keep
    /// the mock implementations simple and deterministic.
    function finalizeWithCandidates(uint256 auctionId, address[] calldata candidates) external;

    function isFinalized(uint256 auctionId) external view returns (bool);
    function winnerOf(uint256 auctionId) external view returns (address);
    function revealBlock(uint256 auctionId, address bidder) external view returns (uint256);
    function requiredConfirmations() external view returns (uint256);
}
