// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Minimal ERC20 interface used by the forwarder to approve tokens

import "src/utils/ApproveHelper.sol";
import "src/utils/IAuctions.sol";

/// @title MaliciousRevert
/// @notice Acts as a bidder contract (forwarder) but reverts on any incoming ETH.
/// Useful to grief push-based payouts or to assert that pull-payments are required.

contract MaliciousRevert is ApproveHelper{
    address public immutable token; // ERC20 token used for deposits/refunds

    constructor(address tokenAddress) {
        require(tokenAddress != address(0), "token required");
        token = tokenAddress;
    }

    /// @notice Always revert on receive to simulate a malicious recipient that refuses funds.
    receive() external payable {
        revert("MaliciousRevert: I refuse funds");
    }

    // -------------------------
    // Forwarding helpers
    // -------------------------

    /// @notice Forward a commit to a VulnerableAuction variant that expects a deposit param.
    /// It first approves the auction to pull `depositAmount` tokens from this contract,
    /// then calls the auction.commit(...) so that the auction sees `msg.sender == address(this)`.
    /// The controller EOA should ensure this contract has sufficient token balance before calling.
    function forwardCommitVulnerable(address auction, uint256 auctionId, bytes32 commitHash, uint256 depositAmount) external {
        // Approve the auction to pull depositAmount from this contract
        require(IERC20Minimal(token).approve(auction, depositAmount), "approve failed");
        // Call the vulnerable commit signature: commit(auctionId, commitHash, depositAmount)
        IVulnerableAuction(auction).commit(auctionId, commitHash, depositAmount);
    }

    /// @notice Forward a commit to the HardenedAuction variant (no deposit param).
    function forwardCommitHardened(address auction, uint256 auctionId, bytes32 commitHash) external {
        IHardenedAuction(auction).commit(auctionId, commitHash);
    }

    /// @notice Forward a reveal (both variants use the same reveal signature)
    function forwardReveal(address auction, uint256 auctionId, uint256 bidAmount, bytes32 salt) external {
        // Try Vulnerable reveal signature first (it matches Hardened as well)
        // Use low-level call to avoid revert if auction ABI differs slightly.
        (bool ok, ) = auction.call(abi.encodeWithSignature("reveal(uint256,uint256,bytes32)", auctionId, bidAmount, salt));
        require(ok, "reveal call failed");
    }

    /// @notice Proxy withdraw: call auction.withdraw(auctionId) from this contract context.
    /// This makes the auction see this contract as caller (msg.sender) and will trigger `receive()` if the auction pushes ETH.
    function proxyWithdraw(address auction, uint256 auctionId) external {
        // call withdraw(uint256)
        (bool ok, ) = auction.call(abi.encodeWithSignature("withdraw(uint256)", auctionId));
        require(ok, "proxyWithdraw failed");
    }
}
