// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MaliciousConditional
/// @notice Acts as a bidder forwarder and reverts on every N-th received call (default every 3rd).

import "src/utils/ApproveHelper.sol";
import "../utils/IAuctions.sol";

contract MaliciousConditional is ApproveHelper {
    uint256 public calls;
    uint256 public revertEvery; // e.g. 3 => revert every 3rd call
    address public token; // ERC20 token used for deposits

    constructor(address _token, uint256 _revertEvery) {
        require(_revertEvery > 0, "revertEvery>0");
        require(_token != address(0), "token=0");
        token = _token;
        revertEvery = _revertEvery;
        calls = 0;
    }

    /// @notice Conditional revert behavior: increments call count and reverts on the configured cadence.
    receive() external payable {
        calls += 1;
        if (calls % revertEvery == 0) {
            revert("MaliciousConditional: reverting on cadence");
        }
        // otherwise accept funds (no-op)
    }

    // -------------------------
    // Forwarding helpers (controller EOA calls these so this contract is msg.sender on auction)
    // -------------------------

    /// Allow the controller EOA to ask this contract to approve a spender for `amount` tokens.
    /// The ERC20 sees the approval coming from THIS contract (so approve sets allowance[thisContract][spender]).
    function forwardCommitVulnerable(address auction, uint256 auctionId, bytes32 commitHash, uint256 depositAmount)
        external
    {
        // Approve the auction to pull depositAmount from this contract.
        require(IERC20Minimal(token).approve(auction, depositAmount), "approve failed");
        // Call the vulnerable commit signature: commit(auctionId, commitHash, depositAmount)
        IVulnerableAuction(auction).commit(auctionId, commitHash, depositAmount);
    }

    /// @notice Forward a commit to the HardenedAuction variant (no deposit param).
    function forwardCommitHardened(address auction, uint256 auctionId, bytes32 commitHash) external {
        IHardenedAuction(auction).commit(auctionId, commitHash);
    }

    /// @notice Forward a reveal (both variants use the same reveal signature)
    /// @notice Forward a reveal (both variants use the same reveal signature)
    function forwardReveal(address auction, uint256 auctionId, uint256 bidAmount, bytes32 salt) external {
        IHardenedAuction(auction).reveal(auctionId, bidAmount, salt);
    }

    /// @notice Proxy withdraw: call auction.withdraw(auctionId) from this contract context.
    /// This makes the auction see this contract as caller (msg.sender) and will trigger `receive()` if the auction pushes ETH.
    function proxyWithdraw(address auction, uint256 auctionId) external {
        // call withdraw(uint256)
        (bool ok,) = auction.call(abi.encodeWithSignature("withdraw(uint256)", auctionId));
        require(ok, "proxyWithdraw failed");
    }
}
