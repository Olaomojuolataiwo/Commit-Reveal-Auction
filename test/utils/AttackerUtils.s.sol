// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attacker utils used by tests and scripts.
/// Provides:
///  - makeCommitment(amount, bidder, nonce) -> bytes32
///  - buildCommitCalldata(bytes32 commitment) -> calldata for commit(bytes32)
///  - buildRevealCalldata(uint256 amount, bytes32 nonce) -> calldata for reveal(uint256,bytes32)
/// These helpers let tests do:
///   vm.prank(actor);
///   (bool ok, ) = address(auction).call{value: deposit}(utils.buildCommitCalldata(commitment));
contract AttackerUtils {
    /// Compute the commitment exactly as the auction expects:
    /// keccak256(abi.encodePacked(amount, bidder, nonce))
    function makeCommitment(uint256 amount, address bidder, bytes32 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(amount, bidder, nonce));
    }

    /// Return calldata bytes for commit(bytes32)
    function buildCommitCalldata(bytes32 commitment) public pure returns (bytes memory) {
        return abi.encodeWithSignature("commit(bytes32)", commitment);
    }

    /// Return calldata bytes for reveal(uint256, bytes32)
    function buildRevealCalldata(uint256 amount, bytes32 nonce) public pure returns (bytes memory) {
        return abi.encodeWithSignature("reveal(uint256,bytes32)", amount, nonce);
    }

    /// Return calldata bytes for finalize()
    function buildFinalizeCalldata() public pure returns (bytes memory) {
        return abi.encodeWithSignature("finalize()");
    }
}
