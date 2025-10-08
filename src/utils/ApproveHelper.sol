// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ApproveHelper {
    /// approve `spender` to pull `amount` tokens from THIS contract (works with tokens that return bool or no-data)
    function approveToken(address tokenAddress, address spender, uint256 amount) public returns (bool) {
        (bool ok, bytes memory data) = tokenAddress.call(
            abi.encodeWithSignature("approve(address,uint256)", spender, amount)
        );
        if (!ok) revert("approve call failed");
        if (data.length == 0) return true;
        return abi.decode(data, (bool));
    }
}
