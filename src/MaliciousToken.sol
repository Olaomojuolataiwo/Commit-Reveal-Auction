// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title MaliciousToken
/// @notice ERC20 that occasionally reverts when it receives ETH.
/// Used to simulate refund failures in Conditional scenario.
contract MaliciousToken is ERC20, Ownable {
    /// @notice Address being monitored (not used by logic, but logged)
    address public watchAddress;

    /// @notice Revert cadence (every Nth receive call)
    uint256 public revertEvery;

    /// @notice Number of receive() calls so far
    uint256 public calls;

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply_,
        address _watchAddress,
        uint256 _revertEvery
    )
        ERC20(name_, symbol_)
        Ownable(msg.sender)
    {
        _mint(msg.sender, initialSupply_);
        watchAddress = _watchAddress;
        revertEvery = _revertEvery;
    }

    /// @notice Conditional revert behavior — reverts on configured cadence.
    receive() external payable {
        calls += 1;
        if (calls % revertEvery == 0) {
            revert("MaliciousConditional: reverting on cadence");
        }
        // otherwise, accept payment silently
    }

    /// @notice Adjust the watch address.
    function setWatchAddress(address _watch) external onlyOwner {
        watchAddress = _watch;
    }

    /// @notice Adjust how often reverts happen.
    function setRevertEvery(uint256 n) external onlyOwner {
        revertEvery = n;
    }
}
