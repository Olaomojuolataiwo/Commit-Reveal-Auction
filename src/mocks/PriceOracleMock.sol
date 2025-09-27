// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../utils/Interfaces.sol";

/// @title PriceOracleMock
/// @notice A mock oracle for testing auction contracts with spot price manipulation.
///         - Allows test scripts to manually set a "price".
///         - Auctions can read it via IPriceOracle.getPrice().
/// @dev Use setPrice() in tests to simulate attacker-controlled spot price.
contract PriceOracleMock is IPriceOracle {
    uint256 private price;

    event PriceUpdated(uint256 newPrice);

    /// @notice Set the oracle price (anyone can call in test/demo).
    function setPrice(uint256 _price) external {
        price = _price;
        emit PriceUpdated(_price);
    }

    /// @notice Get the current oracle price (called by auctions).
    function getPrice() external view override returns (uint256) {
        return price;
    }
}
