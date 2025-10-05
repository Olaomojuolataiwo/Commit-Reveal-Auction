// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/mocks/PriceOracleMock.sol";

/// @title DeployPriceOracleMock
/// @notice Script to deploy the mock oracle on-chain
contract DeployPriceOracleMock is Script {
    function run() external {
        // Load deployer private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the oracle
        PriceOracleMock oracle = new PriceOracleMock();

        // Optionally set an initial price 
        oracle.setPrice(0.005 ether);

        console.log("PriceOracleMock deployed at:", address(oracle));

        vm.stopBroadcast();
    }
}
