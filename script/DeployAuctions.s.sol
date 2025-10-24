// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/VulnAuction.sol";
import "../src/SecureAuction.sol";

/**
 * @title DeployAuctions
 * @notice A Foundry deployment script that deploys both the secure and vulnerable
 *         auction contracts. The test harness will invoke this script to obtain
 *         their addresses and use them for comparative reorg tests.
 */
contract DeployAuctions is Script {
    // Deployment result addresses
    address public secureAuction;
    address public vulnerableAuction;

    function deploy(uint256 confirmations) public returns (address, address) {
        // The deployer will be the script’s msg.sender
        vm.startBroadcast();

        // Deploy both contracts fresh each time for deterministic testing
        SecureAuction secure = new SecureAuction(confirmations);
        VulnAuction vuln = new VulnAuction(confirmations);

        secureAuction = address(secure);
        vulnerableAuction = address(vuln);

        vm.stopBroadcast();

        // Log addresses for test harness
        console.log(" Secure Auction deployed at:", secureAuction);
        console.log(" Vulnerable Auction deployed at:", vulnerableAuction);
        console.log("requiredConfirmations =", confirmations);



        // Return both addresses for test scripts
        return (secureAuction, vulnerableAuction);
    }
    // Convenience overload with a sensible default (3 confirmations)
    function run() external returns (address, address) {
        return deploy(3);
    }

}

