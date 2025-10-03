// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/AuctionManager.sol";

contract DeployAuctionManager is Script {
    function run() external {
        // Start broadcasting with your private key (passed via CLI)
        string memory rpc = vm.envString("RPC_URL_SEPOLIA");
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        // Deploy the AuctionManager contract
        AuctionManager manager = new AuctionManager();

        // Log the deployed contract address
        console.log("AuctionManager deployed at:", address(manager));

        // Stop broadcasting
        vm.stopBroadcast();
    }
}
