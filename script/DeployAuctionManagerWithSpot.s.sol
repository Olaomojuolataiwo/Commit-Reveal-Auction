// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/AuctionManagerWithSpot.sol";

contract DeployAuctionManagerWithSpot is Script {
    function run() external {
        // Load deployer
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        // Load environment variables
        address paymentToken = vm.envAddress("PAYMENT_TOKEN");
        address priceOracle = vm.envAddress("PRICE_ORACLE");

        // Hardcoded params (adjust as needed)
        uint256 depositAmount = 1e18; // 1 token
        uint256 commitPhaseDuration = 20;
        uint256 revealPhaseDuration = 20;

        vm.startBroadcast(deployerKey);

        AuctionManagerWithSpot manager = new AuctionManagerWithSpot();

        console.log("AuctionManagerWithSpot deployed at:", address(manager));

        vm.stopBroadcast();
    }
}
