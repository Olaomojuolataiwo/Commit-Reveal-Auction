// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/vulnerableSealedBidAuctionWithSpot.sol";
import "../src/HardenedSealedBidAuctionWithSpot.sol";

contract DeployAuctionsWithSpot is Script {

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
	address beneficiary = vm.envAddress("BENEFICIARY");
        address paymentToken = vm.envAddress("PAYMENT_TOKEN");
        address priceOracle = vm.envAddress("PRICE_ORACLE");

        // Hardcoded params (adjust buffer if needed)
        uint256 depositAmount = 1e18; // 1 token (assuming 18 decimals)
        uint256 commitEndBlock = block.number + 20;
        uint256 revealEndBlock = block.number + 40;

        vm.startBroadcast(deployerPrivateKey);

        VulnerableSealedBidAuctionWithSpot vulnAuction =
            new VulnerableSealedBidAuctionWithSpot(
		deployer,
                beneficiary,
                paymentToken,
                commitEndBlock,
                revealEndBlock,
		depositAmount,
                priceOracle
            );

        HardenedSealedBidAuctionWithSpot hardenedAuction =
            new HardenedSealedBidAuctionWithSpot(
		deployer,
                beneficiary,
                paymentToken,
                commitEndBlock,
                revealEndBlock,
		depositAmount,
                priceOracle
            );

        console.log("Vulnerable Auction deployed at:", address(vulnAuction));
        console.log("Hardened Auction deployed at:", address(hardenedAuction));

        vm.stopBroadcast();
    }
}

