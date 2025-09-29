// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/VulnerableSealedBidAuctionWithSpot.sol";
import "../src/HardenedSealedBidAuctionWithSpot.sol";

contract DeployWithSpot is Script {
    function run()
        external
        returns (VulnerableSealedBidAuctionWithSpot vuln, HardenedSealedBidAuctionWithSpot hard)
    {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address beneficiary = vm.envAddress("BENEFICIARY");
        address paymentToken = vm.envAddress("PAYMENT_TOKEN");
        address priceOracle = vm.envAddress("PRICE_ORACLE");

        // Hardcoded params (adjust if needed)
        uint256 depositAmount = 1e18; // 1 token (assuming 18 decimals)
        uint256 commitEndBlock = block.number + 20;
        uint256 revealEndBlock = block.number + 40;

        vm.startBroadcast(deployerPrivateKey);

        vuln = new VulnerableSealedBidAuctionWithSpot(
            deployer,
            beneficiary,
            paymentToken,
            commitEndBlock,
            revealEndBlock,
            depositAmount,
            priceOracle
        );

        hard = new HardenedSealedBidAuctionWithSpot(
            deployer,
            beneficiary,
            paymentToken,
            commitEndBlock,
            revealEndBlock,
            depositAmount,
            priceOracle
        );

        vm.stopBroadcast();

        console.log("Vulnerable Auction deployed at:", address(vuln));
        console.log("Hardened Auction deployed at:", address(hard));

        return (vuln, hard);
    }
}
