// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/utils/Interfaces.sol";
import "../src/mocks/PriceOracleMock.sol";
import "../src/vulnerableSealedBidAuctionWithSpot.sol";
import "../src/HardenedSealedBidAuctionWithSpot.sol";

contract DeployWithSpot is Script {
    function run() external {
        // Load deployer private key from env
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        // --- Deploy mock oracle ---
        PriceOracleMock oracle = new PriceOracleMock();

        // --- Common config ---
        address beneficiary = deployer; // you can change beneficiary if needed
        address paymentToken = address(0); // using ETH; swap to MockERC20 address if ERC20
        uint256 commitEndBlock = block.number + 10;
        uint256 revealEndBlock = commitEndBlock + 10;
        uint256 depositAmount = 1 ether;

        // --- Deploy vulnerable ---
        VulnerableSealedBidAuctionWithSpot vuln = new VulnerableSealedBidAuctionWithSpot(
            deployer,
            beneficiary,
            paymentToken,
            commitEndBlock,
            revealEndBlock,
            depositAmount,
            address(oracle) // oracle address
        );

        // --- Deploy hardened ---
        HardenedSealedBidAuctionWithSpot hard = new HardenedSealedBidAuctionWithSpot(
            deployer,
            beneficiary,
            paymentToken,
            commitEndBlock,
            revealEndBlock,
            depositAmount,
            address(oracle) // oracle address
        );

        vm.stopBroadcast();

        console2.log("Deployer:", deployer);
        console2.log("PriceOracleMock:", address(oracle));
        console2.log("Vulnerable Auction:", address(vuln));
        console2.log("Hardened Auction:", address(hard));
    }
}
