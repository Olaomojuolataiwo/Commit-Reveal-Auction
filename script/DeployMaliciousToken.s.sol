// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MaliciousToken.sol";

contract DeployMaliciousToken is Script {
    function run() external returns (address) {
        // required: deployer private key
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        require(deployerKey != 0, "DEPLOYER_KEY required");

        // string fallbacks via bytes to be compatible with older Forge
        string memory name = string(vm.envOr("MAL_TOKEN_NAME", bytes("MaliciousToken")));
        string memory symbol = string(vm.envOr("MAL_TOKEN_SYMBOL", bytes("MAL")));

        // numeric fallbacks
        uint256 initialSupply = uint256(vm.envOr("MAL_TOKEN_SUPPLY", uint256(1_000_000 ether)));
        uint256 revertEvery   = uint256(vm.envOr("MAL_TOKEN_REVERT_EVERY", uint256(2)));

        // watch address (optional)
        address watch = address(0);
        // prefer vm.envAddress when available; try/catch to be robust
        try vm.envAddress("MAL_TOKEN_WATCH") returns (address w) {
            watch = w;
        } catch {
            // keep default address(0) if not set
        }

        vm.startBroadcast(deployerKey);

        MaliciousToken token = new MaliciousToken(
            name,
            symbol,
            initialSupply,
            watch,
            revertEvery
        );

        console.log("Deployed MaliciousToken at", address(token));
        console.log(" name:", name);
        console.log(" symbol:", symbol);
        console.log(" initialSupply:", initialSupply);
        console.log(" watchAddress:", watch);
        console.log(" revertEvery:", revertEvery);

        vm.stopBroadcast();

        return address(token);
    }
}
