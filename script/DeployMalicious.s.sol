// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/malicious_contracts/MaliciousRevert.sol";
import "../src/malicious_contracts/MaliciousGasExhaustion.sol";
import "../src/malicious_contracts/MaliciousReentrant.sol";
import "../src/malicious_contracts/MaliciousConditional.sol";

contract DeployMalicious is Script {
    function run() external {
        // Read env vars (set GASBURN_LOOPS and CONDITIONAL_CADENCE as needed)
        uint256 gasburnLoops = vm.envUint("GASBURN_LOOPS"); // defaults if not set -> 0 (we handle below)
        uint256 conditionalCadence = vm.envUint("CONDITIONAL_CADENCE");

        // Fallback defaults if env not set (small safe defaults)
        if (gasburnLoops == 0) gasburnLoops = 2000;
        if (conditionalCadence == 0) conditionalCadence = 3;

        // Use the provided private key for the broadcast; pass it via --private-key or set PRIVATE_KEY env var
        uint256 deployerKey = vm.envUint("ATTACKER_KEY");
        address tokenAddress = vm.envAddress("TOKEN_ADDRESS");

        vm.startBroadcast(deployerKey);

        //        MaliciousRevert mr = new MaliciousRevert(tokenAddress);
        //        console.log("Deployed MaliciousRevert at", address(mr));

        //        MaliciousGasExhaustion mgb = new MaliciousGasExhaustion(gasburnLoops);
        //        console.log("Deployed MaliciousGasExhaustion at", address(mgb), "loops=", gasburnLoops);

        //        MaliciousReentrant mre = new MaliciousReentrant();
        //        console.log("Deployed MaliciousReentrant at", address(mre));

        MaliciousConditional mc = new MaliciousConditional(tokenAddress, conditionalCadence);
        console.log("Deployed MaliciousConditional at", address(mc), "cadence=", conditionalCadence);

        vm.stopBroadcast();
    }
}
