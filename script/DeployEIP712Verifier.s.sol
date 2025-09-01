// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {EIP712Verifier} from "../src/EIP712Verifier.sol";

contract DeployEIP712Verifier is Script {
    function run() external returns (EIP712Verifier verifier) {
        // Placeholders: set via env before running the script
        // export ZKSYNC_SEPOLIA_RPC_URL=...
        // export PRIVATE_KEY=...
        string memory name = vm.envOr("EIP712_NAME", string("EIP712Verifier"));
        string memory version = vm.envOr("EIP712_VERSION", string("1"));

        vm.startBroadcast();
        verifier = new EIP712Verifier(name, version);
        vm.stopBroadcast();
    }
}


