// SPDX-License-Identifier: UNLICENSED
pragma solidity >0.5.0 <0.8.21;

import {Script, console2} from "forge-std/Script.sol";

contract CounterScript is Script {
    function setUp() public {}

    function run() public {
        vm.broadcast();
    }
}
