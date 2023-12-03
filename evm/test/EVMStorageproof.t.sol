// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {EVMStorageproof} from "../src/EVMStorageproof.sol";

contract EVMStorageproofTest is Test {
    EVMStorageproof public evmStorageproofInstance;

    function setUp() public {
        evmStorageproofInstance = new EVMStorageproof();
    }

    function test_blockhash() public {
        bytes32 expectedHash = 0xd332a3c9ba4ceb22ad9eb94aae2f241b9295cc7f0e49e48b66ecf24b7fc33f56;
        bytes32 actualHash = evmStorageproofInstance.getBlockHash(18702968);
        assertEq(actualHash, expectedHash);
    }
}
