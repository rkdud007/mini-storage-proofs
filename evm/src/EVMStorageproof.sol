// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract EVMStorageproof {
    function getBlockHash(uint256 blockNumber) public view returns (bytes32) {
        // Ensure the block number is within the last 256 blocks
        require(blockNumber < block.number, "Block number is too high");
        require(
            blockNumber >= block.number - 256,
            "Block number is too old, use accumulator"
        );

        return blockhash(blockNumber);
    }

    function getBlockHeader(
        uint256 blockNumber,
        bytes memory blockHeader
    ) public view returns (bool) {
        // Step 1. Retrieve the block hash
        bytes32 retrievedBlockHash = getBlockHash(blockNumber);

        // Step 2. Hash the provided block header and compare
        bytes32 providedBlockHeaderHash = keccak256(blockHeader);

        // Step 3. Verify it
        if (providedBlockHeaderHash == retrievedBlockHash) {
            return true;
        } else {
            return false;
        }
    }
}
