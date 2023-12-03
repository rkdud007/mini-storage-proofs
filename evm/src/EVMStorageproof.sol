// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import "../lib/Solidity-RLP/contracts/RLPReader.sol";
import "./lib/external/trie/Lib_SecureMerkleTrie.sol";

contract EVMStorageproof {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;
    using RLPReader for bytes;

    enum RootType {
        StateRoot,
        TransactionsRoot,
        ReceiptsRoot
    }

    // =================================
    // Step 1. Accessing the block hash
    // =================================

    // get origin chain's block hash on destination chain
    function getBlockHash(uint256 blockNumber) public view returns (bytes32) {
        // Ensure the block number is within the last 256 blocks
        require(blockNumber < block.number, "Block number is too high");
        require(
            blockNumber >= block.number - 256,
            "Block number is too old, use accumulator"
        );

        return blockhash(blockNumber);
    }

    // =================================
    // 2. Accessing the block header
    // =================================

    // verify origin chain's block header on destination chain
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

    // =================================
    // 3. Determining the Desired Root (Optional)
    // =================================

    // get origin chain's state root on destination chain
    function getStateRoot(
        uint256 blockNumber,
        bytes memory blockHeader
    ) public view returns (bytes32) {
        bool is_valid_header = getBlockHeader(blockNumber, blockHeader);
        require(is_valid_header, "Invalid block header");

        RLPReader.RLPItem[] memory items = blockHeader.toRlpItem().toList();
        return bytes32(items[3].toUint()); // The state root is the 4th item in a block header
    }

    // get origin chain's receipt root on destination chain
    function getReceiptsRoot(
        uint256 blockNumber,
        bytes memory blockHeader
    ) public view returns (bytes32) {
        bool is_valid_header = getBlockHeader(blockNumber, blockHeader);
        require(is_valid_header, "Invalid block header");

        RLPReader.RLPItem[] memory items = blockHeader.toRlpItem().toList();
        return bytes32(items[5].toUint()); // The receipts root is the 6th item
    }

    // get origin chain's transaction root on destination chain
    function getTransactionRoot(
        uint256 blockNumber,
        bytes memory blockHeader
    ) public view returns (bytes32) {
        bool is_valid_header = getBlockHeader(blockNumber, blockHeader);
        require(is_valid_header, "Invalid block header");

        RLPReader.RLPItem[] memory items = blockHeader.toRlpItem().toList();
        return bytes32(items[4].toUint()); // The transactions root is the 5th item
    }

    // =================================
    // 4. Verifying Data Against the Chosen Root (Optional)
    // =================================

    function verifyInclusion(
        uint256 blockNumber,
        bytes memory blockHeader,
        RootType rootType,
        bytes32 key,
        bytes memory proof
    ) public view returns (bool) {
        // Retrieve the root based on the specified type
        bytes32 root;
        if (rootType == RootType.StateRoot) {
            root = getStateRoot(blockNumber, blockHeader);
        } else if (rootType == RootType.TransactionsRoot) {
            root = getTransactionRoot(blockNumber, blockHeader);
        } else if (rootType == RootType.ReceiptsRoot) {
            root = getReceiptsRoot(blockNumber, blockHeader);
        } else {
            revert("Invalid root type");
        }

        // 1. Calculate the key hash(=leaf)
        (bool doesExist, bytes memory valueRLP) = Lib_SecureMerkleTrie.get(
            abi.encodePacked(key),
            proof,
            root
        );

        return doesExist;
    }
}
