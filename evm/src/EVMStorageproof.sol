// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "./lib/external/trie/Lib_SecureMerkleTrie.sol";
import "./lib/external/rlp/Lib_RLPReader.sol";

contract EVMStorageproof {
    using Lib_RLPReader for Lib_RLPReader.RLPItem;
    using Lib_RLPReader for bytes;

    uint8 private constant ACCOUNT_NONCE_INDEX = 0;
    uint8 private constant ACCOUNT_BALANCE_INDEX = 1;
    uint8 private constant ACCOUNT_STORAGE_ROOT_INDEX = 2;
    uint8 private constant ACCOUNT_CODE_HASH_INDEX = 3;

    bytes32 private constant EMPTY_TRIE_ROOT_HASH =
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;
    bytes32 private constant EMPTY_CODE_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

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
    // 3. Determining the Desired Root
    // =================================

    // get origin chain's state root on destination chain
    function getStateRoot(
        uint256 blockNumber,
        bytes memory blockHeader
    ) public view returns (bytes32) {
        bool is_valid_header = getBlockHeader(blockNumber, blockHeader);
        require(is_valid_header, "Invalid block header");

        Lib_RLPReader.RLPItem[] memory items = blockHeader
            .toRLPItem()
            .readList();
        return bytes32(items[3].readUint256()); // The state root is the 4th item in a block header
    }

    // get origin chain's receipt root on destination chain
    function getReceiptsRoot(
        uint256 blockNumber,
        bytes memory blockHeader
    ) public view returns (bytes32) {
        bool is_valid_header = getBlockHeader(blockNumber, blockHeader);
        require(is_valid_header, "Invalid block header");

        Lib_RLPReader.RLPItem[] memory items = blockHeader
            .toRLPItem()
            .readList();
        return bytes32(items[5].readUint256()); // The receipts root is the 6th item
    }

    // get origin chain's transaction root on destination chain
    function getTransactionRoot(
        uint256 blockNumber,
        bytes memory blockHeader
    ) public view returns (bytes32) {
        bool is_valid_header = getBlockHeader(blockNumber, blockHeader);
        require(is_valid_header, "Invalid block header");

        Lib_RLPReader.RLPItem[] memory items = blockHeader
            .toRLPItem()
            .readList();
        return bytes32(items[4].readUint256()); // The transactions root is the 5th item
    }

    // =================================
    // 4. Verifying Data Against the Chosen Root (Account)
    // =================================

    function verifyAccount(
        uint256 blockNumber,
        bytes memory blockHeader,
        bytes memory accountTrieProof,
        address account
    )
        public
        view
        returns (
            uint256 nonce,
            uint256 accountBalance,
            bytes32 codeHash,
            bytes32 storageRoot
        )
    {
        // Retrieve the root based on the specified type (valid)
        bytes32 stateRoot = getStateRoot(blockNumber, blockHeader);

        // Retrieve the key from the account
        bytes memory accountKey = abi.encodePacked(account);

        // Verify the account
        (bool doesAccountExist, bytes memory accountRLP) = Lib_SecureMerkleTrie
            .get(accountKey, accountTrieProof, stateRoot);

        // Decode the [`accountRLP`] into a struct
        (nonce, accountBalance, storageRoot, codeHash) = _decodeAccountFields(
            doesAccountExist,
            accountRLP
        );
    }

    // Helper function to rlp decode the account fields ( referenced from Herodotus [FactRegistry.sol](https://github.com/HerodotusDev/herodotus-evm/blob/553a49b1f85d44ef378de13fbbf58e4e944fc289/src/core/FactsRegistry.sol#L134C67-L134C67) )
    function _decodeAccountFields(
        bool doesAccountExist,
        bytes memory accountRLP
    )
        internal
        pure
        returns (
            uint256 nonce,
            uint256 balance,
            bytes32 storageRoot,
            bytes32 codeHash
        )
    {
        if (!doesAccountExist) {
            return (0, 0, EMPTY_TRIE_ROOT_HASH, EMPTY_CODE_HASH);
        }

        Lib_RLPReader.RLPItem[] memory accountFields = accountRLP
            .toRLPItem()
            .readList();

        nonce = accountFields[ACCOUNT_NONCE_INDEX].readUint256();
        balance = accountFields[ACCOUNT_BALANCE_INDEX].readUint256();
        codeHash = accountFields[ACCOUNT_CODE_HASH_INDEX].readBytes32();
        storageRoot = accountFields[ACCOUNT_STORAGE_ROOT_INDEX].readBytes32();
    }

    // =================================
    // 5. Verifying Data Against the Chosen Root (Storage)
    // =================================
    function verifyStorage(
        bytes32 storageRoot,
        bytes32 slot,
        bytes calldata storageSlotTrieProof
    ) public view returns (bytes32 slotValue) {
        // Get valid storage root from account ( Step 4 )

        // Retrieve the key from the storage slot
        bytes memory storageKey = abi.encodePacked(slot);

        // Verify the account
        (, bytes memory slotValueRLP) = Lib_SecureMerkleTrie.get(
            storageKey,
            storageSlotTrieProof,
            storageRoot
        );

        // Decode the [`slotValueRLP`] into a value
        slotValue = slotValueRLP.toRLPItem().readBytes32();
    }
}
