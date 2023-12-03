# Mini Storage Proof

**This project is personal project and atm working in progress. Fixing minor issuses and working on starknet contracts**

This is mini storage proof project, goal is to simplify the whole workflow with minimum implementation from accessing data on chain in trust-less way. This repo forrlowing [Herodotus Storage Proof Workflow](https://docs.herodotus.dev/herodotus-docs/developers/storage-proofs/workflow)

## 1. Accessing the block hash(evm/EVMStorageproof.sol)

In this case used `BLOCKHASH` opcode to access block hash. If want to access older than 256 blocks from latest block, need [historical accumulator](https://docs.herodotus.dev/herodotus-docs/protocol-design/historical-block-hash-accumulator) to store all block hashes onchain in trust-less manner.

```js
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
```

## 2. Accessing the block header(evm/EVMStorageproof.sol & off-chain)

First get block header through off-chain.

```rust
pub async fn get_encoded_block_header() -> Result<()> {
    let block = client.get_block(BlockNumber::Latest).await?.unwrap();
    ...
}
```

<details>
<summary> The result block header bytes will looks like this:</summary>
<div markdown="1">

```
 0xf90236a026cce44dd5ba58adae56e4276aeeaa5a792f5fafc294592ca3e8d29e74f87de1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a05cce51e7db6bf1e2b4ed181f128af4e520366d5e8bb76be4c3751ca0fac93d86a091751be0fd141d7d984b391aad90dcd0d28e42dd9e7c1852d0cf9e2c89170b14a0af86bc4b0c363740f2e144b748f467d0fb72c45e75ed80384052ebb046534d7bb90100020148492000002800000000620101002030051202008901018204020e00000200008804040a00021c00104000002000084100f0c800130c02400418002c2224e1024004a8000010900052098000800400050007020608100048100004108820100090040202404000400080000008010cb000410508000404004010488c60c1a02400ca189009c0240010c00200024080200040102002d01c04428805000000420c80002001380283000010200000280617000000000004000d030400000100900008e2406040448002a000010040080000202000884004001100200843e002043810040021a000000102000000280d000900101200c0c9000000000042060080839ae0728401c9c38083617f1984656c603499d883010b04846765746888676f312e32302e32856c696e7578a0af372462b5534d9942ccaec13fcfabeb44b081fdb28de99b82d401ce212ae5f78800000000000000000da05f6ec98a32825667e4a87a4aeefb6fda5115ccc53b244467e4a86480a98590ac
```

</div>
</details>

Next, pass this block header as input in contract to verify with block hash that we retrieve in previous step:

```js
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
```

## 3. Determining the Desired Root (Optional)(evm/EVMStorageproof.sol)

If you can get verified block header, you could decode it to get any kind of values that you want. But first we need root value for it.

```js
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

```

## 4. Verifying Data Against the Chosen Root (Optional) (evm/EVMStorageproof.sol & off-chain)

You might want to retrieve specific values beneath those root. In this case, first need to generate compatible inclusion proof in off chain

```rust
let proof_response = client
        .get_proof(
            "0x3073F6Cd5799d754Ea93FcF54c53afd802477983",
            vec![H256::zero()],
            Some(BlockId::Number(BlockNumber::Latest)),
        )
        .await?;

```

Then pass the proof in verify function with other values

```js
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
```
