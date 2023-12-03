use std::{sync::Arc, vec};

use anyhow::Result;
use ethers::{prelude::*, utils::keccak256};
use rlp::{Encodable, RlpStream};

use crate::blockheader::{EvmBlockHeader, EvmBlockHeaderFromRpc};

mod blockheader;

fn encode_block_header(header: &EvmBlockHeader) -> Vec<u8> {
    let mut stream = RlpStream::new();
    header.rlp_append(&mut stream);
    stream.out().to_vec()
}

pub async fn get_encoded_block_header() -> Result<()> {
    let client = Provider::<Http>::try_from(
        "https://eth-goerli.g.alchemy.com/v2/OxCXO750oi6BTN1kndUMScfn6a16gFIm",
    )
    .expect("could not instantiate HTTP Provider");

    let client = Arc::new(client);

    let block = client.get_block(BlockNumber::Latest).await?.unwrap();

    println!("{:?}", block.number);

    let header_from_rpc = EvmBlockHeaderFromRpc {
        number: block.number.unwrap().as_u64().to_string(),
        hash: hex::encode(block.hash.unwrap()),
        difficulty: block.difficulty.to_string(),
        extra_data: hex::encode(block.extra_data),
        gas_limit: block.gas_limit.to_string(),
        gas_used: block.gas_used.to_string(),
        logs_bloom: hex::encode(block.logs_bloom.unwrap()),
        miner: hex::encode(block.author.unwrap()),
        mix_hash: hex::encode(block.mix_hash.unwrap()),
        nonce: hex::encode(block.nonce.unwrap()),
        parent_hash: hex::encode(block.parent_hash),
        receipts_root: hex::encode(block.receipts_root),
        sha3_uncles: hex::encode(block.uncles_hash),
        size: block.size.unwrap().to_string(),
        state_root: hex::encode(block.state_root),
        timestamp: block.timestamp.to_string(),
        total_difficulty: block.total_difficulty.unwrap().to_string(),
        transactions_root: hex::encode(block.transactions_root),
        base_fee_per_gas: block.base_fee_per_gas.map(|value| value.to_string()),
        withdrawals_root: block.withdrawals_root.map(|value| hex::encode(value)),
    };

    // println!("{:#?}\n", header_from_rpc);

    let evm_block_header = EvmBlockHeader::from(&header_from_rpc);

    println!("{:#?}", evm_block_header);

    let encoded_block_header = encode_block_header(&evm_block_header);
    let blockheader_hex = hex::encode(&encoded_block_header);
    println!("Hexadecimal Block Header: 0x{}", blockheader_hex);

    let blockhash = keccak256(encoded_block_header);
    let blockhash_hex = hex::encode(blockhash);

    println!("Hexadecimal Block Hash: 0x{}", blockhash_hex);

    Ok(())
}

async fn get_merkle_proof() -> Result<()> {
    let client = Provider::<Http>::try_from(
        "https://eth-goerli.g.alchemy.com/v2/OxCXO750oi6BTN1kndUMScfn6a16gFIm",
    )
    .expect("could not instantiate HTTP Provider");

    let client = Arc::new(client);

    let proof_response = client
        .get_proof(
            "0x3073F6Cd5799d754Ea93FcF54c53afd802477983",
            vec![],
            Some(BlockId::Number(BlockNumber::Latest)),
        )
        .await?;

    println!("{:#?}", proof_response);
    let mut account_proofs = vec![];
    for account_proof in proof_response.account_proof {
        account_proofs.push(account_proof.to_string());
    }

    println!("{:#?}", account_proofs);

    Ok(())
}

#[tokio::main]
async fn main() {
    let _ = get_encoded_block_header().await;
    let _ = get_merkle_proof().await;
}
