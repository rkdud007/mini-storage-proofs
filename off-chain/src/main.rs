use std::vec;

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

pub async fn get_encoded_block_header(rpc_provider: &Provider<Http>) -> Result<u64> {
    let block = rpc_provider.get_block(BlockNumber::Latest).await?.unwrap();

    println!("block number: {:?}\n", block.number);

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
        withdrawals_root: block.withdrawals_root.map(hex::encode),
    };

    let evm_block_header = EvmBlockHeader::from(&header_from_rpc);

    println!("{:#?}", evm_block_header);

    let encoded_block_header = encode_block_header(&evm_block_header);
    let blockheader_hex = hex::encode(&encoded_block_header);
    println!("Hexadecimal Block Header: 0x{}\n", blockheader_hex);

    let blockhash = keccak256(encoded_block_header);
    let blockhash_hex = hex::encode(blockhash);

    println!("Hexadecimal Block Hash: 0x{}\n", blockhash_hex);

    Ok(evm_block_header.number)
}

async fn get_account_proof(
    blocknumber: u64,
    rpc_provider: &Provider<Http>,
    account: &str,
) -> Result<()> {
    let proof_response = rpc_provider
        .get_proof(
            account,
            vec![H256::zero()],
            Some(BlockId::Number(BlockNumber::Number(blocknumber.into()))),
        )
        .await?;

    let account_proofs = proof_response.account_proof;
    let proofs = concatenate_proof(account_proofs);
    let rlp_encoded_proof = encode_rlp(proofs);
    let proof_hex = hex::encode(rlp_encoded_proof);
    println!("proof: 0x{}\n", proof_hex);
    println!("account: {:?}\n", account);

    Ok(())
}

fn concatenate_proof(account_proof: Vec<ethers::types::Bytes>) -> Vec<Vec<u8>> {
    let mut proofs: Vec<Vec<u8>> = Vec::new();
    for node in account_proof {
        proofs.push(node.to_vec()); // Convert each Bytes to Vec<u8> and push to proofs
    }
    proofs
}

fn encode_rlp(proofs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut stream = RlpStream::new();
    stream.begin_list(proofs.len()); // Begin a list to encode the array structure
    for proof in proofs {
        stream.append(&proof); // Append each proof as raw bytes
    }
    stream.out().to_vec() // Get the RLP-encoded bytes
}

async fn get_storage_proof(
    blocknumber: u64,
    rpc_provider: &Provider<Http>,
    account: &str,
    slot: H256,
) -> Result<()> {
    let proof_response = rpc_provider
        .get_proof(
            account,
            vec![slot],
            Some(BlockId::Number(BlockNumber::Number(blocknumber.into()))),
        )
        .await?;

    let storageproof = proof_response.storage_proof;
    let proofs = concatenate_proof(storageproof[0].proof.clone());
    let rlp_encoded_proof = encode_rlp(proofs);
    let proof_hex = hex::encode(rlp_encoded_proof);
    println!("storage proof: 0x{}\n", proof_hex);
    println!("storage account: {:?}\n", account);

    Ok(())
}

#[tokio::main]
async fn main() {
    let rpc_provider = Provider::<Http>::try_from(
        "https://eth-goerli.g.alchemy.com/v2/gfIH02sddAK81ihHEZcniDlaERa3D7d4",
    )
    .unwrap();
    let blocknumber = get_encoded_block_header(&rpc_provider).await.unwrap();
    // Random account
    let account = "0x3073F6Cd5799d754Ea93FcF54c53afd802477983";
    let _ = get_account_proof(blocknumber, &rpc_provider, account).await;

    // Goerli USDC contract address
    let account = "0xd35CCeEAD182dcee0F148EbaC9447DA2c4D449c4";
    let storage_slot = H256::zero();
    let _ = get_storage_proof(blocknumber, &rpc_provider, account, storage_slot).await;
}
