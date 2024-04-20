use ethers::utils::hex;
use rlp::{Encodable, RlpStream};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct EvmBlockHeader {
    pub parent_hash: String,
    pub uncle_hash: String,
    pub coinbase: String,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
    pub logs_bloom: String,
    pub difficulty: u64,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: String,
    pub mix_hash: String,
    pub nonce: String,
    pub base_fee_per_gas: Option<u64>,
    pub withdrawals_root: Option<String>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EvmBlockHeaderFromRpc {
    pub number: String,
    pub hash: String,
    pub difficulty: String,
    pub extra_data: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub logs_bloom: String,
    pub miner: String,
    pub mix_hash: String,
    pub nonce: String,
    pub parent_hash: String,
    pub receipts_root: String,
    pub sha3_uncles: String,
    pub size: String,
    pub state_root: String,
    pub timestamp: String,
    pub total_difficulty: String,
    pub transactions_root: String,
    pub base_fee_per_gas: Option<String>,
    pub withdrawals_root: Option<String>,
    pub blob_gas_used: Option<String>,
    pub excess_blob_gas: Option<String>,
    pub parent_beacon_block_root: Option<String>,
}

impl From<&EvmBlockHeaderFromRpc> for EvmBlockHeader {
    fn from(value: &EvmBlockHeaderFromRpc) -> Self {
        Self {
            parent_hash: value.parent_hash.clone(),
            uncle_hash: value.sha3_uncles.clone(),
            coinbase: value.miner.clone(),
            state_root: value.state_root.clone(),
            transactions_root: value.transactions_root.clone(),
            receipts_root: value.receipts_root.clone(),
            logs_bloom: value.logs_bloom.clone(),
            difficulty: value.difficulty.clone().parse::<u64>().unwrap(),
            number: value.number.clone().parse::<u64>().unwrap(),
            gas_limit: value.gas_limit.clone().parse::<u64>().unwrap(),
            gas_used: value.gas_used.clone().parse::<u64>().unwrap(),
            timestamp: value.timestamp.clone().parse::<u64>().unwrap(),
            extra_data: value.extra_data.clone(),
            mix_hash: value.mix_hash.clone(),
            nonce: value.nonce.clone(),
            base_fee_per_gas: value
                .clone()
                .base_fee_per_gas
                .map(|x| x.parse::<u64>().unwrap()),
            withdrawals_root: value.withdrawals_root.clone(),
            blob_gas_used: value.blob_gas_used.clone().map(|x| x.parse::<u64>().unwrap()),
            excess_blob_gas: value.excess_blob_gas.clone().map(|x| x.parse::<u64>().unwrap()),
            parent_beacon_block_root: value.parent_beacon_block_root.clone(),
        }
    }
}

impl Encodable for EvmBlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(
            15 + self.base_fee_per_gas.is_some() as usize
                + self.withdrawals_root.is_some() as usize
                + self.blob_gas_used.is_some() as usize
                + self.excess_blob_gas.is_some() as usize
                + self.parent_beacon_block_root.is_some() as usize,
        );

        s.append(&safe_hex_decode(&self.parent_hash));
        s.append(&safe_hex_decode(&self.uncle_hash));
        s.append(&safe_hex_decode(&self.coinbase));
        s.append(&safe_hex_decode(&self.state_root));
        s.append(&safe_hex_decode(&self.transactions_root));
        s.append(&safe_hex_decode(&self.receipts_root));
        s.append(&safe_hex_decode(&self.logs_bloom));

        // Numeric fields can be appended directly if they are already u64
        s.append(&self.difficulty);
        s.append(&self.number);
        s.append(&self.gas_limit);
        s.append(&self.gas_used);
        s.append(&self.timestamp);

        s.append(&safe_hex_decode(&self.extra_data));
        s.append(&safe_hex_decode(&self.mix_hash));
        s.append(&safe_hex_decode(&self.nonce));

        if let Some(base_fee) = self.base_fee_per_gas {
            s.append(&base_fee);
        }

        if let Some(ref withdrawals_root) = self.withdrawals_root {
            s.append(&safe_hex_decode(withdrawals_root));
        }

        if let Some(blob_gas_used) = self.blob_gas_used {
            s.append(&blob_gas_used);
        }

        if let Some(excess_blob_gas) = self.excess_blob_gas {
            s.append(&excess_blob_gas);
        }

        if let Some(ref parent_beacon_block_root) = self.parent_beacon_block_root {
            s.append(&safe_hex_decode(parent_beacon_block_root));
        }
    }
}

fn safe_hex_decode(s: &str) -> Vec<u8> {
    // Ensure the string is without the '0x' prefix
    let s = if let Some(s) = s.strip_prefix("0x") {
        s
    } else {
        s
    };

    // Pad the string with a leading zero if it has an odd length
    let s = if s.len() % 2 != 0 {
        format!("0{}", s)
    } else {
        s.to_string()
    };

    hex::decode(s).unwrap()
}
