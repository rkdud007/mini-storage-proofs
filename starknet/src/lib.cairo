#[starknet::interface]
trait IStarknetStorageProofs<TContractState> {
    fn get_block_hash(self: @TContractState, block_number: u64) -> felt252;
//fn get_block_header(self: @TContractState, block_number: u64) -> felt252;
}

#[starknet::contract]
mod StarknetStorageProofs {
    use core::result::ResultTrait;
    use core::box::BoxTrait;
    use starknet::get_block_info;
    use starknet::get_block_hash_syscall;

    #[storage]
    struct Storage {
        balance: felt252,
    }

    #[abi(embed_v0)]
    impl StarknetStorageProofsImpl of super::IStarknetStorageProofs<ContractState> {
        // =================================
        // Step 1. Accessing the block hash
        // =================================

        // get origin chain's block hash on destination chain
        fn get_block_hash(self: @ContractState, block_number: u64) -> felt252 {
            let latest_block_number: u64 = get_block_info().unbox().block_number;
            assert(block_number >= latest_block_number - 256, 'Block number is too old');
            assert(block_number < latest_block_number, 'Block number is too high');

            get_block_hash_syscall(block_number).unwrap()
        }
    }
}
