#[starknet::interface]
trait IStarknetStorageProofs<TContractState> {
    fn get_block_hash(self: @TContractState, block_number: u64) -> felt252;
    fn get_block_header(
        self: @TContractState,
        block_number: felt252,
        global_state_root: felt252,
        sequencer_address: felt252,
        block_timestamp: felt252,
        transaction_count: felt252,
        transaction_commitment: felt252,
        event_count: felt252,
        event_commitment: felt252,
        parent_block_hash: felt252
    ) -> bool;
    fn get_state_root(
        self: @TContractState,
        block_number: felt252,
        global_state_root: felt252,
        sequencer_address: felt252,
        block_timestamp: felt252,
        transaction_count: felt252,
        transaction_commitment: felt252,
        event_count: felt252,
        event_commitment: felt252,
        parent_block_hash: felt252
    ) -> felt252;
}


#[starknet::contract]
mod StarknetStorageProofs {
    use core::traits::TryInto;
    use core::hash::HashStateTrait;
    use core::result::ResultTrait;
    use core::box::BoxTrait;
    use core::pedersen::PedersenImpl;
    use core::pedersen::PedersenTrait;
    use starknet::get_block_info;
    use starknet::get_block_hash_syscall;
    use cairo_lib::utils::types::words64::Words64;

    type Headers = Span<Words64>;

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

        // =================================
        // 2. Accessing the block header
        // =================================

        // verify origin chain's block header on destination chain
        fn get_block_header(
            self: @ContractState,
            block_number: felt252,
            global_state_root: felt252,
            sequencer_address: felt252,
            block_timestamp: felt252,
            transaction_count: felt252,
            transaction_commitment: felt252,
            event_count: felt252,
            event_commitment: felt252,
            parent_block_hash: felt252
        ) -> bool {
            // Step 1. Retrieve the block hash
            let block_number_u64: u64 = block_number.try_into().unwrap();
            let retrieved_block_hash = get_block_hash_syscall(block_number_u64).unwrap();

            let hash_pedersen = PedersenImpl::new(0);
            hash_pedersen.update(block_number);
            hash_pedersen.update(global_state_root);
            hash_pedersen.update(sequencer_address);
            hash_pedersen.update(block_timestamp);
            hash_pedersen.update(transaction_count);
            hash_pedersen.update(transaction_commitment);
            hash_pedersen.update(event_count);
            hash_pedersen.update(event_commitment);
            hash_pedersen.update(0);
            hash_pedersen.update(0);
            hash_pedersen.update(parent_block_hash);
            // Step 2. Hash the provided block header and compare
            let provided_block_header_hash = hash_pedersen.finalize();

            // Step 3. Verify it
            if provided_block_header_hash == retrieved_block_hash {
                return true;
            } else {
                return false;
            }
        }
        // =================================
        // 3. Determining the Desired Root
        // =================================

        // get origin chain's state root on destination chain
        fn get_state_root(
            self: @ContractState,
            block_number: felt252,
            global_state_root: felt252,
            sequencer_address: felt252,
            block_timestamp: felt252,
            transaction_count: felt252,
            transaction_commitment: felt252,
            event_count: felt252,
            event_commitment: felt252,
            parent_block_hash: felt252
        ) -> felt252 {
            let is_valid_header = self
                .get_block_header(
                    block_number,
                    global_state_root,
                    sequencer_address,
                    block_timestamp,
                    transaction_count,
                    transaction_commitment,
                    event_count,
                    event_commitment,
                    parent_block_hash
                );
            assert(is_valid_header, 'Invalid block header');

            return global_state_root;
        }
    }
}
