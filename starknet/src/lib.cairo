use alexandria_merkle_tree::storage_proof::TrieNode;
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
    fn get_contract_trie_root(
        self: @TContractState,
        block_number: felt252,
        global_state_root: felt252,
        contract_trie_root: felt252,
        class_trie_root: felt252
    ) -> felt252;
    fn verify_contract(
        self: @TContractState,
        block_number: felt252,
        contract_trie_root: felt252,
        contract_trie_proof: Span<felt252>,
        class_hash: felt252,
        storage_root: felt252,
        nonce: felt252,
        contract_state_hash_version: felt252,
    ) -> (felt252, felt252, felt252, felt252);
    fn verify_storage(
        self: @TContractState,
        state_commitment: felt252,
        class_commitment: felt252,
        contract_address: felt252,
        storage_address: felt252,
        storage_trie_proof: Span<felt252>,
        contract_trie_proof: Span<felt252>,
        class_hash: felt252,
        storage_root: felt252,
        nonce: felt252,
        contract_state_hash_version: felt252,
    ) -> felt252;
}


#[starknet::contract]
mod StarknetStorageProofs {
    use core::array::ArrayTrait;
    use core::traits::TryInto;
    use core::hash::HashStateTrait;
    use core::result::ResultTrait;
    use core::box::BoxTrait;
    use core::pedersen::PedersenImpl;
    use core::pedersen::PedersenTrait;
    use core::poseidon::PoseidonImpl;
    use core::poseidon::PoseidonTrait;
    use starknet::get_block_info;
    use starknet::get_block_hash_syscall;
    use cairo_lib::utils::types::words64::Words64;
    use alexandria_merkle_tree::merkle_tree::{
        Hasher, MerkleTree, pedersen::PedersenHasherImpl, MerkleTreeTrait,
    };
    use alexandria_merkle_tree::storage_proof::{
        ContractStateProof, ContractData, TrieNode, BinaryNode, EdgeNode, verify
    };

    //? TODO: How to cast in correct format?
    fn cast_proof_type(mut proof: Span<felt252>) -> Array<TrieNode> {
        let mut result: Array<TrieNode> = array![];
        loop {
            match proof.pop_front() {
                Option::Some(proof_element) => {
                    let edge_node = TrieNode::Binary(
                        BinaryNode {
                            left: *proof.pop_front().unwrap(), right: *proof.pop_front().unwrap(),
                        }
                    );
                    result.append(edge_node);
                },
                Option::None => { break; },
            }
        };
        result
    }

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
        // 3. Determining the Desired Root (Contract tree root)
        // =================================

        // get origin chain's contract_trie_root on destination chain
        fn get_contract_trie_root(
            self: @ContractState,
            block_number: felt252,
            global_state_root: felt252,
            contract_trie_root: felt252,
            class_trie_root: felt252
        ) -> felt252 {
            // Step 1. Construct the state commitment
            let hash_poseidon = PoseidonImpl::new();
            hash_poseidon.update('STARKNET_STATE_V0');
            hash_poseidon.update(contract_trie_root);
            hash_poseidon.update(class_trie_root);
            let state_commitment = hash_poseidon.finalize();

            // Step 2. Verify the state commitment
            assert(state_commitment == global_state_root, 'state commitment does not match');

            return contract_trie_root;
        }

        // =================================
        // 4. Verifying Data Against the Chosen Root (Contract)
        // =================================

        fn verify_contract(
            self: @ContractState,
            block_number: felt252,
            contract_trie_root: felt252,
            contract_trie_proof: Span<felt252>,
            class_hash: felt252,
            storage_root: felt252,
            nonce: felt252,
            contract_state_hash_version: felt252,
        ) -> (felt252, felt252, felt252, felt252) {
            // Step 1. Compute the leaf of contract trie
            let hash_pedersen = PedersenImpl::new(0);
            hash_pedersen.update(class_hash);
            hash_pedersen.update(storage_root);
            hash_pedersen.update(nonce);
            hash_pedersen.update(contract_state_hash_version);
            let contract_leaf = hash_pedersen.finalize();

            // Step 2. Verify the root
            let mut merkle_tree: MerkleTree<Hasher> = MerkleTreeTrait::new();
            let computed_root = merkle_tree.compute_root(contract_leaf, contract_trie_proof);
            assert(computed_root == contract_trie_root, 'compute valid root failed');

            // Step 3. Verify the proof
            let result = merkle_tree.verify(computed_root, contract_leaf, contract_trie_proof);
            assert(result, 'verify valid proof failed');

            return (class_hash, storage_root, nonce, contract_state_hash_version);
        }

        // =================================
        // 5. Verifying Data Against the Chosen Root (Storage)
        // =================================
        fn verify_storage(
            self: @ContractState,
            state_commitment: felt252,
            class_commitment: felt252,
            contract_address: felt252,
            storage_address: felt252,
            storage_trie_proof: Span<felt252>,
            contract_trie_proof: Span<felt252>,
            class_hash: felt252,
            storage_root: felt252,
            nonce: felt252,
            contract_state_hash_version: felt252,
        ) -> felt252 {
            let storage_proof = ContractStateProof {
                class_commitment,
                contract_data: ContractData {
                    class_hash,
                    nonce,
                    contract_state_hash_version,
                    storage_proof: cast_proof_type(storage_trie_proof),
                },
                contract_proof: cast_proof_type(contract_trie_proof),
            };

            let storage_value = verify(
                state_commitment, contract_address, storage_address, storage_proof
            );
            return storage_value;
        }
    }
}

