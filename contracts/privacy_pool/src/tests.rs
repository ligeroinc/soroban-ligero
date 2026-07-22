#![cfg(test)]

use super::*;
use soroban_sdk::{Env, U256, Vec, vec, testutils::{Address as _, Ledger as _}};

// ============================================================================
// Batched insertion parity
// ============================================================================
//
// For the same sequence of note commitments, a single batched insert_leaves
// call must produce the same merkle root as N sequential single-leaf inserts.
// These tests use the `t_insert_leaves` test-only entry point so they don't
// have to set up signing / token / authorization for fund/withdraw.

fn deploy(env: &Env) -> ContractClient<'_> {
    let owner = Address::generate(env);
    let id = env.register(Contract, (owner,));
    ContractClient::new(env, &id)
}

#[test]
fn insert_leaves_batch_equals_sequential() {
    let sizes: [u32; 6] = [
        1,  // single leaf — equivalent to old single-leaf API
        2,  // even, no level-0 padding
        3,  // odd → padding at level 0
        5,  // odd, three levels
        7,  // odd at multiple levels
        10, // even, four levels
    ];

    for (s, &count) in sizes.iter().enumerate() {
        let env = Env::default();
        let pool_a = deploy(&env);
        let pool_b = deploy(&env);

        // Pool A: one batched insert of `count` leaves.
        let mut batch: Vec<U256> = Vec::new(&env);
        for i in 0..count {
            batch.push_back(U256::from_u32(&env, 1000 + s as u32 * 100 + i));
        }
        pool_a.t_insert_leaves(&batch);

        // Pool B: `count` sequential single-leaf inserts.
        for i in 0..count {
            let single = vec![&env, U256::from_u32(&env, 1000 + s as u32 * 100 + i)];
            pool_b.t_insert_leaves(&single);
        }

        assert_eq!(pool_a.get_root(), pool_b.get_root(), "root mismatch at size {}", count);
        assert_eq!(pool_a.get_number_of_levels(), pool_b.get_number_of_levels(), "levels mismatch at size {}", count);
        assert_ne!(pool_a.get_root(), U256::from_u32(&env, 0), "root not set at size {}", count);
    }
}

// Cross-batch parity: a sequence of batches of varying sizes must produce the
// same root as inserting the same flattened sequence one-at-a-time. Exercises
// the dummy-replace branch when a prior batch left odd padding at level 0.
#[test]
fn insert_leaves_mixed_batches_equals_sequential() {
    let env = Env::default();
    let pool_a = deploy(&env);
    let pool_b = deploy(&env);

    let batch1 = vec![
        &env,
        U256::from_u32(&env, 11),
        U256::from_u32(&env, 22),
        U256::from_u32(&env, 33),
    ];
    let batch2 = vec![
        &env,
        U256::from_u32(&env, 44),
        U256::from_u32(&env, 55),
    ];
    let batch3 = vec![
        &env,
        U256::from_u32(&env, 66),
        U256::from_u32(&env, 77),
        U256::from_u32(&env, 88),
        U256::from_u32(&env, 99),
    ];

    pool_a.t_insert_leaves(&batch1);
    pool_a.t_insert_leaves(&batch2);
    pool_a.t_insert_leaves(&batch3);

    let flat: [u32; 9] = [11, 22, 33, 44, 55, 66, 77, 88, 99];
    for &v in &flat {
        let single = vec![&env, U256::from_u32(&env, v)];
        pool_b.t_insert_leaves(&single);
    }

    assert_eq!(pool_a.get_root(), pool_b.get_root());
    assert_eq!(pool_a.get_number_of_levels(), pool_b.get_number_of_levels());
}

// ============================================================================
// Frontier differential + bounded root history
// ============================================================================

/// Independent FULL-tree oracle: level 0 = hash(hash(note commitment), block height), fold upward
/// padding odd levels with a single 0, dynamic depth. Uses the contract's own Poseidon so only the
/// tree CONSTRUCTION (full array vs frontier) differs — a true differential check against the
/// on-chain root.
fn oracle_root(env: &Env, pool: &ContractClient, ncs: &Vec<u32>) -> U256 {
    if ncs.len() == 0 {
        return U256::from_u32(env, 0);
    }
    let zero = U256::from_u32(env, 0);
    let block_height = U256::from_u32(env, env.ledger().sequence());
    let mut level: Vec<U256> = Vec::new(env);
    for nc in ncs.iter() {
        // note_commitment_hash = SINGLE Poseidon hash (parity with EVM/Solana/circuit).
        let h1 = pool.hash_single(&U256::from_u32(env, nc));
        level.push_back(pool.hash_pair(&h1, &block_height));
    }
    while level.len() > 1 {
        let m = level.len();
        let padded = m + (m % 2);
        let mut next: Vec<U256> = Vec::new(env);
        let mut i = 0;
        while i < padded {
            let l = level.get_unchecked(i);
            let r = if i + 1 < m { level.get_unchecked(i + 1) } else { zero.clone() };
            next.push_back(pool.hash_pair(&l, &r));
            i += 2;
        }
        level = next;
    }
    level.get_unchecked(0)
}

#[test]
fn inserted_leaf_binds_note_commitment_hash_to_block_height() {
    let env = Env::default();
    env.ledger().set_sequence_number(12345);
    let pool = deploy(&env);
    let commitment = U256::from_u32(&env, 12345);
    let batch = vec![&env, commitment.clone()];

    pool.t_insert_leaves(&batch);

    let hashes = pool.get_hashes();
    let level0 = hashes.get_unchecked(0);
    let inserted_leaf = level0.get_unchecked(0);
    // note_commitment_hash = hash_single(nc); the old height-less leaf was hash_pair(that, 0).
    let note_commitment_hash = pool.hash_single(&commitment);
    let block_height = U256::from_u32(&env, env.ledger().sequence());
    let expected_leaf = pool.hash_pair(&note_commitment_hash, &block_height);
    let old_leaf_without_height = pool.hash_pair(&note_commitment_hash, &U256::from_u32(&env, 0));
    let wrong_height_leaf = pool.hash_pair(
        &note_commitment_hash,
        &U256::from_u32(&env, env.ledger().sequence() + 1),
    );

    assert_eq!(inserted_leaf, expected_leaf);
    assert_ne!(inserted_leaf, old_leaf_without_height);
    assert_ne!(inserted_leaf, wrong_height_leaf);
}

#[test]
fn same_commitment_in_different_blocks_gets_distinct_leaves() {
    let env = Env::default();
    let pool = deploy(&env);
    let commitment = U256::from_u32(&env, 777);
    let batch = vec![&env, commitment.clone()];

    env.ledger().set_sequence_number(111);
    pool.t_insert_leaves(&batch);
    env.ledger().set_sequence_number(222);
    pool.t_insert_leaves(&batch);

    let hashes = pool.get_hashes();
    let level0 = hashes.get_unchecked(0);
    let note_commitment_hash = pool.hash_single(&commitment);
    let first_leaf = pool.hash_pair(&note_commitment_hash, &U256::from_u32(&env, 111));
    let second_leaf = pool.hash_pair(&note_commitment_hash, &U256::from_u32(&env, 222));

    assert_eq!(level0.get_unchecked(0), first_leaf);
    assert_eq!(level0.get_unchecked(1), second_leaf);
    assert_ne!(first_leaf, second_leaf);
}

/// Randomized insert sequences (varied batch sizes crossing odd/even and depth-growth boundaries):
/// the frontier-storage root must equal the full-tree oracle at every step.
#[test]
fn frontier_matches_full_tree_randomized() {
    for trial in 0..6u32 {
        let env = Env::default();
        let pool = deploy(&env);
        let mut all: Vec<u32> = Vec::new(&env);
        let mut nc: u32 = 1;
        // Deterministic pseudo-random batch sizes 1..=4, varied per trial.
        let mut state: u32 = 0x9E3779B9u32.wrapping_add(trial.wrapping_mul(2654435761));
        for _ in 0..25 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            let batch_size = (state % 4) + 1;
            let mut batch: Vec<U256> = Vec::new(&env);
            for _ in 0..batch_size {
                batch.push_back(U256::from_u32(&env, nc));
                all.push_back(nc);
                nc += 1;
            }
            pool.t_insert_leaves(&batch);
            assert_eq!(pool.get_root(), oracle_root(&env, &pool, &all), "frontier root != full-tree root");
        }
        assert_ne!(pool.get_root(), U256::from_u32(&env, 0), "root not set");
    }
}

/// Root history is a bounded ring of ROOT_HISTORY_SIZE: a root stays valid for exactly that many
/// subsequent roots, then is evicted. The empty-tree root 0 stays valid forever.
#[test]
fn root_history_window_eviction() {
    let env = Env::default();
    let pool = deploy(&env);
    let window = ROOT_HISTORY_SIZE;

    let first = vec![&env, U256::from_u32(&env, 1)];
    pool.t_insert_leaves(&first);
    let first_root = pool.get_root();
    assert!(pool.t_root_valid(&first_root), "first root valid");

    // Fund up to `window` total roots: first_root must still be inside the window.
    for k in 2..=window {
        let single = vec![&env, U256::from_u32(&env, k)];
        pool.t_insert_leaves(&single);
    }
    assert!(pool.t_root_valid(&first_root), "first root still valid at window edge");
    assert!(pool.t_root_valid(&U256::from_u32(&env, 0)), "empty-tree root always valid");

    // One more push evicts the slot holding first_root.
    let extra = vec![&env, U256::from_u32(&env, window + 1)];
    pool.t_insert_leaves(&extra);
    assert!(!pool.t_root_valid(&first_root), "first root evicted past the window");
    assert!(pool.t_root_valid(&pool.get_root()), "current root valid");
    assert!(pool.t_root_valid(&U256::from_u32(&env, 0)), "empty-tree root still valid after wrap");
}
