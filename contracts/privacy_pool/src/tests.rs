#![cfg(test)]

use super::*;
use soroban_sdk::{Env, U256, Vec, vec, testutils::Address as _};

#[test]
fn whitelist_enabled_flag_true_is_persisted() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(Contract, (owner, true));
    let client = ContractClient::new(&env, &contract_id);
    assert!(client.whitelist_enabled());
}

#[test]
fn whitelist_enabled_flag_false_is_persisted() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(Contract, (owner, false));
    let client = ContractClient::new(&env, &contract_id);
    assert!(!client.whitelist_enabled());
}

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
    let id = env.register(Contract, (owner, false));
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
