#![cfg(test)]

use crate::*;
use soroban_sdk::{Env, U256, Bytes, bytesn, vec};

/// Helper: build a U256 from a 32-byte big-endian hex constant
fn u256_hex(env: &Env, bytes: soroban_sdk::BytesN<32>) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_slice(env, &bytes.to_array()))
}

#[test]
fn test_hash_pair_1_2() {
    let env = Env::default();
    let result = poseidon2_hash_pair(&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2));
    let expected = u256_hex(&env, bytesn!(&env,
        0x2701c191a56f6c758a256482aad93d24b8304c2f0467001b1b54ee7040f68042));
    assert_eq!(result, expected);
}

#[test]
fn test_hash_single_42() {
    let env = Env::default();
    let result = poseidon2_hash_single(&env, U256::from_u32(&env, 42));
    let expected = u256_hex(&env, bytesn!(&env,
        0x0c1890923359b2af76925562a852aa9004d380499335715791ca25d2333432d4));
    assert_eq!(result, expected);
}

#[test]
fn test_hash_zero() {
    let env = Env::default();
    let result = poseidon2_hash_single(&env, U256::from_u32(&env, 0));
    let expected = u256_hex(&env, bytesn!(&env,
        0x0b4113e6bdb8f48ca9e03ed584ca04822969c634169d1d219b839f2830045913));
    assert_eq!(result, expected);
}

#[test]
fn test_hash_deterministic() {
    let env = Env::default();
    let a = poseidon2_hash_pair(&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2));
    let b = poseidon2_hash_pair(&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2));
    assert_eq!(a, b);
}

#[test]
fn test_hash_not_commutative() {
    // Swapping inputs must change the hash
    let env = Env::default();
    let h12 = poseidon2_hash_pair(&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2));
    let h21 = poseidon2_hash_pair(&env, U256::from_u32(&env, 2), U256::from_u32(&env, 1));

    let expected_12 = u256_hex(&env, bytesn!(&env,
        0x2701c191a56f6c758a256482aad93d24b8304c2f0467001b1b54ee7040f68042));
    let expected_21 = u256_hex(&env, bytesn!(&env,
        0x2261b8def7de4bb9eadb63bb534d767ea8c70500b810478bdf9c6747d1275a05));

    assert_eq!(h12, expected_12);
    assert_eq!(h21, expected_21);
    assert_ne!(h12, h21);
}

#[test]
fn test_hash_single_vs_pair_differ() {
    // hash([7]) != hash([7, 7])
    let env = Env::default();
    let single = poseidon2_hash_single(&env, U256::from_u32(&env, 7));
    let pair = poseidon2_hash_pair(&env, U256::from_u32(&env, 7), U256::from_u32(&env, 7));

    let expected_single = u256_hex(&env, bytesn!(&env,
        0x1e67c49cd10daad0b4b8788056aac59c0bcc37f8b924480842f6fbe6a3fb6e17));
    let expected_pair = u256_hex(&env, bytesn!(&env,
        0x1cfcecdb7d5f1da3e3951e65579e54e75b2ebd3832e8682920b0316be64dceea));

    assert_eq!(single, expected_single);
    assert_eq!(pair, expected_pair);
    assert_ne!(single, pair);
}

#[test]
fn test_hash_large_value() {
    // Value close to the BN254 modulus
    let env = Env::default();
    let big = u256_hex(&env, bytesn!(&env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff));
    let result = poseidon2_hash_single(&env, big);
    let expected = u256_hex(&env, bytesn!(&env,
        0x2ebe2ea4101ed41e481b032f3b6dbd72882e36f0c1bd8d22f4058319d582aa81));
    assert_eq!(result, expected);
}

#[test]
fn test_hash_multiple_elements() {
    // Hash 3 elements: hash(10, 20, 30)
    let env = Env::default();
    let inputs = vec![&env,
        U256::from_u32(&env, 10),
        U256::from_u32(&env, 20),
        U256::from_u32(&env, 30),
    ];
    let result = poseidon2_hash(&env, &inputs);
    let expected = u256_hex(&env, bytesn!(&env,
        0x1bb24d4ec0a621d344d38ecc77492363592d7685fb204e9c8f2ee7d4b2199b5c));
    assert_eq!(result, expected);
}

#[test]
fn test_double_hash() {
    // Double-hashing pattern used for leaf insertion: hash(hash(commitment))
    let env = Env::default();
    let inner = poseidon2_hash_single(&env, U256::from_u32(&env, 12345));
    let outer = poseidon2_hash_single(&env, inner.clone());

    let expected_inner = u256_hex(&env, bytesn!(&env,
        0x087c15ba45847b76952538b50ff7ebb3e26e9e0094a97c681048ce918b2bd4a8));
    let expected_outer = u256_hex(&env, bytesn!(&env,
        0x2a0c0e40ad90b6035cc43a6d0c69546cbda292e69c7cceebbd246409097e67cd));

    assert_eq!(inner, expected_inner);
    assert_eq!(outer, expected_outer);
    assert_ne!(inner, outer);
}

#[test]
fn test_field_add_basic() {
    let env = Env::default();
    let a = U256::from_u32(&env, 3);
    let b = U256::from_u32(&env, 5);
    let result = field_add(&env, a, b);
    assert_eq!(result, U256::from_u32(&env, 8));
}

#[test]
fn test_field_add_wraps_around_modulus() {
    // (modulus - 1) + 2 should wrap to 1
    let env = Env::default();
    let modulus_minus_1 = u256_hex(&env, bytesn!(&env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000));
    let two = U256::from_u32(&env, 2);
    let result = field_add(&env, modulus_minus_1, two);
    assert_eq!(result, U256::from_u32(&env, 1));
}
