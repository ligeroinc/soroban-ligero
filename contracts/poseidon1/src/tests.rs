#![cfg(test)]

use crate::field::Fp;
use crate::*;
use soroban_sdk::{bytesn, Bytes, BytesN, Env, U256};

// --- helpers ---

/// Build a U256 from a 32-byte big-endian constant.
fn u256_hex(env: &Env, bytes: BytesN<32>) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_slice(env, &bytes.to_array()))
}

/// Build an Fp from a small u64 (for field unit tests).
fn fp_u64(v: u64) -> Fp {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&v.to_be_bytes());
    Fp::from_be_bytes(&b)
}

/// Build an Fp from a 32-byte big-endian constant.
fn fp_hex(bytes: &BytesN<32>) -> Fp {
    Fp::from_be_bytes(&bytes.to_array())
}

// ============================================================================
// Parity vectors. All values produced by the authoritative reference
// ligeroclear/public/assets/poseidon1.js (== sol_poseidon).
// ============================================================================

#[test]
fn test_sdk_2to1_anchor() {
    // The published Ligetron SDK example vector:
    // inputs 0x01..01 and 0x02..02. This is the cross-platform parity anchor.
    let env = Env::default();
    let a = u256_hex(
        &env,
        bytesn!(&env, 0x0101010101010101010101010101010101010101010101010101010101010101),
    );
    let b = u256_hex(
        &env,
        bytesn!(&env, 0x0202020202020202020202020202020202020202020202020202020202020202),
    );
    let result = poseidon1_hash_pair(&env, a, b);
    let expected = u256_hex(
        &env,
        bytesn!(&env, 0x0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990),
    );
    assert_eq!(result, expected);
}

#[test]
fn test_hash_pair_1_2() {
    let env = Env::default();
    let result = poseidon1_hash_pair(&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2));
    let expected = u256_hex(
        &env,
        bytesn!(&env, 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a),
    );
    assert_eq!(result, expected);
}

#[test]
fn test_hash_not_commutative() {
    let env = Env::default();
    let h12 = poseidon1_hash_pair(&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2));
    let h21 = poseidon1_hash_pair(&env, U256::from_u32(&env, 2), U256::from_u32(&env, 1));
    let expected_21 = u256_hex(
        &env,
        bytesn!(&env, 0x1576c555b70c9b778666e91d600fdc6d73f30aeed2f6adc5360d6a052259775a),
    );
    assert_eq!(h21, expected_21);
    assert_ne!(h12, h21);
}

#[test]
fn test_hash_single_42() {
    let env = Env::default();
    let result = poseidon1_hash_single(&env, U256::from_u32(&env, 42));
    let expected = u256_hex(
        &env,
        bytesn!(&env, 0x08fb15898b5e4c6b8c1ee35eff746c62fc2f2c64c777e78640ece1f70a326d58),
    );
    assert_eq!(result, expected);
}

#[test]
fn test_single_equals_pair_with_zero() {
    // H([x]) == P2(x, 0) — the left-fold single-input convention.
    let env = Env::default();
    let single = poseidon1_hash_single(&env, U256::from_u32(&env, 42));
    let pair0 = poseidon1_hash_pair(&env, U256::from_u32(&env, 42), U256::from_u32(&env, 0));
    assert_eq!(single, pair0);
}

#[test]
fn test_hash_zero() {
    let env = Env::default();
    let result = poseidon1_hash_single(&env, U256::from_u32(&env, 0));
    let expected = u256_hex(
        &env,
        bytesn!(&env, 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864),
    );
    assert_eq!(result, expected);
}

#[test]
fn test_hash_large_value() {
    // x = F - 1, the largest canonical field element.
    let env = Env::default();
    let big = u256_hex(
        &env,
        bytesn!(&env, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000),
    );
    let result = poseidon1_hash_single(&env, big);
    let expected = u256_hex(
        &env,
        bytesn!(&env, 0x1b694eae0d9995b3dd1f09a0f15f950cfb003d1bd4e8b68d3285a3a8fe319438),
    );
    assert_eq!(result, expected);
}

#[test]
fn test_hash_multiple_elements() {
    // Left-fold of hash(10, 20, 30) = P2(P2(10, 20), 30).
    let env = Env::default();
    let inputs = soroban_sdk::vec![
        &env,
        U256::from_u32(&env, 10),
        U256::from_u32(&env, 20),
        U256::from_u32(&env, 30),
    ];
    let result = poseidon1_hash(&env, &inputs);
    let expected = u256_hex(
        &env,
        bytesn!(&env, 0x142dcc9e30fb00749354a8a4c6590b031337418939372d6bc25595ab2a978c17),
    );
    assert_eq!(result, expected);
}

#[test]
fn test_double_hash() {
    // Leaf-insertion pattern: hash(hash(commitment)).
    let env = Env::default();
    let inner = poseidon1_hash_single(&env, U256::from_u32(&env, 12345));
    let outer = poseidon1_hash_single(&env, inner.clone());
    let expected_inner = u256_hex(
        &env,
        bytesn!(&env, 0x0132013acf7f80aa59c175babe6efacaa47cbd24f81f1be462702e8d8ca34c9d),
    );
    let expected_outer = u256_hex(
        &env,
        bytesn!(&env, 0x2c7eb3e2133f9ed77d8c1dc6a762910827458ad23dcc8714a614fedd70433201),
    );
    assert_eq!(inner, expected_inner);
    assert_eq!(outer, expected_outer);
    assert_ne!(inner, outer);
}

#[test]
fn test_hash_deterministic() {
    let env = Env::default();
    let a = poseidon1_hash_pair(&env, U256::from_u32(&env, 7), U256::from_u32(&env, 9));
    let b = poseidon1_hash_pair(&env, U256::from_u32(&env, 7), U256::from_u32(&env, 9));
    assert_eq!(a, b);
}

#[test]
fn test_single_input_hash_matches_single() {
    // poseidon1_hash([x]) routes to the single-input form.
    let env = Env::default();
    let via_vec = poseidon1_hash(&env, &soroban_sdk::vec![&env, U256::from_u32(&env, 42)]);
    let via_single = poseidon1_hash_single(&env, U256::from_u32(&env, 42));
    assert_eq!(via_vec, via_single);
}

// ============================================================================
// Field (Fp) unit tests.
// ============================================================================

#[test]
fn test_field_roundtrip() {
    let env = Env::default();
    let x = bytesn!(&env, 0x1234567890abcdef00112233445566778899aabbccddeeff0123456789abcdef);
    let fp = fp_hex(&x);
    assert_eq!(fp.to_be_bytes(), x.to_array());
}

#[test]
fn test_field_mul_small() {
    // 6 * 7 = 42
    assert_eq!(fp_u64(6).mul(&fp_u64(7)), fp_u64(42));
}

#[test]
fn test_field_mul_large() {
    // (F - 1)^2 == 1 mod F  (since (-1)^2 = 1)
    let env = Env::default();
    let fm1 = fp_hex(&bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    ));
    assert_eq!(fm1.mul(&fm1), fp_u64(1));
}

#[test]
fn test_field_add_wraps_modulus() {
    // (F - 1) + 2 == 1 mod F
    let env = Env::default();
    let fm1 = fp_hex(&bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    ));
    assert_eq!(fm1.add(&fp_u64(2)), fp_u64(1));
}

#[test]
fn test_field_sub_underflow() {
    // 1 - 2 == F - 1 mod F
    let env = Env::default();
    let fm1 = fp_hex(&bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    ));
    assert_eq!(fp_u64(1).sub(&fp_u64(2)), fm1);
}

#[test]
fn test_field_pow5() {
    // 2^5 = 32
    assert_eq!(fp_u64(2).pow5(), fp_u64(32));
    // 3^5 = 243
    assert_eq!(fp_u64(3).pow5(), fp_u64(243));
}

#[test]
fn test_constants_montgomery_selfcheck() {
    // The generated Montgomery constant table must agree with the field's own canonical-hex
    // conversion. This catches any corruption in the (auto-generated) constants table.
    let env = Env::default();
    // C[0] canonical value (base64 entry 0 of poseidon1.js RAW2.C). In the optimized table this
    // is C_FULL[0] (the first full round's lane-0 constant, unchanged by the folding).
    let c0 = fp_hex(&bytesn!(
        &env,
        0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e
    ));
    assert_eq!(c0, crate::constants::C_FULL[0]);
    // M[0][0] canonical value.
    let m0 = fp_hex(&bytesn!(
        &env,
        0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b
    ));
    assert_eq!(m0, crate::constants::M[0]);
}
