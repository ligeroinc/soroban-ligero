#![no_std]
//! Poseidon1 (iden3/circomlib) hash over BN254 Fr for Soroban — the `sol_poseidon`.
//!
//! This is the cross-platform parity point: the 2-to-1 here is byte-for-byte identical to
//! `sol_poseidon([a, b])`, `poseidon-lite`, the EVM `Poseidon1.sol`, and the off-chain
//! reference `ligeroclear/public/assets/poseidon1.js`. Multi-input hashing is a LEFT-FOLD of
//! the 2-to-1 (not a single wide permutation), matching the SDK circuit and the relayer:
//!     H([x])             = P2(x, 0)
//!     H([e0, e1])        = P2(e0, e1)                          // a Merkle pair
//!     H([e0..e_{n-1}])   = P2(... P2(P2(e0, e1), e2) ..., e_{n-1})
//!
//! Unlike `poseidon2-ligero` (which calls the native `poseidon2_permutation` host function), there
//! is no Poseidon1 host primitive, so the permutation runs entirely in native field arithmetic
//! (see `field.rs`); the host `U256` type is only touched at the API boundary.

use soroban_sdk::{Bytes, Env, U256, Vec};

mod constants;
mod field;

use field::Fp;

const N_ROUNDS_P: usize = 57; // partial rounds for t = 3

/// Dense 3x3 MDS multiply: out = M * [s0, s1, s2] (M row-major).
#[inline(always)]
fn mds(s0: Fp, s1: Fp, s2: Fp, m: &[Fp; 9]) -> (Fp, Fp, Fp) {
    (
        m[0].mul(&s0).add(&m[1].mul(&s1)).add(&m[2].mul(&s2)),
        m[3].mul(&s0).add(&m[4].mul(&s1)).add(&m[5].mul(&s2)),
        m[6].mul(&s0).add(&m[7].mul(&s1)).add(&m[8].mul(&s2)),
    )
}

/// The iden3 Poseidon permutation specialised to t = 3, returning state[0].
/// Mirrors `permuteT3` in `poseidon1.js` (state = [0, a, b], domain tag 0) but uses the
/// OPTIMIZED sparse-MDS factorization for the 57 partial rounds: M = M' * M'' with M' commuting
/// with the partial S-box, so each partial round does a sparse 5-mul mix (`S`) + a folded ARK
/// (`K`) instead of a full 9-mul MDS, with the dense remainder folded into a single pre-sparse
/// matrix (`M_PRE`). This is output-identical to the naive full-MDS form (verified against
/// poseidon-lite on the pinned vectors + thousands of random inputs); see constants.rs.
fn permute(a: Fp, b: Fp) -> Fp {
    use constants::{C_FULL, K, M, M_PRE, S};
    let mut s0 = Fp::zero();
    let mut s1 = a;
    let mut s2 = b;

    // First 3 full rounds: ARK (full), x^5 (all lanes), dense MDS.
    let mut fi = 0; // index into C_FULL
    let mut r = 0;
    while r < 3 {
        s0 = s0.add(&C_FULL[fi]).pow5();
        s1 = s1.add(&C_FULL[fi + 1]).pow5();
        s2 = s2.add(&C_FULL[fi + 2]).pow5();
        fi += 3;
        let (n0, n1, n2) = mds(s0, s1, s2, &M);
        s0 = n0; s1 = n1; s2 = n2;
        r += 1;
    }

    // Round 3 (last of the first full rounds): ARK + S-box, but NO MDS — its mixing is folded
    // into M_PRE at the close of the partial block.
    s0 = s0.add(&C_FULL[fi]).pow5();
    s1 = s1.add(&C_FULL[fi + 1]).pow5();
    s2 = s2.add(&C_FULL[fi + 2]).pow5();
    fi += 3;

    // 57 partial rounds: sparse MDS (5 muls) + folded ARK + x^5 on lane 0 only.
    let mut si = 0; // index into S (5 per round)
    let mut ki = 0; // index into K (3 per round)
    let mut p = 0;
    while p < N_ROUNDS_P {
        // S = [[s00, s01, s02], [w1, 1, 0], [w2, 0, 1]]
        let n0 = S[si].mul(&s0).add(&S[si + 1].mul(&s1)).add(&S[si + 2].mul(&s2));
        let n1 = S[si + 3].mul(&s0).add(&s1);
        let n2 = S[si + 4].mul(&s0).add(&s2);
        si += 5;
        s0 = n0.add(&K[ki]);
        s1 = n1.add(&K[ki + 1]);
        s2 = n2.add(&K[ki + 2]);
        ki += 3;
        s0 = s0.pow5();
        p += 1;
    }

    // Close the partial block with the dense pre-sparse matrix.
    let (n0, n1, n2) = mds(s0, s1, s2, &M_PRE);
    s0 = n0; s1 = n1; s2 = n2;

    // Last 4 full rounds (rounds 61..64): ARK (full), x^5 (all lanes), dense MDS.
    let mut r = 0;
    while r < 4 {
        s0 = s0.add(&C_FULL[fi]).pow5();
        s1 = s1.add(&C_FULL[fi + 1]).pow5();
        s2 = s2.add(&C_FULL[fi + 2]).pow5();
        fi += 3;
        let (n0, n1, n2) = mds(s0, s1, s2, &M);
        s0 = n0; s1 = n1; s2 = n2;
        r += 1;
    }

    s0
}

fn u256_to_fp(x: &U256) -> Fp {
    let bytes = x.to_be_bytes();
    let len = bytes.len() as usize; // <= 32 for a field element
    let mut buf = [0u8; 32];
    let mut i = 0;
    while i < len {
        buf[32 - len + i] = bytes.get_unchecked(i as u32);
        i += 1;
    }
    Fp::from_be_bytes(&buf)
}

fn fp_to_u256(env: &Env, x: &Fp) -> U256 {
    let buf = x.to_be_bytes();
    U256::from_be_bytes(env, &Bytes::from_slice(env, &buf))
}

/// The 2-to-1 primitive: `P2(a, b)` == `sol_poseidon([a, b])`.
pub fn poseidon1_hash_pair(env: &Env, a: U256, b: U256) -> U256 {
    let result = permute(u256_to_fp(&a), u256_to_fp(&b));
    fp_to_u256(env, &result)
}

/// Single-input hash: `P2(a, 0)` == `sol_poseidon([a, 0])` == `H([a])` in the left-fold rule.
pub fn poseidon1_hash_single(env: &Env, a: U256) -> U256 {
    let result = permute(u256_to_fp(&a), Fp::zero());
    fp_to_u256(env, &result)
}

/// Multi-input hash: left-fold of the 2-to-1 primitive (see the module header). Requires at
/// least one input; panics on an empty vector (an empty hash is undefined for the fold rule).
pub fn poseidon1_hash(env: &Env, inputs: &Vec<U256>) -> U256 {
    let n = inputs.len();
    if n == 0 {
        panic!("poseidon1_hash: at least one input required");
    }
    if n == 1 {
        return poseidon1_hash_single(env, inputs.get_unchecked(0));
    }

    let mut acc = permute(
        u256_to_fp(&inputs.get_unchecked(0)),
        u256_to_fp(&inputs.get_unchecked(1)),
    );
    let mut i = 2;
    while i < n {
        acc = permute(acc, u256_to_fp(&inputs.get_unchecked(i)));
        i += 1;
    }
    fp_to_u256(env, &acc)
}

mod tests;
