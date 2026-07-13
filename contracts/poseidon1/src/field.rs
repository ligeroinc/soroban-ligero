//! Minimal BN254 scalar-field (Fr) arithmetic in Montgomery form.
//!
//! Soroban exposes no BN254 field-multiply host function, and `U256::mul` *traps* on a >256-bit
//! product, so Poseidon1's full-MDS permutation has to do its own modular multiplication. We do
//! it in native Rust over `[u64; 4]` little-endian limbs (which compile to cheap in-VM wasm
//! instructions, not host calls). All multiplication goes through CIOS Montgomery reduction using
//! `u128` partial products. The release profile sets `overflow-checks = true`, so every step uses
//! explicit `wrapping_*` / `u128` arithmetic that provably cannot overflow.

/// BN254 Fr modulus p, little-endian limbs.
/// p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// -p^{-1} mod 2^64 (Montgomery reduction constant).
const INV: u64 = 0xc2e1f593efffffff;

/// R^2 mod p, where R = 2^256. Multiplying a canonical integer by this (in Montgomery form)
/// converts it into Montgomery form.
const R2: [u64; 4] = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

/// A BN254 Fr element in Montgomery form (`value * R mod p`), little-endian `[u64; 4]` limbs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fp(pub [u64; 4]);

/// (lo, hi) = a + b*c + carry. Max value is (2^64-1) + (2^64-1)^2 + (2^64-1) = 2^128-1, so the
/// u128 sum never overflows.
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// (sum, carry) = a + b + carry.
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// (diff, borrow) = a - b - borrow. `borrow` is 0 or 1; the returned borrow is 0 or 1.
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (t as u64, ((t >> 64) as u64) & 1)
}

/// CIOS Montgomery multiplication: returns `a * b * R^{-1} mod p` (Koç's algorithm).
/// Correct whenever `a * b < R * p` — in particular for both `a, b < p` and for `a < 2^256`,
/// `b < p` (used by `from_be_bytes` to reduce-and-convert in one shot). The result is < p.
fn mont_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let n = MODULUS;
    let mut t = [0u64; 6]; // s + 2 words, s = 4

    let mut i = 0;
    while i < 4 {
        // t = t + a * b[i]
        let mut carry = 0u64;
        let mut j = 0;
        while j < 4 {
            let (s, c) = mac(t[j], a[j], b[i], carry);
            t[j] = s;
            carry = c;
            j += 1;
        }
        let (s, c) = adc(t[4], carry, 0);
        t[4] = s;
        t[5] = c;

        // m = t[0] * INV mod 2^64 ; t = (t + m * n) / 2^64
        let m = t[0].wrapping_mul(INV);
        let (_zero, mut carry2) = mac(t[0], m, n[0], 0); // low limb is forced to 0, dropped
        let mut j = 1;
        while j < 4 {
            let (s, c) = mac(t[j], m, n[j], carry2);
            t[j - 1] = s;
            carry2 = c;
            j += 1;
        }
        let (s, c) = adc(t[4], carry2, 0);
        t[3] = s;
        t[4] = t[5].wrapping_add(c);

        i += 1;
    }

    // Result is in t[0..4], in [0, 2p); one conditional subtraction lands it in [0, p).
    sub_modulus([t[0], t[1], t[2], t[3]])
}

/// Returns `a - p` if `a >= p`, else `a` (branchless select).
fn sub_modulus(a: [u64; 4]) -> [u64; 4] {
    let (r0, b) = sbb(a[0], MODULUS[0], 0);
    let (r1, b) = sbb(a[1], MODULUS[1], b);
    let (r2, b) = sbb(a[2], MODULUS[2], b);
    let (r3, b) = sbb(a[3], MODULUS[3], b);
    // borrow == 1  <=>  a < p  =>  keep a ; else use the subtracted value.
    let keep = 0u64.wrapping_sub(b); // all-ones when a < p
    [
        (a[0] & keep) | (r0 & !keep),
        (a[1] & keep) | (r1 & !keep),
        (a[2] & keep) | (r2 & !keep),
        (a[3] & keep) | (r3 & !keep),
    ]
}

impl Fp {
    /// The additive identity (Montgomery form of 0 is 0).
    pub const fn zero() -> Fp {
        Fp([0, 0, 0, 0])
    }

    /// (self + other) mod p. Inputs must be < p; the result is < p.
    pub fn add(&self, other: &Fp) -> Fp {
        let (r0, c) = adc(self.0[0], other.0[0], 0);
        let (r1, c) = adc(self.0[1], other.0[1], c);
        let (r2, c) = adc(self.0[2], other.0[2], c);
        let (r3, _c) = adc(self.0[3], other.0[3], c); // inputs < p < 2^255 => no carry out
        Fp(sub_modulus([r0, r1, r2, r3]))
    }

    /// (self - other) mod p. Inputs must be < p; the result is < p.
    /// Part of the field API for completeness; the Poseidon permutation only needs add/mul.
    #[allow(dead_code)]
    pub fn sub(&self, other: &Fp) -> Fp {
        let (r0, b) = sbb(self.0[0], other.0[0], 0);
        let (r1, b) = sbb(self.0[1], other.0[1], b);
        let (r2, b) = sbb(self.0[2], other.0[2], b);
        let (r3, b) = sbb(self.0[3], other.0[3], b);
        // If it underflowed, add p back.
        let add = 0u64.wrapping_sub(b); // all-ones when self < other
        let (a0, c) = adc(r0, MODULUS[0] & add, 0);
        let (a1, c) = adc(r1, MODULUS[1] & add, c);
        let (a2, c) = adc(r2, MODULUS[2] & add, c);
        let (a3, _c) = adc(r3, MODULUS[3] & add, c);
        Fp([a0, a1, a2, a3])
    }

    /// (self * other) mod p.
    pub fn mul(&self, other: &Fp) -> Fp {
        Fp(mont_mul(self.0, other.0))
    }

    /// self^5 (the Poseidon S-box): x^2, x^4 = (x^2)^2, x^5 = x^4 * x — three multiplications.
    pub fn pow5(&self) -> Fp {
        let x2 = self.mul(self);
        let x4 = x2.mul(&x2);
        x4.mul(self)
    }

    /// Interpret 32 big-endian bytes as an integer, reduce mod p, and return it in Montgomery form.
    /// The input need not be < p (CIOS with R2 reduces it).
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Fp {
        let mut limbs = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            let base = 24 - i * 8; // limb 0 (least significant) is the last 8 bytes
            let mut v = 0u64;
            let mut k = 0;
            while k < 8 {
                v = (v << 8) | (bytes[base + k] as u64);
                k += 1;
            }
            limbs[i] = v;
            i += 1;
        }
        Fp(mont_mul(limbs, R2))
    }

    /// Canonical big-endian 32-byte encoding (converts out of Montgomery form; result is < p).
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let canon = mont_mul(self.0, [1, 0, 0, 0]); // self * 1 * R^{-1} = canonical
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 4 {
            let base = 24 - i * 8;
            let v = canon[i];
            let mut k = 0;
            while k < 8 {
                out[base + 7 - k] = ((v >> (8 * k)) & 0xff) as u8;
                k += 1;
            }
            i += 1;
        }
        out
    }
}
