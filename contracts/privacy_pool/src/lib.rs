#![no_std]
use poseidon1::{poseidon1_hash_single, poseidon1_hash_pair};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, String, Symbol, U256, Map, Vec,
    contract, contracterror, contractimpl, log, panic_with_error,
    symbol_short, token, vec,
};

#[contract]
pub struct Contract;

// ═══════════════════════════════════════════════════════════════════════════════
// Contract errors
// ═══════════════════════════════════════════════════════════════════════════════
//
// One variant per failure path. The host emits Error(Contract, N) on
// panic_with_error!, which the relayer maps to a human-readable string via
// SOROBAN_CONTRACT_ERROR_MESSAGES in soroban_client.ts. Keep both lists in sync.
//
// (`log!()` is also called below for dev/debug visibility, but it's a no-op
// in release builds — soroban-sdk gates it on cfg!(debug_assertions) — so we
// can't rely on it for the relayer-side reason extraction.)

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotAdmin = 1,
    NotRelayer = 2,
    RootMismatch = 3,
    InvalidNonce = 4,
    NoteAlreadyUsed = 5,
    CiphertextLengthMismatch = 8,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Storage keys
// ═══════════════════════════════════════════════════════════════════════════════

const HASHES: Symbol = symbol_short!("HASHES");
const ROOT: Symbol = symbol_short!("ROOT");
const LSIZE: Symbol = symbol_short!("LSIZE");
const NLEVELS: Symbol = symbol_short!("NLEVELS");
const NONCE: Symbol = symbol_short!("NONCE");
const ADMINS: Symbol = symbol_short!("ADMINS");
const OWNER: Symbol = symbol_short!("OWNER");
const RELAYER: Symbol = symbol_short!("RELAYER");
const SIGNER: Symbol = symbol_short!("SIGNER");
const ROOTS: Symbol = symbol_short!("ROOTS");
const NULL: Symbol = symbol_short!("NULL");
// Note-metadata ciphertexts: each stored in persistent storage at (CIPHERS, index);
// CCOUNT (instance) tracks the next index. Index order mirrors commitment submission.
const CIPHERS: Symbol = symbol_short!("CIPHERS");
const CCOUNT: Symbol = symbol_short!("CCOUNT");

// Persistent-entry TTL management. Funder-nonce and nullifier entries are the
// sole replay guards; if they expire the protection is lost, so every write
// re-bumps the entry's lifetime to the network maximum (`extend_to` is clamped
// to `max_entry_ttl` by the host).
const LEDGERS_PER_DAY: u32 = 17_280; // ~5s ledger close time
const ENTRY_BUMP_THRESHOLD: u32 = 30 * LEDGERS_PER_DAY;
const ENTRY_BUMP_LEDGERS: u32 = 365 * LEDGERS_PER_DAY;

// ═══════════════════════════════════════════════════════════════════════════════
// Hex encoding helper
// ═══════════════════════════════════════════════════════════════════════════════

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

#[inline(always)]
fn u256_to_hex(value: &U256, out: &mut Bytes) {
    let be_bytes = value.to_be_bytes();
    for i in 0..be_bytes.len() {
        let byte = be_bytes.get_unchecked(i);
        out.push_back(HEX_CHARS[(byte >> 4) as usize]);
        out.push_back(HEX_CHARS[(byte & 0x0F) as usize]);
    }
}

#[contractimpl]
impl Contract {

    // ═══════════════════════════════════════════════════════════════════════════
    // Internal helpers (shared by public functions)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Append note-metadata ciphertexts in commitment-submission order. Each is stored in
    /// persistent storage at (CIPHERS, index) to avoid instance-size limits (mirrors the
    /// per-entry nullifier storage); CCOUNT tracks the next index.
    #[inline(always)]
    fn append_ciphertexts(env: &Env, ciphertexts: &Vec<Bytes>) {
        let mut count: u32 = env.storage().instance().get(&CCOUNT).unwrap_or(0);
        for c in ciphertexts.iter() {
            env.storage().persistent().set(&(CIPHERS, count), &c);
            count += 1;
        }
        env.storage().instance().set(&CCOUNT, &count);
    }

    #[inline(always)]
    fn require_relayer(env: &Env, relayer: &Address) {
        let stored: Address = env.storage().instance().get(&RELAYER).unwrap();
        if *relayer != stored {
            log!(env, "caller is not the relayer");
            panic_with_error!(env, Error::NotRelayer);
        }
        relayer.require_auth();
    }

    #[inline(always)]
    fn require_valid_root(env: &Env, root: &U256) {
        let roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(env));
        if !roots.get(root.clone()).unwrap_or(false) {
            log!(env, "Root verification failed");
            panic_with_error!(env, Error::RootMismatch);
        }
    }

    /// Strictly-increasing nonce kept per funder address, so concurrent funds
    /// from distinct funders never contend on a single counter. Persistent
    /// storage (one entry per funder) avoids the instance-storage size cap.
    #[inline(always)]
    fn check_and_update_funder_nonce(env: &Env, funder: &Address, nonce: u64) {
        let key = (NONCE, funder.clone());
        let current: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        if nonce <= current {
            log!(env, "Invalid nonce");
            panic_with_error!(env, Error::InvalidNonce);
        }
        env.storage().persistent().set(&key, &nonce);
        env.storage()
            .persistent()
            .extend_ttl(&key, ENTRY_BUMP_THRESHOLD, ENTRY_BUMP_LEDGERS);
    }

    /// Check that none of the nullifiers have been used before, then mark them as used.
    /// Uses persistent storage (one entry per nullifier) to avoid instance storage size limits.
    fn check_nullifiers(env: &Env, nullifiers: &Vec<U256>) {
        for n in nullifiers.iter() {
            let key = (NULL, n.clone());
            if env.storage().persistent().has(&key) {
                log!(env, "Note already used");
                panic_with_error!(env, Error::NoteAlreadyUsed);
            }
            env.storage().persistent().set(&key, &true);
            env.storage()
                .persistent()
                .extend_ttl(&key, ENTRY_BUMP_THRESHOLD, ENTRY_BUMP_LEDGERS);
        }
    }

    #[inline(always)]
    fn verify_signer(env: &Env, message_hash: &BytesN<32>, signature: &BytesN<64>) {
        let signer_key: BytesN<32> = env.storage().instance().get(&SIGNER).unwrap();
        let mut msg = Bytes::new(env);
        msg.extend_from_array(&message_hash.to_array());
        env.crypto().ed25519_verify(&signer_key, &msg, signature);
    }

    /// Encode U256 commitments as comma-separated hex into a message buffer.
    #[inline(always)]
    fn append_hex_commitments(commitments: &Vec<U256>, out: &mut Bytes) {
        for (i, nc) in commitments.iter().enumerate() {
            if i > 0 { out.push_back(b','); }
            u256_to_hex(&nc, out);
        }
    }

    /// Start a signed message buffer: "Stellar Signed Message:\n" + prefix + hex_commitments
    #[inline(always)]
    fn build_message_prefix(env: &Env, prefix: &[u8], commitments: &Vec<U256>) -> Bytes {
        let mut msg = Bytes::new(env);
        msg.extend_from_slice(b"Stellar Signed Message:\n");
        msg.extend_from_slice(prefix);
        Self::append_hex_commitments(commitments, &mut msg);
        msg
    }

    /// Build and hash message for fund: commitments + sender + token + amount + nonce
    fn build_fund_message(
        env: &Env, commitments: &Vec<U256>, sender: &Address,
        token: &Address, amount: i128, nonce: u64,
    ) -> BytesN<32> {
        let mut msg = Self::build_message_prefix(env, b"stellar:fund:", commitments);
        msg.push_back(b',');
        msg.append(&sender.to_string().to_bytes());
        msg.push_back(b',');
        msg.append(&token.to_string().to_bytes());
        msg.push_back(b',');
        Self::append_i128_decimal(amount, &mut msg);
        msg.push_back(b',');
        Self::append_u64_decimal(nonce, &mut msg);
        env.crypto().sha256(&msg).into()
    }

    /// Build and hash message for withdraw: commitments + receiver + token + amount + nonce + nullifiers
    fn build_withdraw_message(
        env: &Env, commitments: &Vec<U256>, receiver: &Address,
        token: &Address, amount: i128, nonce: u64, nullifiers: &Vec<U256>,
    ) -> BytesN<32> {
        let mut msg = Self::build_message_prefix(env, b"stellar:withdraw:", commitments);
        msg.push_back(b',');
        msg.append(&receiver.to_string().to_bytes());
        msg.push_back(b',');
        msg.append(&token.to_string().to_bytes());
        msg.push_back(b',');
        Self::append_i128_decimal(amount, &mut msg);
        msg.push_back(b',');
        Self::append_u64_decimal(nonce, &mut msg);
        msg.push_back(b',');
        Self::append_hex_commitments(nullifiers, &mut msg);
        env.crypto().sha256(&msg).into()
    }

    /// Build and hash message for transact: commitments + nonce + nullifiers
    fn build_transact_message(
        env: &Env, commitments: &Vec<U256>, nonce: u64, nullifiers: &Vec<U256>,
    ) -> BytesN<32> {
        let mut msg = Self::build_message_prefix(env, b"stellar:transact:", commitments);
        msg.push_back(b',');
        Self::append_u64_decimal(nonce, &mut msg);
        msg.push_back(b',');
        Self::append_hex_commitments(nullifiers, &mut msg);
        env.crypto().sha256(&msg).into()
    }

    #[inline(always)]
    fn append_i128_decimal(value: i128, out: &mut Bytes) {
        if value == 0 { out.push_back(b'0'); return; }
        let mut v = value;
        if v < 0 { out.push_back(b'-'); v = -v; }
        let mut buf = [0u8; 40];
        let mut pos = 0usize;
        while v > 0 {
            buf[pos] = b'0' + (v % 10) as u8;
            v /= 10;
            pos += 1;
        }
        for i in (0..pos).rev() { out.push_back(buf[i]); }
    }

    #[inline(always)]
    fn append_u64_decimal(value: u64, out: &mut Bytes) {
        if value == 0 { out.push_back(b'0'); return; }
        let mut v = value;
        let mut buf = [0u8; 20]; // u64 max is 20 digits
        let mut pos = 0usize;
        while v > 0 {
            buf[pos] = b'0' + (v % 10) as u8;
            v /= 10;
            pos += 1;
        }
        for i in (0..pos).rev() { out.push_back(buf[i]); }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn __constructor(env: Env, owner: Address) {
        env.storage().instance().set(&OWNER, &owner);
        env.storage().instance().set(&RELAYER, &owner);

        let mut roots: Map<U256, bool> = Map::new(&env);
        roots.set(U256::from_u32(&env, 0), true);
        env.storage().instance().set(&ROOTS, &roots);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Contract admin operations
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn owner(env: Env) -> Address {
        env.storage().instance().get::<_, Address>(&OWNER).unwrap()
    }

    pub fn transfer_ownership(env: &Env, new_owner: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        env.storage().instance().set(&OWNER, &new_owner);
    }

    pub fn get_relayer(env: Env) -> Address {
        env.storage().instance().get(&RELAYER).unwrap()
    }

    pub fn set_relayer(env: &Env, new_relayer: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        env.storage().instance().set(&RELAYER, &new_relayer);
    }

    pub fn get_signer(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&SIGNER)
    }

    pub fn set_signer(env: &Env, signer_public_key: BytesN<32>) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        env.storage().instance().set(&SIGNER, &signer_public_key);
    }

    pub fn get_funder_nonce(env: Env, funder: Address) -> u64 {
        env.storage().persistent().get(&(NONCE, funder)).unwrap_or(0)
    }

    // Note-metadata ciphertext read accessors.
    pub fn get_ciphertext(env: Env, index: u32) -> Option<Bytes> {
        env.storage().persistent().get(&(CIPHERS, index))
    }
    pub fn ciphertext_count(env: Env) -> u32 {
        env.storage().instance().get(&CCOUNT).unwrap_or(0)
    }

    // Admin management

    pub fn add_admin(env: &Env, admin: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        let mut admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(env));
        admins_map.set(admin, true);
        env.storage().instance().set(&ADMINS, &admins_map);
    }

    pub fn remove_admin(env: &Env, admin: Address) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        let mut admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(env));
        admins_map.set(admin, false);
        env.storage().instance().set(&ADMINS, &admins_map);
    }

    pub fn is_admin(env: Env, address: Address) -> bool {
        let admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(&env));
        admins_map.get(address).unwrap_or(false)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Merkle tree operations
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Hashes with POSEIDON V1 (poseidon_s / sol_poseidon), matching the v1 circuit + relayer and
    // every other chain (Solana/EVM). The merkle root produced here therefore agrees with the root
    // the relayer presents to fund/withdraw/transact, so require_valid_root() accepts Stellar spends.
    //
    // Soroban has no Poseidon1 host function (only `poseidon2_permutation`, which takes a diagonal
    // m_diag — Poseidon2-specific) and no BN254 `mulmod` (U256 has no widening multiply), so the
    // full-MDS Poseidon v1 is hand-rolled in native BN254 field arithmetic in the `poseidon1`
    // crate (see Poseidon1.rs). The off-chain reference is public/assets/poseidon1.js /
    // backend/src/merkle.ts (2-to-1 == sol_poseidon, multi-input = left-fold); 

    pub fn hash_single(env: &Env, a: U256) -> U256 {
        poseidon1_hash_single(env, a)
    }

    pub fn hash_pair(env: &Env, a: U256, b: U256) -> U256 {
        poseidon1_hash_pair(env, a, b)
    }

    /// Insert a batch of pre-hashed leaves into the merkle tree.
    ///
    /// Loads tree state once, places all leaves at level 0, then walks up
    /// rebuilding only the pairs that cover changed leaves (tracked via
    /// `first_changed`), and persists all updated state in a single trailing
    /// block of `storage().instance().set(...)` calls. For a batch of K
    /// leaves this replaces K full storage round-trips and K independent
    /// up-walks with one of each.
    fn insert_leaf_hashes(env: &Env, leaves: Vec<U256>) {
        let num_leaves = leaves.len();
        if num_leaves == 0 { return; }

        let mut merkle_tree: Vec<Vec<U256>> = env.storage().instance().get(&HASHES).unwrap_or(Vec::new(env));
        let mut level_size: Vec<u32> = env.storage().instance().get(&LSIZE).unwrap_or(Vec::new(env));
        let mut number_of_levels: u32 = env.storage().instance().get(&NLEVELS).unwrap_or(0);
        let dummy_value = U256::from_u32(env, 0);

        if level_size.len() == 0 {
            level_size.push_back(0);
            merkle_tree.push_back(Vec::new(env));
            number_of_levels = 1;
        }

        // Step 1: place leaves at level 0. First leaf overwrites a trailing
        // DUMMY left by prior odd-padding; the rest are appended.
        let mut level0 = merkle_tree.get_unchecked(0);
        let mut current_size: u32 = level_size.get_unchecked(0);
        let first_changed: u32;

        if current_size > 3 && level0.get_unchecked(current_size - 1) == dummy_value {
            level0.set(current_size - 1, leaves.get_unchecked(0));
            first_changed = current_size - 1;
        } else {
            level0.push_back(leaves.get_unchecked(0));
            first_changed = current_size;
            current_size += 1;
        }

        for i in 1..num_leaves {
            level0.push_back(leaves.get_unchecked(i));
            current_size += 1;
        }
        merkle_tree.set(0, level0);
        level_size.set(0, current_size);

        // Step 2: walk up, rebuilding only pairs covering changed leaves.
        let mut level: u32 = 0;
        let mut changed_from = first_changed;

        while level_size.get_unchecked(level) > 1 {
            let mut current_size = level_size.get_unchecked(level);
            let mut src = merkle_tree.get_unchecked(level);
            let mut padded = false;

            if current_size % 2 != 0 {
                src.push_back(dummy_value.clone());
                current_size += 1;
                padded = true;
                level_size.set(level, current_size);
            }
            if level + 1 >= number_of_levels {
                number_of_levels += 1;
            }

            let first_pair = changed_from / 2;
            let num_pairs = current_size / 2;

            let mut dst: Vec<U256> = if level + 1 < merkle_tree.len() {
                merkle_tree.get_unchecked(level + 1)
            } else {
                Vec::new(env)
            };

            for pair_idx in first_pair..num_pairs {
                let parent = Self::hash_pair(env,
                    src.get_unchecked(pair_idx * 2),
                    src.get_unchecked(pair_idx * 2 + 1),
                );
                if pair_idx < dst.len() {
                    dst.set(pair_idx, parent);
                } else {
                    dst.push_back(parent);
                }
            }

            if padded {
                merkle_tree.set(level, src);
            }
            if level + 1 < merkle_tree.len() {
                merkle_tree.set(level + 1, dst);
            } else {
                merkle_tree.push_back(dst);
            }
            if level + 1 < level_size.len() {
                level_size.set(level + 1, num_pairs);
            } else {
                level_size.push_back(num_pairs);
            }

            changed_from = first_pair;
            level += 1;
        }

        // Step 3: persist updated state in one shot.
        let merkle_tree_root = merkle_tree.get_unchecked(number_of_levels - 1).get_unchecked(0);
        env.storage().instance().set(&HASHES, &merkle_tree);
        env.storage().instance().set(&LSIZE, &level_size);
        env.storage().instance().set(&ROOT, &merkle_tree_root);
        env.storage().instance().set(&NLEVELS, &number_of_levels);

        let mut roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(env));
        roots.set(merkle_tree_root, true);
        env.storage().instance().set(&ROOTS, &roots);
    }

    fn insert_leaves(env: &Env, leaves: Vec<U256>) {
        if leaves.len() == 0 { return; }
        let mut hashed: Vec<U256> = Vec::new(env);
        for leaf in leaves.iter() {
            hashed.push_back(Self::hash_single(env, Self::hash_single(env, leaf)));
        }
        Self::insert_leaf_hashes(env, hashed);
    }

    // Merkle tree read accessors

    pub fn get_hashes(env: &Env) -> Vec<Vec<U256>> {
        env.storage().instance().get(&HASHES).unwrap_or(Vec::new(env))
    }

    pub fn get_number_of_levels(env: &Env) -> u32 {
        env.storage().instance().get(&NLEVELS).unwrap_or(0)
    }

    pub fn get_levels(env: &Env) -> Vec<u32> {
        env.storage().instance().get(&LSIZE).unwrap_or(Vec::new(env))
    }

    pub fn get_root(env: &Env) -> U256 {
        env.storage().instance().get(&ROOT).unwrap_or(U256::from_u32(env, 0))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Main Privacy Pool operations
    // ═══════════════════════════════════════════════════════════════════════════

    /// Fund: Funder (sender) deposits tokens and creates note commitments.
    pub fn fund(
        env: Env,
        relayer: Address,
        note_commitments: Vec<U256>,
        note_ciphertexts: Vec<Bytes>,
        token_address: Address,
        sender_address: Address,
        amount: i128,
        nonce: u64,
        root: U256,
        signer_signature: BytesN<64>,
        funder_public_key: BytesN<32>,
        funder_signature: BytesN<64>,
    ) {
        if note_ciphertexts.len() != note_commitments.len() {
            panic_with_error!(&env, Error::CiphertextLengthMismatch);
        }
        Self::check_and_update_funder_nonce(&env, &sender_address, nonce);
        Self::require_relayer(&env, &relayer);
        Self::require_valid_root(&env, &root);

        let hash = Self::build_fund_message(&env, &note_commitments, &sender_address, &token_address, amount, nonce);

        Self::verify_signer(&env, &hash, &signer_signature);
        // Verify funder signature over the same hash
        let mut hash_bytes = Bytes::new(&env);
        hash_bytes.extend_from_array(&hash.to_array());
        env.crypto().ed25519_verify(&funder_public_key, &hash_bytes, &funder_signature);

        token::Client::new(&env, &token_address)
            .transfer_from(&relayer, &sender_address, &env.current_contract_address(), &amount);
        Self::append_ciphertexts(&env, &note_ciphertexts);
        Self::insert_leaves(&env, note_commitments);
    }

    /// Withdraw: Receiver withdraws tokens by spending note commitments.
    pub fn withdraw(
        env: Env,
        relayer: Address,
        note_commitments: Vec<U256>,
        note_ciphertexts: Vec<Bytes>,
        receiver_address: Address,
        token_address: Address,
        amount: i128,
        nonce: u64,
        nullifiers: Vec<U256>,
        root: U256,
        signer_signature: BytesN<64>,
        withdrawer_public_key: BytesN<32>,
        withdrawer_signature: BytesN<64>,
    ) {
        if note_ciphertexts.len() != note_commitments.len() {
            panic_with_error!(&env, Error::CiphertextLengthMismatch);
        }
        Self::require_relayer(&env, &relayer);
        Self::require_valid_root(&env, &root);
        Self::check_nullifiers(&env, &nullifiers);

        let hash = Self::build_withdraw_message(&env, &note_commitments, &receiver_address, &token_address, amount, nonce, &nullifiers);

        Self::verify_signer(&env, &hash, &signer_signature);
        // Dual-signature (mirrors fund's funder sig): the destination wallet W co-signs the SAME hash.
        // Since the hash binds `receiver_address`, a valid W-signature proves the W-holder authorized
        // payment to exactly this receiver — a malicious relayer cannot redirect (changing the receiver
        // breaks this signature, and only W's holder can produce a fresh one). The W↔receiver pairing is
        // established off-chain: the relayer pays addr(W) and the wallet only ever signs its own address.
        let mut hash_bytes = Bytes::new(&env);
        hash_bytes.extend_from_array(&hash.to_array());
        env.crypto().ed25519_verify(&withdrawer_public_key, &hash_bytes, &withdrawer_signature);

        token::Client::new(&env, &token_address)
            .transfer(&env.current_contract_address(), &receiver_address, &amount);
        Self::append_ciphertexts(&env, &note_ciphertexts);
        Self::insert_leaves(&env, note_commitments);
    }

    /// Transact: Split/join notes without token transfer.
    pub fn transact(
        env: Env,
        relayer: Address,
        nc_outputs: Vec<U256>,
        note_ciphertexts: Vec<Bytes>,
        nonce: u64,
        nullifiers: Vec<U256>,
        root: U256,
        signer_signature: BytesN<64>,
    ) {
        if note_ciphertexts.len() != nc_outputs.len() {
            panic_with_error!(&env, Error::CiphertextLengthMismatch);
        }
        Self::require_relayer(&env, &relayer);
        Self::require_valid_root(&env, &root);
        Self::check_nullifiers(&env, &nullifiers);

        let hash = Self::build_transact_message(&env, &nc_outputs, nonce, &nullifiers);
        Self::verify_signer(&env, &hash, &signer_signature);

        Self::append_ciphertexts(&env, &note_ciphertexts);
        Self::insert_leaves(&env, nc_outputs);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Version
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn version(env: Env) -> Vec<String> {
        vec![&env, String::from_str(&env, "Ligero Privacy Pool v6.0")]
    }
}

// Test-only entry point: exposes the internal `insert_leaves` so unit tests
// can validate the merkle algorithm without standing up the full fund-call
// scaffolding (token mock, ed25519 keypairs, signed messages). Compiled out
// of release builds.
#[cfg(test)]
#[contractimpl]
impl Contract {
    pub fn t_insert_leaves(env: Env, leaves: Vec<U256>) {
        Self::insert_leaves(&env, leaves);
    }
}

mod tests;
