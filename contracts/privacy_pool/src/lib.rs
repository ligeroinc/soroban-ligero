#![no_std]
use poseidon2_ligero::{poseidon2_hash_single, poseidon2_hash_pair};
use soroban_sdk::{Address, Bytes, BytesN, Env, String, Symbol, U256, Map, Vec, contract, contractimpl, symbol_short, token, vec};

#[contract]
pub struct Contract;

// ═══════════════════════════════════════════════════════════════════════════════
// Storage keys
// ═══════════════════════════════════════════════════════════════════════════════

const HASHES: Symbol = symbol_short!("HASHES");
const ROOT: Symbol = symbol_short!("ROOT");
const LSIZE: Symbol = symbol_short!("LSIZE");
const NLEVELS: Symbol = symbol_short!("NLEVELS");
const NONCE: Symbol = symbol_short!("NONCE");
const FUND: Symbol = symbol_short!("FUND");
const WITHDRAW: Symbol = symbol_short!("WITHDRAW");
const ADMINS: Symbol = symbol_short!("ADMINS");
const OWNER: Symbol = symbol_short!("OWNER");
const RELAYER: Symbol = symbol_short!("RELAYER");
const SIGNER: Symbol = symbol_short!("SIGNER");
const ROOTS: Symbol = symbol_short!("ROOTS");
const NULL: Symbol = symbol_short!("NULL");

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

    #[inline(always)]
    fn require_admin(env: &Env, admin: &Address) {
        let admins_map: Map<Address, bool> = env.storage().instance().get(&ADMINS).unwrap_or(Map::new(env));
        assert!(admins_map.get(admin.clone()).unwrap_or(false), "caller should be an admin");
        admin.require_auth();
    }

    #[inline(always)]
    fn whitelist_set(env: &Env, key: &Symbol, address: Address, value: bool) {
        let mut map: Map<Address, bool> = env.storage().instance().get(key).unwrap_or(Map::new(env));
        map.set(address, value);
        env.storage().instance().set(key, &map);
    }

    #[inline(always)]
    fn whitelist_get(env: &Env, key: &Symbol, address: &Address) -> bool {
        let map: Map<Address, bool> = env.storage().instance().get(key).unwrap_or(Map::new(env));
        map.get(address.clone()).unwrap_or(false)
    }

    #[inline(always)]
    fn require_relayer(env: &Env, relayer: &Address) {
        let stored: Address = env.storage().instance().get(&RELAYER).unwrap();
        assert!(*relayer == stored, "caller is not the relayer");
        relayer.require_auth();
    }

    #[inline(always)]
    fn require_valid_root(env: &Env, root: &U256) {
        let roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(env));
        assert!(roots.get(root.clone()).unwrap_or(false), "Root verification failed");
    }

    #[inline(always)]
    fn check_and_update_nonce(env: &Env, nonce: u64) {
        let current: u64 = env.storage().instance().get(&NONCE).unwrap_or(0);
        assert!(nonce > current, "Invalid nonce");
        env.storage().instance().set(&NONCE, &nonce);
    }

    /// Check that none of the nullifiers have been used before, then mark them as used.
    /// Uses persistent storage (one entry per nullifier) to avoid instance storage size limits.
    fn check_nullifiers(env: &Env, nullifiers: &Vec<U256>) {
        for n in nullifiers.iter() {
            let key = (NULL, n.clone());
            assert!(!env.storage().persistent().has(&key), "Note already used");
            env.storage().persistent().set(&key, &true);
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
        env.storage().instance().set(&NONCE, &0u64);

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

    pub fn get_nonce(env: Env) -> u64 {
        env.storage().instance().get(&NONCE).unwrap_or(0)
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
    // Whitelist operations
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn add_whitelist_fund(env: &Env, admin: Address, sender_address: Address) {
        Self::require_admin(env, &admin);
        Self::whitelist_set(env, &FUND, sender_address, true);
    }

    pub fn remove_whitelist_fund(env: &Env, admin: Address, sender_address: Address) {
        Self::require_admin(env, &admin);
        Self::whitelist_set(env, &FUND, sender_address, false);
    }

    pub fn is_whitelisted_fund(env: Env, address: Address) -> bool {
        Self::whitelist_get(&env, &FUND, &address)
    }

    pub fn add_whitelist_withdraw(env: &Env, admin: Address, withdraw_address: Address) {
        Self::require_admin(env, &admin);
        Self::whitelist_set(env, &WITHDRAW, withdraw_address, true);
    }

    pub fn remove_whitelist_withdraw(env: &Env, admin: Address, withdraw_address: Address) {
        Self::require_admin(env, &admin);
        Self::whitelist_set(env, &WITHDRAW, withdraw_address, false);
    }

    pub fn is_whitelisted_withdraw(env: Env, address: Address) -> bool {
        Self::whitelist_get(&env, &WITHDRAW, &address)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Merkle tree operations
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn hash_function_u256(env: &Env, a: U256) -> U256 {
        poseidon2_hash_single(env, a)
    }

    pub fn hash_function_pair(env: &Env, a: U256, b: U256) -> U256 {
        poseidon2_hash_pair(env, a, b)
    }

    fn insert_leaf_hash(env: &Env, leaf: U256) {
        let mut merkle_tree: Vec<Vec<U256>> = env.storage().instance().get(&HASHES).unwrap_or(Vec::new(env));
        let mut level_size: Vec<u32> = env.storage().instance().get(&LSIZE).unwrap_or(Vec::new(env));
        let mut number_of_levels: u32 = env.storage().instance().get(&NLEVELS).unwrap_or(0);
        let dummy_value = U256::from_u32(env, 0);

        if level_size.len() == 0 {
            level_size.push_back(0);
            merkle_tree.push_back(Vec::new(env));
            number_of_levels = 1;
        }

        let mut current_level: u32 = 0;
        let mut current_size = level_size.get_unchecked(0);

        if (current_size > 3) && (merkle_tree.get_unchecked(0).get_unchecked(current_size - 1) == dummy_value) {
            let mut level = merkle_tree.get_unchecked(0);
            level.set(current_size - 1, leaf);
            merkle_tree.set(0, level);
        } else {
            let mut level = merkle_tree.get_unchecked(0);
            level.push_back(leaf);
            merkle_tree.set(0, level);
            current_size += 1;
        }
        level_size.set(0, current_size);

        while current_size > 1 {
            if current_size % 2 != 0 {
                let mut level = merkle_tree.get_unchecked(current_level);
                level.push_back(dummy_value.clone());
                merkle_tree.set(current_level, level);
                current_size += 1;
                level_size.set(current_level, current_size);
            }
            if current_level + 1 >= number_of_levels {
                number_of_levels += 1;
            }

            let value_for_next_level = Self::hash_function_pair(env,
                merkle_tree.get_unchecked(current_level).get_unchecked(current_size - 2),
                merkle_tree.get_unchecked(current_level).get_unchecked(current_size - 1)
            );
            let index_to_update = (current_size + 1) / 2;

            if current_level + 1 < merkle_tree.len() {
                let mut set_level = merkle_tree.get_unchecked(current_level + 1);
                if index_to_update - 1 < set_level.len() {
                    set_level.set(index_to_update - 1, value_for_next_level);
                } else {
                    set_level.push_back(value_for_next_level);
                }
                merkle_tree.set(current_level + 1, set_level);
            } else {
                let mut new_level: Vec<U256> = Vec::new(env);
                new_level.push_back(value_for_next_level);
                merkle_tree.push_back(new_level);
            }

            if current_level + 1 < level_size.len() {
                level_size.set(current_level + 1, index_to_update);
            } else {
                level_size.push_back(index_to_update);
            }
            level_size.set(current_level, current_size);
            current_level += 1;
            current_size = level_size.get_unchecked(current_level);
        }

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
        for leaf in leaves.iter() {
            let hash = Self::hash_function_u256(env, Self::hash_function_u256(env, leaf));
            Self::insert_leaf_hash(env, hash);
        }
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
        token_address: Address,
        sender_address: Address,
        amount: i128,
        nonce: u64,
        root: U256,
        signer_signature: BytesN<64>,
        funder_public_key: BytesN<32>,
        funder_signature: BytesN<64>,
    ) {
        Self::check_and_update_nonce(&env, nonce);
        assert!(Self::whitelist_get(&env, &FUND, &sender_address), "Funder wallet is not whitelisted");
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
        Self::insert_leaves(&env, note_commitments);
    }

    /// Withdraw: Receiver withdraws tokens by spending note commitments.
    pub fn withdraw(
        env: Env,
        relayer: Address,
        note_commitments: Vec<U256>,
        receiver_address: Address,
        token_address: Address,
        amount: i128,
        nonce: u64,
        nullifiers: Vec<U256>,
        root: U256,
        signer_signature: BytesN<64>,
    ) {
        Self::check_and_update_nonce(&env, nonce);
        Self::require_relayer(&env, &relayer);
        assert!(Self::whitelist_get(&env, &WITHDRAW, &receiver_address), "Withdraw wallet is not whitelisted");
        Self::require_valid_root(&env, &root);
        Self::check_nullifiers(&env, &nullifiers);

        let hash = Self::build_withdraw_message(&env, &note_commitments, &receiver_address, &token_address, amount, nonce, &nullifiers);

        Self::verify_signer(&env, &hash, &signer_signature);

        token::Client::new(&env, &token_address)
            .transfer(&env.current_contract_address(), &receiver_address, &amount);
        Self::insert_leaves(&env, note_commitments);
    }

    /// Transact: Split/join notes without token transfer.
    pub fn transact(
        env: Env,
        relayer: Address,
        nc_outputs: Vec<U256>,
        nonce: u64,
        nullifiers: Vec<U256>,
        root: U256,
        signer_signature: BytesN<64>,
    ) {
        Self::check_and_update_nonce(&env, nonce);
        Self::require_relayer(&env, &relayer);
        Self::require_valid_root(&env, &root);
        Self::check_nullifiers(&env, &nullifiers);

        let hash = Self::build_transact_message(&env, &nc_outputs, nonce, &nullifiers);
        Self::verify_signer(&env, &hash, &signer_signature);

        Self::insert_leaves(&env, nc_outputs);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Version
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn version(env: Env) -> Vec<String> {
        vec![&env, String::from_str(&env, "Ligero Privacy Pool v4.0")]
    }
}

mod test;
