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
    SignerNotAuthorized = 9,
    SignerAlreadyAuthorized = 10,
    LastSigner = 11,
    // 12/13 are reserved: the built-in Stellar Asset Contract surfaces token overflow / missing-trustline
    // as Error(Contract, 12/13) through fund()'s transfer_from frame, so PrivacyPool skips them here to
    // keep off-chain error mapping unambiguous (see SAC_TOKEN_ERROR_MESSAGES in soroban_client.ts).
    FundAuthExpired = 14,
    FunderNotAccount = 15,
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
const SIGNERS: Symbol = symbol_short!("SIGNERS");
// Relayer note-encryption (ECDH) public key, 64 bytes x||y.
const ENCKEY: Symbol = symbol_short!("ENCKEY");
const ROOTS: Symbol = symbol_short!("ROOTS");
// Upper-level frontier (rightmost two nodes per level >= 1): FRONTA[level] = node at
// levelSize[level]-2, FRONTB[level] = node at levelSize[level]-1. Level-0 slots are unused.
const FRONTA: Symbol = symbol_short!("FRONTA");
const FRONTB: Symbol = symbol_short!("FRONTB");
// Bounded root history ring buffer + its head index.
const RHIST: Symbol = symbol_short!("RHIST");
const RIDX: Symbol = symbol_short!("RIDX");
const NULL: Symbol = symbol_short!("NULL");
// Note-metadata ciphertexts: each stored in persistent storage at (CIPHERS, index);
// CCOUNT (instance) tracks the next index. Index order mirrors commitment submission.
const CIPHERS: Symbol = symbol_short!("CIPHERS");
const CCOUNT: Symbol = symbol_short!("CCOUNT");

// Persistent-entry TTL management. Funder-nonce and nullifier entries are the
// sole replay guards; if they expire the protection is lost, so every write
// re-bumps the entry's lifetime to the network maximum (`extend_to` is clamped
// to `max_entry_ttl` by the host).
// Bounded root-history window (see push_root / require_valid_root).
const ROOT_HISTORY_SIZE: u32 = 256;

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

/// Lowercase hex of a fixed 32-byte value (the ledger network id).
fn bytes32_to_hex(value: &BytesN<32>, out: &mut Bytes) {
    for byte in value.to_array().iter() {
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
    /// Verify the relayer-signer slot against the AUTHORIZED SIGNER SET.
    ///
    /// The caller must name which authorized key it signed with. That is not a convenience: the
    /// host's `ed25519_verify` PANICS on a bad signature and returns nothing, and Soroban has no
    /// way to catch a host-function panic, so the contract cannot try each key in turn. So:
    /// check membership first (cheap, non-panicking), then verify exactly once.
    ///
    /// Naming the key grants no authority — an attacker naming a key they do not hold simply
    /// fails the verify below.
    fn verify_signer(
        env: &Env,
        signer_public_key: &BytesN<32>,
        message_hash: &BytesN<32>,
        signature: &BytesN<64>,
    ) {
        let signers: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&SIGNERS)
            .unwrap_or(Vec::new(env));
        if !signers.contains(signer_public_key) {
            log!(env, "Signer not authorized");
            panic_with_error!(env, Error::SignerNotAuthorized);
        }
        let mut msg = Bytes::new(env);
        msg.extend_from_array(&message_hash.to_array());
        env.crypto().ed25519_verify(signer_public_key, &msg, signature);
    }

    /// Extract the 32-byte Ed25519 public key that backs a Stellar account address (`G…`).
    ///
    /// This inlines the XDR-slice that soroban-sdk's (feature-gated) `Address::to_payload` performs,
    /// using the ungated `xdr::ToXdr` serialization so we need no extra crate feature. The Address is
    /// serialized to its ScVal XDR form and the account's Ed25519 key is read out of a fixed offset:
    ///   [0..4] ScVal discriminant · [4..8] ScAddress::Account tag · [8..12] PublicKey::Ed25519 tag ·
    ///   [12..44] the 32-byte key.
    /// A contract address (`C…`) has no Ed25519 key and is rejected — the funder must be an account.
    ///
    /// We verify the funder's detached signature against THIS key (the sender's own master key). Our
    /// identity model is SEP-53: the funding wallet signs with the account's Ed25519 key, so the
    /// master key IS the signer. (soroban-sdk flags the general case "hazmat" only because a
    /// custom-signer Stellar account could disable its master key; such accounts are outside this
    /// system, which authenticates the wallet key W directly.)
    fn account_ed25519_pubkey(env: &Env, address: &Address) -> BytesN<32> {
        use soroban_sdk::xdr::ToXdr;
        let xdr = address.clone().to_xdr(env);
        // ScAddress::Account tag == [0,0,0,0]; PublicKey::PublicKeyTypeEd25519 tag == [0,0,0,0].
        let sc_addr_tag: BytesN<4> = xdr.slice(4..8).try_into().unwrap();
        let pk_type_tag: BytesN<4> = xdr.slice(8..12).try_into().unwrap();
        if sc_addr_tag.to_array() != [0, 0, 0, 0] || pk_type_tag.to_array() != [0, 0, 0, 0] {
            panic_with_error!(env, Error::FunderNotAccount);
        }
        xdr.slice(12..44).try_into().unwrap()
    }

    /// Verify the FUNDER's detached wallet signature over the fund message. Unlike EVM's `ecrecover`
    /// (which yields an address), a raw ed25519 check does not by itself tie a supplied key to the
    /// sender — so we DERIVE the key from `sender_address` and verify against that, which binds the
    /// signature to the funder whose allowance is being pulled. `ed25519_verify` panics (reverts) on
    /// a bad signature, which is the desired fail-closed behavior.
    fn verify_funder(
        env: &Env,
        sender_address: &Address,
        message_hash: &BytesN<32>,
        funder_signature: &BytesN<64>,
    ) {
        let funder_public_key = Self::account_ed25519_pubkey(env, sender_address);
        let mut msg = Bytes::new(env);
        msg.extend_from_array(&message_hash.to_array());
        env.crypto().ed25519_verify(&funder_public_key, &msg, funder_signature);
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

    /// Trailing binding fields shared by every signed message:
    ///   ",<network_id hex>,<pool address>"
    ///
    /// - network id pins the signature to one Stellar network. Testnet and mainnet share address
    ///   formats and the SEP-53 envelope carries no network, so without it a testnet signature
    ///   replays on mainnet.
    /// - the pool address pins it to this contract instance; per-funder nonces live in THIS
    ///   contract's storage, so a second pool sees a fresh nonce.
    ///
    /// Ciphertexts are deliberately NOT bound, on any operation. On fund the relayer AUTHORS them
    /// (it re-encrypts each note to its recipient), so the funder cannot sign over bytes it has
    /// never seen; rather than protect one operation and not the others, the rule is uniform. A
    /// swapped ciphertext can never change a note's owner/token/value — those are covered by the
    /// commitment and the signed fields — only how easily it is located off-chain.
    fn append_deployment_binding(env: &Env, out: &mut Bytes) {
        out.push_back(b',');
        bytes32_to_hex(&env.ledger().network_id(), out);
        out.push_back(b',');
        out.append(&env.current_contract_address().to_string().to_bytes());
    }

    /// Build and hash message for fund: commitments + sender + token + amount + nonce
    /// fund's message deliberately does NOT bind the ciphertexts.
    ///
    /// On the fund path the relayer DECRYPTS the funder's transport ciphertext and RE-ENCRYPTS the
    /// metadata to the recipient's key (only the relayer knows that key), so the stored
    /// ciphertexts are RELAYER-AUTHORED. The funder never sees them and cannot sign over them —
    /// binding them makes the funder signature unverifiable by construction.
    ///
    /// Nothing is lost: a digest authored by the relayer proves nothing AGAINST the relayer, and
    /// the note's owner/token/value are already bound by the commitment, which the funder signs.
    /// `build_withdraw_message` DOES bind its change ciphertext — there the client authors it and
    /// the relayer passes it through untouched.
    fn build_fund_message(
        env: &Env, commitments: &Vec<U256>, sender: &Address,
        token: &Address, amount: i128, nonce: u64, expiry: u64,
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
        msg.push_back(b',');
        Self::append_u64_decimal(expiry, &mut msg);
        Self::append_deployment_binding(env, &mut msg);
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
        Self::append_deployment_binding(env, &mut msg);
        env.crypto().sha256(&msg).into()
    }

    /// Build and hash message for transact: commitments + nonce + nullifiers
    fn build_transact_message(
        env: &Env, commitments: &Vec<U256>, nonce: u64,
        nullifiers: &Vec<U256>,
    ) -> BytesN<32> {
        let mut msg = Self::build_message_prefix(env, b"stellar:transact:", commitments);
        msg.push_back(b',');
        Self::append_u64_decimal(nonce, &mut msg);
        msg.push_back(b',');
        Self::append_hex_commitments(nullifiers, &mut msg);
        Self::append_deployment_binding(env, &mut msg);
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

        // Seed the bounded root history: slot 0 holds the empty-tree root 0, which stays valid
        // forever (it is never stored elsewhere in the ring and so never evicted).
        let mut roots: Map<U256, bool> = Map::new(&env);
        roots.set(U256::from_u32(&env, 0), true);
        env.storage().instance().set(&ROOTS, &roots);
        let mut rhist: Vec<U256> = Vec::new(&env);
        rhist.push_back(U256::from_u32(&env, 0));
        env.storage().instance().set(&RHIST, &rhist);
        env.storage().instance().set(&RIDX, &0u32);
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

    /* Authorized signer set.
     *
     * A set, not a single key, so several signing enclaves can serve one pool (rotation, HA).
     */
    pub fn get_signers(env: Env) -> Vec<BytesN<32>> {
        env.storage().instance().get(&SIGNERS).unwrap_or(Vec::new(&env))
    }

    pub fn add_signer(env: Env, signer_public_key: BytesN<32>) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        let mut signers: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&SIGNERS)
            .unwrap_or(Vec::new(&env));
        if signers.contains(&signer_public_key) {
            log!(&env, "Signer already authorized");
            panic_with_error!(&env, Error::SignerAlreadyAuthorized);
        }
        signers.push_back(signer_public_key);
        env.storage().instance().set(&SIGNERS, &signers);
    }

    pub fn remove_signer(env: Env, signer_public_key: BytesN<32>) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        let mut signers: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&SIGNERS)
            .unwrap_or(Vec::new(&env));
        // Refusing to empty the set turns an operator mistake into a failed tx instead of a
        // halted pool awaiting an owner-key ceremony (see the note on the signer set).
        if signers.len() <= 1 {
            log!(&env, "Cannot remove the last signer");
            panic_with_error!(&env, Error::LastSigner);
        }
        match signers.first_index_of(&signer_public_key) {
            Some(i) => { signers.remove(i); }
            None => {
                log!(&env, "Signer not authorized");
                panic_with_error!(&env, Error::SignerNotAuthorized);
            }
        }
        env.storage().instance().set(&SIGNERS, &signers);
    }

    /* Relayer note-encryption public key (ECDH), 64 bytes: x || y, no 0x04 prefix.
     *
     * Published so an owner can identify the relayer's encryption identity without asking the
     * relayer — the pool is readable when the relayer is not.
     *
     * NOT the decryption path. Every stored ciphertext already carries the encrypter's pubkey as
     * its own 64-byte header, and THAT is what a recovery tool must use: this slot holds only the
     * CURRENT key, so notes encrypted under a previously-rotated relayer wallet would not decrypt
     * against it. Audit cross-check, not a source of truth.
     */
    pub fn get_relayer_enc_key(env: Env) -> Option<BytesN<64>> {
        env.storage().instance().get(&ENCKEY)
    }

    pub fn set_relayer_enc_key(env: Env, enc_public_key: BytesN<64>) {
        let owner: Address = env.storage().instance().get(&OWNER).unwrap();
        owner.require_auth();
        env.storage().instance().set(&ENCKEY, &enc_public_key);
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

    /// Push a root into the bounded ring buffer, evicting the one that leaves the window.
    /// The empty-tree root 0 is never stored here, so it is never evicted and stays valid.
    fn push_root(env: &Env, r: U256) {
        let mut roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(env));
        let mut rhist: Vec<U256> = env.storage().instance().get(&RHIST).unwrap_or(Vec::new(env));
        let ridx: u32 = env.storage().instance().get(&RIDX).unwrap_or(0);
        let zero = U256::from_u32(env, 0);

        let idx = (ridx + 1) % ROOT_HISTORY_SIZE;
        while rhist.len() <= idx { rhist.push_back(zero.clone()); }
        let evicted = rhist.get_unchecked(idx);
        if evicted != zero { roots.remove(evicted); }
        rhist.set(idx, r.clone());
        roots.set(r, true);

        env.storage().instance().set(&ROOTS, &roots);
        env.storage().instance().set(&RHIST, &rhist);
        env.storage().instance().set(&RIDX, &idx);
    }

    /// Resolve a source-node read during the up-walk to a level-0 leaf, a node computed earlier in
    /// this call (`fresh`), one of the level's two retained frontier nodes, or the virtual pad 0.
    /// Anything else is a bug and panics — the differential test relies on this.
    #[allow(clippy::too_many_arguments)]
    fn read_src(
        env: &Env,
        level0: &Vec<U256>,
        level: u32,
        idx: u32,
        fresh: &Vec<U256>,
        win_start: u32,
        logical: u32,
        pre_size: &Vec<u32>,
        fa: &Vec<U256>,
        fb: &Vec<U256>,
        pre_levels: u32,
    ) -> U256 {
        if level == 0 { return level0.get_unchecked(idx); }
        if idx >= win_start && idx < win_start + fresh.len() {
            return fresh.get_unchecked(idx - win_start);
        }
        if level < pre_levels {
            let ps = pre_size.get_unchecked(level);
            if ps >= 1 && idx == ps - 1 { return fb.get_unchecked(level); }
            if ps >= 2 && idx == ps - 2 { return fa.get_unchecked(level); }
        }
        if idx >= logical { return U256::from_u32(env, 0); }
        panic!("frontier read out of range")
    }

    /// Insert a batch of pre-hashed leaves into the merkle tree.
    ///
    /// Only the minimum needed to recompute the root incrementally is persisted: level 0 (all
    /// leaves) in full, and for each level >= 1 just its two rightmost nodes (`FRONTA`/`FRONTB`).
    /// An append only touches the right edge, so the sole pre-existing nodes the up-walk re-reads
    /// at a level are its two rightmost; the rest are level-0 leaves or nodes computed earlier in
    /// this same call. Every produced root is byte-identical to a full-tree build.
    fn insert_leaf_hashes(env: &Env, leaves: Vec<U256>) {
        let num_leaves = leaves.len();
        if num_leaves == 0 { return; }

        let mut merkle_tree: Vec<Vec<U256>> = env.storage().instance().get(&HASHES).unwrap_or(Vec::new(env));
        let mut level_size: Vec<u32> = env.storage().instance().get(&LSIZE).unwrap_or(Vec::new(env));
        let mut number_of_levels: u32 = env.storage().instance().get(&NLEVELS).unwrap_or(0);
        let mut fa: Vec<U256> = env.storage().instance().get(&FRONTA).unwrap_or(Vec::new(env));
        let mut fb: Vec<U256> = env.storage().instance().get(&FRONTB).unwrap_or(Vec::new(env));
        let dummy_value = U256::from_u32(env, 0);

        if level_size.len() == 0 {
            level_size.push_back(0);
            merkle_tree.push_back(Vec::new(env));
            number_of_levels = 1;
        }

        // Step 1: place leaves at level 0. First leaf overwrites a trailing DUMMY left by prior
        // odd-padding; the rest are appended. Level 0 is stored in full.
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
        level_size.set(0, current_size);

        // Snapshot the pre-insert upper-level frontier (read before it is overwritten).
        let pre_levels = number_of_levels;
        let pre_size = level_size.clone();

        // Step 2: walk up, recomputing only pairs covering changed nodes; reads served by the
        // frontier snapshot + the freshly computed window.
        let mut level: u32 = 0;
        let mut changed_from = first_changed;
        let mut fresh: Vec<U256> = Vec::new(env); // fresh window for the current source level
        let mut win_start: u32 = 0;
        let mut last_parents: Vec<U256> = Vec::new(env);

        while level_size.get_unchecked(level) > 1 {
            let mut cur_size = level_size.get_unchecked(level);
            let logical = cur_size; // real node count before the virtual right-pad

            if cur_size % 2 != 0 {
                if level == 0 {
                    level0.push_back(dummy_value.clone()); // only level 0's pad is persisted
                }
                cur_size += 1;
                level_size.set(level, cur_size);
            }
            if level + 1 >= number_of_levels {
                number_of_levels += 1;
            }

            let first_pair = changed_from / 2;
            let num_pairs = cur_size / 2;

            let mut parents: Vec<U256> = Vec::new(env);
            for pair_idx in first_pair..num_pairs {
                let l = Self::read_src(env, &level0, level, pair_idx * 2, &fresh, win_start, logical, &pre_size, &fa, &fb, pre_levels);
                let r = Self::read_src(env, &level0, level, pair_idx * 2 + 1, &fresh, win_start, logical, &pre_size, &fa, &fb, pre_levels);
                parents.push_back(Self::hash_pair(env, l, r));
            }

            // Persist this source level's new frontier (its two rightmost nodes) via the same reads.
            if level >= 1 {
                while fa.len() <= level { fa.push_back(dummy_value.clone()); }
                while fb.len() <= level { fb.push_back(dummy_value.clone()); }
                fa.set(level, Self::read_src(env, &level0, level, cur_size - 2, &fresh, win_start, logical, &pre_size, &fa, &fb, pre_levels));
                fb.set(level, Self::read_src(env, &level0, level, cur_size - 1, &fresh, win_start, logical, &pre_size, &fa, &fb, pre_levels));
            }

            if level + 1 < level_size.len() {
                level_size.set(level + 1, num_pairs);
            } else {
                level_size.push_back(num_pairs);
            }

            fresh = parents.clone();
            win_start = first_pair;
            last_parents = parents;
            changed_from = first_pair;
            level += 1;
        }

        // Root + the top level's frontier (a single node).
        let merkle_tree_root: U256;
        if level == 0 {
            merkle_tree_root = level0.get_unchecked(0); // single-leaf tree: root is the sole leaf
        } else {
            merkle_tree_root = last_parents.get_unchecked(0);
            while fa.len() <= level { fa.push_back(dummy_value.clone()); }
            while fb.len() <= level { fb.push_back(dummy_value.clone()); }
            fa.set(level, dummy_value.clone());
            fb.set(level, merkle_tree_root.clone());
        }

        // Step 3: persist. HASHES holds only level 0 (upper levels live in the frontier).
        merkle_tree.set(0, level0);
        while merkle_tree.len() > 1 { merkle_tree.pop_back(); }
        env.storage().instance().set(&HASHES, &merkle_tree);
        env.storage().instance().set(&LSIZE, &level_size);
        env.storage().instance().set(&NLEVELS, &number_of_levels);
        env.storage().instance().set(&FRONTA, &fa);
        env.storage().instance().set(&FRONTB, &fb);
        env.storage().instance().set(&ROOT, &merkle_tree_root);
        Self::push_root(env, merkle_tree_root);
    }

    #[inline(always)]
    fn current_block_height(env: &Env) -> U256 {
        U256::from_u32(env, env.ledger().sequence())
    }

    #[inline(always)]
    fn note_leaf_hash(env: &Env, note_commitment: U256, block_height: U256) -> U256 {
        // note_commitment_hash = SINGLE Poseidon hash of the commitment. The leaf pairs it with the
        // block height: the old height-less leaf was hash_pair(hash_single(nc), 0), so block_height
        // replaces the zero-padding (one Poseidon op, not two). Byte-identical to EVM `hashSingle` /
        // Solana `hash_single` and the shared ZK circuit `note_commitment_hash`.
        let note_commitment_hash = Self::hash_single(env, note_commitment);
        Self::hash_pair(env, note_commitment_hash, block_height)
    }

    fn insert_leaves(env: &Env, leaves: Vec<U256>) {
        if leaves.len() == 0 { return; }
        let block_height = Self::current_block_height(env);
        let mut hashed: Vec<U256> = Vec::new(env);
        for leaf in leaves.iter() {
            hashed.push_back(Self::note_leaf_hash(env, leaf, block_height.clone()));
        }
        Self::insert_leaf_hashes(env, hashed);
    }

    // Merkle tree read accessors

    /// Returns the persisted node structure. Only level 0 (all leaves) is stored in full; upper
    /// levels are not — off-chain proving rebuilds them from level 0 (see backend merkle.ts).
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
        // Upper bound (ledger timestamp) on how long the funder's authorization is valid, so a
        // captured-but-unsettled signature cannot be replayed indefinitely.
        expiry: u64,
        root: U256,
        // Which authorized signer produced `signer_signature` — see verify_signer for why the
        // contract cannot simply try each key.
        signer_public_key: BytesN<32>,
        signer_signature: BytesN<64>,
        // The funder's detached wallet signature over the same fund message (verified against the
        // Ed25519 key derived from `sender_address`).
        funder_signature: BytesN<64>,
    ) {
        if note_ciphertexts.len() != note_commitments.len() {
            panic_with_error!(&env, Error::CiphertextLengthMismatch);
        }
        if env.ledger().timestamp() > expiry {
            panic_with_error!(&env, Error::FundAuthExpired);
        }
        Self::check_and_update_funder_nonce(&env, &sender_address, nonce);
        Self::require_relayer(&env, &relayer);
        Self::require_valid_root(&env, &root);

        let hash = Self::build_fund_message(&env, &note_commitments, &sender_address, &token_address, amount, nonce, expiry);

        // BOTH signatures cover the same expiry-bound message. The relayer (authorized signer)
        // authorizes the submission; the FUNDER's wallet signature authorizes spending their token
        // allowance into exactly these commitments — verified on-chain (index-equivalent to EVM's
        // funder ecrecover) rather than in the ZK circuit.
        Self::verify_signer(&env, &signer_public_key, &hash, &signer_signature);
        Self::verify_funder(&env, &sender_address, &hash, &funder_signature);

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
        signer_public_key: BytesN<32>,
        signer_signature: BytesN<64>,
    ) {
        if note_ciphertexts.len() != note_commitments.len() {
            panic_with_error!(&env, Error::CiphertextLengthMismatch);
        }
        Self::require_relayer(&env, &relayer);
        Self::require_valid_root(&env, &root);
        Self::check_nullifiers(&env, &nullifiers);

        let hash = Self::build_withdraw_message(&env, &note_commitments, &receiver_address, &token_address, amount, nonce, &nullifiers);

        // Relayer (authorized signer) verification stays on-chain. The OWNER's wallet signature — which
        // binds the payout destination (receiver_address is folded into the ZK authDigest) — moved into
        // the ZK circuit, verified off-chain by the VK-pinned relayer (see payroll_verification.cpp).
        Self::verify_signer(&env, &signer_public_key, &hash, &signer_signature);

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
        signer_public_key: BytesN<32>,
        signer_signature: BytesN<64>,
    ) {
        if note_ciphertexts.len() != nc_outputs.len() {
            panic_with_error!(&env, Error::CiphertextLengthMismatch);
        }
        Self::require_relayer(&env, &relayer);
        Self::require_valid_root(&env, &root);
        Self::check_nullifiers(&env, &nullifiers);

        let hash = Self::build_transact_message(&env, &nc_outputs, nonce, &nullifiers);
        Self::verify_signer(&env, &signer_public_key, &hash, &signer_signature);

        Self::append_ciphertexts(&env, &note_ciphertexts);
        Self::insert_leaves(&env, nc_outputs);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Version
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn version(env: Env) -> Vec<String> {
        vec![&env, String::from_str(&env, "Ligero Privacy Pool v7.0")]
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

    /// Test-only view over the bounded root-history membership map.
    pub fn t_root_valid(env: Env, root: U256) -> bool {
        let roots: Map<U256, bool> = env.storage().instance().get(&ROOTS).unwrap_or(Map::new(&env));
        roots.get(root).unwrap_or(false)
    }
}

mod tests;
