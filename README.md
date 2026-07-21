# Ligero Privacy Pool - Soroban Smart Contract

Privacy-preserving pool contract on Stellar, built with [Soroban](https://soroban.stellar.org/).

Uses Poseidon1 hash-based Merkle tree for note commitments with double-hashing (`hash(hash(nc))`) for leaf insertion.

## Contract Source

**[contracts/privacy_pool/src/lib.rs](contracts/privacy_pool/src/lib.rs)**

## Contract Functions

### Main Pool Functionality
- `fund` — Deposit tokens into the privacy pool (creates shielded notes)
- `withdraw` — Withdraw tokens from the privacy pool (spends shielded notes)
- `transact` — Internal shielded transfer (spend notes, create new notes)

### Merkle Tree Operations
- `hash_single` — Poseidon1 single-element hash
- `hash_pair` — Poseidon1 two-element hash
- `get_root` — Get current Merkle tree root
- `get_hashes` — Get all tree levels
- `get_number_of_levels` — Get tree depth
- `get_levels` — Get level sizes

### Contract Admin
- `owner` / `transfer_ownership` — Contract ownership
- `get_relayer` / `set_relayer` — Relayer address management
- `get_signers` / `add_signer` / `remove_signer` — Authorizing-signer set management
- `get_relayer_enc_key` / `set_relayer_enc_key` — Relayer note-encryption (ECDH) public key
- `add_admin` / `remove_admin` / `is_admin` — Admin management
- `version` — Read deployment metadata

> Eligibility (whitelist + blacklist) is proven in-ZK as of v7 (LigeroClear); there are no on-chain whitelist functions.

### Note Storage Reads
- `get_ciphertext` — Read a stored note ciphertext by index
- `ciphertext_count` — Number of stored note ciphertexts
- `get_funder_nonce` — Read a funder's current nonce

## Build

```bash
stellar contract build --optimize \
  --meta source_repo=github:ligeroinc/soroban-ligero
```

## Deploy

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/privacy_pool.wasm \
  --source <OWNER_SECRET> \
  --network testnet \
  --alias privacy_pool \
  -- \
  --owner <OWNER_ADDRESS>
```

## Verify Build

```bash
stellar contract info build \
  --contract-id <CONTRACT_ID> \
  --network testnet
```

## Create XDR via CLI

soroban contract invoke \
  --source <your-secret-key> \
  --network testnet \
  --id <contract-id> \
  --fnc <function-name> \
  --arg1 <arg-value> \
  --xdr # This flag outputs the XDR instead of sending it

**STELLAR TESTNET XLM ADDRESS:** CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC

Use testnet xlm address as a token_address parameter

## Project Structure

This repository uses the recommended structure for a Soroban project:

```text
.
├── contracts
│   └── privacy_pool
│       ├── src
│       │   ├── lib.rs
│       │   └── tests.rs
│       └── Cargo.toml
|   └── poseidon1
│       ├── scripts
│       │   ├── gen_constants.js
│       ├── src
│       │   ├── lib.rs
│       │   └── tests.rs
│       └── Cargo.toml
|   └── poseidon2-ligero
│       ├── src
│       │   ├── lib.rs
│       │   └── tests.rs
│       └── Cargo.toml
├── Cargo.toml
└── README.md
```

- New Soroban contracts can be put in `contracts`, each in their own directory.
- If you initialized this project with any other example contracts via `--with-example`, those contracts will be in the `contracts` directory as well.
- Contracts should have their own `Cargo.toml` files that rely on the top-level `Cargo.toml` workspace for their dependencies.
- Frontend libraries can be added to the top-level directory as well. If you initialized this project with a frontend template via `--frontend-template` you will have those files already included.
