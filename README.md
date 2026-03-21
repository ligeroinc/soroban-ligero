# Ligero Payroll - Soroban Smart Contract

Privacy-preserving payroll contract on Stellar, built with [Soroban](https://soroban.stellar.org/).

Uses Poseidon2 hash-based Merkle tree for note commitments with double-hashing (`hash(hash(nc))`) for leaf insertion.

## Contract Source

**[contracts/payroll/src/lib.rs](contracts/payroll/src/lib.rs)**

## Contract Functions

### Main Payroll Functionality
- `disburse` — Employer deposits tokens into the privacy pool (creates shielded notes)
- `withdraw` — Employee withdraws tokens from the privacy pool (spends shielded notes)

### Merkle Tree Operations
- `hash_function_u256` — Poseidon2 single-element hash
- `hash_function_pair` — Poseidon2 two-element hash
- `insert_leaf_hash` — Insert a pre-hashed leaf into the Merkle tree
- `insert_leaves` — Double-hash and insert multiple leaves
- `get_root` — Get current Merkle tree root
- `get_hashes` — Get all tree levels
- `get_number_of_levels` — Get tree depth
- `get_levels` — Get level sizes

### Contract Admin
- `owner` / `transfer_ownership` — Contract ownership
- `get_relayer` / `set_relayer` — Relayer address management
- `add_admin` / `remove_admin` / `is_admin` — Admin management

### Whitelist Operations
- `add_employer` / `remove_employer` / `is_employer` — Employer whitelist
- `add_employee` / `remove_employee` / `is_employee` — Employee whitelist

## Build

```bash
stellar contract build --optimize \
  --meta source_repo=github:ligeroinc/soroban-ligero
```

## Deploy

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/payroll.wasm \
  --source <OWNER_SECRET> \
  --network testnet \
  --alias payroll \
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
│   └── payroll
│       ├── src
│       │   ├── lib.rs
│       │   └── test.rs
│       └── Cargo.toml
|   └── poseidon2-ligero
│       ├── src
│       │   ├── lib.rs
│       │   └── test.rs
│       └── Cargo.toml
├── Cargo.toml
└── README.md
```

- New Soroban contracts can be put in `contracts`, each in their own directory.
- If you initialized this project with any other example contracts via `--with-example`, those contracts will be in the `contracts` directory as well.
- Contracts should have their own `Cargo.toml` files that rely on the top-level `Cargo.toml` workspace for their dependencies.
- Frontend libraries can be added to the top-level directory as well. If you initialized this project with a frontend template via `--frontend-template` you will have those files already included.
