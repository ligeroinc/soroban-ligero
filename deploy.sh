#!/bin/bash

# WHITELIST_ENABLED=true (default) gates fund/withdraw on the FUND/WITHDRAW
# whitelist maps. Set WHITELIST_ENABLED=false to deploy a pool that skips
# both checks for its lifetime (immutable, set in constructor).
WHITELIST_ENABLED="${WHITELIST_ENABLED:-true}"

stellar contract deploy \
  --wasm target/wasm32v1-none/release/privacy_pool.wasm \
  --source SCJ2CRC2BILZJMN3YE6ECE7Z4LQBGS4SDNURR3APCQQS262R62MN5RTS \
  --network testnet \
  -- \
  --owner GAY7CM62RJNRQ6OYVIYIHR777PC6M7TEHFSYKYZ6VLQDMGKBAAMWGPKA \
  --whitelist_enabled "$WHITELIST_ENABLED"

