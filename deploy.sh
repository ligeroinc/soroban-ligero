#!/bin/bash

# v6 (LigeroClear): no on-chain whitelist — eligibility is proven in the ZK
# circuit, so the constructor takes only --owner.

stellar contract deploy \
  --wasm target/wasm32v1-none/release/privacy_pool.wasm \
  --source SCJ2CRC2BILZJMN3YE6ECE7Z4LQBGS4SDNURR3APCQQS262R62MN5RTS \
  --network testnet \
  -- \
  --owner GAY7CM62RJNRQ6OYVIYIHR777PC6M7TEHFSYKYZ6VLQDMGKBAAMWGPKA

