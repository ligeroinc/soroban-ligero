#!/bin/bash

stellar contract deploy \
  --wasm target/wasm32v1-none/release/payroll.wasm \
  --source-account alice \
  --network testnet \
  --alias payroll \
  -- \
  --owner GAY7CM62RJNRQ6OYVIYIHR777PC6M7TEHFSYKYZ6VLQDMGKBAAMWGPKA
