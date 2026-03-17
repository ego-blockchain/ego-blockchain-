#!/usr/bin/env bash
# faucet.sh — Request testnet EGOC from the faucet.
# Usage: ./faucet.sh <ego-address>
# chmod +x scripts/faucet.sh
set -e

ADDR="${1:?Usage: faucet.sh <ego-address>}"

echo "Requesting faucet for $ADDR ..."
curl -sf "http://localhost:8541/faucet?to=$ADDR" | python3 -m json.tool
