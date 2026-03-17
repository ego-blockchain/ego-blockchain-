#!/usr/bin/env bash
# init.sh — Initialize Ego Testnet data directories and seed genesis config.
# chmod +x scripts/init.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTNET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Ego Testnet — Initialization"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Create node data directories ──────────────────────────────────────────────
NODES=(relay validator1 validator2 validator3 validator4)

for node in "${NODES[@]}"; do
  dir="$TESTNET_DIR/data/$node"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    echo "  created  $dir"
  else
    echo "  exists   $dir"
  fi
done

# ── Seed genesis.json into every data directory ───────────────────────────────
GENESIS="$TESTNET_DIR/genesis.json"

if [ ! -f "$GENESIS" ]; then
  echo ""
  echo "ERROR: genesis.json not found at $GENESIS"
  echo "       Place a valid genesis.json in the testnet/ directory first."
  exit 1
fi

for node in "${NODES[@]}"; do
  dest="$TESTNET_DIR/data/$node/genesis.json"
  cp "$GENESIS" "$dest"
  echo "  copied genesis → $dest"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Ego Testnet initialized."
echo " Run ./scripts/start.sh to launch."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
