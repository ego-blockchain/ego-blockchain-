#!/usr/bin/env bash
# start.sh — Build image (if needed) and bring up the Ego Testnet.
# chmod +x scripts/start.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTNET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Preflight checks ──────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "ERROR: docker is not installed or not in PATH."
  exit 1
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  echo "ERROR: docker-compose (or 'docker compose' plugin) is not installed."
  exit 1
fi

# Prefer the standalone binary; fall back to the plugin.
DC="docker-compose"
if ! command -v docker-compose &>/dev/null; then
  DC="docker compose"
fi

# ── Init data dirs if missing ─────────────────────────────────────────────────
if [ ! -d "$TESTNET_DIR/data/relay" ]; then
  echo "Data directories not found — running init.sh first..."
  bash "$SCRIPT_DIR/init.sh"
fi

# ── Launch ────────────────────────────────────────────────────────────────────
echo "Starting Ego Testnet..."
$DC -f "$TESTNET_DIR/docker-compose.yml" up -d --build

echo ""
echo "Waiting 10 seconds for nodes to come online..."
sleep 10

# ── Health checks ─────────────────────────────────────────────────────────────
declare -A NODES
NODES[Relay]=8540
NODES[Validator1]=8541
NODES[Validator2]=8542
NODES[Validator3]=8543
NODES[Validator4]=8544

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "%-12s %-6s %-10s\n" "Node" "Port" "Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for name in Relay Validator1 Validator2 Validator3 Validator4; do
  port="${NODES[$name]}"
  if curl -sf "http://localhost:$port/health" >/dev/null 2>&1; then
    status="online"
  else
    status="not ready"
  fi
  printf "%-12s %-6s %-10s\n" "$name" "$port" "$status"
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Ego Testnet Running"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Relay   RPC: http://localhost:8540"
echo " Node 1  RPC: http://localhost:8541"
echo " Node 2  RPC: http://localhost:8542"
echo " Node 3  RPC: http://localhost:8543"
echo " Node 4  RPC: http://localhost:8544"
echo " Load Balanced RPC: http://localhost:80/rpc"
echo " Faucet: http://localhost:80/faucet?to=<YOUR_ADDRESS>"
echo " Chain ID: 1399"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
