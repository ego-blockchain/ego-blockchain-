#!/usr/bin/env bash
# status.sh — Show container status and current block heights for all nodes.
# chmod +x scripts/status.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTNET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── JSON parser: prefer jq, fall back to python3 ─────────────────────────────
get_block_height() {
  local port="$1"
  local response
  response=$(curl -sf --max-time 5 "http://localhost:$port/health" 2>/dev/null || true)
  if [ -z "$response" ]; then
    echo "offline"
    return
  fi
  if command -v jq &>/dev/null; then
    printf '%s' "$response" | jq -r '.block_height // "N/A"'
  else
    printf '%s' "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('block_height', 'N/A'))
except Exception:
    print('N/A')
"
  fi
}

# ── docker-compose ps ─────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Container Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v docker-compose &>/dev/null; then
  docker-compose -f "$TESTNET_DIR/docker-compose.yml" ps
elif docker compose version &>/dev/null 2>&1; then
  docker compose -f "$TESTNET_DIR/docker-compose.yml" ps
else
  echo "WARNING: docker-compose not found; skipping container status."
fi

# ── Block heights ─────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Block Heights"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

NAMES=(Relay     Validator1 Validator2 Validator3 Validator4)
PORTS=(8540      8541       8542       8543       8544)

printf "%-12s %-6s %-14s\n" "Node" "Port" "Block Height"
echo "──────────────────────────────────────"

for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  port="${PORTS[$i]}"
  height=$(get_block_height "$port")
  printf "%-12s %-6s %-14s\n" "$name" "$port" "#$height"
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
