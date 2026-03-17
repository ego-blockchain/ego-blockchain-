#!/usr/bin/env bash
# health.sh — Query all nodes and print a health summary table.
# chmod +x scripts/health.sh
set -e

# ── JSON parser: prefer jq, fall back to python3 ─────────────────────────────
parse_json() {
  local json="$1"
  local field="$2"
  if command -v jq &>/dev/null; then
    printf '%s' "$json" | jq -r ".$field // \"N/A\""
  else
    printf '%s' "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('$field', 'N/A'))
except Exception:
    print('N/A')
"
  fi
}

# ── Node list: name → RPC port ────────────────────────────────────────────────
NAMES=(Relay Validator1 Validator2 Validator3 Validator4)
PORTS=(8540  8541       8542       8543       8544)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "%-12s %-6s %-10s %-15s %-20s\n" \
       "Node" "Port" "Status" "Block Height" "Peer ID"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  port="${PORTS[$i]}"

  response=$(curl -sf --max-time 5 "http://localhost:$port/health" 2>/dev/null || true)

  if [ -z "$response" ]; then
    printf "%-12s %-6s %-10s %-15s %-20s\n" \
           "$name" "$port" "offline" "—" "—"
    continue
  fi

  block_height=$(parse_json "$response" "block_height")
  peer_id=$(parse_json "$response" "peer_id")

  # Truncate peer_id to 18 chars for table readability
  short_peer="${peer_id:0:18}..."

  printf "%-12s %-6s %-10s %-15s %-20s\n" \
         "$name" "$port" "online" "#$block_height" "$short_peer"
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
