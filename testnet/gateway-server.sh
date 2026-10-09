#!/usr/bin/env bash
# gateway-server.sh — turn the server's headless Ego Desktop into an always-on
# phone gateway. Run with sudo on the server, with the new build as $1.
#
# It updates the node that already listens on the P2P port, so the server keeps
# its wallet and chain data, then tells it to announce itself and opens the
# gateway port. If the gateway doesn't come up, the old build is put back.
#
# Oracle Cloud also filters traffic outside the VM: allow TCP 47398 in the
# subnet's security list once, in the console.
set -euo pipefail

NEW_BIN="${1:?usage: gateway-server.sh <new ego-desktop binary>}"
P2P_PORT="${EGO_P2P_PORT:-47393}"
GATEWAY_PORT="${EGO_GATEWAY_PORT:-47398}"

fail() { echo "error: $*" >&2; exit 1; }

# ── The running node ──────────────────────────────────────────────────────────
PID=$(ss -ltnpH "sport = :$P2P_PORT" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2 || true)
[ -n "$PID" ] || fail "nothing listens on port $P2P_PORT, so there's no headless node to update."
EXE=$(readlink -f "/proc/$PID/exe")
UNIT=$(grep -o '[^/]*\.service' "/proc/$PID/cgroup" | head -1 || true)
[ -n "$UNIT" ] || fail "the node on port $P2P_PORT (pid $PID) isn't a systemd service; update it by hand."
echo "Node: $UNIT ($EXE)"

# ── The new build must run here before it replaces the old one ──────────────
chmod +x "$NEW_BIN"
MISSING=$(ldd "$NEW_BIN" | grep 'not found' || true)
[ -z "$MISSING" ] || fail "the new build needs libraries this server doesn't have:
$MISSING"

# ── Swap the binary and set the gateway switches ─────────────────────────────
# .original is the build from before this script ever ran and is never
# overwritten; .previous is the last build, put back if this one fails.
# (The first version of this script only kept .previous, so that's the original.)
if [ ! -e "$EXE.original" ]; then
  if [ -e "$EXE.previous" ]; then cp -p "$EXE.previous" "$EXE.original"; else cp -p "$EXE" "$EXE.original"; fi
fi
cp -p "$EXE" "$EXE.previous"
install -m 755 "$NEW_BIN" "$EXE"
mkdir -p "/etc/systemd/system/$UNIT.d"
cat > "/etc/systemd/system/$UNIT.d/gateway.conf" <<EOF
[Service]
Environment=EGO_GATEWAY=1
Environment=EGO_GATEWAY_PUBLIC=1
Environment=EGO_GATEWAY_PORT=$GATEWAY_PORT
EOF

# ── Open the gateway port in the VM's own firewall ───────────────────────────
if ! iptables -C INPUT -p tcp --dport "$GATEWAY_PORT" -j ACCEPT 2>/dev/null; then
  iptables -I INPUT 1 -p tcp --dport "$GATEWAY_PORT" -j ACCEPT
  command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null
fi
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow "$GATEWAY_PORT/tcp" >/dev/null
fi

systemctl daemon-reload
systemctl restart "$UNIT"

# ── Check it, or put the old build back ──────────────────────────────────────
for _ in $(seq 1 30); do
  if curl -fsk -m 5 "https://127.0.0.1:$GATEWAY_PORT/health" | grep -q ego-gateway; then
    echo "Gateway is up on port $GATEWAY_PORT."
    exit 0
  fi
  sleep 4
done
echo "The gateway didn't answer within two minutes; restoring the previous build." >&2
install -m 755 "$EXE.previous" "$EXE"
systemctl daemon-reload
systemctl restart "$UNIT"
exit 1
