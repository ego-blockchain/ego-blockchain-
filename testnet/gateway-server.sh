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
MIN_MEMORY_MB=1800

fail() { echo "error: $*" >&2; exit 1; }

MEMORY_MB=$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)
[ "$MEMORY_MB" -ge "$MIN_MEMORY_MB" ] || fail "this server has ${MEMORY_MB} MB of memory and a node needs about 2 GB, so nothing was changed. Use a server with 2 GB or more."

open_port() {
  local proto="$1" port="$2"
  if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p "$proto" --dport "$port" -j ACCEPT
  fi
  if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    ufw allow "$port/$proto" >/dev/null
  fi
}

save_firewall() {
  if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null; fi
}

wait_for_gateway() {
  for _ in $(seq 1 "$1"); do
    if curl -fsk -m 5 "https://127.0.0.1:$GATEWAY_PORT/health" | grep -q ego-gateway; then
      return 0
    fi
    sleep 4
  done
  return 1
}

# ── The new build must run here before it replaces the old one ──────────────
chmod +x "$NEW_BIN"
MISSING=$(ldd "$NEW_BIN" | grep 'not found' || true)
if [ -n "$MISSING" ] && command -v apt-get >/dev/null; then
  echo "Installing the libraries the build needs..."
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libwebkit2gtk-4.0-37 libgtk-3-0 \
    libayatana-appindicator3-1 librsvg2-2 libssl3 >/dev/null || true
  MISSING=$(ldd "$NEW_BIN" | grep 'not found' || true)
fi
[ -z "$MISSING" ] || fail "the new build needs libraries this server doesn't have (use Ubuntu 22.04):
$MISSING"

# ── The running node ──────────────────────────────────────────────────────────
PID=$(ss -ltnpH "sport = :$P2P_PORT" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2 || true)

if [ -z "$PID" ]; then
  UNIT=ego-gateway.service
  EXE=/opt/ego/ego-desktop
  DATA=/var/lib/ego-gateway
  if systemctl cat "$UNIT" >/dev/null 2>&1; then
    systemctl is-active --quiet "$UNIT" && fail "$UNIT is running but nothing listens on port $P2P_PORT. Check: journalctl -u $UNIT"
    echo "$UNIT is installed but stopped: installing the new build and starting it."
  else
    echo "Nothing listens on port $P2P_PORT: installing a new gateway as $UNIT (observer mode, it serves phones and never makes blocks)."
  fi
  id ego >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin ego
  install -d -m 755 /opt/ego
  install -d -o ego -g ego -m 700 "$DATA"
  if [ -e "$EXE" ]; then cp -p "$EXE" "$EXE.previous"; fi
  install -m 755 "$NEW_BIN" "$EXE"
  cat > "/etc/systemd/system/$UNIT" <<EOF
[Unit]
Description=Ego phone gateway (headless Ego Desktop)
After=network-online.target
Wants=network-online.target

[Service]
User=ego
Group=ego
WorkingDirectory=$DATA
ExecStart=$EXE
Restart=always
RestartSec=10
LimitNOFILE=65536
Environment=EGO_HEADLESS=1
Environment=EGO_OBSERVER=1
Environment=EGO_DATA_DIR=$DATA
Environment=EGO_P2P_PORT=$P2P_PORT
Environment=EGO_GATEWAY=1
Environment=EGO_GATEWAY_PUBLIC=1
Environment=EGO_GATEWAY_PORT=$GATEWAY_PORT

[Install]
WantedBy=multi-user.target
EOF
  open_port tcp "$P2P_PORT"
  open_port tcp "$GATEWAY_PORT"
  open_port udp "$GATEWAY_PORT"
  save_firewall
  systemctl daemon-reload
  systemctl enable "$UNIT" >/dev/null 2>&1
  systemctl restart "$UNIT"
  if wait_for_gateway 75; then
    echo "Gateway is up on port $GATEWAY_PORT. It keeps syncing the chain in the background."
    exit 0
  fi
  echo "The gateway didn't answer within five minutes. Last log lines:" >&2
  journalctl -u "$UNIT" --no-pager -n 30 >&2 || true
  exit 1
fi

EXE=$(readlink -f "/proc/$PID/exe")
UNIT=$(grep -o '[^/]*\.service' "/proc/$PID/cgroup" | head -1 || true)
[ -n "$UNIT" ] || fail "the node on port $P2P_PORT (pid $PID) isn't a systemd service; update it by hand."
echo "Node: $UNIT ($EXE)"

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
open_port tcp "$GATEWAY_PORT"
open_port udp "$GATEWAY_PORT"
save_firewall

systemctl daemon-reload
systemctl restart "$UNIT"

# ── Check it, or put the old build back ──────────────────────────────────────
if wait_for_gateway 30; then
  echo "Gateway is up on port $GATEWAY_PORT."
  exit 0
fi
echo "The gateway didn't answer within two minutes; restoring the previous build." >&2
install -m 755 "$EXE.previous" "$EXE"
systemctl daemon-reload
systemctl restart "$UNIT"
exit 1
