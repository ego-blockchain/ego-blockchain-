#!/usr/bin/env bash
# deploy-vps.sh — Deploy a single Ego blockchain node on Ubuntu 22.04 LTS.
# Usage:  bash deploy-vps.sh [validator|relay] [bootstrap_multiaddr]
# Run as root or with sudo on a fresh Ubuntu 22.04 VPS.
# chmod +x deploy-vps.sh
set -e

ROLE="${1:-validator}"
BOOTSTRAP="${2:-}"
CHAIN_ID=1399
RPC_PORT=8545
P2P_PORT=9000

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Ego Blockchain Node Installer"
echo " Role: $ROLE  |  Chain ID: $CHAIN_ID"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── System dependencies ───────────────────────────────────────────────────────
echo "[1/6] Installing system dependencies..."
apt-get update -qq
apt-get install -y curl git pkg-config libssl-dev build-essential ufw

# ── Rust ──────────────────────────────────────────────────────────────────────
echo "[2/6] Checking Rust toolchain..."
if ! command -v cargo &>/dev/null; then
  echo "  Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
else
  echo "  Rust already installed: $(rustc --version)"
fi

# ── Clone repository ──────────────────────────────────────────────────────────
echo "[3/6] Cloning Ego Blockchain repository..."
if [ ! -d /opt/ego-blockchain ]; then
  git clone https://github.com/egoblockchain/ego-blockchain /opt/ego-blockchain
else
  echo "  Repository already present — pulling latest..."
  git -C /opt/ego-blockchain pull --ff-only
fi
cd /opt/ego-blockchain

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[4/6] Building ego-node (this may take several minutes)..."
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release --bin ego-node
cp target/release/ego-node /usr/local/bin/ego-node
echo "  Binary installed at /usr/local/bin/ego-node"

# ── Data directory & genesis ──────────────────────────────────────────────────
echo "[5/6] Setting up data directory..."
mkdir -p /var/lib/ego-node
if [ -f /opt/ego-blockchain/testnet/genesis.json ]; then
  cp /opt/ego-blockchain/testnet/genesis.json /var/lib/ego-node/genesis.json
  echo "  genesis.json copied."
else
  echo "  WARNING: testnet/genesis.json not found; node may fail to start."
fi

# ── Systemd service ───────────────────────────────────────────────────────────
echo "[6/6] Creating systemd service..."

# Build the bootstrap flag string only when a bootstrap address is provided.
BOOTSTRAP_FLAG=""
if [ -n "$BOOTSTRAP" ]; then
  BOOTSTRAP_FLAG="--bootstrap $BOOTSTRAP"
fi

cat > /etc/systemd/system/ego-node.service << EOF
[Unit]
Description=Ego Blockchain Node ($ROLE)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/ego-node
ExecStart=/usr/local/bin/ego-node \\
  --type $ROLE \\
  --port $P2P_PORT \\
  --shards 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 \\
  --storage 500 \\
  --bandwidth 1000 \\
  --metrics \\
  $BOOTSTRAP_FLAG
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=RUST_LOG=info
Environment=EGO_CHAIN_ID=$CHAIN_ID
Environment=EGO_DATA_DIR=/var/lib/ego-node

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ego-node
systemctl start ego-node

# ── Firewall ──────────────────────────────────────────────────────────────────
echo "Opening firewall ports..."
ufw allow "$P2P_PORT/tcp" || true
ufw allow "$RPC_PORT/tcp" || true

# ── Done ──────────────────────────────────────────────────────────────────────
PUBLIC_IP=$(curl -sf --max-time 5 ifconfig.me 2>/dev/null || echo "<your-ip>")

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " ego-node installed and running"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Logs:    journalctl -u ego-node -f"
echo " Status:  systemctl status ego-node"
echo " RPC:     http://$PUBLIC_IP:$RPC_PORT/health"
echo " P2P:     /ip4/$PUBLIC_IP/tcp/$P2P_PORT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
