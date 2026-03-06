# Ego Desktop MVP

> **TESTNET NOTICE**: This application runs on the Ego Testnet. All EGOC tokens are test tokens with no real monetary value. Do not use real funds.

A quantum-safe blockchain desktop application demonstrating EGO Blockchain capabilities — wallet, encrypted file sharing, P2P messenger, and block explorer.

---

## Features

### Quantum-Safe Wallet
- Ed25519 + Dilithium-2 (post-quantum) keypair generation
- Kyber-768 key encapsulation for secure key exchange
- Send and receive EGOC with feeless transactions and memo support
- Transaction history with full block explorer integration
- Bech32 address format (`egot1...`) with QR code display
- 24-word recovery phrase backed by BIP39 wordlist

### EgoSafe — Encrypted File Vault
- Encrypt any file locally with AES-256-GCM before it leaves your device
- Share encrypted files with contacts via a single copy-paste bundle (`egoshare1:...`)
- Recipient decrypts and verifies file integrity on their device
- No cloud upload — files stay local and are shared peer-to-peer

### P2P Encrypted Messenger
- End-to-end encrypted chat between any two Ego Desktop users
- Works across different networks, NATs, and firewalls (see P2P Network section below)
- Contact pairing via copy-paste bundle (`egocontact1:...`) — no central server or account required
- Messages encrypted with AES-256-GCM per contact pair

### Block Explorer
- Browse real blocks, transactions, and file events from the local ledger
- Network stats: latest block height, total transactions, files stored, node count

### Earnings & Staking (Testnet Demo)
- Simulated rewards for storage, consensus, and coverage roles
- Staking interface with 30-day lock periods and estimated APR

### Settings & Security
- Optional PIN protection for recovery phrase access
- View all public keys (Ed25519, Dilithium, Kyber) with QR codes
- Multi-wallet support — create, rename, switch, and delete wallets

---

## P2P Network

Every Ego Desktop installation gets a unique **Peer ID** — a cryptographic identity (Ed25519 keypair) that is stable across restarts and stored locally at `%LOCALAPPDATA%/EgoDesktop/p2p_identity.bin`.

The app uses **[libp2p](https://libp2p.io/)** (Rust implementation) with three layers of connectivity, so peers can reach each other regardless of their network environment:

### Layer 1 — Direct Connection
If both peers are on the same LAN or have public IP addresses, the app connects directly over TCP or QUIC (UDP). This is the fastest path.

### Layer 2 — NAT Hole Punching (DCUtR)
Most users are behind NAT routers (home broadband, mobile hotspots). The app uses the **Direct Connection Upgrade through Relay (DCUtR)** protocol: both peers first connect to a public relay node, then the relay coordinates a simultaneous dial so they punch through their respective NATs and establish a direct connection. Once the hole punch succeeds the relay is no longer in the path.

### Layer 3 — Circuit Relay (Fallback)
If NAT hole punching fails (symmetric NAT, strict firewall), messages are relayed end-to-end through Protocol Labs public relay nodes. The relay only sees encrypted bytes — it cannot read message content.

The app automatically picks the best available path. Your **Peer Address** (shown when you copy your contact bundle) is a libp2p multiaddr:

```
/ip4/1.2.3.4/tcp/47393/p2p/12D3KooW...
```

Share this address with contacts by copying your contact bundle from the Messenger tab.

---

## Downloads

| Platform | File |
|----------|------|
| Windows  | `EgoDesktop_x64-setup.exe` |
| macOS (Apple Silicon) | `EgoDesktop.dmg` |

Installers are attached to each [GitHub Release](../../releases).

---

## Build from Source

**Prerequisites**: Rust (stable), Node.js 18+

```bash
# Clone the repo
git clone https://github.com/ego-blockchain/ego-blockchain
cd ego-blockchain/ego-desktop-mvp

# Install frontend dependencies
npm install

# Run in development mode (hot-reload)
npm run tauri-dev

# Build release installer
npm run tauri-build
```

Output: `src-tauri/target/release/bundle/`

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Tailwind CSS + Vite |
| Backend | Rust + Tauri v1 |
| Cryptography | Ed25519, Dilithium-2, Kyber-768, AES-256-GCM, BLAKE2 |
| P2P Networking | libp2p 0.56 (TCP + QUIC + DCUtR + AutoRelay + AutoNAT) |
| Storage | Local JSON ledger, AES-256-GCM encrypted files |

---

## License

MIT — see [LICENSE](../LICENSE) for details.
