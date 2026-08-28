# Ego Desktop

> **TESTNET NOTICE**: This application runs on the Ego Testnet. All EGOC tokens are test tokens with no real monetary value.

A quantum-safe blockchain desktop application — wallet, encrypted file sharing, P2P messenger, decentralized hosting, smart contracts, block explorer, and DAO governance.

---

## Features

### Quantum-Safe Wallet
- Ed25519 + Dilithium-2 (post-quantum) keypair generation
- Kyber-768 key encapsulation for secure key exchange
- Send and receive EGOC with memo support; fees are priced in USD via oracle and burned
- Transaction history with full block explorer integration
- Bech32 address format (`egot1...`) with QR code display
- 24-word recovery phrase backed by BIP39 wordlist

### EgoSafe — Encrypted File Vault
- Encrypt any file locally with AES-256-GCM before it leaves your device
- Share encrypted files with contacts via a single copy-paste bundle (`egoshare1:...`)
- Recipient decrypts and verifies file integrity on their device
- No cloud upload — files stay local and are shared peer-to-peer

### Decentralized Hosting
- Host static websites directly from your node
- Sites served over the Ego P2P network with automatic peer replication
- Custom domain support via DNS configuration
- Live preview and one-click site removal

### P2P Encrypted Messenger
- End-to-end encrypted chat between any two Ego Desktop users
- Works across different networks, NATs, and firewalls
- Contact pairing via copy-paste bundle (`egocontact1:...`) — no central server required
- Messages encrypted with AES-256-GCM per contact pair

### Storage
- Allocate disk space and earn 0.5 EGOC per GB per day
- Files are split, encrypted and distributed — an operator never holds a complete file
- Replication and per-period escrow with a grace window for offline replicas

### Coverage
- Prove real wireless signal at your location and earn 8 EGOC per day
- H3 geohashing with a live coverage map

### Compute
- Rent out CPU and GPU capacity; each reservation runs isolated in its own Docker container
- Jobs without Docker isolation are labelled "Shared Host"

### Contracts & dApp IDE
- Write, compile and deploy Urego smart contracts without leaving the app
- Monaco editor with contract templates
- Deployed-contract browser with call and query interfaces

### Market
- Browse and trade storage, compute and bandwidth capacity offered by other nodes

### Block Explorer
- Browse real blocks, transactions, and file events from the local ledger
- Network stats: latest block height, total transactions, files stored, node count

### DAO Governance
- Community proposal creation and voting
- Dual-vote system: stake weight + knowledge test
- Live results and on-chain proposal history

### Earnings & Staking
- Real-time rewards for storage, consensus, coverage, and retrieval roles
- Staking interface with lock periods and estimated APR
- Live session earnings counter

### Settings & Security
- Optional PIN protection for recovery phrase access
- View all public keys (Ed25519, Dilithium, Kyber) with QR codes
- Multi-wallet support — create, rename, switch, and delete wallets

---

## P2P Network

Every Ego Desktop installation gets a unique **Peer ID** — a cryptographic identity (Ed25519 keypair) stored locally at `%APPDATA%/EgoDesktop/p2p_identity.bin` (Roaming, not Local; override the whole data directory with `EGO_DATA_DIR`).

The app uses **[libp2p](https://libp2p.io/)** (Rust) with three connectivity layers:

### Layer 1 — Direct Connection
Direct TCP or QUIC connection when both peers are on the same LAN or have public IPs.

### Layer 2 — NAT Hole Punching (DCUtR)
Both peers connect to a public relay node, which coordinates a simultaneous dial to punch through NAT. Once the hole punch succeeds the relay is no longer in the path.

### Layer 3 — Circuit Relay (Fallback)
If NAT hole punching fails, messages relay end-to-end through public relay nodes. The relay only sees encrypted bytes.

---

## Downloads

| Platform | File |
|----------|------|
| **Windows** | `Ego Desktop_*_x64_en-US.msi` ← recommended |
| **Windows** (alt) | `Ego Desktop_*_x64-setup.exe` |
| **macOS** (M1/M2/M3/M4) | `Ego Desktop_*_aarch64.dmg` |
| **macOS** (Intel) | `Ego Desktop_*_x64.dmg` |
| **Linux** (Debian/Ubuntu) | `Ego Desktop_*_amd64.deb` |
| **Linux** (universal) | `Ego Desktop_*_amd64.AppImage` |

Installers are attached to each [GitHub Release](../../releases).

---

## Build from Source

**Prerequisites**: Rust 1.85+ (the workspace uses edition 2024), Node.js 20+

```bash
git clone https://github.com/ego-blockchain/ego-blockchain-
cd ego-blockchain-/ego-desktop

npm install
npm run tauri dev      # development mode with hot-reload
npm run tauri build    # production installer
```

Output: `src-tauri/target/release/bundle/`

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Tailwind CSS + Vite |
| Backend | Rust + Tauri v1 |
| Cryptography | Ed25519, Dilithium-2, Kyber-768, AES-256-GCM, BLAKE2 |
| P2P Networking | libp2p 0.56 (TCP + QUIC + DCUtR + AutoRelay + AutoNAT + Kademlia) |
| Storage | RocksDB chain, AES-256-GCM encrypted files, atomic writes |
| Consensus | BFT committee, PoC (Proof of Coverage) |

---

## License

MIT — see [LICENSE](../LICENSE) for details.
