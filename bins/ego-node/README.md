# ego-node

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

Headless full node for the Ego Blockchain. Runs consensus, storage, retrieval and coverage roles without the desktop GUI — intended for servers, VPS deployments and anyone who wants a node under systemd rather than a window.

> **Status: public testnet.** Testnet addresses use the `egot` prefix (`chain_id = 1`). EGOC earned on testnet is not tradeable.

For a graphical client with a wallet, file storage and messaging, use [Ego Desktop](https://egoblockchain.com/download) instead.

## Features

### Core
- **Multi-role**: validator, storage, gateway, relay, witness, seed, indexer
- **Cross-shard**: participate in several shards simultaneously
- **Proof systems**: Proof-of-Coverage (PoC) and Proof-of-Spacetime (PoST)
- **Full transaction validation and execution**
- **JSON-RPC** endpoint for wallets and tooling

### Network optimisation
- **Intelligent switching** between WiFi, 5G, Ethernet and 4G
- **5G network slicing** support via `--slice-id`
- **Cost controls**: monthly spend and data thresholds with automatic throttling
- **Geolocation**: H3 geohashing for location-aware operations
- **Compression**: Gzip, Zstd and LZ4

### Bandwidth monetisation
Earn EGOC by sharing unused bandwidth, across three tiers.

### Security
- **Signatures**: Ed25519 alongside CRYSTALS-Dilithium-2 (ML-DSA-44, FIPS 204)
- **Key exchange**: CRYSTALS-Kyber (ML-KEM-768)
- **Hashing**: BLAKE2s
- **Transport**: Noise protocol encryption over libp2p
- **Keystore**: Argon2-derived key encryption with account binding

## Quick start

Requires **Rust 1.85+** (the workspace uses edition 2024).

```bash
git clone https://github.com/ego-blockchain/ego-blockchain-
cd ego-blockchain-

cargo build --release --bin ego-node

./target/release/ego-node --type full --port 9000 --interactive
```

### Examples

```bash
# Validator
ego-node --type validator --shards 0,1,2 --port 9000 --interactive

# Storage provider
ego-node --type storage --storage 500 --lat 40.7128 --lon -74.0060 --enable-sharing

# 5G gateway
ego-node --type gateway --slice-id "iot-slice-1" --lat 40.7128 --lon -74.0060 --bandwidth 1000

# Seed / bootstrap
ego-node --type seed --port 8000 --sharing-bandwidth 200 --sharing-limit 5000
```

Running several nodes on one machine? Give each its own `EGO_DATA_DIR`, or they will contend for the same RocksDB lock and fail to start.

## Node types

| Type | Roles | Use case |
|---|---|---|
| **full** | Validator, Storage, Relay, Witness | General purpose, home users |
| **validator** | Validator, Relay | High-performance servers |
| **storage** | Storage, Witness | Storage providers |
| **gateway** | Gateway, Witness, Relay | 5G / edge infrastructure |
| **seed** | Seed, Relay | Network bootstrapping |
| **indexer** | Indexer, Storage | Analytics and search |

## Options

### Basic
```
--type <TYPE>              validator | storage | gateway | full | seed | indexer  (default: full)
--port <PORT>              P2P listen port (default: 9000)
--shards <IDS>             comma-separated shard IDs (default: 0,1,2)
--storage <GB>             storage capacity (default: 100)
--bandwidth <MBPS>         bandwidth capacity (default: 500)
--interactive              run the built-in command shell
--metrics                  enable metrics collection
```

### RPC and payouts
```
--rpc-port <PORT>          JSON-RPC listen port
--rpc-advertise <ADDR>     address to advertise for RPC
--payout-address <ADDR>    EGOC address to receive earnings
--payout-interval <SECS>   payout frequency
```

### Location and 5G
```
--slice-id <ID>            5G network slice identifier
--lat <LATITUDE>           node latitude
--lon <LONGITUDE>          node longitude
```

### Bandwidth sharing
```
--enable-sharing           enable sharing to earn EGOC
--sharing-bandwidth <MBPS> max bandwidth to share (default: 50)
--sharing-limit <MB>       daily data limit (default: 1000)
```

### Cost control
```
--cost-threshold <USD>     monthly cost ceiling (default: 100)
--data-threshold <GB>      monthly data ceiling (default: 40)
--disable-compression      turn off data compression
--disable-auto-switch      turn off automatic network switching
```

### Networking
```
--bootstrap <PEERS>        bootstrap multiaddresses (comma-separated)
--max-peers <COUNT>        maximum peers (default: 200)
--disable-mdns             disable mDNS local discovery
--disable-autonat          disable AutoNAT
```

Compression and auto-switching are **on by default** — there are only `--disable-*` flags, no `--enable-*` counterparts.

## Interactive mode

With `--interactive`:

```
status            detailed node status
peers             connected peers
blockchain        chain state
account           account details
network           network status and usage
sharing           bandwidth sharing stats
metrics           performance metrics

enable-sharing    turn bandwidth sharing on
disable-sharing   turn it off
switch-wifi       switch to WiFi
switch-5g         switch to 5G
reset-stats       reset counters
transfer          create a test transaction
connect           retry bootstrap connections
help              list commands
```

## Bandwidth sharing tiers

Defined in [`src/bandwidth_sharing.rs`](src/bandwidth_sharing.rs):

| Tier | Price per MB | Max speed |
|---|---|---|
| Basic | 0.005 EGOC | 5 Mbps |
| Standard | 0.01 EGOC | 20 Mbps |
| Premium | 0.02 EGOC | 50 Mbps |

Actual earnings depend on how much bandwidth peers consume, not on capacity offered.

## Architecture

```
src/
  node.rs                  main node implementation
  engine.rs                block production and execution
  consensus_integration.rs consensus engine wiring
  mempool.rs               transaction pool
  store.rs                 chain persistence
  rpc.rs                   JSON-RPC server
  network_manager.rs       interface selection and switching
  bandwidth_sharing.rs     bandwidth monetisation
  data_optimizer.rs        compression and batching
  keystore.rs              encrypted key management
  supervisor.rs            task supervision and restart
```

**Network stack** — TCP with Yamux multiplexing, Noise encryption, mDNS + Kademlia DHT + AutoNAT discovery, GossipSub messaging, DCUtR and relay for NAT traversal.

## Development

```bash
cargo build                          # debug
cargo build --release                # optimised
cargo test                           # tests
RUST_LOG=debug cargo run --bin ego-node -- --interactive
```

## Troubleshooting

**No peers connecting** — check that your P2P port is reachable, then try explicit bootstrap peers:
```bash
ego-node --bootstrap "/ip4/1.2.3.4/tcp/9000/p2p/12D3K..."
```

**Data usage too high** — tighten the ceilings (compression is already on by default):
```bash
ego-node --data-threshold 10 --cost-threshold 20
```

**Database lock error on startup** — another node or Ego Desktop is using the same data directory. Set a unique `EGO_DATA_DIR` per node.

## Contributing

Issues and pull requests are welcome. Consensus, cryptography and tokenomics are consensus-critical: please open an issue before submitting changes to those areas.

## Links

- Documentation — <https://egoblockchain.com/docs>
- Block explorer — <https://egoblockchain.com/explorer>
- Issues — <https://github.com/ego-blockchain/ego-blockchain-/issues>

## License

MIT — see [LICENSE](../../LICENSE).
