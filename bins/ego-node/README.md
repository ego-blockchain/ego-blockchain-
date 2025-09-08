# Ego Blockchain Node

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/ego-blockchain/ego-node)

A high-performance, 5G-enabled blockchain node implementation for the Ego distributed network. Built with Rust and libp2p, featuring advanced sharding, proof-of-coverage (PoC), proof-of-spacetime (PoST), and seamless 5G network integration.

## 🌟 Features

### Core Blockchain Features
- **Multi-Shard Support**: Participate in multiple blockchain shards simultaneously
- **Role-Based Architecture**: Flexible node roles (Validator, Storage, Gateway, Relay, Witness, Seed, Indexer)
- **Advanced Consensus**: Cross-shard validation and finality commitment
- **Distributed Storage**: Erasure coding with replica management and automated repair
- **Proof Systems**: Proof-of-Coverage (PoC) and Proof-of-Spacetime (PoST)

### 5G Network Integration
- **Network Slice Support**: Configure nodes for specific 5G network slices
- **Geolocation Awareness**: H3-based geographical indexing and coverage proofs
- **Edge Computing**: Optimized for 5G edge deployments
- **High-Bandwidth Operations**: Support for 100+ Mbps network requirements

### Networking & Discovery
- **Peer-to-Peer Networking**: Built on libp2p with gossipsub, Kademlia DHT, and mDNS
- **Auto-NAT Traversal**: Automatic NAT detection and traversal
- **Bootstrap Support**: Connect to existing network via bootstrap peers
- **Resource Management**: Configurable peer and topic limits

## 🚀 Quick Start

### Prerequisites

- **Rust 1.70+**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning the repository

### Installation

```bash
# Clone the repository
git clone https://github.com/ego-blockchain/ego-node.git
cd ego-node

# Build the project
cargo build --release

# Or run directly in development mode
cargo run -- --help
```

### Basic Usage

```bash
# Run a full node with interactive mode
cargo run -- --type full --shards 0,1,2 --interactive

# Run a validator node for specific shards
cargo run -- --type validator --shards 0,1,2 --port 9000

# Run a storage miner with high capacity
cargo run -- --type storage --storage 500 --lat 37.7749 --lon -122.4194

# Run a 5G edge gateway
cargo run -- --type gateway --slice-id "slice-001" --lat 40.7128 --lon -74.0060 --bandwidth 1000
```

## 📖 Node Types

### Validator Node
Validates transactions and participates in consensus.

```bash
# Basic validator
cargo run -- --type validator --shards 0,1,2

# Validator with metrics
cargo run -- --type validator --shards 0,1,2 --metrics --interactive
```

**Capabilities**: Block validation, consensus participation, cross-shard validation

### Storage Node
Provides distributed storage with proof-of-spacetime.

```bash
# Storage miner with 1TB capacity
cargo run -- --type storage --storage 1000 --lat 34.0522 --lon -118.2437

# Storage node with specific geolocation
cargo run -- --type storage --storage 500 --lat 51.5074 --lon -0.1278 --interactive
```

**Capabilities**: Data storage, proof-of-spacetime, erasure coding, beacon reporting

### Gateway Node
API gateway with 5G network slice integration.

```bash
# 5G edge gateway
cargo run -- --type gateway \
  --slice-id "urllc-slice" \
  --lat 35.6762 --lon 139.6503 \
  --bandwidth 2000 \
  --port 8080

# Gateway with bootstrap peers
cargo run -- --type gateway \
  --bootstrap "/ip4/203.0.113.1/tcp/9000,/ip4/203.0.113.2/tcp/9000" \
  --interactive
```

**Capabilities**: API gateway, HTTP interface, rate limiting, packet routing, network relay, proof-of-coverage

### Full Node
Combines validator, storage, and relay capabilities.

```bash
# Full node with comprehensive setup
cargo run -- --type full \
  --shards 0,1,2,3 \
  --storage 250 \
  --bandwidth 500 \
  --port 9000 \
  --metrics \
  --interactive

# Full node with 5G configuration
cargo run -- --type full \
  --shards 0,1 \
  --storage 100 \
  --slice-id "embb-slice" \
  --lat 48.8566 --lon 2.3522 \
  --bandwidth 1500
```

**Capabilities**: Block validation, data storage, network relay, consensus participation, proof-of-spacetime

### Seed Node
Provides peer discovery and network bootstrapping.

```bash
# Seed node for network bootstrapping
cargo run -- --type seed --port 9000

# Seed node with high peer capacity
cargo run -- --type seed --port 9000 --metrics
```

**Capabilities**: Peer discovery, bootstrap service, DHT seeding, packet routing

### Indexer Node
Indexes blockchain data for search and analytics.

```bash
# Indexer node with storage
cargo run -- --type indexer --storage 200 --shards 0,1,2

# Indexer with cross-shard support
cargo run -- --type indexer --storage 500 --shards 0,1,2,3,4 --interactive
```

**Capabilities**: Data indexing, search service, cross-shard indexing, data storage

## ⚙️ Configuration Options

### Command Line Arguments

| Argument | Short | Description | Default | Example |
|----------|-------|-------------|---------|---------|
| `--type` | `-t` | Node type (validator, storage, gateway, full, seed, indexer) | `full` | `--type validator` |
| `--shards` | `-s` | Comma-separated shard IDs | `0,1` | `--shards 0,1,2,3` |
| `--port` | `-p` | P2P listen port | `9000` | `--port 8080` |
| `--bootstrap` | `-b` | Bootstrap peer addresses | `""` | `--bootstrap "/ip4/1.2.3.4/tcp/9000"` |
| `--storage` | | Storage capacity in GB | `100` | `--storage 500` |
| `--lat` | | Node latitude | | `--lat 37.7749` |
| `--lon` | | Node longitude | | `--lon -122.4194` |
| `--bandwidth` | | Bandwidth capacity in Mbps | `100` | `--bandwidth 1000` |
| `--slice-id` | | 5G network slice identifier | | `--slice-id "slice-001"` |
| `--interactive` | `-i` | Enable interactive mode | `false` | `--interactive` |
| `--metrics` | `-m` | Enable metrics collection | `false` | `--metrics` |

### Network Configuration Examples

```bash
# Connect to existing network
cargo run -- --type full \
  --bootstrap "/ip4/203.0.113.10/tcp/9000,/ip4/203.0.113.11/tcp/9000" \
  --shards 0,1,2

# Custom port configuration
cargo run -- --type validator --port 8545 --shards 0

# High-performance setup
cargo run -- --type full \
  --storage 1000 \
  --bandwidth 5000 \
  --port 9000 \
  --metrics \
  --interactive
```

## 🎮 Interactive Mode

Launch any node with `--interactive` to access the command interface:

```bash
cargo run -- --type full --shards 0,1,2 --interactive
```

### Available Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `status` | Display detailed node status |
| `peers` | List connected peers |
| `roles` | Show current node roles |
| `capabilities` | Display node capabilities |
| `proofs` | Show recent proof events |
| `5g` | Display 5G configuration status |
| `metrics` | Show performance metrics |
| `test-poc` | Generate test Proof of Coverage |
| `test-post` | Generate test Proof of Spacetime |
| `quit`/`exit` | Shutdown the node |

### Interactive Session Example

```
> status
📊 Detailed Node Status
════════════════════════
Peer ID: 12D3KooWExample...
Roles: [Validator, Storage, Relay]
Shards: [0, 1, 2]
Storage Capacity: 100 GB
5G Ready: true

> peers
Connected peers: [12D3KooWPeer1..., 12D3KooWPeer2...]

> test-post
Generated PoST proof for shard 0

> metrics
📈 Node Metrics
═══════════════
Connected Peers: 5
Recent Proof Events: 23
Active Placements: 12
```

## 🌐 5G Integration

### Prerequisites for 5G Features

- **Minimum Bandwidth**: 100 Mbps for 5G readiness
- **Geolocation**: Latitude and longitude coordinates
- **Network Slice**: Valid 5G slice identifier

### 5G Edge Gateway Setup

```bash
# Urban 5G deployment
cargo run -- --type gateway \
  --slice-id "urllc-automotive" \
  --lat 40.7128 --lon -74.0060 \
  --bandwidth 2000 \
  --port 9000 \
  --interactive

# Industrial IoT 5G slice
cargo run -- --type gateway \
  --slice-id "mmtc-industrial" \
  --lat 52.5200 --lon 13.4050 \
  --bandwidth 1500 \
  --storage 200
```

### Verifying 5G Readiness

```bash
# Check 5G status in interactive mode
> 5g
5G Ready: true
Slice ID: urllc-automotive

# Or check programmatically
cargo run -- --type gateway --slice-id "test" --lat 0 --lon 0 --bandwidth 150
```

## 📊 Monitoring & Metrics

### Enable Metrics Collection

```bash
# Run with metrics enabled
cargo run -- --type full --metrics --interactive

# View metrics in interactive mode
> metrics
📈 Node Metrics
═══════════════
Connected Peers: 8
Recent Proof Events: 45
Active Placements: 23
Network Bandwidth: 500 Mbps
Storage Utilization: 250 GB available
```

### Performance Monitoring

```bash
# High-performance monitoring setup
cargo run -- --type full \
  --shards 0,1,2,3,4 \
  --storage 1000 \
  --bandwidth 2000 \
  --metrics \
  --interactive

# Check proof generation
> proofs
Recent proofs: 15 events
  1: post - 12D3KooWExample...
  2: poc - 12D3KooWExample...
  3: repair - 12D3KooWExample...
```

## 🔧 Advanced Configuration

### Multi-Shard Validator

```bash
# Validator for multiple shards with high capacity
cargo run -- --type validator \
  --shards 0,1,2,3,4,5,6,7 \
  --port 9000 \
  --bootstrap "/ip4/seed1.ego.network/tcp/9000" \
  --metrics
```

### Distributed Storage Cluster

```bash
# Storage node 1
cargo run -- --type storage \
  --storage 500 \
  --lat 37.7749 --lon -122.4194 \
  --port 9001 \
  --bootstrap "/ip4/seed.ego.network/tcp/9000"

# Storage node 2
cargo run -- --type storage \
  --storage 500 \
  --lat 40.7128 --lon -74.0060 \
  --port 9002 \
  --bootstrap "/ip4/seed.ego.network/tcp/9000"
```

### Network Bootstrapping

```bash
# Seed node for network
cargo run -- --type seed --port 9000

# Connect new nodes to the network
cargo run -- --type full \
  --bootstrap "/ip4/your-seed-node/tcp/9000" \
  --shards 0,1,2
```

## 🏗️ Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/ego-blockchain/ego-blockchain.git
cd bins/ego-node

# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy lints
cargo clippy -- -D warnings
```

### Project Structure

```
ego-node/
├── src/
│   ├── main.rs          # CLI interface and node orchestration
│   ├── node.rs          # Core node implementation
│   ├── keystore.rs      # Cryptographic key management
│   ├── types.rs         # Data structures and enums
│   └── lib.rs           # Library exports
├── Cargo.toml           # Dependencies and metadata
└── README.md            # This file
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs.ego-blockchain.io](https:egoblockchain.io)
- **Issues**: [GitHub Issues](https://github.com/ego-blockchain/bins/ego-node/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ego-blockchain/bins/ego-node/discussions)

## 🌟 Acknowledgments

- Built with [libp2p](https://libp2p.io/) for robust peer-to-peer networking
- Powered by [Rust](https://www.rust-lang.org/) for performance and safety
- Inspired by cutting-edge blockchain and 5G technologies

---

**Ego Blockchain Node** - Empowering the next generation of decentralized 5G networks.
