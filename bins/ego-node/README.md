# Ego Blockchain Node

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/ego-blockchain/ego-node)

A high-performance, 5G-enabled blockchain node implementation for the Ego distributed network. Built with Rust and libp2p, featuring advanced sharding, proof-of-coverage (PoC), proof-of-spacetime (PoST), seamless 5G network integration, bandwidth sharing monetization, and intelligent cost optimization.

## 🌟 Features

### Core Blockchain Features
- **Multi-Shard Support**: Participate in multiple blockchain shards simultaneously
- **Role-Based Architecture**: Flexible node roles (Validator, Storage, Gateway, Relay, Witness, Seed, Indexer)
- **Advanced Consensus**: Cross-shard validation and finality commitment
- **Distributed Storage**: Erasure coding with replica management and automated repair
- **Proof Systems**: Proof-of-Coverage (PoC) and Proof-of-Spacetime (PoST)

### 5G Network Integration & Cost Optimization
- **Network Slice Support**: Configure nodes for specific 5G network slices
- **Intelligent Network Switching**: Automatically switch between WiFi, 5G, Ethernet, and Cellular based on cost and performance
- **Data Usage Monitoring**: Track monthly data usage and costs across all network interfaces
- **Off-Peak Optimization**: Schedule heavy operations during cost-effective hours
- **Cost Thresholds**: Automatically switch networks when cost or data thresholds are reached

### Bandwidth Sharing & Monetization
- **Bandwidth Sharing**: Share unused bandwidth with other devices and earn EGOC tokens
- **Tiered Pricing**: Multiple bandwidth tiers (Basic, Standard, Premium) with different pricing
- **Device Management**: Allow/deny specific devices for bandwidth sharing
- **Usage Tracking**: Monitor shared data usage and earnings in real-time
- **Rate Limiting**: Control bandwidth allocation per connected device

### Data Optimization
- **Compression**: Intelligent data compression with multiple algorithms (Gzip, Zstd, Lz4)
- **Batch Processing**: Group similar operations for more efficient network usage
- **Operation Scheduling**: Schedule heavy operations for off-peak hours to reduce costs
- **Bandwidth Savings Tracking**: Monitor how much bandwidth and cost savings are achieved

### Networking & Discovery
- **Peer-to-Peer Networking**: Built on libp2p with gossipsub, Kademlia DHT, and mDNS
- **Auto-NAT Traversal**: Automatic NAT detection and traversal
- **Bootstrap Support**: Connect to existing network via bootstrap peers
- **Resource Management**: Configurable peer and topic limits

## 🚀 Quick Start

### Prerequisites

- **Rust 1.70+**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning the repository
- **Network Access**: Internet connection (WiFi/Ethernet recommended for initial sync)

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
# Run a full node with cost optimization and bandwidth sharing
cargo run -- --type full --shards 0,1,2 --interactive \
  --enable-sharing --sharing-bandwidth 50 --sharing-limit 1000

# Run a validator node with data compression
cargo run -- --type validator --shards 0,1,2 --port 9000 \
  --cost-threshold 100 --data-threshold 40

# Run a storage miner with advanced optimization
cargo run -- --type storage --storage 500 --lat 37.7749 --lon -122.4194 \
  --enable-sharing --sharing-bandwidth 100 --sharing-limit 2000

# Run a 5G edge gateway with full optimization
cargo run -- --type gateway --slice-id "slice-001" \
  --lat 40.7128 --lon -74.0060 --bandwidth 1000 \
  --enable-sharing --cost-threshold 200 --interactive
```

## 📖 Node Types

### Validator Node
Validates transactions and participates in consensus with cost optimization.

```bash
# Basic validator with cost optimization
cargo run -- --type validator --shards 0,1,2 \
  --cost-threshold 50 --data-threshold 20

# Validator with bandwidth sharing
cargo run -- --type validator --shards 0,1,2 \
  --enable-sharing --sharing-bandwidth 25 --metrics --interactive
```

**Capabilities**: Block validation, consensus participation, cross-shard validation, bandwidth sharing, data optimization, network switching, cost optimization

### Storage Node
Provides distributed storage with proof-of-spacetime and monetization features.

```bash
# Storage miner with 1TB capacity and bandwidth sharing
cargo run -- --type storage --storage 1000 --lat 34.0522 --lon -118.2437 \
  --enable-sharing --sharing-bandwidth 75 --sharing-limit 1500

# Storage node with full optimization
cargo run -- --type storage --storage 500 --lat 51.5074 --lon -0.1278 \
  --enable-sharing --cost-threshold 75 --interactive
```

**Capabilities**: Data storage, proof-of-spacetime, erasure coding, beacon reporting, bandwidth sharing, data optimization, network switching, cost optimization

### Gateway Node
API gateway with 5G network slice integration and advanced cost management.

```bash
# 5G edge gateway with full optimization
cargo run -- --type gateway \
  --slice-id "urllc-slice" \
  --lat 35.6762 --lon 139.6503 \
  --bandwidth 2000 \
  --port 8080 \
  --enable-sharing --sharing-bandwidth 200 \
  --cost-threshold 300 --data-threshold 100

# Gateway with bootstrap peers and optimization
cargo run -- --type gateway \
  --bootstrap "/ip4/203.0.113.1/tcp/9000,/ip4/203.0.113.2/tcp/9000" \
  --enable-sharing --sharing-limit 5000 --interactive
```

**Capabilities**: API gateway, HTTP interface, rate limiting, packet routing, network relay, proof-of-coverage, bandwidth sharing, data optimization, network switching, cost optimization

### Full Node
Combines validator, storage, and relay capabilities with comprehensive optimization.

```bash
# Full node with comprehensive optimization setup
cargo run -- --type full \
  --shards 0,1,2,3 \
  --storage 250 \
  --bandwidth 500 \
  --port 9000 \
  --enable-sharing --sharing-bandwidth 100 --sharing-limit 2000 \
  --cost-threshold 150 --data-threshold 50 \
  --metrics --interactive

# Full node with 5G configuration and monetization
cargo run -- --type full \
  --shards 0,1 \
  --storage 100 \
  --slice-id "embb-slice" \
  --lat 48.8566 --lon 2.3522 \
  --bandwidth 1500 \
  --enable-sharing --sharing-bandwidth 150
```

**Capabilities**: Block validation, data storage, network relay, consensus participation, proof-of-spacetime, bandwidth sharing, data optimization, network switching, cost optimization

### Seed Node
Provides peer discovery and network bootstrapping with bandwidth sharing.

```bash
# Seed node with bandwidth sharing for network bootstrapping
cargo run -- --type seed --port 9000 \
  --enable-sharing --sharing-bandwidth 200 --sharing-limit 3000

# High-capacity seed node with metrics
cargo run -- --type seed --port 9000 \
  --enable-sharing --sharing-bandwidth 500 --metrics
```

**Capabilities**: Peer discovery, bootstrap service, DHT seeding, packet routing, bandwidth sharing, data optimization, network switching, cost optimization

### Indexer Node
Indexes blockchain data with optimization features.

```bash
# Indexer node with cost optimization
cargo run -- --type indexer --storage 200 --shards 0,1,2 \
  --cost-threshold 100 --data-threshold 30

# Indexer with cross-shard support and bandwidth sharing
cargo run -- --type indexer --storage 500 --shards 0,1,2,3,4 \
  --enable-sharing --sharing-bandwidth 50 --interactive
```

**Capabilities**: Data indexing, search service, cross-shard indexing, data storage, bandwidth sharing, data optimization, network switching, cost optimization

## ⚙️ Configuration Options

### Command Line Arguments

| Argument | Short | Description | Default | Example |
|----------|-------|-------------|---------|---------|
| `--type` | `-t` | Node type | `full` | `--type validator` |
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

### Cost Optimization Arguments

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--cost-threshold` | Monthly cost threshold in USD | `100` | `--cost-threshold 200` |
| `--data-threshold` | Monthly data threshold in GB | `40` | `--data-threshold 100` |
| `--disable-compression` | Disable data compression | `false` | `--disable-compression` |
| `--disable-auto-switch` | Disable automatic network switching | `false` | `--disable-auto-switch` |

### Bandwidth Sharing Arguments

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--enable-sharing` | Enable bandwidth sharing | `false` | `--enable-sharing` |
| `--sharing-bandwidth` | Max bandwidth to share in Mbps | `50` | `--sharing-bandwidth 100` |
| `--sharing-limit` | Daily data sharing limit in MB | `1000` | `--sharing-limit 2000` |

### Network Configuration Examples

```bash
# Cost-optimized setup
cargo run -- --type full \
  --bootstrap "/ip4/203.0.113.10/tcp/9000" \
  --shards 0,1,2 \
  --cost-threshold 75 --data-threshold 30 \
  --enable-sharing --sharing-bandwidth 50

# High-performance with monetization
cargo run -- --type full \
  --storage 1000 \
  --bandwidth 5000 \
  --port 9000 \
  --enable-sharing --sharing-bandwidth 500 --sharing-limit 5000 \
  --cost-threshold 500 \
  --metrics --interactive

# Mobile/5G optimized node
cargo run -- --type gateway \
  --slice-id "mobile-slice" \
  --lat 40.7128 --lon -74.0060 \
  --bandwidth 2000 \
  --cost-threshold 200 --data-threshold 80 \
  --enable-sharing --sharing-bandwidth 200
```

## 🎮 Interactive Mode

Launch any node with `--interactive` to access the command interface:

```bash
cargo run -- --type full --shards 0,1,2 --enable-sharing --interactive
```

### Available Commands

#### Basic Commands
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

#### Optimization Commands
| Command | Description |
|---------|-------------|
| `network` | Show network status and usage |
| `sharing` | Show bandwidth sharing statistics |
| `compression` | Show data compression statistics |
| `enable-sharing` | Enable bandwidth sharing |
| `disable-sharing` | Disable bandwidth sharing |
| `switch-wifi` | Switch to WiFi network |
| `switch-5g` | Switch to 5G network |

#### Testing Commands
| Command | Description |
|---------|-------------|
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

🔧 Optimization Features
Current Network: WiFi
Data Usage - Total: 2.45 GB, Monthly: 1.23 GB, Daily: 0.15 GB, Cost: $0.00
Bandwidth Sharing: true (active: 2)
Data Saved: 125.4 MB

> sharing
Bandwidth Sharing Stats:
  Enabled: true
  Active connections: 2
  Daily shared: 234.5 MB / 1000 MB
  Total earned: 2.3450 EGOC
  Available bandwidth: 35 Mbps

> compression
Data Optimization Stats:
  Operations compressed: 45
  Compression ratio: 0.68
  Bandwidth saved: 125.4 MB
  Pending operations: 3

> network
Current network: WiFi
Data Usage - Total: 2.45 GB, Monthly: 1.23 GB, Daily: 0.15 GB, Cost: $0.00
Current Interface: WiFi
Off-peak hours: false

> switch-5g
✅ Switched to 5G (simulated)

> enable-sharing
✅ Bandwidth sharing enabled
```

## 💰 Cost Optimization & Monetization

### Bandwidth Sharing

Earn EGOC tokens by sharing unused bandwidth:

```bash
# Enable bandwidth sharing with 100 Mbps capacity
cargo run -- --type full --enable-sharing --sharing-bandwidth 100 --sharing-limit 2000

# Configure different sharing tiers
# Basic: 5 Mbps, 50MB daily, 0.005 EGOC/MB
# Standard: 20 Mbps, 200MB daily, 0.01 EGOC/MB
# Premium: 50 Mbps, 500MB daily, 0.02 EGOC/MB
```

### Network Cost Management

```bash
# Set monthly cost threshold to $150
cargo run -- --type full --cost-threshold 150

# Set data usage threshold to 75GB
cargo run -- --type full --data-threshold 75

# Combine both for aggressive cost control
cargo run -- --type validator --cost-threshold 50 --data-threshold 20
```

### Data Compression & Batching

```bash
# Enable compression (default)
cargo run -- --type storage

# Disable compression if needed
cargo run -- --type storage --disable-compression

# The system automatically:
# - Compresses data >1KB
# - Batches operations for efficiency
# - Schedules heavy operations for off-peak hours (11PM-6AM)
```

## 🌐 5G Integration & Network Intelligence

### Prerequisites for 5G Features

- **Minimum Bandwidth**: 100 Mbps for 5G readiness
- **Geolocation**: Latitude and longitude coordinates
- **Network Slice**: Valid 5G slice identifier

### 5G Edge Gateway Setup

```bash
# Urban 5G deployment with monetization
cargo run -- --type gateway \
  --slice-id "urllc-automotive" \
  --lat 40.7128 --lon -74.0060 \
  --bandwidth 2000 \
  --port 9000 \
  --enable-sharing --sharing-bandwidth 300 --sharing-limit 5000 \
  --cost-threshold 300 \
  --interactive

# Industrial IoT 5G slice with cost optimization
cargo run -- --type gateway \
  --slice-id "mmtc-industrial" \
  --lat 52.5200 --lon 13.4050 \
  --bandwidth 1500 \
  --storage 200 \
  --cost-threshold 200 --data-threshold 60
```

### Network Interface Management

The node automatically manages multiple network interfaces:

- **WiFi**: Prioritized for cost (usually free)
- **Ethernet**: High reliability, often unlimited
- **5G**: High performance, mobility support
- **Cellular 4G**: Fallback option

```bash
# The system automatically switches based on:
# 1. Cost effectiveness
# 2. Signal strength
# 3. Available bandwidth
# 4. Data limits
# 5. Off-peak hours (23:00-06:00)
```

## 📊 Monitoring & Metrics

### Enable Comprehensive Metrics

```bash
# Run with full metrics and optimization tracking
cargo run -- --type full --metrics --interactive \
  --enable-sharing --sharing-bandwidth 100 \
  --cost-threshold 100 --data-threshold 40

# View metrics in interactive mode
> metrics
📈 Node Metrics
═══════════════
Connected Peers: 8
Recent Proof Events: 45
Active Placements: 23
Network Bandwidth: 500 Mbps
Storage Utilization: 250 GB available

💰 Optimization Metrics
═══════════════════════
Bandwidth Sharing:
  Status: Enabled
  Active Connections: 3
  Daily Shared: 456.2/2000 MB
  Total Earned: 4.5620 EGOC
  Available: 65 Mbps

Data Optimization:
  Operations Compressed: 127
  Compression Ratio: 0.72
  Bandwidth Saved: 234.5 MB
  Pending Operations: 5
  Pending Batches: 2

Network Usage:
  Data Usage - Total: 5.67 GB, Monthly: 2.34 GB, Daily: 0.23 GB, Cost: $0.00
  Current Interface: WiFi
  Off-Peak Hours: false
```

### Performance Monitoring

```bash
# High-performance monitoring setup with all features
cargo run -- --type full \
  --shards 0,1,2,3,4 \
  --storage 1000 \
  --bandwidth 2000 \
  --enable-sharing --sharing-bandwidth 200 --sharing-limit 3000 \
  --cost-threshold 250 --data-threshold 100 \
  --metrics --interactive

# Monitor bandwidth sharing earnings
> sharing
Bandwidth Sharing Stats:
  Enabled: true
  Active connections: 4
  Daily shared: 1,234.5 MB / 3,000 MB
  Total earned: 12.3450 EGOC
  Available bandwidth: 150 Mbps

# Check data optimization savings
> compression
Data Optimization Stats:
  Operations compressed: 234
  Compression ratio: 0.65
  Bandwidth saved: 456.7 MB
  Pending operations: 8
  Pending batches: 3
```

## 🔧 Advanced Configuration

### High-Earning Bandwidth Sharing Node

```bash
# Maximize bandwidth sharing revenue
cargo run -- --type storage \
  --storage 1000 \
  --bandwidth 5000 \
  --enable-sharing --sharing-bandwidth 1000 --sharing-limit 10000 \
  --lat 37.7749 --lon -122.4194 \
  --cost-threshold 500 \
  --metrics --interactive
```

### Cost-Constrained Mobile Node

```bash
# Minimize data costs for mobile/cellular deployment
cargo run -- --type validator \
  --shards 0,1 \
  --cost-threshold 25 --data-threshold 5 \
  --slice-id "mobile-slice" \
  --disable-compression \
  --interactive
```

### Multi-Interface Edge Gateway

```bash
# Gateway with multiple network interfaces
cargo run -- --type gateway \
  --slice-id "edge-computing" \
  --lat 51.5074 --lon -0.1278 \
  --bandwidth 3000 \
  --storage 500 \
  --enable-sharing --sharing-bandwidth 500 --sharing-limit 5000 \
  --cost-threshold 400 --data-threshold 150 \
  --port 8080 \
  --metrics --interactive
```

### Distributed Storage with Monetization

```bash
# Storage cluster with bandwidth sharing
# Node 1
cargo run -- --type storage \
  --storage 500 \
  --lat 37.7749 --lon -122.4194 \
  --port 9001 \
  --enable-sharing --sharing-bandwidth 150 --sharing-limit 2000 \
  --bootstrap "/ip4/seed.ego.network/tcp/9000"

# Node 2
cargo run -- --type storage \
  --storage 500 \
  --lat 40.7128 --lon -74.0060 \
  --port 9002 \
  --enable-sharing --sharing-bandwidth 150 --sharing-limit 2000 \
  --bootstrap "/ip4/seed.ego.network/tcp/9000"
```

## 🔧 Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/ego-blockchain/ego-blockchain.git
cd bins/ego-node

# Development build
cargo build

# Release build (recommended for production)
cargo build --release

# Run tests including optimization features
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
│   ├── main.rs              # CLI interface and node orchestration
│   ├── node.rs              # Core node implementation
│   ├── keystore.rs          # Cryptographic key management
│   ├── types.rs             # Data structures and enums
│   ├── network_manager.rs   # Network interface management & cost optimization
│   ├── bandwidth_sharing.rs # Bandwidth sharing and monetization
│   ├── data_optimizer.rs    # Data compression, batching & scheduling
│   └── lib.rs               # Library exports
├── Cargo.toml               # Dependencies and metadata
└── README.md                # This file
```

### Key Dependencies

```toml
[dependencies]
libp2p = "0.53"              # P2P networking
tokio = "1.0"                # Async runtime
serde = "1.0"                # Serialization
tracing = "0.1"              # Logging
clap = "4.0"                 # CLI parsing
anyhow = "1.0"               # Error handling
flate2 = "1.0"               # Gzip compression
chrono = "0.4"               # Time handling
rand = "0.8"                 # Random number generation
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

- **Documentation**: [docs.ego-blockchain.io](https://ego-blockchain.io)
- **Issues**: [GitHub Issues](https://github.com/ego-blockchain/bins/ego-node/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ego-blockchain/bins/ego-node/discussions)

## 🌟 Acknowledgments

- Built with [libp2p](https://libp2p.io/) for robust peer-to-peer networking
- Powered by [Rust](https://www.rust-lang.org/) for performance and safety
- Inspired by cutting-edge blockchain and 5G technologies
- Features intelligent cost optimization for mobile and edge deployments

---

**Ego Blockchain Node** - Empowering the next generation of decentralized 5G networks with intelligent cost optimization and bandwidth monetization.
