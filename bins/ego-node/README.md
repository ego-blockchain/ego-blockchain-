# Ego Blockchain Node 🚀

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![5G Ready](https://img.shields.io/badge/5G-Ready-green.svg)](#5g-features)

**Ego Blockchain Node** - Next-generation decentralized network node with advanced 5G optimization, intelligent cost management, and bandwidth monetization capabilities.

## ✨ Features

### 🌐 Core Blockchain Capabilities
- **Multi-Role Support**: Validator, Storage, Gateway, Relay, Witness, Seed, Indexer
- **Cross-Shard Operations**: Participate in multiple blockchain shards simultaneously
- **Proof Systems**: Proof-of-Coverage (PoC) and Proof-of-Spacetime (PoST)
- **State Management**: Complete blockchain state with account management
- **Transaction Processing**: Full transaction validation and execution

### 📡 5G & Network Optimization
- **5G Network Slicing**: Native support for 5G network slices with dedicated bandwidth
- **Intelligent Network Switching**: Automatic switching between WiFi, 5G, Ethernet, and 4G
- **Cost Optimization**: Real-time monitoring of data usage and costs with configurable thresholds
- **Geolocation Integration**: H3-based geohashing for location-aware operations
- **Off-Peak Optimization**: Smart scheduling for cost-effective operations

### 💰 Bandwidth Monetization
- **Bandwidth Sharing**: Earn EGOC tokens by sharing unused bandwidth
- **Tiered Pricing**: Multiple bandwidth sharing tiers (Basic, Standard, Premium)
- **Usage Limits**: Configurable daily and monthly data limits
- **Real-time Monitoring**: Live tracking of earnings and data usage

### ⚡ Data Optimization
- **Advanced Compression**: Gzip, Zstd, and LZ4 compression algorithms
- **Batch Processing**: Intelligent batching of operations to reduce network overhead
- **Scheduled Operations**: Off-peak scheduling for heavy operations
- **Bandwidth Savings**: Significant reduction in data usage through optimization

### 🔒 Security & Privacy
- **Secure Keystore**: Hardware-backed key management with account binding
- **Cryptographic Proofs**: Ed25519 signatures for all operations
- **Peer-to-Peer Security**: Noise protocol encryption for all network communications
- **Account Binding**: Secure linking of on-chain accounts to node identity

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+
- At least 4GB RAM
- Stable internet connection (WiFi/Ethernet/5G)
- Storage space (varies by node type)

### Installation

```bash
# Clone the repository
git clone https://github.com/ego-blockchain/ego-node.git
cd ego-node

# Build the project
cargo build --release

# Run a full node
./target/release/ego-node --type full --port 9000 --interactive
```

### Quick Examples

#### 🏛️ Run a Validator Node
```bash
ego-node --type validator --shards 0,1,2 --port 9000 --interactive
```

#### 💾 Run a Storage Node
```bash
ego-node --type storage --storage 500 --lat 40.7128 --lon -74.0060 --enable-sharing
```

#### 🌐 Run a 5G Gateway
```bash
ego-node --type gateway --slice-id "emergency-services" --lat 40.7128 --lon -74.0060 --bandwidth 1000
```

#### 🌱 Run a Seed Node
```bash
ego-node --type seed --port 8000 --sharing-bandwidth 200 --sharing-limit 5000
```

## 📋 Node Types

| Type | Description | Primary Roles | Use Case |
|------|-------------|---------------|----------|
| **Full** | Complete blockchain node | Validator, Storage, Relay, Witness | General purpose, home users |
| **Validator** | Block validation and consensus | Validator, Relay | High-performance servers |
| **Storage** | Data storage and retrieval | Storage, Witness | Storage providers |
| **Gateway** | 5G edge computing | Gateway, Witness, Relay | 5G infrastructure |
| **Seed** | Network bootstrapping | Seed, Relay | Network infrastructure |
| **Indexer** | Data indexing and search | Indexer, Storage | Analytics and search |

## ⚙️ Configuration

### Command Line Options

#### Basic Configuration
```bash
--type <NODE_TYPE>           # Node type: validator, storage, gateway, full, seed, indexer
--port <PORT>                # P2P listen port (default: 9000)
--shards <SHARD_IDS>         # Comma-separated shard IDs (default: 0,1,2)
--storage <GB>               # Storage capacity in GB (default: 100)
--bandwidth <MBPS>           # Bandwidth capacity in Mbps (default: 500)
```

#### 5G & Location
```bash
--slice-id <SLICE_ID>        # 5G network slice identifier
--lat <LATITUDE>             # Node latitude for geolocation
--lon <LONGITUDE>            # Node longitude for geolocation
```

#### Bandwidth Sharing
```bash
--enable-sharing             # Enable bandwidth sharing to earn EGOC
--sharing-bandwidth <MBPS>   # Max bandwidth to share (default: 50)
--sharing-limit <MB>         # Daily data sharing limit (default: 1000)
```

#### Cost Optimization
```bash
--cost-threshold <USD>       # Monthly cost threshold (default: $100)
--data-threshold <GB>        # Monthly data threshold (default: 40GB)
--disable-compression        # Disable data compression
--disable-auto-switch        # Disable automatic network switching
```

#### Networking
```bash
--bootstrap <PEERS>          # Bootstrap peer addresses (comma-separated)
--max-peers <COUNT>          # Maximum number of peers (default: 200)
--disable-mdns               # Disable mDNS local discovery
--disable-autonat            # Disable AutoNAT
```

### Example Configurations

#### High-Performance Validator
```bash
ego-node \
  --type validator \
  --shards 0,1,2,3 \
  --port 9000 \
  --max-peers 300 \
  --bandwidth 1000 \
  --enable-sharing \
  --sharing-bandwidth 100
```

#### 5G Edge Gateway
```bash
ego-node \
  --type gateway \
  --slice-id "iot-slice-1" \
  --lat 37.7749 \
  --lon -122.4194 \
  --bandwidth 2000 \
  --storage 200 \
  --enable-sharing \
  --sharing-bandwidth 500 \
  --cost-threshold 500
```

#### Cost-Optimized Home Node
```bash
ego-node \
  --type full \
  --storage 100 \
  --bandwidth 100 \
  --enable-sharing \
  --cost-threshold 50 \
  --data-threshold 20 \
  --enable-auto-switch
```

## 🖥️ Interactive Mode

Run with `--interactive` to access the built-in command interface:

### Essential Commands
```
status          - Show detailed node status
peers           - List connected peers
blockchain      - Show blockchain state
account         - Show account details
network         - Show network status and usage
sharing         - Show bandwidth sharing stats
metrics         - Show performance metrics
```

### Control Commands
```
enable-sharing  - Enable bandwidth sharing
disable-sharing - Disable bandwidth sharing
switch-wifi     - Switch to WiFi network
switch-5g       - Switch to 5G network
reset-stats     - Reset statistics
```

### Test Commands
```
test-poc        - Generate Proof of Coverage
test-post       - Generate Proof of Spacetime
transfer        - Create test transaction
connect         - Retry bootstrap connections
```

## 💰 Earning EGOC Tokens

### Bandwidth Sharing Tiers

| Tier | Daily Limit | Price per MB | Max Speed | Earnings Potential |
|------|-------------|--------------|-----------|-------------------|
| **Basic** | 50 MB | 0.005 EGOC | 5 Mbps | ~0.25 EGOC/day |
| **Standard** | 200 MB | 0.01 EGOC | 20 Mbps | ~2 EGOC/day |
| **Premium** | 500 MB | 0.02 EGOC | 50 Mbps | ~10 EGOC/day |

### Optimization Features
- **Data Compression**: Save up to 60% on bandwidth costs
- **Smart Scheduling**: Operations during off-peak hours (11PM-6AM)
- **Network Intelligence**: Automatic switching to most cost-effective connection
- **Usage Monitoring**: Real-time tracking of data usage and costs

## 🏗️ Architecture

### Core Components

```
ego-node/
├── bandwidth_sharing/    # Bandwidth monetization system
├── data_optimizer/       # Compression and batching
├── keystore/            # Secure key management
├── network_manager/     # Network interface management
└── node/               # Main node implementation
```

### Network Stack
- **Transport**: TCP with Yamux multiplexing
- **Security**: Noise protocol encryption
- **Discovery**: mDNS, Kademlia DHT, AutoNAT
- **Messaging**: GossipSub for pub/sub communication
- **Peer Management**: Connection limits and quality scoring

### Blockchain Integration
- **State Management**: Account balances and validator stakes
- **Transaction Processing**: Full validation and execution
- **Cross-Shard Communication**: Efficient shard coordination
- **Proof Verification**: PoC and PoST proof validation

## 🔧 Development

### Building from Source
```bash
# Development build
cargo build

# Optimized release build
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- --interactive
```

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_bandwidth_sharing

# Run with output
cargo test -- --nocapture
```

### Code Structure
```rust
// Key traits and interfaces
pub trait NodeRole: Clone + Debug + Hash + Eq {}
pub trait NetworkOptimization {
    fn optimize_for_cost(&mut self) -> Result<(), NetworkError>;
    fn optimize_for_performance(&mut self) -> Result<(), NetworkError>;
}

// Main node implementation
pub struct Node {
    pub peer_id: PeerId,
    pub roles: HashSet<NodeRole>,
    pub network_manager: NetworkManager,
    pub bandwidth_sharing: BandwidthSharingManager,
    pub data_optimizer: DataOptimizer,
    // ... other components
}
```

## 🌍 Network Topology

### Shard Architecture
- **Cross-Shard Coordination**: Efficient communication between shards
- **Load Balancing**: Dynamic peer distribution across shards
- **Fault Tolerance**: Automatic failover and recovery mechanisms

### 5G Integration
- **Network Slicing**: Dedicated bandwidth allocation for different services
- **Edge Computing**: Local processing to reduce latency
- **Quality of Service**: Prioritization of critical blockchain operations

## 📊 Monitoring & Metrics

### Performance Metrics
- **Uptime**: Node availability and reliability
- **Throughput**: Messages and transactions per second
- **Latency**: Network round-trip times
- **Resource Usage**: CPU, memory, storage, bandwidth

### Financial Metrics
- **EGOC Earnings**: Real-time bandwidth sharing revenue
- **Cost Savings**: Network optimization benefits
- **ROI Tracking**: Return on infrastructure investment

### Network Health
- **Peer Connectivity**: Connected peer count and quality
- **Data Usage**: Bandwidth consumption by service type
- **Error Rates**: Network and transaction error tracking

## 🚨 Troubleshooting

### Common Issues

#### No Peers Connected
```bash
# Check network connectivity
ping 8.8.8.8

# Verify firewall settings
sudo ufw status

# Try different bootstrap peers
ego-node --bootstrap "/ip4/1.2.3.4/tcp/9000/p2p/12D3K..."
```

#### High Data Usage
```bash
# Enable compression
ego-node --enable-compression

# Set strict data limits
ego-node --data-threshold 10 --cost-threshold 20

# Use WiFi only
ego-node --disable-auto-switch
```

#### Low EGOC Earnings
```bash
# Check bandwidth sharing status
> sharing

# Increase shared bandwidth
> enable-sharing

# Verify network connectivity
> network
```

### Getting Help
- **Interactive Help**: Type `help` in interactive mode
- **Logs**: Check `RUST_LOG=debug` output for detailed information
- **Community**: Join our Discord server for support
- **Issues**: Report bugs on GitHub

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with tests
4. Run the test suite: `cargo test`
5. Submit a pull request

### Coding Standards
- Follow Rust best practices and idioms
- Add comprehensive tests for new features
- Update documentation for API changes
- Use descriptive commit messages

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎯 Roadmap

### 2024 Q4
- [ ] Enhanced 5G network slicing
- [ ] Advanced machine learning for network optimization
- [ ] Mobile app for node monitoring
- [ ] Staking rewards integration

### 2025 Q1
- [ ] Cross-chain bridge support
- [ ] Enhanced consensus mechanisms
- [ ] Advanced analytics dashboard
- [ ] Enterprise deployment tools

## 📞 Support

- **Documentation**: [https://docs.ego-blockchain.org](https://docs.ego-blockchain.org)
- **Community**: [Discord Server](https://discord.gg/ego-blockchain)
- **Issues**: [GitHub Issues](https://github.com/ego-blockchain/ego-node/issues)
- **Email**: support@ego-blockchain.org

---

**Built with ❤️ by the Ego Blockchain Team**

*Making decentralized infrastructure accessible, profitable, and intelligent.*
