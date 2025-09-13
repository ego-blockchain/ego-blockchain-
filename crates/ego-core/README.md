# Ego Core

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/ego-blockchain/ego-core)

The core blockchain infrastructure for the Ego distributed network. This library provides the fundamental building blocks for blockchain operations, including accounts, transactions, blocks, state management, and cryptographic primitives optimized for 5G networks and edge computing.

## 🌟 Features

### Core Blockchain Components
- **Account Management**: Multi-type accounts (User, Device, Validator, Contract, System)
- **Transaction Processing**: Comprehensive transaction types with validation and execution
- **Block Structure**: Optimized block format with metadata for 5G networks
- **State Management**: Efficient state tracking with cross-shard support
- **Cryptographic Primitives**: Ed25519 signatures with Blake3 hashing

### Advanced Features
- **Sharding Support**: Built-in multi-shard architecture
- **Rollup Integration**: Layer-2 rollup aggregation and fraud proofs
- **5G Network Slices**: Native support for network slice management
- **Cross-Shard Communication**: Seamless inter-shard transactions
- **Proof Systems**: Proof-of-Coverage (PoC) and Proof-of-Spacetime (PoST)

### Performance & Optimization
- **High Throughput**: Optimized for 100ms block times
- **Memory Efficient**: DashMap-based concurrent state management
- **Serialization**: Fast bincode serialization for network efficiency
- **Validation**: Comprehensive transaction and block validation

## 🏗️ Architecture

### Core Components

```
ego-core/
├── src/
│   ├── account.rs          # Account types and management
│   ├── block.rs            # Block structure and validation
│   ├── crypto.rs           # Cryptographic primitives
│   ├── error.rs            # Error types and handling
│   ├── rollup.rs           # Layer-2 rollup aggregation
│   ├── shard.rs            # Shard management and configuration
│   ├── state.rs            # State management and execution
│   ├── transaction.rs      # Transaction types and processing
│   ├── types.rs            # Core data types
│   ├── utils.rs            # Utility functions and helpers
│   └── lib.rs              # Library exports
├── Cargo.toml              # Dependencies and metadata
└── README.md               # This file
```

### Data Flow

```
Transaction → Validation → Execution → State Update → Block Creation
     ↓              ↓           ↓            ↓             ↓
  Signature    Account     State       Merkle        Block
  Verification  Checks    Changes      Trees         Hash
```

## 🚀 Quick Start

### Add to Cargo.toml

```toml
[dependencies]
ego-core = "1.0.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use ego_core::{
    Account, Address, Balance, Block, BlockHeight, ShardId,
    StateManager, Transaction, TransactionPayload, KeyPair
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create cryptographic keypair
    let keypair = KeyPair::generate();
    let address = Address::from_public_key(&keypair.public_key());

    // Create account
    let account = Account::new_user(address);
    println!("Created account: {}", account.summary());

    // Create state manager
    let mut state = StateManager::new();
    state.set_account(account);

    // Create and sign transaction
    let payload = TransactionPayload::Transfer {
        to: Address::new([1u8; 20]),
        amount: Balance::from_egoc(100),
        memo: Some("Test transfer".to_string()),
    };

    let mut tx = Transaction::new(
        address,
        1,
        payload,
        ShardId::new(0)?,
        None
    );

    tx.sign(&keypair)?;
    println!("Transaction hash: {}", tx.hash);

    // Execute transaction
    let result = state.execute_transaction(&tx)?;
    println!("Transaction executed: {}", result.success);

    Ok(())
}
```

## 📊 Account Types

### User Account
Standard user account for token transfers and basic operations.

```rust
let user_account = Account::new_user(address);
```

### Device Account
5G device account with capabilities and coverage tracking.

```rust
let capabilities = DeviceCapabilities {
    bandwidth_capacity: 1_000_000_000, // 1 Gbps
    storage_capacity: 100_000_000_000,  // 100 GB
    supported_slices: vec![SliceId::new("embb-slice".to_string())],
    coverage_area: Some("geohash_abc123".to_string()),
    hardware_specs: HashMap::new(),
    last_poc: None,
    post_stats: PostStats::default(),
};

let device_account = Account::new_device(
    address,
    "device-001".to_string(),
    capabilities
);
```

### Validator Account
Validator account for consensus participation and staking.

```rust
let validator_account = Account::new_validator(
    address,
    validator_pubkey,
    500, // 5% commission
    Balance::from_egoc(10000) // Initial stake
)?;
```

## 💳 Transaction Types

### Transfer
Basic token transfer between accounts.

```rust
let payload = TransactionPayload::Transfer {
    to: recipient_address,
    amount: Balance::from_egoc(100),
    memo: Some("Payment for services".to_string()),
};
```

### Store Data
Store data chunks with 5G network slice integration.

```rust
let payload = TransactionPayload::StoreData {
    chunk_id: Hash::new([1u8; 32]),
    data_size: 1024 * 1024, // 1 MB
    duration: 1000, // 1000 blocks
    data_hash: Hash::new([2u8; 32]),
    slice_id: SliceId::new("urllc-slice".to_string()),
};
```

### Submit Proof
Submit Proof-of-Coverage or Proof-of-Spacetime.

```rust
let payload = TransactionPayload::SubmitProof {
    proof_type: "poc".to_string(),
    proof_data: vec![1, 2, 3, 4], // Proof data
    challenge_hash: Hash::new([3u8; 32]),
    location_id: "geohash_def456".to_string(),
};
```

### Staking Operations
Stake tokens to become a validator or delegate to existing validators.

```rust
// Stake to become validator
let stake_payload = TransactionPayload::Stake {
    amount: Balance::from_egoc(5000),
    validator_pubkey: keypair.public_key(),
    commission_rate: Some(300), // 3%
};

// Delegate to validator
let delegate_payload = TransactionPayload::Delegate {
    amount: Balance::from_egoc(1000),
    validator_pubkey: validator_pubkey,
};
```

## 🔗 Block Structure

### Block Creation

```rust
let block = Block::new(
    BlockHeight::new(1),
    previous_hash,
    ShardId::new(0)?,
    EpochNumber::new(1),
    proposer_address,
    transactions,
    rollup_commitments,
);
```

### Block Validation

```rust
// Validate block structure
block.validate_structure()?;

// Verify proposer signature
let is_valid = block.verify_signature(&proposer_pubkey)?;

// Get block summary
println!("Block: {}", block.summary());
```

## 🌐 State Management

### State Operations

```rust
let mut state = StateManager::new();

// Create account
state.create_account(address, AccountType::User)?;

// Execute transaction
let result = state.execute_transaction(&transaction)?;

// Get account
let account = state.get_account(&address);

// Compute state root
let state_root = state.compute_state_root();

// Get statistics
let stats = state.get_stats();
println!("Total accounts: {}", stats.total_accounts);
```

### Cross-Shard State

```rust
// Track cross-shard state
let cross_shard_state = CrossShardState {
    shard_id: ShardId::new(1)?,
    last_state_root: Hash::new([4u8; 32]),
    last_block_height: BlockHeight::new(100),
    pending_receipts: vec![],
    receipt_nonce: 0,
};
```

## 🔄 Rollup Integration

### Rollup Aggregator

```rust
let config = RollupConfig::default();
let mut aggregator = RollupAggregator::new(
    "my-rollup".to_string(),
    operator_address,
    config
);

// Add transactions to batch
aggregator.add_transaction(transaction)?;

// Process batch
aggregator.process_batch(0)?;

// Create commitment
let commitment = aggregator.create_commitment(
    (0, 10), // batch range
    (BlockHeight::new(100), BlockHeight::new(110))
)?;
```

### Fraud Proofs

```rust
// Submit challenge
let challenge_id = aggregator.submit_challenge(
    challenger_address,
    batch_sequence,
    ChallengeType::InvalidStateTransition,
    proof_data,
    bond_amount
)?;

// Resolve challenge
aggregator.resolve_challenge(challenge_id, ChallengeStatus::ChallengerWins)?;
```

## 🏗️ Shard Management

### Shard Configuration

```rust
let shard_config = ShardConfig {
    shard_id: ShardId::new(0)?,
    committee_size: 21,
    replication_factor: 3,
    max_txs_per_block: 1000,
    target_block_time_ms: 100,
    cross_shard_enabled: true,
    storage_config: ShardStorageConfig::default(),
    preferred_slices: vec!["embb-slice".to_string()],
    geo_constraints: Some(GeoConstraints {
        allowed_regions: vec!["us-west".to_string()],
        max_latency_ms: 50,
        min_nodes_per_region: 3,
    }),
};
```

### Shard Manager

```rust
let mut shard = ShardManager::new(shard_config);

// Add transaction to pool
shard.add_transaction(transaction).await?;

// Get transactions for block
let txs = shard.get_transactions_for_block(100).await;

// Process block
shard.process_block(block).await?;

// Get statistics
let stats = shard.get_stats().await;
```

## 🔐 Cryptographic Operations

### Key Management

```rust
// Generate keypair
let keypair = KeyPair::generate();

// Create from seed
let keypair = KeyPair::from_bytes(&seed_bytes)?;

// Get public key and address
let pubkey = keypair.public_key();
let address = Address::from_public_key(&pubkey);
```

### Signing and Verification

```rust
// Sign data
let signature = keypair.sign(message);

// Verify signature
let is_valid = verify_signature(&pubkey, message, &signature)?;
```

### Hashing

```rust
// Hash data
let hash = hash_data(data);

// Hash multiple pieces
let hash = hash_multiple(&[piece1, piece2, piece3]);
```

### Merkle Trees

```rust
// Build merkle tree
let items = vec![data1, data2, data3, data4];
let tree = MerkleTree::build(items);

// Get root hash
let root = tree.root_hash();

// Create and verify proof
let proof = MerkleProof { /* ... */ };
let is_valid = proof.verify(root_hash)?;
```

## 📈 Performance Monitoring

### Metrics Collection

```rust
let mut monitor = PerformanceMonitor::new(1000);

// Record metrics
monitor.record("tps", 1500.0, None);
monitor.record("latency_ms", 45.0, Some(labels));

// Get statistics
let stats = monitor.get_stats("tps").unwrap();
println!("Average TPS: {:.2}", stats.mean);
```

### Configuration Management

```rust
let mut config = ConfigManager::new();

// Set configuration values
config.set("max_peers".to_string(), ConfigValue::Integer(200));
config.set("enable_compression".to_string(), ConfigValue::Boolean(true));

// Load from file
let config = ConfigManager::load_from_file("config.json")?;

// Save to file
config.save_to_file("config.json")?;
```

## 🛠️ Utility Functions

### Data Formatting

```rust
// Format bytes
let formatted = Utils::format_bytes(1024 * 1024); // "1.00 MB"

// Format duration
let formatted = Utils::format_duration(1500); // "1.5s"

// Calculate percentage
let pct = Utils::percentage(75, 100); // 75.0
```

### Validation

```rust
// Validate geohash
let is_valid = Utils::validate_geohash("9q5b2h");

// Validate slice ID
let is_valid = Utils::validate_slice_id("embb-slice-1");

// Validate timestamp
let is_valid = Utils::is_timestamp_valid(timestamp, 5000);
```

### Data Conversion

```rust
// Hex conversion
let hex = Utils::bytes_to_hex(&bytes);
let bytes = Utils::hex_to_bytes("0123456789abcdef")?;

// Moving average
let averages = Utils::moving_average(&values, 5);
```

## 🔧 Integration with Ego Node

Ego Core is designed to be used with [ego-node](https://github.com/ego-blockchain/ego-node) for complete blockchain functionality:

```rust
use ego_core::{StateManager, Block, Transaction};
use ego_node::Node;

// Create node with core integration
let mut node = Node::new_full_node(vec![0, 1, 2], 1000).await?;

// Process transactions using core
let mut state = StateManager::new();
let result = state.execute_transaction(&transaction)?;

// Create and validate blocks
let mut block = Block::new(/* ... */);
block.validate_structure()?;
```

## 📊 Constants and Limits

```rust
pub const PROTOCOL_VERSION: u32 = 1;
pub const TARGET_BLOCK_TIME_MS: u64 = 100;
pub const TARGET_EPOCH_DURATION_MS: u64 = 1000;
pub const MAX_TXS_PER_BLOCK: usize = 1000;
pub const MAX_ROLLUP_COMMITS_PER_BLOCK: usize = 100;
pub const GLOBAL_FINALITY_TARGET_SECS: u64 = 3;
pub const MAX_SHARD_COUNT: u32 = 1024;
pub const DEFAULT_TRIAD_SIZE: usize = 3;
pub const EGOC_DECIMALS: u8 = 18;
pub const EGOC_BASE_UNIT: u128 = 1_000_000_000_000_000_000;
```

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific test module
cargo test account::tests

# Run with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

## 📚 Examples

Check out the `examples/` directory for complete usage examples:

- `basic_usage.rs` - Basic account and transaction operations
- `state_management.rs` - State management and execution
- `block_creation.rs` - Block creation and validation
- `rollup_aggregation.rs` - Layer-2 rollup operations
- `shard_management.rs` - Multi-shard operations
- `crypto_operations.rs` - Cryptographic primitives

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

- **Documentation**: [docs.ego-blockchain.io](https://docs.ego-blockchain.io)
- **Issues**: [GitHub Issues](https://github.com/ego-blockchain/ego-core/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ego-blockchain/ego-core/discussions)

## 🌟 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for performance and safety
- Uses [Ed25519](https://ed25519.cr.yp.to/) for digital signatures
- Powered by [Blake3](https://github.com/BLAKE3-team/BLAKE3) for fast hashing
- Optimized for 5G networks and edge computing environments

---

**Ego Core** - The foundation of next-generation decentralized 5G networks with intelligent blockchain infrastructure.
