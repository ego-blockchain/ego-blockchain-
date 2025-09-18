# Ego Core

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/ego-blockchain/ego-core)

The core blockchain infrastructure for the Ego distributed network. This library provides the fundamental building blocks for blockchain operations, including accounts, transactions, blocks, state management, and cryptographic primitives optimized for 5G networks and edge computing.

## 🌟 Features

### Core Blockchain Components
- **Multi-Type Account System**: EOA, Device, Contract, System, and Validator accounts
- **Advanced Transaction Processing**: 15+ transaction types with comprehensive validation
- **Sharded Architecture**: Built-in multi-shard support with cross-shard communication
- **State Management**: Efficient concurrent state tracking with DashMap
- **Cryptographic Security**: Ed25519 + Dilithium + ML-KEM post-quantum cryptography

### 5G Network Integration
- **Network Slices**: Native support for eMBB, URLLC, and mMTC slice types
- **Device Capabilities**: Bandwidth, storage, and coverage area tracking
- **Proof Systems**: Proof-of-Coverage (PoC) and Proof-of-Spacetime (PoST)
- **Geospatial Support**: H3 geohash integration for location-based operations

### Advanced Features
- **Layer-2 Rollups**: Complete rollup aggregation with fraud proof system
- **DRS (Distributed Reputation System)**: Dynamic node scoring and penalty system
- **Deploy Policy Management**: Smart contract and data deployment governance
- **Cross-Shard Communication**: Seamless inter-shard transaction processing
- **Storage Management**: Erasure coding, replication, and garbage collection

### Performance & Optimization
- **Ultra-Fast Block Times**: Optimized for 100ms block production
- **High Throughput**: 1000+ TPS per shard capability
- **Memory Efficient**: Lock-free concurrent data structures
- **Network Optimized**: Binary serialization with compression support

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           Ego Core Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│  Applications & Smart Contracts                                 │
├─────────────────────┬─────────────────┬─────────────────────────┤
│  Transaction Layer  │   State Layer   │   Consensus Layer       │
│  ┌─────────────────┐│  ┌─────────────┐│  ┌─────────────────────┐│
│  │ • Transfer      ││  │ • Accounts  ││  │ • Block Creation    ││
│  │ • Staking       ││  │ • Storage   ││  │ • Validation       ││
│  │ • Cross-Shard   ││  │ • Slices    ││  │ • Finalization     ││
│  │ • Rollup Commit ││  │ • Validators││  │ • Cross-Shard Sync ││
│  └─────────────────┘│  └─────────────┘│  └─────────────────────┘│
├─────────────────────┼─────────────────┼─────────────────────────┤
│       Sharding Layer       │       Rollup Layer                 │
│  ┌─────────────────────────┐│  ┌─────────────────────────────────┐│
│  │ • Multi-Shard Support   ││  │ • Batch Aggregation             ││
│  │ • Cross-Shard Receipts  ││  │ • Fraud Proof System           ││
│  │ • Load Balancing        ││  │ • Challenge Resolution          ││
│  └─────────────────────────┘│  └─────────────────────────────────┘│
├─────────────────────────────┼─────────────────────────────────────┤
│         5G Integration Layer         │    DRS & Policy Layer    │
│  ┌─────────────────────────────────┐│  ┌─────────────────────────┐│
│  │ • Network Slices (eMBB/URLLC)   ││  │ • Reputation Scoring   ││
│  │ • Device Capabilities          ││  │ • Deploy Governance    ││
│  │ • Coverage Proofs              ││  │ • Resource Management  ││
│  └─────────────────────────────────┘│  └─────────────────────────┘│
├─────────────────────────────────────┼─────────────────────────────┤
│              Cryptography Layer              │  Storage Layer    │
│  ┌─────────────────────────────────────────┐│  ┌─────────────────┐│
│  │ • Ed25519 + Dilithium Signatures       ││  │ • Merkle Trees  ││
│  │ • ML-KEM Post-Quantum Encryption       ││  │ • State Tries   ││
│  │ • Blake3 Hashing                       ││  │ • Data Chunks   ││
│  └─────────────────────────────────────────┘│  └─────────────────┘│
└─────────────────────────────────────────────┴─────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ with Cargo
- Git for cloning repositories

### Installation

1. **Clone the Repository**
```bash
git clone https://github.com/ego-blockchain/ego-blockchain.git
cd ego-blockchain
```

2. **Add to Your Project**
```toml
[dependencies]
ego-core = { path = "./crates/ego-core" }
tokio = { version = "1.0", features = ["full"] }
```

3. **Basic Usage Example**
```rust
use ego_core::{
    Account, Address, Balance, KeyPair, Transaction, TransactionPayload,
    StateManager, Block, ShardId
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate cryptographic keys
    let keypair = KeyPair::generate();
    let address = Address::from_public_key(&keypair.public_key());

    // Create account with initial balance
    let mut account = Account::new_eoa(address, keypair.dilithium_public_key());
    account.credit(Balance::from_egoc(1000));

    println!("Account created: {}", account.summary());

    // Setup state manager
    let mut state = StateManager::new();
    state.set_account(account);

    // Create and execute transaction
    let payload = TransactionPayload::Transfer {
        to: Address::new([1u8; 20]),
        amount: Balance::from_egoc(100),
        memo: Some("First transaction".to_string()),
    };

    let mut tx = Transaction::new(
        address,
        1,
        payload,
        ShardId::new(0)?,
        None
    );
    tx.sign(&keypair)?;

    let result = state.execute_transaction(&tx)?;
    println!("Transaction executed successfully: {}", result.success);

    Ok(())
}
```

### Running Tests
```bash
# Run all tests
cargo test

# Run specific module tests
cargo test account::tests
cargo test transaction::tests
cargo test crypto::tests

# Run tests with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

### Building Documentation
```bash
cargo doc --open
```

## 📖 Core Components Guide

### 1. Account Management

#### Account Types
The system supports five distinct account types:

**EOA (Externally Owned Account)**
```rust
let account = Account::new_eoa(
    address,
    dilithium_public_key.clone()
);
```

**Device Account (5G Device)**
```rust
let capabilities = DeviceCapabilities {
    bandwidth_capacity: 1_000_000_000,  // 1 Gbps
    storage_capacity: 100_000_000_000,  // 100 GB
    supported_slices: vec![SliceId::new("embb-slice-1".to_string())],
    coverage_area: Some("9q5b2h".to_string()), // Geohash
    hardware_specs: HashMap::new(),
    last_poc: None,
    post_stats: PostStats::default(),
};

let device = Account::new_device(
    address,
    "device-001".to_string(),
    capabilities,
    dilithium_pk,
    "12D3KooW...".to_string() // Peer ID
);
```

**Validator Account**
```rust
let validator = Account::new_validator(
    address,
    validator_pubkey,
    500,  // 5% commission rate
    Balance::from_egoc(10_000), // Minimum stake
    dilithium_pk
)?;
```

#### Account Operations
```rust
// Balance management
account.credit(Balance::from_egoc(500));
account.debit(Balance::from_egoc(100))?;

// Storage operations
account.add_storage_credits(1000);
account.use_storage_credits(100)?;
account.update_storage_usage(1024 * 1024)?; // 1 MB

// Slice authorization
account.authorize_slice(SliceId::new("urllc-slice".to_string()));
let authorized = account.is_authorized_for_slice(&slice_id);

// DRS score updates
account.update_drs_score(95.5, 10); // Score: 95.5, Epoch: 10
```

### 2. Transaction System

#### Transaction Types

**Basic Transfer**
```rust
let payload = TransactionPayload::Transfer {
    to: recipient_address,
    amount: Balance::from_egoc(100),
    memo: Some("Payment for services".to_string()),
};
```

**Account Creation**
```rust
let payload = TransactionPayload::CreateAccount {
    account_address: new_address,
    account_type: AccountType::Device {
        device_id: "device-002".to_string(),
        geohash: Some("9q5b2j".to_string()),
    },
    initial_balance: Balance::from_egoc(50),
    dilithium_pk: dilithium_public_key,
};
```

**Data Storage with 5G Slices**
```rust
let payload = TransactionPayload::StoreData {
    chunk_id: Hash::new([1u8; 32]),
    data_size: 1024 * 1024, // 1 MB
    duration: 1000, // 1000 blocks
    data_hash: Hash::new([2u8; 32]),
    slice_id: SliceId::new("embb-slice-1".to_string()),
    storage_credits: 1000,
};
```

**Proof Submission (PoC/PoST)**
```rust
let witness_data = WitnessData {
    rsrp: -80,        // Signal strength
    rsrq: -10,        // Signal quality
    sinr: 20,         // Signal-to-noise ratio
    timing_advance: 100,
    gps_coords: Some((37_7749, -122_4194)), // San Francisco
    witnesses: vec![witness1, witness2],
};

let payload = TransactionPayload::SubmitProof {
    proof_type: "poc".to_string(),
    proof_data: vec![/* proof bytes */],
    challenge_hash: Hash::new([3u8; 32]),
    location_id: "9q5b2h".to_string(),
    witness_data: Some(witness_data),
};
```

**Staking Operations**
```rust
// Become a validator
let payload = TransactionPayload::Stake {
    amount: Balance::from_egoc(5000),
    validator_pubkey: keypair.public_key(),
    commission_rate: Some(300), // 3%
};

// Delegate to existing validator
let payload = TransactionPayload::Delegate {
    amount: Balance::from_egoc(1000),
    validator_pubkey: validator_pubkey,
};
```

**Cross-Shard Transactions**
```rust
let payload = TransactionPayload::CrossShard {
    target_shard: ShardId::new(1)?,
    message: serde_json::to_vec(&cross_shard_data)?,
    response_hash: Some(Hash::new([4u8; 32])),
};
```

**Smart Contract Deployment**
```rust
let payload = TransactionPayload::DeployContract {
    contract_code: std::fs::read("contract.wasm")?,
    constructor_args: constructor_data,
    deploy_credits: 5000,
    use_free_quota: false,
};
```

#### Transaction Lifecycle
```rust
// Create transaction
let mut tx = Transaction::new(sender, nonce, payload, shard_id, slice_id);

// Sign transaction (Ed25519 + Dilithium for critical operations)
tx.sign(&keypair)?;

// Validate transaction
tx.verify_signature()?;
let account = state.get_account(&tx.from).unwrap();
tx.validate_against_account(&account)?;

// Execute transaction
let result = state.execute_transaction(&tx)?;

// Check results
if result.success {
    println!("Transaction executed successfully");
    for event in result.events {
        println!("Event: {} - {}", event.event_type, event.data);
    }
} else {
    println!("Transaction failed: {}", result.error.unwrap_or_default());
}
```

### 3. Block Structure and Processing

#### Block Creation
```rust
use ego_core::{Block, BlockHeight, EpochNumber, RollupCommitment};

let block = Block::new(
    BlockHeight::new(1000),
    previous_hash,
    ShardId::new(0)?,
    EpochNumber::new(10),
    proposer_address,
    transactions,
    rollup_commitments,
);
```

#### Block Validation and Signing
```rust
// Sign block as proposer
let mut block = Block::new(/* ... */);
block.sign(&proposer_keypair)?;

// Validate block structure
block.validate_structure()?;

// Verify proposer signature
let is_valid = block.verify_signature(&proposer_pubkey)?;
```

#### Block Processing
```rust
let mut shard = ShardManager::new(shard_config);

// Add transactions to pool
for tx in transactions {
    shard.add_transaction(tx).await?;
}

// Get transactions for next block
let pending_txs = shard.get_transactions_for_block(1000).await;

// Process block
shard.process_block(block).await?;

// Get statistics
let stats = shard.get_stats().await;
println!("Shard {} - TPS: {:.2}, BPS: {:.2}",
         stats.shard_id, stats.metrics.tps, stats.metrics.bps);
```

### 4. Sharding System

#### Shard Configuration
```rust
let shard_config = ShardConfig {
    shard_id: ShardId::new(0)?,
    committee_size: 21,
    replication_factor: 3,
    max_txs_per_block: 1000,
    target_block_time_ms: 100, // 100ms blocks
    cross_shard_enabled: true,
    storage_config: ShardStorageConfig {
        max_storage_per_node: 100 * 1024 * 1024 * 1024, // 100 GB
        proof_frequency: 100, // Every 100 blocks
        retention_period: 100_000,
        erasure_coding: ErasureCodingConfig {
            data_chunks: 4,
            parity_chunks: 2,
            chunk_size: 1024 * 1024,
        },
        gc_config: GarbageCollectionConfig {
            frequency: 1000,
            threshold: 0.8,
            aggressive_mode: false,
        },
    },
    preferred_slices: vec!["embb-slice-1".to_string()],
    geo_constraints: Some(GeoConstraints {
        allowed_regions: vec!["us-west".to_string(), "us-east".to_string()],
        max_latency_ms: 50,
        min_nodes_per_region: 3,
    }),
};
```

#### Multi-Shard Operations
```rust
// Create multiple shards
let mut shards = Vec::new();
for i in 0..4 {
    let config = ShardConfig {
        shard_id: ShardId::new(i)?,
        ..Default::default()
    };
    shards.push(ShardManager::new(config));
}

// Route transactions to appropriate shards
fn route_transaction(tx: &Transaction) -> u32 {
    // Simple routing based on account address
    let hash = blake3::hash(tx.from.as_bytes());
    u32::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1],
                       hash.as_bytes()[2], hash.as_bytes()[3]]) % 4
}
```

### 5. Layer-2 Rollup System

#### Rollup Configuration
```rust
let rollup_config = RollupConfig {
    max_txs_per_batch: 1000,
    max_batch_size_bytes: 1024 * 1024, // 1 MB
    batch_timeout_ms: 10_000, // 10 seconds
    target_shard: ShardId::new(0)?,
    min_operator_stake: Balance::from_egoc(10_000),
    challenge_period: 1000, // 1000 blocks
    fraud_proof_config: FraudProofConfig {
        challenge_window: 500,
        challenge_bond: Balance::from_egoc(100),
        fraud_proof_reward: Balance::from_egoc(1000),
        max_proof_size: 1024 * 1024,
    },
    fee_structure: FeeStructure {
        base_fee: Balance::new(1000),
        per_byte_fee: Balance::new(10),
        operator_commission: 500, // 5%
        priority_multiplier: 1.5,
    },
};
```

#### Rollup Operations
```rust
let mut aggregator = RollupAggregator::new(
    "my-rollup".to_string(),
    operator_address,
    rollup_config
);

// Add transactions to current batch
for tx in layer2_transactions {
    aggregator.add_transaction(tx)?;
}

// Seal current batch when full or timeout
aggregator.seal_current_batch()?;

// Process batches
aggregator.process_batch(0)?;

// Create L1 commitment
let commitment = aggregator.create_commitment(
    (0, 10), // Batch range
    (BlockHeight::new(1000), BlockHeight::new(1100))
)?;

// Submit fraud proof challenge
let challenge_id = aggregator.submit_challenge(
    challenger_address,
    suspicious_batch_sequence,
    ChallengeType::InvalidStateTransition,
    proof_data,
    bond_amount
)?;
```

### 6. DRS (Distributed Reputation System)

#### DRS Configuration
```rust
let drs_config = DRSConfig {
    uptime_weight: 0.25,
    proof_success_weight: 0.25,
    witness_quality_weight: 0.20,
    coverage_value_weight: 0.20,
    utility_weight: 0.10,
    density_penalty_rate: 0.10,
    density_min_multiplier: 0.40,
    score_bounds: (0.0, 100.0),
};

let mut drs_manager = DRSManager::new(drs_config);
```

#### Node Metrics and Scoring
```rust
let node_metrics = NodeMetrics {
    node_id: device_address,
    epoch: 10,
    uptime_ms: 86_400_000, // 24 hours
    total_epoch_ms: 86_400_000,
    proofs_submitted: 100,
    proofs_successful: 95,
    witnesses_provided: 200,
    witness_accuracy: 0.98,
    coverage_areas: vec!["9q5b2h".to_string(), "9q5b2j".to_string()],
    proposer_blocks: 5,
    validator_participation: 0.99,
    location: Some(GeospatialData {
        h3_cell: "8928308280fffff".to_string(),
        lat: 37.7749,
        lon: -122.4194,
        altitude: Some(100.0),
        witness_count: 10,
        dwell_time_pct: 0.95,
    }),
};

// Calculate DRS score
let density_data = Some(DensityData {
    h3_cell: "8928308280fffff".to_string(),
    device_count: 3,
    dwell_time_pct: 0.95,
    witnesses: vec![witness1, witness2],
});

let drs_score = drs_manager.calculate_drs_score(&node_metrics, density_data)?;
println!("Node DRS Score: {:.2}", drs_score.total_score);
```

#### Reward Multipliers
```rust
// Apply DRS-based reward multiplier
let base_reward = 1000u128;
let final_reward = drs_manager.apply_reward_multiplier(base_reward, &node_address);

// Check quota eligibility
let min_score = 75.0;
let qualifies = drs_manager.qualifies_for_quota(&node_address, min_score);
```

### 7. Deploy Policy Management

#### Policy Configuration
```rust
let deploy_config = DeployPolicyConfig {
    free_deploys_per_epoch: 5,
    min_stake_for_quota: Balance::from_egoc(1000),
    credits_per_kb: 100,
    credits_per_ru: 10,
    max_deploy_size_kb: 1024,
    max_ru_per_deploy: 10000,
    deploy_bond_amount: Balance::new(1000000),
    bond_lock_duration_blocks: 1000,
    bond_slash_threshold: 3,
    max_deploys_per_epoch: 10000,
    max_deploys_per_user_per_epoch: 50,
    max_total_size_per_epoch_gb: 100,
    enable_dedup: true,
    dedup_lookback_epochs: 10,
};

let mut deploy_manager = DeployPolicyManager::new(deploy_config);
```

#### Deploy Request Processing
```rust
let deploy_request = DeployRequest {
    deployer: deployer_address,
    deploy_type: DeployType::SmartContract {
        code_size_kb: 256,
        estimated_ru: 5000,
    },
    code: contract_bytecode,
    metadata: HashMap::new(),
    use_free_quota: true,
    preferred_shard: Some(0),
};

// Evaluate deploy request
let decision = deploy_manager.evaluate_deploy_request(
    &deploy_request,
    Some(Balance::from_egoc(5000)), // Staker balance
    current_block
)?;

match decision {
    DeployDecision::AcceptWithFreeQuota { deploy_id } => {
        println!("Deploy accepted with free quota: {}", deploy_id);
    },
    DeployDecision::AcceptWithCredits { deploy_id, credits_required, bond_required } => {
        println!("Deploy accepted - Credits: {}, Bond: {:?}",
                credits_required, bond_required);
    },
    DeployDecision::Reject { deploy_id, reason } => {
        println!("Deploy rejected: {}", reason);
    },
}
```

### 8. 5G Network Slices

#### Slice Configuration
```rust
let slice_config = SliceConfig {
    slice_id: "embb-slice-1".to_string(),
    slice_type: SliceType::EMbb, // Enhanced Mobile Broadband
    authorized_devices: vec![device1, device2],
    bandwidth_allocation: 1_000_000_000, // 1 Gbps
    latency_ms: 20,
    reliability_score: 95,
    status: SliceStatus::Active,
    created_at: Timestamp::now(),
    updated_at: Timestamp::now(),
};

// Different slice types
let urllc_slice = SliceConfig {
    slice_type: SliceType::Urllc, // Ultra-Reliable Low Latency
    bandwidth_allocation: 100_000_000, // 100 Mbps
    latency_ms: 1, // 1ms latency
    reliability_score: 99,
    ..slice_config.clone()
};

let custom_slice = SliceConfig {
    slice_type: SliceType::Custom {
        name: "IoT-Monitoring".to_string()
    },
    bandwidth_allocation: 10_000_000, // 10 Mbps
    latency_ms: 100,
    reliability_score: 90,
    ..slice_config
};
```

#### Slice Operations
```rust
// Slice operation transaction
let payload = TransactionPayload::SliceOperation {
    operation: SliceOperationType::Create,
    slice_id: SliceId::new("new-slice-1".to_string()),
    params: {
        let mut params = HashMap::new();
        params.insert("bandwidth".to_string(), "500000000".to_string()); // 500 Mbps
        params.insert("latency_ms".to_string(), "10".to_string());
        params.insert("slice_type".to_string(), "embb".to_string());
        params
    },
};
```

### 9. Cryptographic Operations

#### Key Management
```rust
// Generate new keypair
let keypair = KeyPair::generate();

// Create from seed
let seed: [u8; 32] = [/* seed bytes */];
let keypair = KeyPair::from_bytes(&seed)?;

// Get public keys
let ed25519_pk = keypair.public_key();
let dilithium_pk = keypair.dilithium_public_key();
let kyber_pk = keypair.kyber_public_key();

// Derive address
let address = Address::from_public_key(&ed25519_pk);
```

#### Digital Signatures
```rust
let message = b"Important message to sign";

// Ed25519 signature (fast, standard)
let signature = keypair.sign(message);
let is_valid = verify_signature(&ed25519_pk, message, &signature)?;

// Dilithium signature (post-quantum)
let dilithium_sig = keypair.sign_dilithium(message);
let is_valid = verify_dilithium_signature(&dilithium_pk, message, &dilithium_sig)?;
```

#### Hashing and Merkle Trees
```rust
// Blake3 hashing
let hash = hash_data(b"some data");
let multi_hash = hash_multiple(&[b"piece1", b"piece2", b"piece3"]);

// Merkle tree operations
let data_items = vec![
    b"item1".to_vec(),
    b"item2".to_vec(),
    b"item3".to_vec(),
    b"item4".to_vec(),
];

let merkle_tree = MerkleTree::build(data_items);
let root_hash = merkle_tree.root_hash().unwrap();

// Verify merkle proof
let proof = MerkleProof {
    leaf_index: 2,
    leaf_hash: hash_data(b"item3"),
    proof_hashes: vec![/* proof hashes */],
    tree_size: 4,
};

let is_valid = proof.verify(root_hash)?;
```

#### Post-Quantum Encryption
```rust
// ML-KEM key encapsulation
let (shared_secret, ciphertext) = kyber_encapsulate(&kyber_pk)?;
let decrypted_secret = kyber_decapsulate(&kyber_sk, &ciphertext)?;

// XChaCha20-Poly1305 encryption
let key: [u8; 32] = [/* key bytes */];
let nonce: [u8; 24] = [/* nonce bytes */];
let plaintext = b"confidential data";
let associated_data = b"public metadata";

let ciphertext = xchacha20poly1305_encrypt(&key, &nonce, plaintext, associated_data)?;
let decrypted = xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, associated_data)?;
```

### 10. State Management

#### State Operations
```rust
let mut state = StateManager::new();

// Account operations
state.create_account(address, AccountType::EOA)?;
let account = state.get_account(&address);
state.set_account(updated_account);

// Transaction execution
let result = state.execute_transaction(&transaction)?;

// State root computation
let state_root = state.compute_state_root();

// Statistics
let stats = state.get_stats();
println!("Total accounts: {}, Total balance: {}",
         stats.total_accounts, stats.total_balance);
```

#### Storage Management
```rust
let storage_entry = StorageEntry {
    data_hash: Hash::new([5u8; 32]),
    size: 1024 * 1024, // 1 MB
    expires_at: BlockHeight::new(10000),
    provider: provider_address,
    slice_id: Some("embb-slice-1".to_string()),
    stored_at: Timestamp::now(),
    replica_count: 3,
    payment: Balance::from_egoc(10),
};

// Storage operations handled through state manager
```

## 🔧 Integration Examples

### Building a Complete Node
```rust
use ego_core::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> EgoResult<()> {
    // Initialize cryptography
    let keypair = KeyPair::generate();
    let address = Address::from_public_key(&keypair.public_key());

    // Setup state management
    let mut state = StateManager::new();

    // Create validator account
    let validator = Account::new_validator(
        address,
        keypair.public_key(),
        500, // 5% commission
        Balance::from_egoc(50_000),
        keypair.dilithium_public_key(),
    )?;
    state.set_account(validator);

    // Setup sharding
    let shard_config = ShardConfig {
        shard_id: ShardId::new(0)?,
        committee_size: 21,
        target_block_time_ms: 100,
        cross_shard_enabled: true,
        ..Default::default()
    };
    let mut shard = ShardManager::new(shard_config);

    // Setup DRS
    let drs_config = DRSConfig::default();
    let mut drs_manager = DRSManager::new(drs_config);

    // Setup deploy policies
    let deploy_config = DeployPolicyConfig::default();
    let mut deploy_manager = DeployPolicyManager::new(deploy_config);

    // Process transactions
    let transactions = generate_test_transactions()?;
    for tx in transactions {
        shard.add_transaction(tx).await?;
    }

    // Create and process block
    let pending_txs = shard.get_transactions_for_block(1000).await;
    let mut block = Block::new(
        BlockHeight::new(1),
        Hash::ZERO,
        ShardId::new(0)?,
        EpochNumber::new(1),
        address,
        pending_txs,
        vec![],
    );

    block.sign(&keypair)?;
    shard.process_block(block).await?;

    println!("Node successfully processed block!");

    Ok(())
}

fn generate_test_transactions() -> EgoResult<Vec<Transaction>> {
    let keypair = KeyPair::generate();
    let address = Address::from_public_key(&keypair.public_key());

    let mut transactions = Vec::new();

    // Transfer transaction
    let payload = TransactionPayload::Transfer {
        to: Address::new([1u8; 20]),
        amount: Balance::from_egoc(10),
        memo: Some("Test transfer".to_string()),
    };

    let mut tx = Transaction::new(
        address,
        1,
        payload,
        ShardId::new(0)?,
        None,
    );
    tx.sign(&keypair)?;
    transactions.push(tx);

    Ok(transactions)
}
```

### Setting Up Rollup Operator
```rust
use ego_core::*;

async fn setup_rollup_operator() -> EgoResult<()> {
    let keypair = KeyPair::generate();
    let operator_address = Address::from_public_key(&keypair.public_key());

    // Configure rollup
    let rollup_config = RollupConfig {
        max_txs_per_batch: 1000,
        batch_timeout_ms: 5000,
        min_operator_stake: Balance::from_egoc(10_000),
        fraud_proof_config: FraudProofConfig {
            challenge_window: 1000,
            challenge_bond: Balance::from_egoc(100),
            fraud_proof_reward: Balance::from_egoc(1000),
            max_proof_size: 1024 * 1024,
        },
        ..Default::default()
    };

    let mut aggregator = RollupAggregator::new(
        "high-throughput-rollup".to_string(),
        operator_address,
        rollup_config,
    );

    // Simulate rollup operations
    let l2_transactions = generate_l2_transactions().await?;

    for tx in l2_transactions {
        aggregator.add_transaction(tx)?;

        // Auto-seal when batch is full
        if aggregator.current_batch.transactions.len() >= 1000 {
            aggregator.seal_current_batch()?;
            aggregator.process_batch(aggregator.state.next_batch_sequence - 1)?;
        }
    }

    // Create commitment for L1 submission
    let commitment = aggregator.create_commitment(
        (0, 10),
        (BlockHeight::new(1000), BlockHeight::new(1100))
    )?;

    println!("Rollup commitment created: {}", commitment.rollup_id);

    Ok(())
}

async fn generate_l2_transactions() -> EgoResult<Vec<Transaction>> {
    // Generate sample L2 transactions
    let keypair = KeyPair::generate();
    let address = Address::from_public_key(&keypair.public_key());

    let mut transactions = Vec::new();

    for i in 1..=100 {
        let payload = TransactionPayload::Transfer {
            to: Address::new([(i % 255) as u8; 20]),
            amount: Balance::from_egoc(1),
            memo: Some(format!("L2 transaction {}", i)),
        };

        let mut tx = Transaction::new(
            address,
            i as u64,
            payload,
            ShardId::new(0)?,
            None,
        );
        tx.sign(&keypair)?;
        transactions.push(tx);
    }

    Ok(transactions)
}
```

## 📊 Performance Monitoring

### Metrics Collection
```rust
use ego_core::utils::PerformanceMonitor;

let mut monitor = PerformanceMonitor::new(1000);

// Record transaction processing metrics
monitor.record("tps", 1250.0, None);
monitor.record("block_time_ms", 98.0, None);
monitor.record("validation_time_ms", 15.0, Some({
    let mut labels = HashMap::new();
    labels.insert("tx_type".to_string(), "transfer".to_string());
    labels
}));

// Get statistics
if let Some(stats) = monitor.get_stats("tps") {
    println!("TPS - Mean: {:.2}, Max: {:.2}, Std Dev: {:.2}",
             stats.mean, stats.max, stats.std_dev);
}
```

### Configuration Management
```rust
use ego_core::utils::{ConfigManager, ConfigValue};

let mut config = ConfigManager::new();

// Set configuration values
config.set("max_block_size".to_string(), ConfigValue::Integer(1024 * 1024));
config.set("enable_cross_shard".to_string(), ConfigValue::Boolean(true));
config.set("supported_slices".to_string(), ConfigValue::Array(vec![
    ConfigValue::String("embb-slice-1".to_string()),
    ConfigValue::String("urllc-slice-1".to_string()),
]));

// Save and load configuration
config.save_to_file("node-config.json")?;
let loaded_config = ConfigManager::load_from_file("node-config.json")?;
```

## 🧪 Testing and Development

### Unit Testing
```bash
# Run all tests
cargo test

# Run specific component tests
cargo test account
cargo test transaction
cargo test crypto
cargo test state
cargo test rollup
cargo test drs

# Run integration tests
cargo test --test integration

# Run tests with coverage
cargo install cargo-tarpaulin
cargo tarpaulin --out html
```

### Benchmarking
```bash
# Run benchmarks
cargo bench

# Run specific benchmarks
cargo bench crypto
cargo bench transaction_validation
cargo bench state_management
```

### Example Test
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_transaction_flow() {
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public_key());

        // Create account
        let mut account = Account::new_eoa(address, keypair.dilithium_public_key());
        account.credit(Balance::from_egoc(1000));

        // Setup state
        let mut state = StateManager::new();
        state.set_account(account);

        // Create transaction
        let payload = TransactionPayload::Transfer {
            to: Address::new([1u8; 20]),
            amount: Balance::from_egoc(100),
            memo: None,
        };

        let mut tx = Transaction::new(
            address,
            1,
            payload,
            ShardId::new(0).unwrap(),
            None,
        );

        tx.sign(&keypair).unwrap();

        // Execute transaction
        let result = state.execute_transaction(&tx).unwrap();

        assert!(result.success);
        assert_eq!(result.state_changes.len(), 2); // Sender and receiver balance updates
    }

    #[tokio::test]
    async fn test_shard_block_processing() {
        let shard_config = ShardConfig::default();
        let mut shard = ShardManager::new(shard_config);

        // Create test transactions
        let transactions = generate_test_transactions().unwrap();

        // Add to transaction pool
        for tx in transactions.clone() {
            shard.add_transaction(tx).await.unwrap();
        }

        // Create block
        let keypair = KeyPair::generate();
        let proposer = Address::from_public_key(&keypair.public_key());

        let mut block = Block::new(
            BlockHeight::new(1),
            Hash::ZERO,
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            transactions,
            vec![],
        );

        block.sign(&keypair).unwrap();

        // Process block
        shard.process_block(block).await.unwrap();

        // Verify stats
        let stats = shard.get_stats().await;
        assert_eq!(stats.current_block_height, BlockHeight::new(1));
    }
}
```

## 📚 API Reference

### Core Types
- `Address` - 20-byte account address
- `Hash` - 32-byte Blake3 hash
- `Balance` - 128-bit balance with EGOC denomination
- `Timestamp` - Millisecond-precision timestamp
- `ShardId` - Shard identifier (0-1023)
- `SliceId` - 5G network slice identifier
- `PublicKey` - 32-byte Ed25519 public key
- `Signature` - 64-byte Ed25519 signature

### Account System
- `Account` - Multi-type account structure
- `AccountType` - EOA, Device, Contract, System types
- `DeviceCapabilities` - 5G device specifications
- `PostStats` - Proof-of-Spacetime statistics

### Transaction System
- `Transaction` - Complete transaction structure
- `TransactionPayload` - 15+ transaction types
- `TransactionResult` - Execution results and events
- `StateChange` - State modification records

### Block System
- `Block` - Complete block structure
- `BlockHeader` - Block metadata and consensus info
- `QuorumCert` - Multi-signature consensus certificate
- `CrossShardReceipt` - Inter-shard communication

### State Management
- `StateManager` - Concurrent state operations
- `StorageEntry` - Distributed storage records
- `ValidatorInfo` - Validator metadata and performance
- `SliceConfig` - 5G network slice configuration

### Cryptography
- `KeyPair` - Multi-algorithm key management
- `MerkleTree` - Merkle tree implementation
- `MerkleProof` - Merkle proof verification

### Advanced Features
- `RollupAggregator` - Layer-2 rollup management
- `DRSManager` - Distributed reputation system
- `DeployPolicyManager` - Deployment governance
- `ShardManager` - Multi-shard coordination

## 🚀 Production Deployment

### Performance Tuning
```rust
// Optimize for high throughput
let optimized_config = ShardConfig {
    max_txs_per_block: 2000,        // Higher transaction throughput
    target_block_time_ms: 50,       // Faster block times
    committee_size: 11,             // Smaller committee for speed
    micro_slot_duration_ms: 25,     // Faster slots
    storage_config: ShardStorageConfig {
        max_storage_per_node: 1_000_000_000_000, // 1 TB
        proof_frequency: 50,        // More frequent proofs
        gc_config: GarbageCollectionConfig {
            frequency: 500,         // More frequent cleanup
            threshold: 0.7,         // Earlier cleanup trigger
            aggressive_mode: true,  // Aggressive cleanup
        },
        ..Default::default()
    },
    ..Default::default()
};
```

### Monitoring and Observability
```rust
// Setup comprehensive monitoring
let mut monitor = PerformanceMonitor::new(10_000);

// Critical metrics to track
monitor.record("tps", tps_value, None);
monitor.record("block_time_ms", block_time, None);
monitor.record("finality_time_ms", finality_time, None);
monitor.record("cross_shard_latency_ms", cross_shard_latency, None);
monitor.record("drs_score_avg", avg_drs_score, None);
monitor.record("storage_utilization_pct", storage_pct, None);
monitor.record("validator_participation_pct", participation_pct, None);

// Memory and resource usage
monitor.record("memory_usage_mb", memory_mb, None);
monitor.record("cpu_usage_pct", cpu_pct, None);
monitor.record("network_throughput_mbps", network_mbps, None);
```

## 🎯 Roadmap

### Current Features (v1.0)
- ✅ Multi-type account system
- ✅ Comprehensive transaction processing
- ✅ Sharded architecture with cross-shard communication
- ✅ Layer-2 rollup integration
- ✅ 5G network slice support
- ✅ DRS (Distributed Reputation System)
- ✅ Post-quantum cryptography
- ✅ Proof systems (PoC/PoST)

### Upcoming Features (v1.1)
- 🔄 WebAssembly smart contract runtime
- 🔄 Advanced consensus mechanisms
- 🔄 Enhanced cross-shard atomic transactions
- 🔄 AI-powered resource optimization
- 🔄 Advanced fraud detection system

### Future Features (v2.0)
- 📋 Zero-knowledge proof integration
- 📋 Advanced privacy features
- 📋 Multi-chain interoperability
- 📋 Enhanced governance mechanisms
- 📋 Mobile device optimization

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the Repository**
```bash
git clone https://github.com/ego-blockchain/ego-blockchain.git
cd ego-blockchain
```

2. **Set Up Development Environment**
```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install required tools
cargo install cargo-watch cargo-tarpaulin
```

3. **Create Feature Branch**
```bash
git checkout -b feature/amazing-new-feature
```

4. **Run Tests**
```bash
cargo test
cargo clippy
cargo fmt
```

5. **Submit Pull Request**

### Code Style
- Follow Rust standard formatting (`cargo fmt`)
- Pass all clippy lints (`cargo clippy`)
- Maintain test coverage above 80%
- Document all public APIs
- Include integration tests for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support and Community

- **Documentation**: [docs.ego-blockchain.io](https://docs.ego-blockchain.io)
- **GitHub Issues**: [Report bugs and request features](https://github.com/ego-blockchain/ego-blockchain/issues)
- **GitHub Discussions**: [Community discussions](https://github.com/ego-blockchain/ego-blockchain/discussions)
- **Discord**: [Join our community](https://discord.gg/ego-blockchain)
- **Twitter**: [@EgoBlockchain](https://twitter.com/EgoBlockchain)

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for performance and safety
- Uses [Ed25519](https://ed25519.cr.yp.to/) for digital signatures
- Post-quantum cryptography with [Dilithium](https://pq-crystals.org/dilithium/) and [ML-KEM](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- Powered by [Blake3](https://github.com/BLAKE3-team/BLAKE3) for fast hashing
- Optimized for 5G networks and edge computing environments
- Inspired by cutting-edge blockchain research and production systems

---

**Ego Core** - The foundation of next-generation decentralized 5G networks with intelligent blockchain infrastructure.

*Built for performance, designed for the future.*
