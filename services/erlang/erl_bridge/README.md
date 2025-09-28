# ERL Bridge - Sharded Byzantine Fault Tolerant Consensus

A high-performance, scalable blockchain consensus implementation in Erlang/OTP for 5G edge computing networks. This project implements Sharded Byzantine Fault Tolerant (SBFT) consensus with cross-shard communication capabilities.

## 🚀 Features

- **Sharded Byzantine Fault Tolerant Consensus**: Scalable BFT consensus across multiple shards
- **Cross-Shard Communication**: Efficient receipt-based communication between shards
- **Validator Management**: Dynamic validator registration, staking, and slashing
- **5G Edge Optimization**: Designed for ARM64 edge devices with 5G connectivity
- **High Availability**: Built on Erlang/OTP's fault-tolerant architecture
- **Real-time Metrics**: Comprehensive consensus and performance monitoring

## 🏗️ Byzantine Fault Tolerant Consensus Architecture

### What is Byzantine Fault Tolerant (BFT) Consensus?

Byzantine Fault Tolerant consensus is a distributed computing protocol that ensures network agreement even when up to 1/3 of validators are malicious, offline, or behaving arbitrarily. In our 5G and libp2p-based blockchain:

1. **Safety**: No two honest validators will commit conflicting blocks
2. **Liveness**: The network will continue to make progress as long as >2/3 validators are honest
3. **Finality**: Once a block is committed, it cannot be reverted

### Three-Phase BFT Protocol

Our implementation uses a classic three-phase BFT protocol:

```
1. PREPARE Phase:
   - Leader proposes a block
   - Validators vote "PREPARE" if block is valid
   - Need >2/3 PREPARE votes to proceed

2. COMMIT Phase:
   - Validators vote "COMMIT" after seeing >2/3 PREPARE votes
   - Need >2/3 COMMIT votes to finalize

3. FINALIZATION:
   - Block is committed to blockchain
   - Move to next view with new leader

View Change (Timeout/Failure Recovery):
   - If leader fails or timeout occurs
   - Validators vote for VIEW_CHANGE
   - New leader is selected deterministically
```

### Integration with 5G and libp2p

- **5G Edge Nodes**: Each ARM64 device runs a validator with stake-based voting
- **libp2p Networking**: Go sidecar handles P2P communication (QUIC, GossipSub)
- **Cross-Shard**: Erlang manages receipts between shards for scalability
- **Fault Tolerance**: Erlang/OTP supervision ensures high availability

## 📋 Prerequisites

- Erlang/OTP 24+
- Rebar3 build tool
- ARM64 or x86_64 architecture
- Ubuntu 22.04 LTS (recommended for 5G edge deployment)

## 🛠️ Installation & Setup

### 1. Clone and Build

```bash
git clone <repository-url>
cd erl_bridge
rebar3 compile
```

### 2. Start the Application

```bash
# Start Erlang shell with the application
rebar3 shell
```

## 🎯 Quick Start Guide

### Method 1: Using the Demo (Recommended)

```erlang
% Load record definitions for shell access
rr("include/sbft.hrl").

% Start a complete demo with 3 validators
sbft_helper:start_demo().
```

Expected output:
```
Shard consensus started successfully with PID: <0.242.0>
Shard status: #{shard_id => <<"shard_001">>, view => 0, phase => prepare, ...}
Block proposed
Final shard status: #{...}
{ok,<0.242.0>}
```

### Method 2: Manual Setup

```erlang
% Load record definitions
rr("include/sbft.hrl").

% Create validators
ShardId = <<"shard_001">>,
Validator1 = sbft_helper:create_validator(<<"validator_1">>, <<"pubkey_1">>, 1000, ShardId),
Validator2 = sbft_helper:create_validator(<<"validator_2">>, <<"pubkey_2">>, 1500, ShardId),
Validator3 = sbft_helper:create_validator(<<"validator_3">>, <<"pubkey_3">>, 2000, ShardId),

% Create configuration
Config = sbft_helper:create_config([Validator1, Validator2, Validator3], 3000),

% Start shard consensus
{ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),

% Check status
{ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
io:format("Status: ~p~n", [Status]).
```

## 📊 Complete API Reference

### Consensus Manager API

```erlang
% Start shard consensus
{ok, Pid} = sbft_consensus_manager:start_shard_consensus(<<"shard_001">>, Config).

% Get shard status
{ok, Status} = sbft_consensus_manager:get_shard_status(<<"shard_001">>).

% Stop shard consensus
ok = sbft_consensus_manager:stop_shard_consensus(<<"shard_001">>).

% Get all active shards
{ok, Shards} = sbft_consensus_manager:get_all_shards().
```

### Shard Consensus API

```erlang
% Propose a new block
Block = sbft_helper:create_block(<<"block_hash_1">>, 0, <<"validator_1">>,
                                [<<"tx1">>, <<"tx2">>], <<"genesis">>, <<"shard_001">>),
sbft_shard_consensus:propose_block(Pid, Block).

% Submit a vote
Vote = sbft_helper:create_vote(<<"validator_1">>, 0, <<"block_hash_1">>,
                              prepare, <<"shard_001">>, <<"signature">>),
sbft_shard_consensus:submit_vote(Pid, Vote).

% Get consensus status
Status = sbft_shard_consensus:get_status(Pid).

% Add/remove validators
Validator = sbft_helper:create_validator(<<"new_validator">>, <<"pubkey">>, 1000, <<"shard_001">>),
sbft_shard_consensus:add_validator(Pid, Validator),
sbft_shard_consensus:remove_validator(Pid, <<"validator_id">>).
```

### Validator Manager API

```erlang
% Register new validator
ValidatorData = #{
    public_key => <<"validator_public_key">>,
    stake => 1000,
    shard_id => <<"shard_001">>,
    is_active => true
},
sbft_validator_manager:register_validator(<<"validator_4">>, ValidatorData).

% Update validator stake
sbft_validator_manager:update_stake(<<"validator_4">>, 1500).

% Slash validator for misbehavior
sbft_validator_manager:slash_validator(<<"validator_4">>, <<"double_voting">>).

% Get validator information
{ok, Validator} = sbft_validator_manager:get_validator(<<"validator_4">>).

% Get all validators
{ok, AllValidators} = sbft_validator_manager:get_all_validators().
```

### Cross-Shard Communication API

```erlang
% Register shard for cross-shard communication
sbft_cross_shard:register_shard(<<"shard_001">>).

% Send cross-shard receipt
ReceiptData = <<"transaction_data">>,
sbft_cross_shard:send_receipt(<<"shard_001">>, <<"shard_002">>, ReceiptData).

% Get pending receipts for shard
{ok, Receipts} = sbft_cross_shard:get_pending_receipts(<<"shard_002">>).

% Process received receipt (when receipt is received)
[Receipt|_] = Receipts,
sbft_cross_shard:process_receipt(Receipt).
```

### Helper Functions

```erlang
% Create validator record
Validator = sbft_helper:create_validator(<<"id">>, <<"pubkey">>, 1000, <<"shard_001">>).

% Create block record
Block = sbft_helper:create_block(<<"hash">>, 0, <<"proposer">>, [<<"tx1">>], <<"parent">>, <<"shard_001">>).

% Create vote record
Vote = sbft_helper:create_vote(<<"validator">>, 0, <<"block_hash">>, prepare, <<"shard_001">>, <<"sig">>).

% Create configuration
Config = sbft_helper:create_config([Validator1, Validator2], 3000).

% Start complete demo
sbft_helper:start_demo().
```

## 🧪 Testing Examples

### Test Consensus Flow

```erlang
% Start demo
rr("include/sbft.hrl").
{ok, Pid} = sbft_helper:start_demo().

% Check initial status
{ok, Status1} = sbft_consensus_manager:get_shard_status(<<"shard_001">>).
io:format("Initial: ~p~n", [maps:get(phase, Status1)]).

% Propose another block
Block2 = sbft_helper:create_block(<<"block_hash_2">>, 1, <<"validator_2">>,
                                 [<<"tx3">>, <<"tx4">>], <<"block_hash_1">>, <<"shard_001">>),
sbft_shard_consensus:propose_block(Pid, Block2).

% Check status after proposal
timer:sleep(1000),
{ok, Status2} = sbft_consensus_manager:get_shard_status(<<"shard_001">>).
io:format("After proposal: ~p~n", [maps:get(metrics, Status2)]).
```

### Test Validator Management

```erlang
% Register a new validator
ValidatorData = #{
    public_key => <<"new_validator_pubkey">>,
    stake => 2000,
    shard_id => <<"shard_001">>,
    is_active => true
},
ok = sbft_validator_manager:register_validator(<<"validator_new">>, ValidatorData).

% Check all validators
{ok, AllValidators} = sbft_validator_manager:get_all_validators(),
io:format("Total validators: ~p~n", [length(AllValidators)]).

% Update stake
ok = sbft_validator_manager:update_stake(<<"validator_new">>, 2500).

% Verify update
{ok, UpdatedValidator} = sbft_validator_manager:get_validator(<<"validator_new">>),
io:format("Updated stake: ~p~n", [UpdatedValidator#sbft_validator_record.stake]).
```

### Test Cross-Shard Communication

```erlang
% Register multiple shards
sbft_cross_shard:register_shard(<<"shard_001">>),
sbft_cross_shard:register_shard(<<"shard_002">>).

% Send cross-shard receipt
ReceiptData = <<"cross_shard_transaction_data">>,
sbft_cross_shard:send_receipt(<<"shard_001">>, <<"shard_002">>, ReceiptData).

% Check pending receipts
{ok, PendingReceipts} = sbft_cross_shard:get_pending_receipts(<<"shard_002">>),
io:format("Pending receipts: ~p~n", [length(PendingReceipts)]).

% Process the receipt
[FirstReceipt|_] = PendingReceipts,
sbft_cross_shard:process_receipt(FirstReceipt).

% Verify processing
{ok, RemainingReceipts} = sbft_cross_shard:get_pending_receipts(<<"shard_002">>),
io:format("Remaining receipts: ~p~n", [length(RemainingReceipts)]).
```

## 📈 Monitoring & Metrics

```erlang
% Get comprehensive metrics
{ok, Status} = sbft_consensus_manager:get_shard_status(<<"shard_001">>),
Metrics = maps:get(metrics, Status),

% Available metrics:
% - blocks_proposed: Total blocks proposed
% - blocks_committed: Total blocks finalized
% - view_changes: Number of view changes

io:format("Blocks proposed: ~p~n", [maps:get(blocks_proposed, Metrics)]),
io:format("Blocks committed: ~p~n", [maps:get(blocks_committed, Metrics)]),
io:format("View changes: ~p~n", [maps:get(view_changes, Metrics)]).
```

## 🔒 Security Features

- **Byzantine Fault Tolerance**: Tolerates up to 1/3 malicious validators
- **Cryptographic Signatures**: All votes and blocks are cryptographically signed
- **Slashing Protection**: Automatic slashing for equivocation and misbehavior
- **Stake-based Voting**: Voting power proportional to validator stake
- **View Change Protection**: Automatic leader rotation on failures

## 🌐 5G Edge Integration

### Hardware Requirements
- ARM64 SBC (RK3588-class or better)
- 8-16 GB LPDDR4/5 RAM
- 512 GB - 1 TB NVMe SSD
- 5G modem with eSIM support
- TPM 2.0 or secure element

### Network Optimization
- Automatic 5G/Wi-Fi switching for cost optimization
- Data compression for all network frames
- Batch operations during off-peak hours
- Local P2P connectivity prioritization

## 🚨 Troubleshooting

### Common Issues

1. **Record undefined error**:
   ```erlang
   % Always load records first
   rr("include/sbft.hrl").
   ```

2. **Variable unbound error**:
   ```erlang
   % Define variables before using
   ValidatorId = <<"validator_1">>,
   ValidatorData = #{...}.
   ```

3. **Consensus timeout**:
   ```erlang
   % Check if enough validators are active
   {ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
   ValidatorCount = maps:get(validators_count, Status).
   ```

## 🗺️ Next Steps & TODO

Based on your current implementation, here are the recommended next steps:

### Immediate TODOs:

1. **Integration with Rust Core**:
   - Create Erlang ports to communicate with your Rust ego-node and ego-core
   - Implement message passing between Erlang consensus and Rust blockchain state
   - Add serialization/deserialization for cross-language communication

2. **libp2p Go Sidecar Integration**:
   - Implement gRPC/UDS communication between Erlang and Go libp2p sidecar
   - Add network message routing for consensus messages
   - Implement peer discovery and connection management

3. **Post-Quantum Cryptography**:
   - Integrate Rust PQC ports (Kyber/Dilithium) with Erlang consensus
   - Add signature verification for votes and blocks
   - Implement secure key management

### Regarding RabbitMQ/Ra for Multi-Raft:

**No, don't add RabbitMQ/Ra** for the following reasons:

1. **You already have BFT**: BFT consensus is superior to Raft for blockchain applications because it handles Byzantine (malicious) failures, not just crash failures.

2. **Complexity**: Adding Raft on top of BFT would create unnecessary complexity and potential conflicts.

3. **Performance**: Multiple consensus layers would hurt performance.

**Instead, focus on**:
- **Sharding**: Scale horizontally with multiple BFT shards (which you already have)
- **Cross-shard coordination**: Improve your existing cross-shard receipt system
- **Integration**: Connect your Erlang BFT with Rust blockchain core

### Architecture Recommendation:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Rust Core     │◄──►│  Erlang BFT      │◄──►│  Go libp2p      │
│  (ego-node/     │    │  Consensus       │    │  Sidecar        │
│   ego-core)     │    │  (Current)       │    │  (Network)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
   Blockchain State         Consensus Logic           P2P Network
   Transactions             Validator Management      Message Routing
   Account Management       Cross-shard Receipts      Peer Discovery
```

This gives you the best of all worlds: Rust performance for core blockchain operations, Erlang reliability for consensus, and Go efficiency for networking.

---

Built with ❤️ using Erlang/OTP for the decentralized future.
