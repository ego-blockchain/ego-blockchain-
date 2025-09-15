# ERL Bridge - Test Commands Reference

This file contains all the commands you can copy-paste to test the BFT consensus system.

## Quick Start Commands

### Load Records and Start Demo
```erlang
% Load record definitions (ALWAYS run this first)
rr("include/sbft.hrl").

% Start complete demo with 3 validators
sbft_helper:start_demo().
```

### Run All Demonstration Examples
```erlang
% Load records first
rr("include/sbft.hrl").

% Run comprehensive demos
complete_demo:run_all_demos().
```

## Manual Testing Commands

### Basic Consensus Setup
```erlang
% Load records
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

### Block Proposal and Voting
```erlang
% Propose a block
Block = sbft_helper:create_block(<<"block_hash_1">>, 0, <<"validator_1">>,
                                [<<"tx1">>, <<"tx2">>], <<"genesis">>, ShardId),
sbft_shard_consensus:propose_block(Pid, Block),

% Submit votes
Vote1 = sbft_helper:create_vote(<<"validator_1">>, 0, <<"block_hash_1">>,
                               prepare, ShardId, <<"signature1">>),
Vote2 = sbft_helper:create_vote(<<"validator_2">>, 0, <<"block_hash_1">>,
                               prepare, ShardId, <<"signature2">>),
sbft_shard_consensus:submit_vote(Pid, Vote1),
sbft_shard_consensus:submit_vote(Pid, Vote2),

% Check status after voting
timer:sleep(1000),
{ok, NewStatus} = sbft_consensus_manager:get_shard_status(ShardId),
io:format("After voting: ~p~n", [maps:get(phase, NewStatus)]).
```

### Validator Management
```erlang
% Register new validator
ValidatorData = #{
    public_key => <<"validator_public_key">>,
    stake => 1000,
    shard_id => <<"shard_001">>,
    is_active => true
},
sbft_validator_manager:register_validator(<<"validator_4">>, ValidatorData),

% Update stake
sbft_validator_manager:update_stake(<<"validator_4">>, 1500),

% Get validator info
{ok, Validator} = sbft_validator_manager:get_validator(<<"validator_4">>),
io:format("Validator: ~p~n", [Validator]),

% Get all validators
{ok, AllValidators} = sbft_validator_manager:get_all_validators(),
io:format("Total validators: ~p~n", [length(AllValidators)]),

% Slash validator
sbft_validator_manager:slash_validator(<<"validator_4">>, <<"double_voting">>).
```

### Cross-Shard Communication
```erlang
% Register shards
sbft_cross_shard:register_shard(<<"shard_001">>),
sbft_cross_shard:register_shard(<<"shard_002">>),

% Send cross-shard receipt
ReceiptData = <<"transaction_data_123">>,
sbft_cross_shard:send_receipt(<<"shard_001">>, <<"shard_002">>, ReceiptData),

% Check pending receipts
{ok, Receipts} = sbft_cross_shard:get_pending_receipts(<<"shard_002">>),
io:format("Pending receipts: ~p~n", [length(Receipts)]),

% Process receipt
[Receipt|_] = Receipts,
sbft_cross_shard:process_receipt(Receipt),

% Verify processing
{ok, RemainingReceipts} = sbft_cross_shard:get_pending_receipts(<<"shard_002">>),
io:format("Remaining: ~p~n", [length(RemainingReceipts)]).
```

### Metrics and Monitoring
```erlang
% Get detailed metrics
{ok, Status} = sbft_consensus_manager:get_shard_status(<<"shard_001">>),
Metrics = maps:get(metrics, Status),

% Display all metrics
io:format("=== Consensus Metrics ===~n"),
io:format("Shard ID: ~p~n", [maps:get(shard_id, Status)]),
io:format("Current View: ~p~n", [maps:get(view, Status)]),
io:format("Current Phase: ~p~n", [maps:get(phase, Status)]),
io:format("Total Stake: ~p~n", [maps:get(total_stake, Status)]),
io:format("Validators: ~p~n", [maps:get(validators_count, Status)]),
io:format("Blocks Proposed: ~p~n", [maps:get(blocks_proposed, Metrics)]),
io:format("Blocks Committed: ~p~n", [maps:get(blocks_committed, Metrics)]),
io:format("View Changes: ~p~n", [maps:get(view_changes, Metrics)]).
```

### Cleanup Commands
```erlang
% Stop shard consensus
sbft_consensus_manager:stop_shard_consensus(<<"shard_001">>),

% Check all shards
{ok, Shards} = sbft_consensus_manager:get_all_shards(),
io:format("Active shards: ~p~n", [Shards]).
```

## Testing Scenarios

### Scenario 1: Normal Consensus Flow
```erlang
rr("include/sbft.hrl").
{ok, Pid} = sbft_helper:start_demo().
% Observe the consensus working normally
```

### Scenario 2: Multiple Block Proposals
```erlang
rr("include/sbft.hrl").
{ok, Pid} = sbft_helper:start_demo().
Block2 = sbft_helper:create_block(<<"block_2">>, 1, <<"validator_2">>, [<<"tx3">>], <<"block_hash_1">>, <<"shard_001">>).
sbft_shard_consensus:propose_block(Pid, Block2).
timer:sleep(1000).
{ok, Status} = sbft_consensus_manager:get_shard_status(<<"shard_001">>).
io:format("Metrics: ~p~n", [maps:get(metrics, Status)]).
```

### Scenario 3: Validator Lifecycle
```erlang
rr("include/sbft.hrl").
ValidatorData = #{public_key => <<"test_key">>, stake => 2000, shard_id => <<"shard_001">>, is_active => true}.
sbft_validator_manager:register_validator(<<"test_validator">>, ValidatorData).
sbft_validator_manager:update_stake(<<"test_validator">>, 3000).
{ok, Validator} = sbft_validator_manager:get_validator(<<"test_validator">>).
io:format("Stake: ~p~n", [Validator#sbft_validator_record.stake]).
sbft_validator_manager:slash_validator(<<"test_validator">>, <<"misbehavior">>).
```

### Scenario 4: Cross-Shard Operations
```erlang
rr("include/sbft.hrl").
sbft_cross_shard:register_shard(<<"shard_A">>).
sbft_cross_shard:register_shard(<<"shard_B">>).
sbft_cross_shard:send_receipt(<<"shard_A">>, <<"shard_B">>, <<"data_123">>).
{ok, Receipts} = sbft_cross_shard:get_pending_receipts(<<"shard_B">>).
[Receipt|_] = Receipts.
sbft_cross_shard:process_receipt(Receipt).
```

## Troubleshooting Commands

### Check System Status
```erlang
% Check if all processes are running
whereis(sbft_consensus_manager).
whereis(sbft_cross_shard).
whereis(sbft_validator_manager).

% Check ETS tables
ets:info(validators_table).
```

### Debug Information
```erlang
% Get process info
process_info(whereis(sbft_consensus_manager)).

% Check active shards
{ok, Shards} = sbft_consensus_manager:get_all_shards().
io:format("Active shards: ~p~n", [Shards]).
```

Remember to always run `rr("include/sbft.hrl").` first to load record definitions!
