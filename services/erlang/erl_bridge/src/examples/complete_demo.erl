-module(complete_demo).
-include("../include/sbft.hrl").
-export([run_all_demos/0, basic_consensus_demo/0, validator_management_demo/0,
         cross_shard_demo/0, metrics_demo/0]).

run_all_demos() ->
    io:format("=== Running Complete ERL Bridge BFT Consensus Demos ===~n~n"),

    basic_consensus_demo(),
    timer:sleep(2000),

    validator_management_demo(),
    timer:sleep(2000),

    cross_shard_demo(),
    timer:sleep(2000),

    metrics_demo(),

    io:format("~n=== All demos completed successfully! ===~n").

basic_consensus_demo() ->
    io:format("--- Basic Consensus Demo ---~n"),

    {ok, Pid} = sbft_helper:start_demo(),

    {ok, Status1} = sbft_consensus_manager:get_shard_status(<<"shard_001">>),
    io:format("Initial phase: ~p~n", [maps:get(phase, Status1)]),

    Block2 = sbft_helper:create_block(<<"block_hash_2">>, 1, <<"validator_2">>,
                                     [<<"tx3">>, <<"tx4">>], <<"block_hash_1">>, <<"shard_001">>),
    sbft_shard_consensus:propose_block(Pid, Block2),

    timer:sleep(1000),

    {ok, Status2} = sbft_consensus_manager:get_shard_status(<<"shard_001">>),
    Metrics = maps:get(metrics, Status2),
    io:format("Blocks proposed: ~p, Blocks committed: ~p~n",
              [maps:get(blocks_proposed, Metrics), maps:get(blocks_committed, Metrics)]),

    sbft_consensus_manager:stop_shard_consensus(<<"shard_001">>),
    io:format("Basic consensus demo completed~n~n").

validator_management_demo() ->
    io:format("--- Validator Management Demo ---~n"),

    ValidatorData = #{
        public_key => <<"new_validator_pubkey">>,
        stake => 2000,
        shard_id => <<"shard_001">>,
        is_active => true
    },
    ok = sbft_validator_manager:register_validator(<<"validator_new">>, ValidatorData),
    io:format("Registered new validator~n"),

    {ok, AllValidators} = sbft_validator_manager:get_all_validators(),
    io:format("Total validators: ~p~n", [length(AllValidators)]),

    ok = sbft_validator_manager:update_stake(<<"validator_new">>, 2500),
    io:format("Updated validator stake~n"),

    {ok, UpdatedValidator} = sbft_validator_manager:get_validator(<<"validator_new">>),
    io:format("Updated stake: ~p~n", [UpdatedValidator#sbft_validator_record.stake]),

    ok = sbft_validator_manager:slash_validator(<<"validator_new">>, <<"double_voting">>),
    io:format("Validator slashed for double voting~n"),

    {ok, SlashedValidator} = sbft_validator_manager:get_validator(<<"validator_new">>),
    io:format("Validator active status: ~p~n", [SlashedValidator#sbft_validator_record.is_active]),

    io:format("Validator management demo completed~n~n").

cross_shard_demo() ->
    io:format("--- Cross-Shard Communication Demo ---~n"),

    ok = sbft_cross_shard:register_shard(<<"shard_001">>),
    ok = sbft_cross_shard:register_shard(<<"shard_002">>),
    io:format("Registered shards~n"),

    ReceiptData = <<"cross_shard_transaction_data">>,
    sbft_cross_shard:send_receipt(<<"shard_001">>, <<"shard_002">>, ReceiptData),
    io:format("Sent cross-shard receipt~n"),

    {ok, PendingReceipts} = sbft_cross_shard:get_pending_receipts(<<"shard_002">>),
    io:format("Pending receipts for shard_002: ~p~n", [length(PendingReceipts)]),

    [FirstReceipt|_] = PendingReceipts,
    sbft_cross_shard:process_receipt(FirstReceipt),
    io:format("Processed receipt~n"),

    {ok, RemainingReceipts} = sbft_cross_shard:get_pending_receipts(<<"shard_002">>),
    io:format("Remaining receipts: ~p~n", [length(RemainingReceipts)]),

    io:format("Cross-shard communication demo completed~n~n").

metrics_demo() ->
    io:format("--- Metrics Demo ---~n"),

    ShardId = <<"metrics_shard">>,
    Validator1 = sbft_helper:create_validator(<<"metrics_val_1">>, <<"pubkey_1">>, 1000, ShardId),
    Validator2 = sbft_helper:create_validator(<<"metrics_val_2">>, <<"pubkey_2">>, 1500, ShardId),
    Config = sbft_helper:create_config([Validator1, Validator2], 2000),

    {ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),

    Block1 = sbft_helper:create_block(<<"metrics_block_1">>, 0, <<"metrics_val_1">>,
                                     [<<"tx1">>], <<"genesis">>, ShardId),
    Block2 = sbft_helper:create_block(<<"metrics_block_2">>, 1, <<"metrics_val_2">>,
                                     [<<"tx2">>], <<"metrics_block_1">>, ShardId),

    sbft_shard_consensus:propose_block(Pid, Block1),
    timer:sleep(500),
    sbft_shard_consensus:propose_block(Pid, Block2),
    timer:sleep(500),

    {ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
    Metrics = maps:get(metrics, Status),

    io:format("=== Consensus Metrics ===~n"),
    io:format("Shard ID: ~p~n", [maps:get(shard_id, Status)]),
    io:format("Current View: ~p~n", [maps:get(view, Status)]),
    io:format("Current Phase: ~p~n", [maps:get(phase, Status)]),
    io:format("Total Stake: ~p~n", [maps:get(total_stake, Status)]),
    io:format("Validators Count: ~p~n", [maps:get(validators_count, Status)]),
    io:format("Last Finalized View: ~p~n", [maps:get(last_finalized_view, Status)]),
    io:format("Blocks Proposed: ~p~n", [maps:get(blocks_proposed, Metrics)]),
    io:format("Blocks Committed: ~p~n", [maps:get(blocks_committed, Metrics)]),
    io:format("View Changes: ~p~n", [maps:get(view_changes, Metrics)]),

    sbft_consensus_manager:stop_shard_consensus(ShardId),
    io:format("Metrics demo completed~n~n").
