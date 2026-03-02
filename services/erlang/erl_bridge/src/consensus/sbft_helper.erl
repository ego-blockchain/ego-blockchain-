-module(sbft_helper).

-include("../include/sbft.hrl").

-export([
    create_validator/4,
    create_validator/5,
    create_validator_with_pqc/5,
    create_block/6,
    create_block/7,
    create_vote/6,
    create_vote_pqc/7,
    create_config/2,
    create_config/3,
    create_cross_shard_receipt/4,
    create_poc_report/7,
    create_drs_event/4,
    generate_pqc_validator/4,
    start_demo/0,
    run_basic_demo/0,
    run_multi_shard_demo/0,
    run_pqc_demo/0,
    run_cross_shard_demo/0,
    run_slashing_demo/0,
    run_drs_demo/0,
    run_full_demo/0,
    wait_for_finality/2,
    wait_for_finality/3,
    assert_phase/2,
    assert_metric/3,
    print_shard_status/1,
    print_validator_stats/1,
    print_global_status/0
]).

-define(DEMO_CONSENSUS_TIMEOUT,     2000).
-define(DEMO_VIEW_CHANGE_TIMEOUT,   4000).
-define(DEMO_FINALITY_POLL_MS,      200).
-define(DEMO_FINALITY_MAX_WAIT_MS,  10000).

create_validator(Id, PublicKey, Stake, ShardId) ->
    create_validator(Id, PublicKey, Stake, ShardId, ed25519).

create_validator(Id, PublicKey, Stake, ShardId, SigAlgorithm) ->
    #sbft_validator_record{
        id                = Id,
        public_key        = PublicKey,
        pqc_public_key    = undefined,
        kem_public_key    = undefined,
        sig_algorithm     = SigAlgorithm,
        stake             = Stake,
        is_active         = true,
        shard_id          = ShardId,
        role              = replica,
        capability        = legacy,
        reputation        = 1.0,
        performance_score = 1.0,
        last_seen         = erlang:system_time(millisecond),
        last_vote_view    = undefined,
        slashing_events   = 0
    }.

create_validator_with_pqc(Id, Stake, ShardId, PQCPublicKey, KEMPublicKey) ->
    SigAlgo = case byte_size(PQCPublicKey) of
        ?MLKEM768_PK_SIZE -> dilithium2;
        _                 -> hybrid
    end,
    Capability = case SigAlgo of
        dilithium2 -> pqc_primary;
        hybrid     -> pqc_hybrid;
        _          -> legacy
    end,
    #sbft_validator_record{
        id                = Id,
        public_key        = sbft_crypto:hash(blake2s, PQCPublicKey),
        pqc_public_key    = PQCPublicKey,
        kem_public_key    = KEMPublicKey,
        sig_algorithm     = SigAlgo,
        stake             = Stake,
        is_active         = true,
        shard_id          = ShardId,
        role              = replica,
        capability        = Capability,
        reputation        = 1.0,
        performance_score = 1.0,
        last_seen         = erlang:system_time(millisecond),
        last_vote_view    = undefined,
        slashing_events   = 0
    }.

generate_pqc_validator(Id, Stake, ShardId, Algorithm) ->
    case sbft_nif:dilithium2_keypair() of
        {ok, PK, _SK} ->
            case sbft_nif:mlkem768_keypair() of
                {ok, KemPK, _KemSK} ->
                    Validator = create_validator_with_pqc(Id, Stake, ShardId, PK, KemPK),
                    {ok, Validator#sbft_validator_record{sig_algorithm = Algorithm}};
                {error, Reason} ->
                    {error, {kem_keypair_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {sig_keypair_failed, Reason}}
    end.

create_block(Hash, View, Proposer, Transactions, ParentHash, ShardId) ->
    create_block(Hash, View, Proposer, Transactions, ParentHash, ShardId, #{}).

create_block(Hash, View, Proposer, Transactions, ParentHash, ShardId, Opts) ->
    TxRoot     = compute_tx_root(Transactions),
    SizeBytes  = compute_block_size(Transactions),
    Height     = maps:get(height, Opts, 0),
    Receipts   = maps:get(cross_shard_receipts, Opts, []),
    Payload    = sbft_crypto:hash(blake2s, term_to_binary({
        Hash, View, Proposer, ParentHash, ShardId, TxRoot
    })),
    #sbft_block_record{
        hash                 = Hash,
        view                 = View,
        height               = Height,
        proposer             = Proposer,
        transactions         = Transactions,
        parent_hash          = ParentHash,
        timestamp            = erlang:system_time(millisecond),
        signature            = Payload,
        pqc_signature        = undefined,
        shard_id             = ShardId,
        cross_shard_receipts = Receipts,
        state_root           = sbft_crypto:hash(blake2s, Payload),
        receipt_root         = compute_receipt_root(Receipts),
        tx_root              = TxRoot,
        gas_used             = maps:get(gas_used, Opts, 0),
        size_bytes           = SizeBytes,
        erasure_coded        = maps:get(erasure_coded, Opts, false)
    }.

create_vote(ValidatorId, View, BlockHash, VoteType, ShardId, Signature) ->
    #sbft_vote_record{
        validator_id  = ValidatorId,
        view          = View,
        block_hash    = BlockHash,
        vote_type     = VoteType,
        signature     = Signature,
        pqc_signature = undefined,
        timestamp     = erlang:system_time(millisecond),
        shard_id      = ShardId,
        justified_view = undefined
    }.

create_vote_pqc(ValidatorId, View, BlockHash, VoteType, ShardId, Signature, PQCSig) ->
    Vote = create_vote(ValidatorId, View, BlockHash, VoteType, ShardId, Signature),
    Vote#sbft_vote_record{pqc_signature = PQCSig}.

create_config(Validators, Timeout) ->
    create_config(Validators, Timeout, #{}).

create_config(Validators, Timeout, Opts) ->
    #{
        validators          => Validators,
        consensus_timeout   => Timeout,
        view_change_timeout => maps:get(view_change_timeout, Opts, Timeout * 2),
        pqc_enabled         => maps:get(pqc_enabled, Opts, true),
        sig_algorithm       => maps:get(sig_algorithm, Opts, dilithium2)
    }.

create_cross_shard_receipt(FromShard, ToShard, TxData, Opts) ->
    Now       = erlang:system_time(millisecond),
    TxHash    = sbft_crypto:hash(blake2s, TxData),
    ReceiptId = sbft_crypto:hash(blake2s, <<TxHash/binary,
                                             FromShard/binary,
                                             ToShard/binary,
                                             Now:64/big>>),
    #cross_shard_receipt{
        receipt_id       = ReceiptId,
        from_shard       = FromShard,
        to_shard         = ToShard,
        transaction_hash = TxHash,
        receipt_data     = TxData,
        merkle_proof     = undefined,
        merkle_root      = undefined,
        status           = pending,
        timestamp        = Now,
        expiry_timestamp = maps:get(expiry_ms, Opts, Now + ?RECEIPT_EXPIRY_MS),
        retry_count      = 0,
        signature        = undefined,
        pqc_signature    = undefined
    }.

create_poc_report(NodeId, ShardId, RSRP, RSRQ, SINR, TimingAdvance, GPS) ->
    {Lat, Lon} = GPS,
    H3Index    = compute_h3_index(Lat, Lon),
    Geohash    = compute_geohash(Lat, Lon),
    Payload    = sbft_crypto:hash(blake2s, term_to_binary({
        NodeId, ShardId, RSRP, RSRQ, SINR, TimingAdvance, Lat, Lon
    })),
    #poc_report{
        node_id        = NodeId,
        shard_id       = ShardId,
        rsrp           = RSRP,
        rsrq           = RSRQ,
        sinr           = SINR,
        timing_advance = TimingAdvance,
        gps_lat        = Lat,
        gps_lon        = Lon,
        h3_index       = H3Index,
        geohash        = Geohash,
        timestamp      = erlang:system_time(millisecond),
        signature      = Payload,
        pqc_signature  = undefined
    }.

create_drs_event(NodeId, ShardId, RawScore, Epoch) ->
    Multiplier = clamp_drs_multiplier(RawScore),
    #drs_score_event{
        node_id            = NodeId,
        shard_id           = ShardId,
        raw_score          = RawScore,
        bounded_multiplier = Multiplier,
        epoch              = Epoch,
        component_scores   = #{
            poc_score      => RawScore * 0.4,
            uptime_score   => RawScore * 0.3,
            latency_score  => RawScore * 0.3
        },
        emitted_at         = erlang:system_time(millisecond)
    }.

clamp_drs_multiplier(RawScore) ->
    Normalized = max(0.0, min(1.0, RawScore)),
    ?DRS_MIN_MULTIPLIER + (Normalized * (?DRS_MAX_MULTIPLIER - ?DRS_MIN_MULTIPLIER)).

start_demo() ->
    run_basic_demo().

run_full_demo() ->
    io:format("~n=== ERL Bridge BFT Consensus Full Demo ===~n~n"),
    run_basic_demo(),
    timer:sleep(1000),
    run_pqc_demo(),
    timer:sleep(1000),
    run_multi_shard_demo(),
    timer:sleep(1000),
    run_cross_shard_demo(),
    timer:sleep(1000),
    run_slashing_demo(),
    timer:sleep(1000),
    run_drs_demo(),
    io:format("~n=== Full Demo Completed ===~n"),
    ok.

run_basic_demo() ->
    io:format("--- Basic Single-Shard Consensus Demo ---~n"),
    ShardId    = <<"demo_shard_001">>,
    Validator1 = create_validator(<<"val_1">>, <<"pk_1">>, 1000, ShardId),
    Validator2 = create_validator(<<"val_2">>, <<"pk_2">>, 1500, ShardId),
    Validator3 = create_validator(<<"val_3">>, <<"pk_3">>, 2000, ShardId),
    Validator4 = create_validator(<<"val_4">>, <<"pk_4">>, 1200, ShardId),
    Config     = create_config(
        [Validator1, Validator2, Validator3, Validator4],
        ?DEMO_CONSENSUS_TIMEOUT
    ),
    {ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    io:format("Shard started: ~p~n", [Pid]),
    Block1 = create_block(<<"hash_1">>, 0, <<"val_1">>,
                          [<<"tx_a">>, <<"tx_b">>], <<"genesis">>, ShardId),
    sbft_shard_consensus:propose_block(Pid, Block1),
    io:format("Block 1 proposed~n"),
    case wait_for_finality(ShardId, 0) of
        {ok, finalized} ->
            io:format("Block 1 finalized~n");
        {error, timeout} ->
            io:format("Block 1 finality timeout (expected in basic demo)~n")
    end,
    print_shard_status(ShardId),
    sbft_consensus_manager:stop_shard_consensus(ShardId),
    io:format("Basic demo completed~n~n"),
    ok.

run_pqc_demo() ->
    io:format("--- PQC Key Generation and Signing Demo ---~n"),
    Caps = sbft_nif:capabilities(),
    io:format("NIF capabilities: ~p~n", [Caps]),
    case sbft_nif:dilithium2_keypair() of
        {ok, PK, SK} ->
            io:format("Dilithium2 keypair generated: PK=~p bytes, SK=~p bytes~n",
                      [byte_size(PK), byte_size(SK)]),
            Payload = <<"test consensus message">>,
            case sbft_nif:dilithium2_sign(SK, Payload) of
                {ok, Sig} ->
                    io:format("Dilithium2 signature: ~p bytes~n", [byte_size(Sig)]),
                    {ok, Valid} = sbft_nif:dilithium2_verify(PK, Payload, Sig),
                    io:format("Signature valid: ~p~n", [Valid]);
                {error, R} ->
                    io:format("Sign error: ~p~n", [R])
            end;
        {error, Reason} ->
            io:format("Dilithium2 keypair error: ~p~n", [Reason])
    end,
    case sbft_nif:mlkem768_keypair() of
        {ok, KemPK, KemSK} ->
            io:format("ML-KEM-768 keypair: PK=~p bytes, SK=~p bytes~n",
                      [byte_size(KemPK), byte_size(KemSK)]),
            {ok, CT, SS1} = sbft_nif:mlkem768_encapsulate(KemPK),
            io:format("Encapsulated: CT=~p bytes, SS=~p bytes~n",
                      [byte_size(CT), byte_size(SS1)]),
            {ok, SS2} = sbft_nif:mlkem768_decapsulate(KemSK, CT),
            Match = sbft_crypto:constant_time_compare(SS1, SS2),
            io:format("Shared secret match: ~p~n", [Match]);
        {error, R2} ->
            io:format("ML-KEM-768 keypair error: ~p~n", [R2])
    end,
    HashResult = sbft_crypto:hash(blake2s, <<"ego blockchain test">>),
    io:format("BLAKE2s hash: ~p bytes~n", [byte_size(HashResult)]),
    io:format("PQC demo completed~n~n"),
    ok.

run_multi_shard_demo() ->
    io:format("--- Multi-Shard Demo ---~n"),
    Shards = [<<"shard_A">>, <<"shard_B">>, <<"shard_C">>],
    Pids   = lists:map(fun(ShardId) ->
        Validators = [
            create_validator(<<ShardId/binary, "_v1">>, <<"pk1">>, 1000, ShardId),
            create_validator(<<ShardId/binary, "_v2">>, <<"pk2">>, 1500, ShardId),
            create_validator(<<ShardId/binary, "_v3">>, <<"pk3">>, 2000, ShardId),
            create_validator(<<ShardId/binary, "_v4">>, <<"pk4">>, 1000, ShardId)
        ],
        Config = create_config(Validators, ?DEMO_CONSENSUS_TIMEOUT),
        {ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
        io:format("Shard ~p started: ~p~n", [ShardId, Pid]),
        {ShardId, Pid}
    end, Shards),
    timer:sleep(500),
    lists:foreach(fun({ShardId, Pid}) ->
        Block = create_block(
            sbft_crypto:hash(blake2s, ShardId),
            0,
            <<ShardId/binary, "_v1">>,
            [<<"tx1">>, <<"tx2">>],
            <<"genesis">>,
            ShardId
        ),
        sbft_shard_consensus:propose_block(Pid, Block),
        io:format("Block proposed to shard ~p~n", [ShardId])
    end, Pids),
    timer:sleep(1000),
    {ok, Finality} = sbft_consensus_manager:get_global_finality(),
    io:format("Global finality state: ~p~n", [Finality]),
    lists:foreach(fun({ShardId, _Pid}) ->
        sbft_consensus_manager:stop_shard_consensus(ShardId)
    end, Pids),
    io:format("Multi-shard demo completed~n~n"),
    ok.

run_cross_shard_demo() ->
    io:format("--- Cross-Shard Receipt with Merkle Proof Demo ---~n"),
    ShardA = <<"xshard_A">>,
    ShardB = <<"xshard_B">>,
    ok = sbft_cross_shard:register_shard(ShardA),
    ok = sbft_cross_shard:register_shard(ShardB),
    io:format("Shards registered~n"),
    TxData1 = <<"cross_shard_transfer_1000_tokens">>,
    TxData2 = <<"cross_shard_message_hello">>,
    TxData3 = <<"cross_shard_state_update">>,
    sbft_cross_shard:send_receipt(ShardA, ShardB, TxData1, #{}),
    sbft_cross_shard:send_receipt(ShardA, ShardB, TxData2, #{}),
    sbft_cross_shard:send_receipt(ShardA, ShardB, TxData3, #{}),
    timer:sleep(200),
    io:format("3 receipts sent from ~p to ~p~n", [ShardA, ShardB]),
    {ok, Root, Proofs} = sbft_cross_shard:build_receipt_tree(ShardB),
    io:format("Merkle root: ~p~n", [Root]),
    io:format("Merkle proofs generated: ~p~n", [length(Proofs)]),
    {ok, Pending} = sbft_cross_shard:get_pending_receipts(ShardB),
    io:format("Pending receipts: ~p~n", [length(Pending)]),
    case Pending of
        [First | _] ->
            Result = sbft_cross_shard:verify_receipt(First),
            io:format("First receipt verification: ~p~n", [Result]),
            sbft_cross_shard:process_receipt(First);
        [] ->
            ok
    end,
    timer:sleep(200),
    {ok, Remaining} = sbft_cross_shard:get_pending_receipts(ShardB),
    io:format("Remaining pending after processing: ~p~n", [length(Remaining)]),
    {ok, Metrics} = sbft_cross_shard:get_metrics(),
    io:format("Cross-shard metrics: ~p~n", [Metrics]),
    io:format("Cross-shard demo completed~n~n"),
    ok.

run_slashing_demo() ->
    io:format("--- Slashing Pipeline Demo ---~n"),
    ValidatorId = <<"slashing_demo_validator">>,
    ValidatorData = #{
        public_key => <<"demo_pk">>,
        stake      => 5000,
        shard_id   => <<"slash_shard">>,
        is_active  => true
    },
    ok = sbft_validator_manager:register_validator(ValidatorId, ValidatorData),
    io:format("Validator registered with stake 5000~n"),
    Vote1 = create_vote(ValidatorId, 5, <<"hash_A">>, prepare, <<"slash_shard">>, <<"sig1">>),
    Vote2 = create_vote(ValidatorId, 5, <<"hash_B">>, prepare, <<"slash_shard">>, <<"sig2">>),
    sbft_slashing:report_double_vote(ValidatorId, Vote1, Vote2),
    timer:sleep(200),
    {ok, Validator} = sbft_validator_manager:get_validator(ValidatorId),
    io:format("Validator active after double vote report: ~p~n",
              [Validator#sbft_validator_record.is_active]),
    io:format("Slashing events: ~p~n",
              [Validator#sbft_validator_record.slashing_events]),
    {ok, History} = sbft_slashing:get_slashing_history(ValidatorId),
    io:format("Slashing history entries: ~p~n", [length(History)]),
    {ok, Metrics} = sbft_validator_manager:get_metrics(),
    io:format("Validator manager metrics: ~p~n", [Metrics]),
    io:format("Slashing demo completed~n~n"),
    ok.

run_drs_demo() ->
    io:format("--- DRS Score and PoC Report Demo ---~n"),
    NodeId  = <<"drs_demo_node">>,
    ShardId = <<"drs_shard">>,
    ValidatorData = #{
        public_key => <<"drs_pk">>,
        stake      => 3000,
        shard_id   => ShardId,
        is_active  => true
    },
    ok = sbft_validator_manager:register_validator(NodeId, ValidatorData),
    PoCReport = create_poc_report(
        NodeId, ShardId,
        -85.5, -12.3, 18.7, 4,
        {37.7749, -122.4194}
    ),
    io:format("PoC report created: RSRP=~p RSRQ=~p SINR=~p~n",
              [PoCReport#poc_report.rsrp,
               PoCReport#poc_report.rsrq,
               PoCReport#poc_report.sinr]),
    sbft_event_bus:publish(poc_report_received, #{
        node_id        => PoCReport#poc_report.node_id,
        shard_id       => PoCReport#poc_report.shard_id,
        rsrp           => PoCReport#poc_report.rsrp,
        rsrq           => PoCReport#poc_report.rsrq,
        sinr           => PoCReport#poc_report.sinr,
        timing_advance => PoCReport#poc_report.timing_advance,
        h3_index       => PoCReport#poc_report.h3_index
    }),
    Scores = [0.3, 0.55, 0.72, 0.88, 0.91],
    lists:foldl(fun(Score, Epoch) ->
        DRSEvent = create_drs_event(NodeId, ShardId, Score, Epoch),
        sbft_validator_manager:apply_drs_score(NodeId, DRSEvent),
        io:format("Epoch ~p DRS score: ~.3f multiplier: ~.3f~n",
                  [Epoch, Score, DRSEvent#drs_score_event.bounded_multiplier]),
        Epoch + 1
    end, 1, Scores),
    timer:sleep(200),
    {ok, Multiplier} = sbft_validator_manager:get_drs_score(NodeId),
    io:format("Final DRS multiplier: ~.3f~n", [Multiplier]),
    {ok, EpochStats} = sbft_validator_manager:get_epoch_stats(),
    io:format("Epoch stats: ~p~n", [EpochStats]),
    io:format("DRS demo completed~n~n"),
    ok.

wait_for_finality(ShardId, TargetView) ->
    wait_for_finality(ShardId, TargetView, ?DEMO_FINALITY_MAX_WAIT_MS).

wait_for_finality(ShardId, TargetView, MaxWaitMs) ->
    Deadline = erlang:system_time(millisecond) + MaxWaitMs,
    wait_for_finality_loop(ShardId, TargetView, Deadline).

wait_for_finality_loop(ShardId, TargetView, Deadline) ->
    Now = erlang:system_time(millisecond),
    case Now > Deadline of
        true ->
            {error, timeout};
        false ->
            case sbft_consensus_manager:get_shard_status(ShardId) of
                {ok, Status} ->
                    LastFinalized = maps:get(last_finalized_view, Status, -1),
                    case LastFinalized >= TargetView of
                        true  -> {ok, finalized};
                        false ->
                            timer:sleep(?DEMO_FINALITY_POLL_MS),
                            wait_for_finality_loop(ShardId, TargetView, Deadline)
                    end;
                {error, _} ->
                    timer:sleep(?DEMO_FINALITY_POLL_MS),
                    wait_for_finality_loop(ShardId, TargetView, Deadline)
            end
    end.

assert_phase(ShardId, ExpectedPhase) ->
    {ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
    ActualPhase  = maps:get(phase, Status),
    case ActualPhase =:= ExpectedPhase of
        true  ->
            ok;
        false ->
            error({phase_mismatch, #{
                expected => ExpectedPhase,
                actual   => ActualPhase,
                shard    => ShardId
            }})
    end.

assert_metric(ShardId, MetricKey, ExpectedValue) ->
    {ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
    Metrics      = maps:get(metrics, Status, #{}),
    ActualValue  = maps:get(MetricKey, Metrics, undefined),
    case ActualValue =:= ExpectedValue of
        true  ->
            ok;
        false ->
            error({metric_mismatch, #{
                key      => MetricKey,
                expected => ExpectedValue,
                actual   => ActualValue,
                shard    => ShardId
            }})
    end.

print_shard_status(ShardId) ->
    case sbft_consensus_manager:get_shard_status(ShardId) of
        {ok, Status} ->
            io:format("~n--- Shard Status: ~p ---~n", [ShardId]),
            io:format("  View:              ~p~n", [maps:get(view, Status)]),
            io:format("  Height:            ~p~n", [maps:get(height, Status)]),
            io:format("  Phase:             ~p~n", [maps:get(phase, Status)]),
            io:format("  Leader:            ~p~n", [maps:get(current_leader, Status)]),
            io:format("  Validators:        ~p~n", [maps:get(validators_count, Status)]),
            io:format("  Total Stake:       ~p~n", [maps:get(total_stake, Status)]),
            io:format("  Last Finalized:    ~p~n", [maps:get(last_finalized_view, Status)]),
            io:format("  Locked View:       ~p~n", [maps:get(locked_view, Status)]),
            io:format("  High QC View:      ~p~n", [maps:get(high_qc_view, Status)]),
            io:format("  PQC Enabled:       ~p~n", [maps:get(pqc_enabled, Status)]),
            Metrics = maps:get(metrics, Status, #{}),
            io:format("  Blocks Proposed:   ~p~n", [maps:get(blocks_proposed, Metrics, 0)]),
            io:format("  Blocks Committed:  ~p~n", [maps:get(blocks_committed, Metrics, 0)]),
            io:format("  View Changes:      ~p~n", [maps:get(view_changes, Metrics, 0)]),
            io:format("  Equivocations:     ~p~n",
                      [maps:get(equivocations_detected, Metrics, 0)]);
        {error, Reason} ->
            io:format("Shard ~p status error: ~p~n", [ShardId, Reason])
    end.

print_validator_stats(ValidatorId) ->
    case sbft_validator_manager:get_validator(ValidatorId) of
        {ok, V} ->
            io:format("~n--- Validator: ~p ---~n", [ValidatorId]),
            io:format("  Shard:          ~p~n", [V#sbft_validator_record.shard_id]),
            io:format("  Stake:          ~p~n", [V#sbft_validator_record.stake]),
            io:format("  Active:         ~p~n", [V#sbft_validator_record.is_active]),
            io:format("  Capability:     ~p~n", [V#sbft_validator_record.capability]),
            io:format("  Sig Algorithm:  ~p~n", [V#sbft_validator_record.sig_algorithm]),
            io:format("  Reputation:     ~.4f~n", [V#sbft_validator_record.reputation]),
            io:format("  Performance:    ~.4f~n", [V#sbft_validator_record.performance_score]),
            io:format("  Slash Events:   ~p~n", [V#sbft_validator_record.slashing_events]),
            case sbft_validator_manager:get_drs_score(ValidatorId) of
                {ok, Multiplier} ->
                    io:format("  DRS Multiplier: ~.4f~n", [Multiplier]);
                _ ->
                    ok
            end;
        {error, Reason} ->
            io:format("Validator ~p error: ~p~n", [ValidatorId, Reason])
    end.

print_global_status() ->
    io:format("~n=== Global Consensus Status ===~n"),
    {ok, ActiveShards} = sbft_consensus_manager:get_active_shards(),
    io:format("Active shards: ~p~n", [length(ActiveShards)]),
    {ok, Finality}     = sbft_consensus_manager:get_global_finality(),
    io:format("Global finality: ~p~n", [Finality]),
    {ok, AllValidators} = sbft_validator_manager:get_all_validators(),
    Active = lists:filter(fun(V) -> V#sbft_validator_record.is_active end, AllValidators),
    io:format("Total validators: ~p  Active: ~p~n",
              [length(AllValidators), length(Active)]),
    {ok, TotalStake} = sbft_validator_manager:get_total_stake(),
    io:format("Total stake:      ~p~n", [TotalStake]),
    {ok, BusMetrics} = sbft_event_bus:get_metrics(),
    io:format("Events published: ~p  Delivered: ~p  FFI forwarded: ~p~n",
              [maps:get(published_total, BusMetrics, 0),
               maps:get(delivered_total, BusMetrics, 0),
               maps:get(ffi_forwarded, BusMetrics, 0)]),
    {ok, SlashHistory} = sbft_slashing:get_slashing_history(),
    io:format("Slashing events:  ~p~n", [length(SlashHistory)]),
    io:format("================================~n").

compute_tx_root([]) ->
    sbft_crypto:hash(blake2s, <<>>);
compute_tx_root(Transactions) ->
    Leaves = lists:map(fun(Tx) -> sbft_crypto:hash(blake2s, Tx) end, Transactions),
    sbft_crypto:hash(blake2s, list_to_binary(Leaves)).

compute_receipt_root([]) ->
    undefined;
compute_receipt_root(Receipts) ->
    Leaves = lists:map(fun(R) ->
        sbft_crypto:hash(blake2s, R#cross_shard_receipt.transaction_hash)
    end, Receipts),
    sbft_crypto:hash(blake2s, list_to_binary(Leaves)).

compute_block_size(Transactions) ->
    lists:foldl(fun(Tx, Acc) -> Acc + byte_size(Tx) end, 0, Transactions).

compute_h3_index(Lat, Lon) ->
    Raw = sbft_crypto:hash(blake2s, term_to_binary({h3, Lat, Lon})),
    <<"h3:", (binary:part(Raw, 0, 8))/binary>>.

compute_geohash(Lat, Lon) ->
    Raw = sbft_crypto:hash(blake2s, term_to_binary({geohash, Lat, Lon})),
    <<"gh:", (binary:part(Raw, 0, 6))/binary>>.
