-module(sbft_validator_manager).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([
    start_link/0,
    register_validator/2,
    deregister_validator/1,
    get_validator/1,
    get_all_validators/0,
    get_active_validators/0,
    get_validators_for_shard/1,
    get_active_validators_for_shard/1,
    update_stake/2,
    slash_validator/2,
    reactivate_validator/1,
    update_last_seen/1,
    update_last_vote_view/2,
    record_block_proposed/1,
    record_block_committed/1,
    record_vote_cast/1,
    record_missed_vote/1,
    update_capability/2,
    update_pqc_keys/3,
    apply_drs_score/2,
    get_drs_score/1,
    rotate_epoch/1,
    get_epoch_stats/0,
    get_total_stake/0,
    get_total_stake_for_shard/1,
    is_active/1,
    check_capability/2,
    get_metrics/0
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(SERVER,                     ?MODULE).
-define(VALIDATORS_TABLE,           sbft_validators_table).
-define(PERFORMANCE_TABLE,          sbft_performance_table).
-define(DRS_TABLE,                  sbft_drs_table).
-define(REPUTATION_DECAY_FACTOR,    0.95).
-define(REPUTATION_VOTE_REWARD,     0.01).
-define(REPUTATION_MISS_PENALTY,    0.05).
-define(REPUTATION_BLOCK_REWARD,    0.02).
-define(MIN_REPUTATION,             0.0).
-define(MAX_REPUTATION,             1.0).
-define(PERFORMANCE_WINDOW,         100).
-define(UNAVAILABILITY_THRESHOLD,   0.33).
-define(EPOCH_ROTATION_CHECK_MS,    60000).

-record(validator_performance, {
    validator_id            :: validator_id(),
    votes_cast              = 0  :: non_neg_integer(),
    votes_missed            = 0  :: non_neg_integer(),
    blocks_proposed         = 0  :: non_neg_integer(),
    blocks_committed        = 0  :: non_neg_integer(),
    consecutive_misses      = 0  :: non_neg_integer(),
    last_activity_at        :: timestamp_ms() | undefined,
    uptime_samples          = [] :: [boolean()],
    avg_response_time_ms    = 0.0 :: float()
}).

-record(validator_drs, {
    validator_id            :: validator_id(),
    raw_score               = 0.0 :: float(),
    bounded_multiplier      = 1.0 :: float(),
    last_epoch              = 0   :: epoch_number(),
    component_scores        = #{} :: map(),
    score_history           = []  :: [float()]
}).

-record(manager_state, {
    total_stake             = 0   :: stake_amount(),
    current_epoch           = 0   :: epoch_number(),
    epoch_timer             :: reference() | undefined,
    metrics                 = #{} :: map(),
    slash_counts            = #{} :: #{validator_id() => non_neg_integer()}
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

register_validator(ValidatorId, ValidatorData) ->
    gen_server:call(?SERVER, {register_validator, ValidatorId, ValidatorData}).

deregister_validator(ValidatorId) ->
    gen_server:call(?SERVER, {deregister_validator, ValidatorId}).

get_validator(ValidatorId) ->
    gen_server:call(?SERVER, {get_validator, ValidatorId}).

get_all_validators() ->
    gen_server:call(?SERVER, get_all_validators).

get_active_validators() ->
    gen_server:call(?SERVER, get_active_validators).

get_validators_for_shard(ShardId) ->
    gen_server:call(?SERVER, {get_validators_for_shard, ShardId}).

get_active_validators_for_shard(ShardId) ->
    gen_server:call(?SERVER, {get_active_validators_for_shard, ShardId}).

update_stake(ValidatorId, NewStake) ->
    gen_server:call(?SERVER, {update_stake, ValidatorId, NewStake}).

slash_validator(ValidatorId, Reason) ->
    gen_server:call(?SERVER, {slash_validator, ValidatorId, Reason}).

reactivate_validator(ValidatorId) ->
    gen_server:call(?SERVER, {reactivate_validator, ValidatorId}).

update_last_seen(ValidatorId) ->
    gen_server:cast(?SERVER, {update_last_seen, ValidatorId}).

update_last_vote_view(ValidatorId, View) ->
    gen_server:cast(?SERVER, {update_last_vote_view, ValidatorId, View}).

record_block_proposed(ValidatorId) ->
    gen_server:cast(?SERVER, {record_block_proposed, ValidatorId}).

record_block_committed(ValidatorId) ->
    gen_server:cast(?SERVER, {record_block_committed, ValidatorId}).

record_vote_cast(ValidatorId) ->
    gen_server:cast(?SERVER, {record_vote_cast, ValidatorId}).

record_missed_vote(ValidatorId) ->
    gen_server:cast(?SERVER, {record_missed_vote, ValidatorId}).

update_capability(ValidatorId, Capability) ->
    gen_server:call(?SERVER, {update_capability, ValidatorId, Capability}).

update_pqc_keys(ValidatorId, PQCPublicKey, KEMPublicKey) ->
    gen_server:call(?SERVER, {update_pqc_keys, ValidatorId, PQCPublicKey, KEMPublicKey}).

apply_drs_score(ValidatorId, DRSEvent) ->
    gen_server:cast(?SERVER, {apply_drs_score, ValidatorId, DRSEvent}).

get_drs_score(ValidatorId) ->
    gen_server:call(?SERVER, {get_drs_score, ValidatorId}).

rotate_epoch(NewEpoch) ->
    gen_server:call(?SERVER, {rotate_epoch, NewEpoch}).

get_epoch_stats() ->
    gen_server:call(?SERVER, get_epoch_stats).

get_total_stake() ->
    gen_server:call(?SERVER, get_total_stake).

get_total_stake_for_shard(ShardId) ->
    gen_server:call(?SERVER, {get_total_stake_for_shard, ShardId}).

is_active(ValidatorId) ->
    gen_server:call(?SERVER, {is_active, ValidatorId}).

check_capability(ValidatorId, RequiredCapability) ->
    gen_server:call(?SERVER, {check_capability, ValidatorId, RequiredCapability}).

get_metrics() ->
    gen_server:call(?SERVER, get_metrics).

init([]) ->
    ets:new(?VALIDATORS_TABLE, [
        named_table, set, protected,
        {keypos, #sbft_validator_record.id}
    ]),
    ets:new(?PERFORMANCE_TABLE, [
        named_table, set, protected,
        {keypos, #validator_performance.validator_id}
    ]),
    ets:new(?DRS_TABLE, [
        named_table, set, protected,
        {keypos, #validator_drs.validator_id}
    ]),
    EpochTimer = erlang:send_after(?EPOCH_ROTATION_CHECK_MS, self(), check_unavailability),
    {ok, #manager_state{
        epoch_timer = EpochTimer,
        metrics     = init_metrics()
    }}.

handle_call({register_validator, ValidatorId, ValidatorData}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [_] ->
            {reply, {error, already_exists}, State};
        [] ->
            Validator = build_validator_record(ValidatorId, ValidatorData),
            ets:insert(?VALIDATORS_TABLE, Validator),
            ets:insert(?PERFORMANCE_TABLE, #validator_performance{
                validator_id     = ValidatorId,
                last_activity_at = erlang:system_time(millisecond)
            }),
            ets:insert(?DRS_TABLE, #validator_drs{
                validator_id = ValidatorId
            }),
            NewTotalStake = State#manager_state.total_stake +
                            Validator#sbft_validator_record.stake,
            Metrics = bump_metric(validators_registered, State#manager_state.metrics),
            NewState = State#manager_state{
                total_stake = NewTotalStake,
                metrics     = Metrics
            },
            sbft_event_bus:publish(validator_registered, #{
                validator_id  => ValidatorId,
                shard_id      => Validator#sbft_validator_record.shard_id,
                stake         => Validator#sbft_validator_record.stake,
                capability    => Validator#sbft_validator_record.capability
            }),
            {reply, ok, NewState}
    end;

handle_call({deregister_validator, ValidatorId}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            {reply, {error, not_found}, State};
        [Validator] ->
            StakeRemoved  = Validator#sbft_validator_record.stake,
            NewTotalStake = max(0, State#manager_state.total_stake - StakeRemoved),
            ets:delete(?VALIDATORS_TABLE, ValidatorId),
            ets:delete(?PERFORMANCE_TABLE, ValidatorId),
            ets:delete(?DRS_TABLE, ValidatorId),
            Metrics  = bump_metric(validators_deregistered, State#manager_state.metrics),
            NewState = State#manager_state{
                total_stake = NewTotalStake,
                metrics     = Metrics
            },
            {reply, ok, NewState}
    end;

handle_call({get_validator, ValidatorId}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [Validator] -> {reply, {ok, Validator}, State};
        []          -> {reply, {error, not_found}, State}
    end;

handle_call(get_all_validators, _From, State) ->
    Validators = ets:tab2list(?VALIDATORS_TABLE),
    {reply, {ok, Validators}, State};

handle_call(get_active_validators, _From, State) ->
    Active = ets:select(?VALIDATORS_TABLE, [
        {#sbft_validator_record{is_active = true, _ = '_'}, [], ['$_']}
    ]),
    {reply, {ok, Active}, State};

handle_call({get_validators_for_shard, ShardId}, _From, State) ->
    Validators = ets:select(?VALIDATORS_TABLE, [
        {#sbft_validator_record{shard_id = ShardId, _ = '_'}, [], ['$_']}
    ]),
    {reply, {ok, Validators}, State};

handle_call({get_active_validators_for_shard, ShardId}, _From, State) ->
    Validators = ets:select(?VALIDATORS_TABLE, [
        {#sbft_validator_record{shard_id = ShardId, is_active = true, _ = '_'},
         [], ['$_']}
    ]),
    {reply, {ok, Validators}, State};

handle_call({update_stake, ValidatorId, NewStake}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            {reply, {error, not_found}, State};
        [Validator] ->
            OldStake      = Validator#sbft_validator_record.stake,
            Updated       = Validator#sbft_validator_record{stake = NewStake},
            ets:insert(?VALIDATORS_TABLE, Updated),
            StakeDiff     = NewStake - OldStake,
            NewTotalStake = State#manager_state.total_stake + StakeDiff,
            {reply, ok, State#manager_state{total_stake = NewTotalStake}}
    end;

handle_call({slash_validator, ValidatorId, Reason}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            {reply, {error, not_found}, State};
        [Validator] ->
            Slashed = Validator#sbft_validator_record{
                is_active       = false,
                slashing_events = Validator#sbft_validator_record.slashing_events + 1,
                reputation      = ?MIN_REPUTATION
            },
            ets:insert(?VALIDATORS_TABLE, Slashed),
            StakeRemoved  = Validator#sbft_validator_record.stake,
            NewTotalStake = max(0, State#manager_state.total_stake - StakeRemoved),
            SlashCounts   = State#manager_state.slash_counts,
            NewCounts     = maps:update_with(ValidatorId, fun(C) -> C + 1 end, 1, SlashCounts),
            Metrics       = bump_metric(validators_slashed, State#manager_state.metrics),
            NewState      = State#manager_state{
                total_stake  = NewTotalStake,
                slash_counts = NewCounts,
                metrics      = Metrics
            },
            sbft_event_bus:publish(validator_deactivated, #{
                validator_id => ValidatorId,
                reason       => Reason,
                shard_id     => Validator#sbft_validator_record.shard_id
            }),
            {reply, ok, NewState}
    end;

handle_call({reactivate_validator, ValidatorId}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            {reply, {error, not_found}, State};
        [Validator] ->
            case Validator#sbft_validator_record.slashing_events > 0 of
                true ->
                    {reply, {error, permanently_slashed}, State};
                false ->
                    Reactivated = Validator#sbft_validator_record{
                        is_active  = true,
                        reputation = 0.5
                    },
                    ets:insert(?VALIDATORS_TABLE, Reactivated),
                    NewTotalStake = State#manager_state.total_stake +
                                    Reactivated#sbft_validator_record.stake,
                    {reply, ok, State#manager_state{total_stake = NewTotalStake}}
            end
    end;

handle_call({update_capability, ValidatorId, Capability}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            {reply, {error, not_found}, State};
        [Validator] ->
            Updated = Validator#sbft_validator_record{capability = Capability},
            ets:insert(?VALIDATORS_TABLE, Updated),
            {reply, ok, State}
    end;

handle_call({update_pqc_keys, ValidatorId, PQCPublicKey, KEMPublicKey}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            {reply, {error, not_found}, State};
        [Validator] ->
            SigAlgo  = infer_sig_algorithm(PQCPublicKey),
            Updated  = Validator#sbft_validator_record{
                pqc_public_key = PQCPublicKey,
                kem_public_key = KEMPublicKey,
                sig_algorithm  = SigAlgo,
                capability     = upgrade_capability(Validator#sbft_validator_record.capability,
                                                    SigAlgo)
            },
            ets:insert(?VALIDATORS_TABLE, Updated),
            {reply, ok, State}
    end;

handle_call({get_drs_score, ValidatorId}, _From, State) ->
    case ets:lookup(?DRS_TABLE, ValidatorId) of
        [DRS] -> {reply, {ok, DRS#validator_drs.bounded_multiplier}, State};
        []    -> {reply, {error, not_found}, State}
    end;

handle_call({rotate_epoch, NewEpoch}, _From, State) ->
    ok = do_epoch_rotation(NewEpoch, State),
    NewState = State#manager_state{current_epoch = NewEpoch},
    {reply, ok, NewState};

handle_call(get_epoch_stats, _From, State) ->
    Stats = build_epoch_stats(State),
    {reply, {ok, Stats}, State};

handle_call(get_total_stake, _From, State) ->
    {reply, {ok, State#manager_state.total_stake}, State};

handle_call({get_total_stake_for_shard, ShardId}, _From, State) ->
    Validators = ets:select(?VALIDATORS_TABLE, [
        {#sbft_validator_record{shard_id = ShardId, is_active = true, _ = '_'},
         [], ['$_']}
    ]),
    Total = lists:foldl(fun(V, Acc) ->
        Acc + V#sbft_validator_record.stake
    end, 0, Validators),
    {reply, {ok, Total}, State};

handle_call({is_active, ValidatorId}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [V] -> {reply, V#sbft_validator_record.is_active, State};
        []  -> {reply, false, State}
    end;

handle_call({check_capability, ValidatorId, Required}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            {reply, {error, not_found}, State};
        [V] ->
            Result = capability_satisfies(V#sbft_validator_record.capability, Required),
            {reply, {ok, Result}, State}
    end;

handle_call(get_metrics, _From, State) ->
    {reply, {ok, State#manager_state.metrics}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({update_last_seen, ValidatorId}, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [V] ->
            ets:insert(?VALIDATORS_TABLE,
                       V#sbft_validator_record{
                           last_seen = erlang:system_time(millisecond)
                       });
        [] -> ok
    end,
    {noreply, State};

handle_cast({update_last_vote_view, ValidatorId, View}, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [V] ->
            ets:insert(?VALIDATORS_TABLE,
                       V#sbft_validator_record{last_vote_view = View});
        [] -> ok
    end,
    {noreply, State};

handle_cast({record_block_proposed, ValidatorId}, State) ->
    update_performance(ValidatorId, fun(P) ->
        P#validator_performance{
            blocks_proposed  = P#validator_performance.blocks_proposed + 1,
            last_activity_at = erlang:system_time(millisecond)
        }
    end),
    apply_reputation_delta(ValidatorId, ?REPUTATION_BLOCK_REWARD),
    {noreply, State};

handle_cast({record_block_committed, ValidatorId}, State) ->
    update_performance(ValidatorId, fun(P) ->
        P#validator_performance{
            blocks_committed = P#validator_performance.blocks_committed + 1,
            last_activity_at = erlang:system_time(millisecond)
        }
    end),
    apply_reputation_delta(ValidatorId, ?REPUTATION_BLOCK_REWARD),
    {noreply, State};

handle_cast({record_vote_cast, ValidatorId}, State) ->
    update_performance(ValidatorId, fun(P) ->
        Samples = sample_uptime(true, P#validator_performance.uptime_samples),
        P#validator_performance{
            votes_cast         = P#validator_performance.votes_cast + 1,
            consecutive_misses = 0,
            uptime_samples     = Samples,
            last_activity_at   = erlang:system_time(millisecond)
        }
    end),
    apply_reputation_delta(ValidatorId, ?REPUTATION_VOTE_REWARD),
    {noreply, State};

handle_cast({record_missed_vote, ValidatorId}, State) ->
    update_performance(ValidatorId, fun(P) ->
        Samples = sample_uptime(false, P#validator_performance.uptime_samples),
        P#validator_performance{
            votes_missed       = P#validator_performance.votes_missed + 1,
            consecutive_misses = P#validator_performance.consecutive_misses + 1,
            uptime_samples     = Samples,
            last_activity_at   = erlang:system_time(millisecond)
        }
    end),
    apply_reputation_delta(ValidatorId, -?REPUTATION_MISS_PENALTY),
    NewState = maybe_slash_for_unavailability(ValidatorId, State),
    {noreply, NewState};

handle_cast({apply_drs_score, ValidatorId, DRSEvent}, State) ->
    do_apply_drs_score(ValidatorId, DRSEvent),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(check_unavailability, State) ->
    NewState = check_all_unavailability(State),
    Timer    = erlang:send_after(?EPOCH_ROTATION_CHECK_MS, self(), check_unavailability),
    {noreply, NewState#manager_state{epoch_timer = Timer}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timer(State#manager_state.epoch_timer),
    ets:delete(?VALIDATORS_TABLE),
    ets:delete(?PERFORMANCE_TABLE),
    ets:delete(?DRS_TABLE),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

build_validator_record(ValidatorId, Data) ->
    SigAlgo = maps:get(sig_algorithm, Data, ed25519),
    #sbft_validator_record{
        id                = ValidatorId,
        public_key        = maps:get(public_key, Data),
        pqc_public_key    = maps:get(pqc_public_key, Data, undefined),
        kem_public_key    = maps:get(kem_public_key, Data, undefined),
        sig_algorithm     = SigAlgo,
        stake             = maps:get(stake, Data, 0),
        is_active         = maps:get(is_active, Data, true),
        shard_id          = maps:get(shard_id, Data),
        role              = maps:get(role, Data, replica),
        capability        = infer_capability(SigAlgo,
                                maps:get(pqc_public_key, Data, undefined)),
        reputation        = 1.0,
        performance_score = 1.0,
        last_seen         = erlang:system_time(millisecond),
        last_vote_view    = undefined,
        slashing_events   = 0
    }.

infer_capability(dilithium2, PK) when PK =/= undefined -> pqc_primary;
infer_capability(hybrid, PK)     when PK =/= undefined -> pqc_hybrid;
infer_capability(_, _)                                  -> legacy.

infer_sig_algorithm(PQCPublicKey) ->
    case byte_size(PQCPublicKey) of
        1312 -> dilithium2;
        64   -> ed25519;
        _    -> hybrid
    end.

upgrade_capability(legacy, dilithium2)  -> pqc_primary;
upgrade_capability(legacy, hybrid)      -> pqc_hybrid;
upgrade_capability(pqc_hybrid, dilithium2) -> pqc_primary;
upgrade_capability(Current, _)          -> Current.

capability_satisfies(pqc_primary, pqc_primary) -> true;
capability_satisfies(pqc_primary, pqc_hybrid)  -> true;
capability_satisfies(pqc_primary, legacy)       -> true;
capability_satisfies(pqc_hybrid, pqc_hybrid)    -> true;
capability_satisfies(pqc_hybrid, legacy)        -> true;
capability_satisfies(legacy, legacy)            -> true;
capability_satisfies(_, _)                      -> false.

update_performance(ValidatorId, UpdateFun) ->
    case ets:lookup(?PERFORMANCE_TABLE, ValidatorId) of
        [Perf] ->
            Updated = UpdateFun(Perf),
            ets:insert(?PERFORMANCE_TABLE, Updated),
            update_performance_score(ValidatorId, Updated);
        [] ->
            ok
    end.

update_performance_score(ValidatorId, Perf) ->
    Total    = Perf#validator_performance.votes_cast +
               Perf#validator_performance.votes_missed,
    Score    = case Total of
        0 -> 1.0;
        N ->
            UptimeScore  = compute_uptime_score(Perf#validator_performance.uptime_samples),
            ProposalScore = case Perf#validator_performance.blocks_proposed of
                0 -> 1.0;
                P ->
                    CommitRatio = Perf#validator_performance.blocks_committed / P,
                    CommitRatio
            end,
            (UptimeScore * 0.7) + (ProposalScore * 0.3)
    end,
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [V] ->
            ets:insert(?VALIDATORS_TABLE,
                       V#sbft_validator_record{performance_score = Score});
        [] -> ok
    end.

compute_uptime_score([]) ->
    1.0;
compute_uptime_score(Samples) ->
    Successes = length(lists:filter(fun(X) -> X end, Samples)),
    Successes / length(Samples).

sample_uptime(Success, Samples) ->
    Trimmed = case length(Samples) >= ?PERFORMANCE_WINDOW of
        true  -> lists:droplast(Samples);
        false -> Samples
    end,
    [Success | Trimmed].

apply_reputation_delta(ValidatorId, Delta) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [V] ->
            NewRep = clamp(
                V#sbft_validator_record.reputation * ?REPUTATION_DECAY_FACTOR + Delta,
                ?MIN_REPUTATION,
                ?MAX_REPUTATION
            ),
            ets:insert(?VALIDATORS_TABLE,
                       V#sbft_validator_record{reputation = NewRep});
        [] -> ok
    end.

clamp(Value, Min, Max) ->
    max(Min, min(Max, Value)).

maybe_slash_for_unavailability(ValidatorId, State) ->
    case ets:lookup(?PERFORMANCE_TABLE, ValidatorId) of
        [Perf] ->
            ConsecMisses = Perf#validator_performance.consecutive_misses,
            Threshold    = round(?UNAVAILABILITY_THRESHOLD * ?PERFORMANCE_WINDOW),
            case ConsecMisses >= Threshold of
                true ->
                    sbft_slashing:report_unavailability(ValidatorId,
                        get_validator_shard(ValidatorId)),
                    Metrics = bump_metric(unavailability_reports,
                                         State#manager_state.metrics),
                    State#manager_state{metrics = Metrics};
                false ->
                    State
            end;
        [] ->
            State
    end.

get_validator_shard(ValidatorId) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [V] -> V#sbft_validator_record.shard_id;
        []  -> <<>>
    end.

do_apply_drs_score(ValidatorId, DRSEvent) ->
    RawScore    = DRSEvent#drs_score_event.raw_score,
    Multiplier  = DRSEvent#drs_score_event.bounded_multiplier,
    Epoch       = DRSEvent#drs_score_event.epoch,
    Components  = DRSEvent#drs_score_event.component_scores,
    case ets:lookup(?DRS_TABLE, ValidatorId) of
        [DRS] ->
            History    = [RawScore | lists:sublist(DRS#validator_drs.score_history, 9)],
            Updated    = DRS#validator_drs{
                raw_score          = RawScore,
                bounded_multiplier = Multiplier,
                last_epoch         = Epoch,
                component_scores   = Components,
                score_history      = History
            },
            ets:insert(?DRS_TABLE, Updated),
            apply_drs_reputation_effect(ValidatorId, Multiplier);
        [] ->
            ets:insert(?DRS_TABLE, #validator_drs{
                validator_id       = ValidatorId,
                raw_score          = RawScore,
                bounded_multiplier = Multiplier,
                last_epoch         = Epoch,
                component_scores   = Components,
                score_history      = [RawScore]
            })
    end.

apply_drs_reputation_effect(ValidatorId, Multiplier) ->
    Delta = (Multiplier - 1.0) * 0.05,
    apply_reputation_delta(ValidatorId, Delta).

do_epoch_rotation(NewEpoch, _State) ->
    AllValidators = ets:tab2list(?VALIDATORS_TABLE),
    lists:foreach(fun(V) ->
        apply_reputation_delta(V#sbft_validator_record.id, 0.0),
        maybe_check_rotation_eligibility(V, NewEpoch)
    end, AllValidators),
    sbft_event_bus:publish(epoch_rotated, #{
        epoch             => NewEpoch,
        total_validators  => length(AllValidators)
    }),
    ok.

maybe_check_rotation_eligibility(Validator, _NewEpoch) ->
    case Validator#sbft_validator_record.reputation < 0.1 andalso
         Validator#sbft_validator_record.is_active of
        true ->
            error_logger:warning_msg(
                "[sbft_validator_manager] validator ~p has critically low "
                "reputation ~p, candidate for rotation~n",
                [Validator#sbft_validator_record.id,
                 Validator#sbft_validator_record.reputation]
            );
        false ->
            ok
    end.

check_all_unavailability(State) ->
    Now          = erlang:system_time(millisecond),
    StaleThresh  = Now - (?EPOCH_ROTATION_CHECK_MS * 3),
    AllPerf      = ets:tab2list(?PERFORMANCE_TABLE),
    lists:foldl(fun(Perf, AccState) ->
        ValidatorId = Perf#validator_performance.validator_id,
        LastActive  = case Perf#validator_performance.last_activity_at of
            undefined -> 0;
            T         -> T
        end,
        case LastActive < StaleThresh of
            true  ->
                sbft_slashing:report_unavailability(ValidatorId,
                    get_validator_shard(ValidatorId)),
                bump_metric_in_state(unavailability_reports, AccState);
            false ->
                AccState
        end
    end, State, AllPerf).

build_epoch_stats(State) ->
    AllValidators = ets:tab2list(?VALIDATORS_TABLE),
    Active        = lists:filter(fun(V) -> V#sbft_validator_record.is_active end, AllValidators),
    PQCCapable    = lists:filter(fun(V) ->
        V#sbft_validator_record.capability =/= legacy
    end, Active),
    AvgReputation = case Active of
        [] -> 0.0;
        _  ->
            Sum = lists:foldl(fun(V, Acc) ->
                Acc + V#sbft_validator_record.reputation
            end, 0.0, Active),
            Sum / length(Active)
    end,
    #{
        epoch             => State#manager_state.current_epoch,
        total_validators  => length(AllValidators),
        active_validators => length(Active),
        pqc_capable       => length(PQCCapable),
        total_stake       => State#manager_state.total_stake,
        avg_reputation    => AvgReputation
    }.

bump_metric_in_state(Key, State) ->
    Metrics = bump_metric(Key, State#manager_state.metrics),
    State#manager_state{metrics = Metrics}.

cancel_timer(undefined) -> ok;
cancel_timer(Ref)       -> erlang:cancel_timer(Ref), ok.

init_metrics() ->
    #{
        validators_registered   => 0,
        validators_deregistered => 0,
        validators_slashed      => 0,
        unavailability_reports  => 0
    }.

bump_metric(Key, Metrics) ->
    maps:update_with(Key, fun(V) -> V + 1 end, 1, Metrics).
