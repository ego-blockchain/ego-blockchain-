-module(sbft_consensus_manager).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([
    start_link/0,
    start_shard_consensus/2,
    stop_shard_consensus/1,
    restart_shard_consensus/1,
    get_shard_status/1,
    get_all_shards/0,
    get_active_shards/0,
    get_shard_pid/1,
    propose_to_shard/2,
    submit_vote_to_shard/2,
    get_global_finality/0,
    get_committed_block/2,
    get_cross_shard_receipts/1,
    sync_shard_validators/1,
    get_metrics/0,
    broadcast_to_all_shards/1,
    get_shard_leader/1
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
-define(SHARD_RESTART_DELAY_MS,     2000).
-define(GLOBAL_FINALITY_CHECK_MS,   5000).
-define(MAX_SHARD_RESTARTS,         5).
-define(SHARD_RESTART_WINDOW_MS,    60000).

-record(shard_entry, {
    shard_id        :: shard_id(),
    pid             :: pid(),
    config          :: map(),
    started_at      :: timestamp_ms(),
    restart_count   = 0  :: non_neg_integer(),
    last_restart_at :: timestamp_ms() | undefined,
    last_finalized_view = -1 :: integer(),
    last_finalized_hash :: block_hash() | undefined,
    height          = 0  :: non_neg_integer()
}).

-record(manager_state, {
    shards              = #{} :: #{shard_id() => #shard_entry{}},
    global_finalized    = #{} :: #{shard_id() => view_number()},
    global_height       = #{} :: #{shard_id() => non_neg_integer()},
    finality_timer      :: reference() | undefined,
    metrics             = #{} :: map(),
    current_epoch       = 0   :: epoch_number()
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

start_shard_consensus(ShardId, Config) ->
    gen_server:call(?SERVER, {start_shard, ShardId, Config}).

stop_shard_consensus(ShardId) ->
    gen_server:call(?SERVER, {stop_shard, ShardId}).

restart_shard_consensus(ShardId) ->
    gen_server:call(?SERVER, {restart_shard, ShardId}).

get_shard_status(ShardId) ->
    gen_server:call(?SERVER, {get_shard_status, ShardId}).

get_all_shards() ->
    gen_server:call(?SERVER, get_all_shards).

get_active_shards() ->
    gen_server:call(?SERVER, get_active_shards).

get_shard_pid(ShardId) ->
    gen_server:call(?SERVER, {get_shard_pid, ShardId}).

propose_to_shard(ShardId, Block) ->
    gen_server:cast(?SERVER, {propose_to_shard, ShardId, Block}).

submit_vote_to_shard(ShardId, Vote) ->
    gen_server:cast(?SERVER, {submit_vote_to_shard, ShardId, Vote}).

get_global_finality() ->
    gen_server:call(?SERVER, get_global_finality).

get_committed_block(ShardId, View) ->
    gen_server:call(?SERVER, {get_committed_block, ShardId, View}).

get_cross_shard_receipts(ShardId) ->
    gen_server:call(?SERVER, {get_cross_shard_receipts, ShardId}).

sync_shard_validators(ShardId) ->
    gen_server:call(?SERVER, {sync_shard_validators, ShardId}).

get_metrics() ->
    gen_server:call(?SERVER, get_metrics).

broadcast_to_all_shards(Message) ->
    gen_server:cast(?SERVER, {broadcast_to_all_shards, Message}).

get_shard_leader(ShardId) ->
    gen_server:call(?SERVER, {get_shard_leader, ShardId}).

init([]) ->
    process_flag(trap_exit, true),
    ok = subscribe_to_events(),
    FinalityTimer = erlang:send_after(?GLOBAL_FINALITY_CHECK_MS, self(),
                                      check_global_finality),
    {ok, #manager_state{
        finality_timer = FinalityTimer,
        metrics        = init_metrics()
    }}.

handle_call({start_shard, ShardId, Config}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            do_start_shard(ShardId, Config, State);
        Entry ->
            case erlang:is_process_alive(Entry#shard_entry.pid) of
                true  ->
                    {reply, {ok, Entry#shard_entry.pid}, State};
                false ->
                    do_start_shard(ShardId, Config, State)
            end
    end;

handle_call({stop_shard, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            catch sbft_shard_consensus:stop(Entry#shard_entry.pid),
            unlink(Entry#shard_entry.pid),
            NewShards  = maps:remove(ShardId, State#manager_state.shards),
            NewGlobal  = maps:remove(ShardId, State#manager_state.global_finalized),
            NewHeights = maps:remove(ShardId, State#manager_state.global_height),
            Metrics    = bump_metric(shards_stopped, State#manager_state.metrics),
            NewState   = State#manager_state{
                shards           = NewShards,
                global_finalized = NewGlobal,
                global_height    = NewHeights,
                metrics          = Metrics
            },
            sbft_event_bus:publish(shard_stopped, #{shard_id => ShardId}),
            {reply, ok, NewState}
    end;

handle_call({restart_shard, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            case can_restart(Entry) of
                false ->
                    {reply, {error, max_restarts_exceeded}, State};
                true ->
                    catch sbft_shard_consensus:stop(Entry#shard_entry.pid),
                    unlink(Entry#shard_entry.pid),
                    Config    = Entry#shard_entry.config,
                    NewShards = maps:remove(ShardId, State#manager_state.shards),
                    TempState = State#manager_state{shards = NewShards},
                    do_start_shard_with_restart_count(
                        ShardId, Config,
                        Entry#shard_entry.restart_count + 1,
                        TempState
                    )
            end
    end;

handle_call({get_shard_status, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            case erlang:is_process_alive(Entry#shard_entry.pid) of
                false ->
                    {reply, {error, shard_down}, State};
                true ->
                    Status = sbft_shard_consensus:get_status(Entry#shard_entry.pid),
                    {reply, {ok, Status}, State}
            end
    end;

handle_call(get_all_shards, _From, State) ->
    Shards = maps:keys(State#manager_state.shards),
    {reply, {ok, Shards}, State};

handle_call(get_active_shards, _From, State) ->
    Active = maps:fold(fun(ShardId, Entry, Acc) ->
        case erlang:is_process_alive(Entry#shard_entry.pid) of
            true  -> [ShardId | Acc];
            false -> Acc
        end
    end, [], State#manager_state.shards),
    {reply, {ok, Active}, State};

handle_call({get_shard_pid, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            case erlang:is_process_alive(Entry#shard_entry.pid) of
                true  -> {reply, {ok, Entry#shard_entry.pid}, State};
                false -> {reply, {error, shard_down}, State}
            end
    end;

handle_call(get_global_finality, _From, State) ->
    Result = #{
        finalized_views => State#manager_state.global_finalized,
        heights         => State#manager_state.global_height,
        shard_count     => maps:size(State#manager_state.shards),
        epoch           => State#manager_state.current_epoch
    },
    {reply, {ok, Result}, State};

handle_call({get_committed_block, ShardId, View}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            Result = sbft_shard_consensus:get_committed_block(Entry#shard_entry.pid, View),
            {reply, Result, State}
    end;

handle_call({get_cross_shard_receipts, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            Receipts = sbft_shard_consensus:get_pending_receipts(Entry#shard_entry.pid),
            {reply, {ok, Receipts}, State}
    end;

handle_call({sync_shard_validators, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            Result = do_sync_validators(ShardId, Entry),
            {reply, Result, State}
    end;

handle_call({get_shard_leader, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            Status = sbft_shard_consensus:get_status(Entry#shard_entry.pid),
            Leader = maps:get(current_leader, Status, undefined),
            {reply, {ok, Leader}, State}
    end;

handle_call(get_metrics, _From, State) ->
    {reply, {ok, State#manager_state.metrics}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({propose_to_shard, ShardId, Block}, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined -> ok;
        Entry     ->
            case erlang:is_process_alive(Entry#shard_entry.pid) of
                true  -> sbft_shard_consensus:propose_block(Entry#shard_entry.pid, Block);
                false -> ok
            end
    end,
    {noreply, State};

handle_cast({submit_vote_to_shard, ShardId, Vote}, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined -> ok;
        Entry     ->
            case erlang:is_process_alive(Entry#shard_entry.pid) of
                true  -> sbft_shard_consensus:submit_vote(Entry#shard_entry.pid, Vote);
                false -> ok
            end
    end,
    {noreply, State};

handle_cast({broadcast_to_all_shards, Message}, State) ->
    maps:foreach(fun(_ShardId, Entry) ->
        case erlang:is_process_alive(Entry#shard_entry.pid) of
            true  -> Entry#shard_entry.pid ! Message;
            false -> ok
        end
    end, State#manager_state.shards),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({sbft_event, block_finalized, Payload}, State) ->
    NewState = handle_block_finalized(Payload, State),
    {noreply, NewState};

handle_info({sbft_event, validator_slashed, Payload}, State) ->
    NewState = handle_validator_slashed(Payload, State),
    {noreply, NewState};

handle_info({sbft_event, new_view_started, Payload}, State) ->
    NewState = handle_new_view(Payload, State),
    {noreply, NewState};

handle_info(check_global_finality, State) ->
    NewState    = do_check_global_finality(State),
    FinalityTimer = erlang:send_after(?GLOBAL_FINALITY_CHECK_MS, self(),
                                       check_global_finality),
    {noreply, NewState#manager_state{finality_timer = FinalityTimer}};

handle_info({shard_restart, ShardId}, State) ->
    case maps:get(ShardId, State#manager_state.shards, undefined) of
        undefined ->
            {noreply, State};
        Entry ->
            Config = Entry#shard_entry.config,
            NewState = case do_start_shard_with_restart_count(
                             ShardId, Config,
                             Entry#shard_entry.restart_count,
                             State) of
                {reply, {ok, _Pid}, S} -> S;
                {reply, {error, _}, S} -> S
            end,
            {noreply, NewState}
    end;

handle_info({'EXIT', Pid, Reason}, State) ->
    case find_shard_by_pid(Pid, State#manager_state.shards) of
        {ok, ShardId, Entry} ->
            error_logger:error_msg(
                "[sbft_consensus_manager] shard ~p crashed: ~p~n",
                [ShardId, Reason]
            ),
            Metrics   = bump_metric(shard_crashes, State#manager_state.metrics),
            NewShards = maps:remove(ShardId, State#manager_state.shards),
            NewState  = State#manager_state{
                shards  = NewShards,
                metrics = Metrics
            },
            FinalState = maybe_schedule_restart(ShardId, Entry, Reason, NewState),
            sbft_event_bus:publish(shard_crashed, #{
                shard_id => ShardId,
                reason   => Reason
            }),
            {noreply, FinalState};
        not_found ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timer(State#manager_state.finality_timer),
    maps:foreach(fun(_ShardId, Entry) ->
        catch sbft_shard_consensus:stop(Entry#shard_entry.pid)
    end, State#manager_state.shards),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

do_start_shard(ShardId, Config, State) ->
    do_start_shard_with_restart_count(ShardId, Config, 0, State).

do_start_shard_with_restart_count(ShardId, Config, RestartCount, State) ->
    EnrichedConfig = enrich_config_with_validators(ShardId, Config),
    case sbft_shard_consensus:start_link(ShardId, EnrichedConfig) of
        {ok, Pid} ->
            link(Pid),
            Entry = #shard_entry{
                shard_id        = ShardId,
                pid             = Pid,
                config          = Config,
                started_at      = erlang:system_time(millisecond),
                restart_count   = RestartCount,
                last_restart_at = case RestartCount > 0 of
                    true  -> erlang:system_time(millisecond);
                    false -> undefined
                end
            },
            NewShards = maps:put(ShardId, Entry, State#manager_state.shards),
            NewGlobal = maps:put(ShardId, -1, State#manager_state.global_finalized),
            NewHeights = maps:put(ShardId, 0, State#manager_state.global_height),
            Metrics   = bump_metric(shards_started, State#manager_state.metrics),
            NewState  = State#manager_state{
                shards           = NewShards,
                global_finalized = NewGlobal,
                global_height    = NewHeights,
                metrics          = Metrics
            },
            sbft_event_bus:publish(shard_started, #{
                shard_id      => ShardId,
                restart_count => RestartCount
            }),
            {reply, {ok, Pid}, NewState};
        {error, Reason} ->
            error_logger:error_msg(
                "[sbft_consensus_manager] failed to start shard ~p: ~p~n",
                [ShardId, Reason]
            ),
            {reply, {error, Reason}, State}
    end.

enrich_config_with_validators(ShardId, Config) ->
    case maps:get(validators, Config, undefined) of
        undefined ->
            case sbft_validator_manager:get_active_validators_for_shard(ShardId) of
                {ok, Validators} ->
                    Config#{validators => Validators};
                {error, _} ->
                    Config#{validators => []}
            end;
        _ ->
            Config
    end.

do_sync_validators(ShardId, Entry) ->
    case sbft_validator_manager:get_active_validators_for_shard(ShardId) of
        {ok, Validators} ->
            case sbft_shard_consensus:get_status(Entry#shard_entry.pid) of
                #{validators_count := CurrentCount} ->
                    NewCount = length(Validators),
                    case NewCount =/= CurrentCount of
                        true ->
                            lists:foreach(fun(V) ->
                                sbft_shard_consensus:add_validator(
                                    Entry#shard_entry.pid, V
                                )
                            end, Validators),
                            {ok, synced};
                        false ->
                            {ok, no_change}
                    end;
                _ ->
                    {error, status_unavailable}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

handle_block_finalized(Payload, State) ->
    ShardId  = maps:get(shard_id, Payload, undefined),
    View     = maps:get(view, Payload, 0),
    Height   = maps:get(height, Payload, 0),
    Hash     = maps:get(block_hash, Payload, undefined),
    Receipts = maps:get(receipts, Payload, []),
    case ShardId of
        undefined ->
            State;
        _ ->
            NewGlobal  = maps:put(ShardId, View,
                                   State#manager_state.global_finalized),
            NewHeights = maps:put(ShardId, Height,
                                   State#manager_state.global_height),
            NewShards  = case maps:get(ShardId, State#manager_state.shards, undefined) of
                undefined -> State#manager_state.shards;
                Entry ->
                    Updated = Entry#shard_entry{
                        last_finalized_view = View,
                        last_finalized_hash = Hash,
                        height              = Height
                    },
                    maps:put(ShardId, Updated, State#manager_state.shards)
            end,
            Metrics = bump_metric(blocks_finalized, State#manager_state.metrics),
            NewState = State#manager_state{
                global_finalized = NewGlobal,
                global_height    = NewHeights,
                shards           = NewShards,
                metrics          = Metrics
            },
            ok = route_cross_shard_receipts(Receipts, ShardId),
            NewState
    end.

handle_validator_slashed(Payload, State) ->
    ValidatorId = maps:get(validator_id, Payload, undefined),
    ShardId     = maps:get(shard_id, Payload, undefined),
    case ValidatorId =/= undefined andalso ShardId =/= undefined of
        false -> State;
        true  ->
            case maps:get(ShardId, State#manager_state.shards, undefined) of
                undefined -> State;
                Entry ->
                    catch sbft_shard_consensus:remove_validator(
                        Entry#shard_entry.pid,
                        ValidatorId
                    ),
                    State
            end
    end.

handle_new_view(Payload, State) ->
    ShardId   = maps:get(shard_id, Payload, undefined),
    NewView   = maps:get(new_view, Payload, 0),
    NewLeader = maps:get(new_leader, Payload, undefined),
    error_logger:info_msg(
        "[sbft_consensus_manager] shard ~p new view ~p leader ~p~n",
        [ShardId, NewView, NewLeader]
    ),
    Metrics = bump_metric(view_changes_observed, State#manager_state.metrics),
    State#manager_state{metrics = Metrics}.

do_check_global_finality(State) ->
    AllShards = maps:keys(State#manager_state.shards),
    case AllShards of
        [] ->
            State;
        _ ->
            FinalizedViews = maps:values(State#manager_state.global_finalized),
            AllFinalized   = lists:all(fun(V) -> V >= 0 end, FinalizedViews),
            MinView        = lists:min(FinalizedViews),
            MaxView        = lists:max(FinalizedViews),
            Gap            = MaxView - MinView,
            case AllFinalized of
                true ->
                    maybe_emit_global_finality(Gap, MinView, State);
                false ->
                    State
            end
    end.

maybe_emit_global_finality(Gap, MinView, State) ->
    case Gap > 10 of
        true ->
            error_logger:warning_msg(
                "[sbft_consensus_manager] global finality gap detected: ~p views~n",
                [Gap]
            ),
            Metrics = bump_metric(finality_gaps, State#manager_state.metrics),
            State#manager_state{metrics = Metrics};
        false ->
            sbft_event_bus:publish(global_finality_reached, #{
                min_view   => MinView,
                shard_count => maps:size(State#manager_state.shards)
            }),
            State
    end.

route_cross_shard_receipts([], _FromShard) ->
    ok;
route_cross_shard_receipts(Receipts, FromShard) ->
    lists:foreach(fun(Receipt) ->
        case is_record(Receipt, cross_shard_receipt) of
            true ->
                ToShard = Receipt#cross_shard_receipt.to_shard,
                case ToShard =/= FromShard of
                    true ->
                        sbft_cross_shard:send_receipt(
                            FromShard,
                            ToShard,
                            Receipt#cross_shard_receipt.receipt_data,
                            #{expiry_ms => Receipt#cross_shard_receipt.expiry_timestamp}
                        );
                    false ->
                        ok
                end;
            false ->
                ok
        end
    end, Receipts).

maybe_schedule_restart(ShardId, _Entry, normal, State) ->
    error_logger:info_msg(
        "[sbft_consensus_manager] shard ~p stopped normally, not restarting~n",
        [ShardId]
    ),
    State;
maybe_schedule_restart(ShardId, Entry, _Reason, State) ->
    case can_restart(Entry) of
        false ->
            error_logger:error_msg(
                "[sbft_consensus_manager] shard ~p exceeded max restarts (~p), "
                "giving up~n",
                [ShardId, Entry#shard_entry.restart_count]
            ),
            State;
        true ->
            Delay    = restart_delay(Entry#shard_entry.restart_count),
            TimerRef = erlang:send_after(Delay, self(), {shard_restart, ShardId}),
            NewEntry = Entry#shard_entry{
                restart_count   = Entry#shard_entry.restart_count + 1,
                last_restart_at = erlang:system_time(millisecond)
            },
            NewShards = maps:put(ShardId, NewEntry, State#manager_state.shards),
            error_logger:info_msg(
                "[sbft_consensus_manager] scheduling shard ~p restart in ~p ms "
                "(attempt ~p)~n",
                [ShardId, Delay, Entry#shard_entry.restart_count + 1]
            ),
            _ = TimerRef,
            State#manager_state{shards = NewShards}
    end.

can_restart(Entry) ->
    Now          = erlang:system_time(millisecond),
    WindowStart  = Now - ?SHARD_RESTART_WINDOW_MS,
    RecentRestart = case Entry#shard_entry.last_restart_at of
        undefined -> false;
        T         -> T > WindowStart
    end,
    case RecentRestart of
        true  -> Entry#shard_entry.restart_count < ?MAX_SHARD_RESTARTS;
        false -> true
    end.

restart_delay(RestartCount) ->
    Base   = ?SHARD_RESTART_DELAY_MS,
    Delay  = Base * (1 bsl min(RestartCount, 5)),
    Jitter = rand:uniform(Delay div 4 + 1),
    min(Delay + Jitter, 30000).

find_shard_by_pid(Pid, Shards) ->
    maps:fold(fun(ShardId, Entry, Acc) ->
        case Entry#shard_entry.pid =:= Pid of
            true  -> {ok, ShardId, Entry};
            false -> Acc
        end
    end, not_found, Shards).

subscribe_to_events() ->
    sbft_event_bus:subscribe([
        block_finalized,
        validator_slashed,
        new_view_started
    ]),
    ok.

cancel_timer(undefined) -> ok;
cancel_timer(Ref)       -> erlang:cancel_timer(Ref), ok.

init_metrics() ->
    #{
        shards_started          => 0,
        shards_stopped          => 0,
        shard_crashes           => 0,
        blocks_finalized        => 0,
        view_changes_observed   => 0,
        finality_gaps           => 0
    }.

bump_metric(Key, Metrics) ->
    maps:update_with(Key, fun(V) -> V + 1 end, 1, Metrics).
