-module(sbft_event_bus).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([
    start_link/0,
    publish/2,
    subscribe/1,
    subscribe/2,
    unsubscribe/1,
    get_subscribers/0,
    get_subscribers/1,
    get_metrics/0,
    replay_last/1,
    replay_last/2
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(SERVER,             ?MODULE).
-define(SUBSCRIBERS_TABLE,  sbft_event_subscribers).
-define(LAST_EVENTS_TABLE,  sbft_last_events).
-define(MAX_QUEUE_LEN,      1000).
-define(FFI_TIMEOUT_MS,     5000).

-type topic() ::
    block_finalized         |
    new_view_started        |
    validator_slashed       |
    cross_shard_receipt     |
    view_change_initiated   |
    block_proposed          |
    qc_formed               |
    poc_report_received     |
    drs_score_emitted       |
    deploy_requested        |
    deploy_accepted         |
    deploy_rejected         |
    bandwidth_slot_updated  |
    validator_registered    |
    validator_deactivated   |
    any.

-record(subscriber, {
    pid         :: pid(),
    topics      :: [topic()],
    filter      :: fun((topic(), map()) -> boolean()) | undefined,
    ref         :: reference(),
    registered_at :: timestamp_ms()
}).

-record(bus_state, {
    subscribers     = #{} :: #{pid() => #subscriber{}},
    rust_bridge_pid :: pid() | undefined,
    rust_topics     = [] :: [topic()],
    metrics         = #{} :: map(),
    last_events     = #{} :: #{topic() => map()}
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

publish(Topic, Payload) when is_atom(Topic), is_map(Payload) ->
    gen_server:cast(?SERVER, {publish, Topic, Payload, erlang:system_time(millisecond)}).

subscribe(Topics) ->
    subscribe(Topics, undefined).

subscribe(Topics, FilterFun) when is_list(Topics) ->
    gen_server:call(?SERVER, {subscribe, self(), Topics, FilterFun});
subscribe(Topic, FilterFun) when is_atom(Topic) ->
    subscribe([Topic], FilterFun).

unsubscribe(Topics) when is_list(Topics) ->
    gen_server:call(?SERVER, {unsubscribe, self(), Topics});
unsubscribe(Topic) when is_atom(Topic) ->
    unsubscribe([Topic]).

get_subscribers() ->
    gen_server:call(?SERVER, get_subscribers).

get_subscribers(Topic) ->
    gen_server:call(?SERVER, {get_subscribers, Topic}).

get_metrics() ->
    gen_server:call(?SERVER, get_metrics).

replay_last(Topic) ->
    gen_server:call(?SERVER, {replay_last, Topic}).

replay_last(Topic, SubscriberPid) ->
    gen_server:call(?SERVER, {replay_last, Topic, SubscriberPid}).

init([]) ->
    process_flag(trap_exit, true),
    ets:new(?SUBSCRIBERS_TABLE, [named_table, set, protected]),
    ets:new(?LAST_EVENTS_TABLE, [named_table, set, protected]),
    RustBridgePid = maybe_start_rust_bridge(),
    State = #bus_state{
        rust_bridge_pid = RustBridgePid,
        rust_topics     = rust_forwarded_topics(),
        metrics         = init_metrics()
    },
    {ok, State}.

handle_call({subscribe, Pid, Topics, FilterFun}, _From, State) ->
    Ref = erlang:monitor(process, Pid),
    Sub = #subscriber{
        pid           = Pid,
        topics        = Topics,
        filter        = FilterFun,
        ref           = Ref,
        registered_at = erlang:system_time(millisecond)
    },
    NewSubs = maps:put(Pid, Sub, State#bus_state.subscribers),
    ets:insert(?SUBSCRIBERS_TABLE, {Pid, Topics}),
    {reply, {ok, Ref}, State#bus_state{subscribers = NewSubs}};

handle_call({unsubscribe, Pid, Topics}, _From, State) ->
    case maps:get(Pid, State#bus_state.subscribers, undefined) of
        undefined ->
            {reply, {error, not_subscribed}, State};
        Sub ->
            NewTopics = Sub#subscriber.topics -- Topics,
            case NewTopics of
                [] ->
                    erlang:demonitor(Sub#subscriber.ref, [flush]),
                    NewSubs = maps:remove(Pid, State#bus_state.subscribers),
                    ets:delete(?SUBSCRIBERS_TABLE, Pid),
                    {reply, ok, State#bus_state{subscribers = NewSubs}};
                _ ->
                    UpdatedSub  = Sub#subscriber{topics = NewTopics},
                    NewSubs     = maps:put(Pid, UpdatedSub, State#bus_state.subscribers),
                    {reply, ok, State#bus_state{subscribers = NewSubs}}
            end
    end;

handle_call(get_subscribers, _From, State) ->
    Subs = maps:values(State#bus_state.subscribers),
    Info = lists:map(fun(S) ->
        #{
            pid    => S#subscriber.pid,
            topics => S#subscriber.topics,
            since  => S#subscriber.registered_at
        }
    end, Subs),
    {reply, {ok, Info}, State};

handle_call({get_subscribers, Topic}, _From, State) ->
    Subs = maps:filter(fun(_Pid, Sub) ->
        lists:member(Topic, Sub#subscriber.topics) orelse
        lists:member(any, Sub#subscriber.topics)
    end, State#bus_state.subscribers),
    Info = maps:keys(Subs),
    {reply, {ok, Info}, State};

handle_call(get_metrics, _From, State) ->
    {reply, {ok, State#bus_state.metrics}, State};

handle_call({replay_last, Topic}, _From, State) ->
    Result = maps:get(Topic, State#bus_state.last_events, undefined),
    {reply, {ok, Result}, State};

handle_call({replay_last, Topic, SubscriberPid}, _From, State) ->
    case maps:get(Topic, State#bus_state.last_events, undefined) of
        undefined ->
            {reply, {ok, no_event}, State};
        LastEvent ->
            deliver_to_pid(SubscriberPid, Topic, LastEvent, undefined),
            {reply, {ok, delivered}, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({publish, Topic, Payload, Timestamp}, State) ->
    EnrichedPayload = Payload#{
        bus_topic     => Topic,
        bus_timestamp => Timestamp,
        bus_seq       => next_seq()
    },
    State1 = store_last_event(Topic, EnrichedPayload, State),
    State2 = dispatch_to_subscribers(Topic, EnrichedPayload, State1),
    State3 = maybe_forward_to_rust(Topic, EnrichedPayload, State2),
    State4 = bump_publish_metric(Topic, State3),
    {noreply, State4};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', Ref, process, Pid, Reason}, State) ->
    case maps:get(Pid, State#bus_state.subscribers, undefined) of
        undefined ->
            {noreply, State};
        Sub ->
            case Sub#subscriber.ref =:= Ref of
                true ->
                    error_logger:info_msg(
                        "[sbft_event_bus] subscriber ~p down: ~p~n",
                        [Pid, Reason]
                    ),
                    NewSubs = maps:remove(Pid, State#bus_state.subscribers),
                    ets:delete(?SUBSCRIBERS_TABLE, Pid),
                    {noreply, State#bus_state{subscribers = NewSubs}};
                false ->
                    {noreply, State}
            end
    end;

handle_info({rust_bridge_ready, BridgePid}, State) ->
    error_logger:info_msg("[sbft_event_bus] Rust bridge connected: ~p~n", [BridgePid]),
    {noreply, State#bus_state{rust_bridge_pid = BridgePid}};

handle_info({rust_bridge_down, Reason}, State) ->
    error_logger:warning_msg(
        "[sbft_event_bus] Rust bridge disconnected: ~p, attempting reconnect~n",
        [Reason]
    ),
    NewBridgePid = maybe_start_rust_bridge(),
    {noreply, State#bus_state{rust_bridge_pid = NewBridgePid}};

handle_info({'EXIT', Pid, Reason}, State) ->
    case State#bus_state.rust_bridge_pid =:= Pid of
        true ->
            error_logger:warning_msg(
                "[sbft_event_bus] Rust bridge process exited: ~p~n",
                [Reason]
            ),
            NewBridgePid = maybe_start_rust_bridge(),
            {noreply, State#bus_state{rust_bridge_pid = NewBridgePid}};
        false ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ets:delete(?SUBSCRIBERS_TABLE),
    ets:delete(?LAST_EVENTS_TABLE),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

dispatch_to_subscribers(Topic, Payload, State) ->
    maps:fold(fun(Pid, Sub, AccState) ->
        case should_deliver(Topic, Payload, Sub) of
            true ->
                deliver_to_pid(Pid, Topic, Payload, Sub#subscriber.filter),
                bump_delivery_metric(AccState);
            false ->
                AccState
        end
    end, State, State#bus_state.subscribers).

should_deliver(Topic, Payload, Sub) ->
    TopicMatch = lists:member(Topic, Sub#subscriber.topics) orelse
                 lists:member(any, Sub#subscriber.topics),
    case TopicMatch of
        false -> false;
        true  ->
            case Sub#subscriber.filter of
                undefined -> true;
                FilterFun ->
                    try FilterFun(Topic, Payload)
                    catch _:_ -> false
                    end
            end
    end.

deliver_to_pid(Pid, Topic, Payload, _Filter) ->
    case erlang:is_process_alive(Pid) of
        true ->
            Pid ! {sbft_event, Topic, Payload};
        false ->
            ok
    end.

maybe_forward_to_rust(Topic, Payload, State) ->
    case lists:member(Topic, State#bus_state.rust_topics) of
        false ->
            State;
        true ->
            case State#bus_state.rust_bridge_pid of
                undefined ->
                    State;
                BridgePid ->
                    forward_to_rust(BridgePid, Topic, Payload, State)
            end
    end.

forward_to_rust(BridgePid, Topic, Payload, State) ->
    Encoded = encode_for_rust(Topic, Payload),
    case erlang:is_process_alive(BridgePid) of
        false ->
            error_logger:warning_msg(
                "[sbft_event_bus] Rust bridge pid dead, dropping event ~p~n",
                [Topic]
            ),
            State#bus_state{rust_bridge_pid = undefined};
        true ->
            BridgePid ! {ffi_event, Topic, Encoded},
            bump_ffi_metric(State)
    end.

encode_for_rust(block_finalized, Payload) ->
    #{
        type       => <<"block_finalized">>,
        shard_id   => maps:get(shard_id, Payload, <<>>),
        block_hash => maps:get(block_hash, Payload, <<>>),
        view       => maps:get(view, Payload, 0),
        height     => maps:get(height, Payload, 0),
        timestamp  => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(new_view_started, Payload) ->
    #{
        type       => <<"new_view_started">>,
        shard_id   => maps:get(shard_id, Payload, <<>>),
        new_view   => maps:get(new_view, Payload, 0),
        new_leader => maps:get(new_leader, Payload, <<>>),
        timestamp  => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(validator_slashed, Payload) ->
    #{
        type          => <<"validator_slashed">>,
        validator_id  => maps:get(validator_id, Payload, <<>>),
        reason        => atom_to_binary(maps:get(reason, Payload, unknown), utf8),
        shard_id      => maps:get(shard_id, Payload, <<>>),
        stake_slashed => maps:get(stake_slashed, Payload, 0),
        timestamp     => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(cross_shard_receipt, Payload) ->
    #{
        type             => <<"cross_shard_receipt">>,
        from_shard       => maps:get(from_shard, Payload, <<>>),
        to_shard         => maps:get(to_shard, Payload, <<>>),
        transaction_hash => maps:get(transaction_hash, Payload, <<>>),
        timestamp        => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(qc_formed, Payload) ->
    #{
        type       => <<"qc_formed">>,
        shard_id   => maps:get(shard_id, Payload, <<>>),
        view       => maps:get(view, Payload, 0),
        block_hash => maps:get(block_hash, Payload, <<>>),
        timestamp  => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(validator_deactivated, Payload) ->
    #{
        type         => <<"validator_deactivated">>,
        validator_id => maps:get(validator_id, Payload, <<>>),
        timestamp    => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(poc_report_received, Payload) ->
    #{
        type           => <<"poc_report">>,
        node_id        => maps:get(node_id, Payload, <<>>),
        shard_id       => maps:get(shard_id, Payload, <<>>),
        rsrp           => maps:get(rsrp, Payload, 0.0),
        rsrq           => maps:get(rsrq, Payload, 0.0),
        sinr           => maps:get(sinr, Payload, 0.0),
        timing_advance => maps:get(timing_advance, Payload, 0),
        h3_index       => maps:get(h3_index, Payload, <<>>),
        timestamp      => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(drs_score_emitted, Payload) ->
    #{
        type               => <<"drs_score">>,
        node_id            => maps:get(node_id, Payload, <<>>),
        shard_id           => maps:get(shard_id, Payload, <<>>),
        raw_score          => maps:get(raw_score, Payload, 0.0),
        bounded_multiplier => maps:get(bounded_multiplier, Payload, 0.0),
        epoch              => maps:get(epoch, Payload, 0),
        timestamp          => maps:get(bus_timestamp, Payload, 0)
    };
encode_for_rust(Topic, Payload) ->
    #{
        type      => atom_to_binary(Topic, utf8),
        payload   => term_to_binary(Payload),
        timestamp => maps:get(bus_timestamp, Payload, 0)
    }.

store_last_event(Topic, Payload, State) ->
    NewLastEvents = maps:put(Topic, Payload, State#bus_state.last_events),
    ets:insert(?LAST_EVENTS_TABLE, {Topic, Payload}),
    State#bus_state{last_events = NewLastEvents}.

maybe_start_rust_bridge() ->
    case application:get_env(erl_bridge, rust_bridge_enabled, false) of
        true ->
            case sbft_rust_bridge:connect() of
                {ok, Pid} ->
                    link(Pid),
                    Pid;
                {error, Reason} ->
                    error_logger:warning_msg(
                        "[sbft_event_bus] Rust bridge connect failed: ~p~n",
                        [Reason]
                    ),
                    undefined
            end;
        false ->
            undefined
    end.

rust_forwarded_topics() ->
    [
        block_finalized,
        new_view_started,
        validator_slashed,
        validator_deactivated,
        cross_shard_receipt,
        qc_formed,
        poc_report_received,
        drs_score_emitted,
        deploy_accepted,
        deploy_rejected
    ].

next_seq() ->
    case ets:update_counter(?LAST_EVENTS_TABLE, '_seq', {2, 1}, {'_seq', 0}) of
        N -> N
    end.

init_metrics() ->
    #{
        published_total    => 0,
        delivered_total    => 0,
        ffi_forwarded      => 0,
        by_topic           => #{}
    }.

bump_publish_metric(Topic, State) ->
    M  = State#bus_state.metrics,
    M1 = maps:update_with(published_total, fun(V) -> V + 1 end, 1, M),
    ByTopic  = maps:get(by_topic, M1, #{}),
    ByTopic1 = maps:update_with(Topic, fun(V) -> V + 1 end, 1, ByTopic),
    State#bus_state{metrics = M1#{by_topic => ByTopic1}}.

bump_delivery_metric(State) ->
    M  = State#bus_state.metrics,
    M1 = maps:update_with(delivered_total, fun(V) -> V + 1 end, 1, M),
    State#bus_state{metrics = M1}.

bump_ffi_metric(State) ->
    M  = State#bus_state.metrics,
    M1 = maps:update_with(ffi_forwarded, fun(V) -> V + 1 end, 1, M),
    State#bus_state{metrics = M1}.
