-module(sbft_rust_bridge).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([
    start_link/0,
    connect/0,
    disconnect/0,
    send_event/2,
    send_command/2,
    send_command_sync/3,
    get_status/0,
    get_metrics/0,
    is_connected/0,
    set_rust_topics/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(SERVER,                 ?MODULE).
-define(SOCKET_PATH_ENV,        rust_bridge_socket_path).
-define(DEFAULT_SOCKET_PATH,    "/tmp/ego_sbft_bridge.sock").
-define(DEFAULT_PORT,           14777).
-define(CONNECT_TIMEOUT_MS,     3000).
-define(SEND_TIMEOUT_MS,        1000).
-define(HEARTBEAT_INTERVAL_MS,  5000).
-define(MAX_BACKOFF_MS,         60000).
-define(BASE_BACKOFF_MS,        500).
-define(MAX_QUEUE_LEN,          2000).
-define(BACKPRESSURE_HIGH,      1500).
-define(BACKPRESSURE_LOW,       500).
-define(PROTOCOL_VERSION,       1).
-define(MSG_TYPE_EVENT,         1).
-define(MSG_TYPE_COMMAND,       2).
-define(MSG_TYPE_REPLY,         3).
-define(MSG_TYPE_HEARTBEAT,     4).
-define(MSG_TYPE_HANDSHAKE,     5).

-type connection_state() :: disconnected | connecting | connected | backpressure.
-type transport()        :: tcp | unix_socket.

-record(pending_call, {
    from        :: gen_server:from(),
    command_id  :: binary(),
    sent_at     :: timestamp_ms(),
    timeout_ref :: reference()
}).

-record(bridge_state, {
    connection_state    = disconnected :: connection_state(),
    transport           = tcp          :: transport(),
    socket              :: gen_tcp:socket() | undefined,
    host                :: string(),
    port                :: inet:port_number(),
    socket_path         :: string(),
    reconnect_attempts  = 0    :: non_neg_integer(),
    reconnect_timer     :: reference() | undefined,
    heartbeat_timer     :: reference() | undefined,
    outbound_queue      = []   :: [binary()],
    queue_len           = 0    :: non_neg_integer(),
    pending_calls       = #{}  :: #{binary() => #pending_call{}},
    metrics             = #{}  :: map(),
    rust_topics         = []   :: [atom()],
    last_heartbeat_at   :: timestamp_ms() | undefined,
    protocol_version    = ?PROTOCOL_VERSION :: non_neg_integer(),
    partial_buffer      = <<>> :: binary()
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

connect() ->
    gen_server:call(?SERVER, connect).

disconnect() ->
    gen_server:call(?SERVER, disconnect).

send_event(Topic, Payload) when is_atom(Topic), is_map(Payload) ->
    gen_server:cast(?SERVER, {send_event, Topic, Payload}).

send_command(Command, Args) when is_atom(Command), is_map(Args) ->
    gen_server:cast(?SERVER, {send_command, Command, Args, undefined}).

send_command_sync(Command, Args, TimeoutMs) ->
    gen_server:call(?SERVER, {send_command_sync, Command, Args, TimeoutMs}, TimeoutMs + 1000).

get_status() ->
    gen_server:call(?SERVER, get_status).

get_metrics() ->
    gen_server:call(?SERVER, get_metrics).

is_connected() ->
    gen_server:call(?SERVER, is_connected).

set_rust_topics(Topics) ->
    gen_server:call(?SERVER, {set_rust_topics, Topics}).

init([]) ->
    process_flag(trap_exit, true),
    Host       = application:get_env(erl_bridge, rust_bridge_host, "127.0.0.1"),
    Port       = application:get_env(erl_bridge, rust_bridge_port, ?DEFAULT_PORT),
    SocketPath = application:get_env(erl_bridge, rust_bridge_socket_path, ?DEFAULT_SOCKET_PATH),
    Transport  = application:get_env(erl_bridge, rust_bridge_transport, tcp),
    State = #bridge_state{
        transport   = Transport,
        host        = Host,
        port        = Port,
        socket_path = SocketPath,
        metrics     = init_metrics(),
        rust_topics = default_rust_topics()
    },
    self() ! attempt_connect,
    {ok, State}.

handle_call(connect, _From, State) ->
    case do_connect(State) of
        {ok, NewState} ->
            {reply, {ok, self()}, NewState};
        {error, Reason, NewState} ->
            {reply, {error, Reason}, NewState}
    end;

handle_call(disconnect, _From, State) ->
    NewState = do_disconnect(State),
    {reply, ok, NewState};

handle_call({send_command_sync, Command, Args, TimeoutMs}, From, State) ->
    case State#bridge_state.connection_state of
        connected ->
            CommandId  = generate_command_id(),
            Encoded    = encode_command(CommandId, Command, Args),
            TimerRef   = erlang:send_after(TimeoutMs, self(), {command_timeout, CommandId}),
            Pending    = #pending_call{
                from        = From,
                command_id  = CommandId,
                sent_at     = erlang:system_time(millisecond),
                timeout_ref = TimerRef
            },
            NewPending = maps:put(CommandId, Pending, State#bridge_state.pending_calls),
            NewState   = enqueue_message(Encoded, State#bridge_state{pending_calls = NewPending}),
            {noreply, NewState};
        _ ->
            {reply, {error, not_connected}, State}
    end;

handle_call(get_status, _From, State) ->
    Status = #{
        connection_state   => State#bridge_state.connection_state,
        transport          => State#bridge_state.transport,
        reconnect_attempts => State#bridge_state.reconnect_attempts,
        queue_len          => State#bridge_state.queue_len,
        pending_calls      => maps:size(State#bridge_state.pending_calls),
        last_heartbeat_at  => State#bridge_state.last_heartbeat_at
    },
    {reply, {ok, Status}, State};

handle_call(get_metrics, _From, State) ->
    {reply, {ok, State#bridge_state.metrics}, State};

handle_call(is_connected, _From, State) ->
    {reply, State#bridge_state.connection_state =:= connected, State};

handle_call({set_rust_topics, Topics}, _From, State) ->
    {reply, ok, State#bridge_state{rust_topics = Topics}};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({send_event, Topic, Payload}, State) ->
    case State#bridge_state.connection_state of
        disconnected ->
            {noreply, State};
        backpressure ->
            Metrics  = bump_metric(dropped_backpressure, State#bridge_state.metrics),
            {noreply, State#bridge_state{metrics = Metrics}};
        _ ->
            Encoded  = encode_event(Topic, Payload),
            NewState = enqueue_message(Encoded, State),
            {noreply, NewState}
    end;

handle_cast({send_command, Command, Args, _From}, State) ->
    case State#bridge_state.connection_state of
        connected ->
            CommandId = generate_command_id(),
            Encoded   = encode_command(CommandId, Command, Args),
            NewState  = enqueue_message(Encoded, State),
            {noreply, NewState};
        _ ->
            {noreply, State}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(attempt_connect, State) ->
    case do_connect(State) of
        {ok, NewState} ->
            {noreply, NewState};
        {error, _Reason, NewState} ->
            ScheduledState = schedule_reconnect(NewState),
            {noreply, ScheduledState}
    end;

handle_info(send_queued, State) ->
    NewState = flush_outbound_queue(State),
    {noreply, NewState};

handle_info(heartbeat, State) ->
    NewState = send_heartbeat(State),
    {noreply, NewState};

handle_info({command_timeout, CommandId}, State) ->
    case maps:get(CommandId, State#bridge_state.pending_calls, undefined) of
        undefined ->
            {noreply, State};
        Pending ->
            gen_server:reply(Pending#pending_call.from, {error, timeout}),
            NewPending = maps:remove(CommandId, State#bridge_state.pending_calls),
            Metrics    = bump_metric(command_timeouts, State#bridge_state.metrics),
            {noreply, State#bridge_state{
                pending_calls = NewPending,
                metrics       = Metrics
            }}
    end;

handle_info({tcp, Socket, Data}, #bridge_state{socket = Socket} = State) ->
    NewState = handle_incoming_data(Data, State),
    {noreply, NewState};

handle_info({tcp_closed, Socket}, #bridge_state{socket = Socket} = State) ->
    error_logger:warning_msg("[sbft_rust_bridge] TCP connection closed~n"),
    NewState = handle_disconnect(State),
    {noreply, NewState};

handle_info({tcp_error, Socket, Reason}, #bridge_state{socket = Socket} = State) ->
    error_logger:warning_msg("[sbft_rust_bridge] TCP error: ~p~n", [Reason]),
    NewState = handle_disconnect(State),
    {noreply, NewState};

handle_info({'EXIT', _Pid, Reason}, State) ->
    error_logger:warning_msg("[sbft_rust_bridge] linked process exited: ~p~n", [Reason]),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timer(State#bridge_state.reconnect_timer),
    cancel_timer(State#bridge_state.heartbeat_timer),
    do_disconnect(State),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

do_connect(State) ->
    NewState0 = State#bridge_state{connection_state = connecting},
    Result = case State#bridge_state.transport of
        tcp          -> connect_tcp(NewState0);
        unix_socket  -> connect_unix(NewState0)
    end,
    case Result of
        {ok, ConnectedState} ->
            FinalState = on_connected(ConnectedState),
            {ok, FinalState};
        {error, Reason} ->
            Metrics    = bump_metric(connect_failures, State#bridge_state.metrics),
            ErrorState = State#bridge_state{
                connection_state   = disconnected,
                reconnect_attempts = State#bridge_state.reconnect_attempts + 1,
                metrics            = Metrics
            },
            {error, Reason, ErrorState}
    end.

connect_tcp(State) ->
    Host    = State#bridge_state.host,
    Port    = State#bridge_state.port,
    Options = [
        binary,
        {active, true},
        {packet, 4},
        {nodelay, true},
        {keepalive, true},
        {send_timeout, ?SEND_TIMEOUT_MS}
    ],
    case gen_tcp:connect(Host, Port, Options, ?CONNECT_TIMEOUT_MS) of
        {ok, Socket} ->
            {ok, State#bridge_state{socket = Socket}};
        {error, Reason} ->
            {error, Reason}
    end.

connect_unix(State) ->
    SocketPath = State#bridge_state.socket_path,
    Options    = [
        binary,
        {active, true},
        {packet, 4},
        {nodelay, true}
    ],
    case gen_tcp:connect({local, SocketPath}, 0, Options, ?CONNECT_TIMEOUT_MS) of
        {ok, Socket} ->
            {ok, State#bridge_state{socket = Socket}};
        {error, Reason} ->
            {error, Reason}
    end.

on_connected(State) ->
    cancel_timer(State#bridge_state.reconnect_timer),
    HeartbeatRef = erlang:send_after(?HEARTBEAT_INTERVAL_MS, self(), heartbeat),
    NewState = State#bridge_state{
        connection_state   = connected,
        reconnect_attempts = 0,
        reconnect_timer    = undefined,
        heartbeat_timer    = HeartbeatRef,
        last_heartbeat_at  = erlang:system_time(millisecond)
    },
    Metrics  = bump_metric(successful_connects, NewState#bridge_state.metrics),
    NewState1 = NewState#bridge_state{metrics = Metrics},
    send_handshake(NewState1),
    sbft_event_bus:publish(rust_bridge_connected, #{
        transport => NewState1#bridge_state.transport,
        host      => NewState1#bridge_state.host,
        port      => NewState1#bridge_state.port
    }),
    error_logger:info_msg("[sbft_rust_bridge] connected to Rust ego-consensus~n"),
    flush_outbound_queue(NewState1).

do_disconnect(State) ->
    cancel_timer(State#bridge_state.heartbeat_timer),
    case State#bridge_state.socket of
        undefined -> ok;
        Socket    -> catch gen_tcp:close(Socket)
    end,
    fail_pending_calls(State#bridge_state.pending_calls),
    State#bridge_state{
        connection_state = disconnected,
        socket           = undefined,
        heartbeat_timer  = undefined,
        pending_calls    = #{}
    }.

handle_disconnect(State) ->
    NewState = do_disconnect(State),
    schedule_reconnect(NewState).

schedule_reconnect(State) ->
    cancel_timer(State#bridge_state.reconnect_timer),
    Attempts  = State#bridge_state.reconnect_attempts,
    BackoffMs = min(?BASE_BACKOFF_MS * (1 bsl min(Attempts, 7)), ?MAX_BACKOFF_MS),
    Jitter    = rand:uniform(BackoffMs div 4 + 1),
    Delay     = BackoffMs + Jitter,
    error_logger:info_msg(
        "[sbft_rust_bridge] reconnecting in ~p ms (attempt ~p)~n",
        [Delay, Attempts + 1]
    ),
    TimerRef = erlang:send_after(Delay, self(), attempt_connect),
    State#bridge_state{
        reconnect_timer    = TimerRef,
        reconnect_attempts = Attempts + 1
    }.

send_handshake(State) ->
    Handshake = #{
        msg_type         => ?MSG_TYPE_HANDSHAKE,
        protocol_version => State#bridge_state.protocol_version,
        node_id          => get_node_id(),
        capabilities     => sbft_nif:capabilities(),
        subscribed_topics => [atom_to_binary(T, utf8) || T <- State#bridge_state.rust_topics],
        timestamp        => erlang:system_time(millisecond)
    },
    Encoded = encode_message(Handshake),
    send_raw(Encoded, State).

send_heartbeat(State) ->
    case State#bridge_state.connection_state of
        connected ->
            Hb = #{
                msg_type  => ?MSG_TYPE_HEARTBEAT,
                timestamp => erlang:system_time(millisecond),
                queue_len => State#bridge_state.queue_len
            },
            Encoded  = encode_message(Hb),
            NewState = send_raw(Encoded, State),
            HbTimer  = erlang:send_after(?HEARTBEAT_INTERVAL_MS, self(), heartbeat),
            NewState#bridge_state{
                heartbeat_timer   = HbTimer,
                last_heartbeat_at = erlang:system_time(millisecond)
            };
        _ ->
            State
    end.

enqueue_message(Encoded, State) ->
    QueueLen = State#bridge_state.queue_len,
    case QueueLen >= ?MAX_QUEUE_LEN of
        true ->
            Metrics = bump_metric(dropped_overflow, State#bridge_state.metrics),
            State#bridge_state{metrics = Metrics};
        false ->
            NewQueue   = State#bridge_state.outbound_queue ++ [Encoded],
            NewQueueLen = QueueLen + 1,
            NewState   = State#bridge_state{
                outbound_queue = NewQueue,
                queue_len      = NewQueueLen
            },
            case NewQueueLen >= ?BACKPRESSURE_HIGH of
                true  ->
                    error_logger:warning_msg(
                        "[sbft_rust_bridge] backpressure threshold reached (~p msgs)~n",
                        [NewQueueLen]
                    ),
                    NewState#bridge_state{connection_state = backpressure};
                false ->
                    self() ! send_queued,
                    NewState
            end
    end.

flush_outbound_queue(State) ->
    case State#bridge_state.socket of
        undefined ->
            State;
        _ ->
            {Sent, Remaining, FinalState} = lists:foldl(
                fun(Msg, {SentAcc, [], S}) ->
                    case send_raw(Msg, S) of
                        S2 when is_record(S2, bridge_state) ->
                            {SentAcc + 1, [], S2};
                        _ ->
                            {SentAcc, [Msg], S}
                    end;
                   (Msg, {SentAcc, Remaining, S}) ->
                    {SentAcc, Remaining ++ [Msg], S}
                end,
                {0, [], State},
                State#bridge_state.outbound_queue
            ),
            NewQueueLen = length(Remaining),
            Metrics     = bump_metric_by(messages_sent, Sent, FinalState#bridge_state.metrics),
            NewConnState = case NewQueueLen =< ?BACKPRESSURE_LOW of
                true  -> connected;
                false -> FinalState#bridge_state.connection_state
            end,
            FinalState#bridge_state{
                outbound_queue   = Remaining,
                queue_len        = NewQueueLen,
                metrics          = Metrics,
                connection_state = NewConnState
            }
    end.

send_raw(Encoded, State) ->
    case State#bridge_state.socket of
        undefined ->
            State;
        Socket ->
            case gen_tcp:send(Socket, Encoded) of
                ok ->
                    State;
                {error, Reason} ->
                    error_logger:warning_msg(
                        "[sbft_rust_bridge] send failed: ~p~n",
                        [Reason]
                    ),
                    handle_disconnect(State)
            end
    end.

handle_incoming_data(Data, State) ->
    Buffer  = <<(State#bridge_state.partial_buffer)/binary, Data/binary>>,
    {Messages, Remaining} = split_messages(Buffer),
    NewState = State#bridge_state{partial_buffer = Remaining},
    lists:foldl(fun(Msg, AccState) ->
        process_incoming_message(Msg, AccState)
    end, NewState, Messages).

split_messages(Buffer) ->
    split_messages(Buffer, []).

split_messages(<<Len:32/big, Rest/binary>> = Buffer, Acc) ->
    case byte_size(Rest) >= Len of
        true ->
            <<Msg:Len/binary, Remaining/binary>> = Rest,
            split_messages(Remaining, [Msg | Acc]);
        false ->
            {lists:reverse(Acc), Buffer}
    end;
split_messages(Buffer, Acc) ->
    {lists:reverse(Acc), Buffer}.

process_incoming_message(RawMsg, State) ->
    case decode_message(RawMsg) of
        {ok, Decoded} ->
            dispatch_incoming(Decoded, State);
        {error, Reason} ->
            error_logger:warning_msg(
                "[sbft_rust_bridge] failed to decode message: ~p~n",
                [Reason]
            ),
            Metrics = bump_metric(decode_errors, State#bridge_state.metrics),
            State#bridge_state{metrics = Metrics}
    end.

dispatch_incoming(#{msg_type := ?MSG_TYPE_REPLY} = Msg, State) ->
    handle_command_reply(Msg, State);
dispatch_incoming(#{msg_type := ?MSG_TYPE_HEARTBEAT}, State) ->
    State#bridge_state{last_heartbeat_at = erlang:system_time(millisecond)};
dispatch_incoming(#{msg_type := ?MSG_TYPE_COMMAND} = Msg, State) ->
    handle_rust_command(Msg, State);
dispatch_incoming(Msg, State) ->
    error_logger:warning_msg(
        "[sbft_rust_bridge] unknown message type: ~p~n",
        [maps:get(msg_type, Msg, undefined)]
    ),
    State.

handle_command_reply(Msg, State) ->
    CommandId = maps:get(command_id, Msg, undefined),
    case maps:get(CommandId, State#bridge_state.pending_calls, undefined) of
        undefined ->
            State;
        Pending ->
            cancel_timer(Pending#pending_call.timeout_ref),
            Result     = maps:get(result, Msg, ok),
            gen_server:reply(Pending#pending_call.from, {ok, Result}),
            NewPending = maps:remove(CommandId, State#bridge_state.pending_calls),
            Metrics    = bump_metric(command_replies_received, State#bridge_state.metrics),
            State#bridge_state{
                pending_calls = NewPending,
                metrics       = Metrics
            }
    end.

handle_rust_command(Msg, State) ->
    Command = maps:get(command, Msg, undefined),
    Args    = maps:get(args, Msg, #{}),
    dispatch_rust_command(Command, Args, State).

dispatch_rust_command(<<"propose_block">>, Args, State) ->
    ShardId   = maps:get(<<"shard_id">>, Args, undefined),
    BlockData = maps:get(<<"block">>, Args, #{}),
    case ShardId =/= undefined of
        true ->
            case sbft_consensus_manager:get_shard_status(ShardId) of
                {ok, _} ->
                    Block = decode_block_from_rust(BlockData),
                    sbft_consensus_manager:propose_to_shard(ShardId, Block);
                {error, _} ->
                    ok
            end;
        false ->
            ok
    end,
    State;

dispatch_rust_command(<<"add_validator">>, Args, State) ->
    ShardId   = maps:get(<<"shard_id">>, Args, undefined),
    ValidatorData = maps:get(<<"validator">>, Args, #{}),
    case ShardId =/= undefined of
        true ->
            Validator = decode_validator_from_rust(ValidatorData),
            sbft_validator_manager:register_validator(
                Validator#sbft_validator_record.id,
                validator_to_map(Validator)
            );
        false ->
            ok
    end,
    State;

dispatch_rust_command(<<"remove_validator">>, Args, State) ->
    ValidatorId = maps:get(<<"validator_id">>, Args, undefined),
    ShardId     = maps:get(<<"shard_id">>, Args, undefined),
    case ValidatorId =/= undefined andalso ShardId =/= undefined of
        true  -> sbft_validator_manager:slash_validator(ValidatorId, removed_by_rust);
        false -> ok
    end,
    State;

dispatch_rust_command(<<"get_shard_status">>, Args, State) ->
    ShardId   = maps:get(<<"shard_id">>, Args, undefined),
    CommandId = maps:get(command_id, Args, undefined),
    case ShardId =/= undefined of
        true ->
            Result = case sbft_consensus_manager:get_shard_status(ShardId) of
                {ok, Status} -> Status;
                {error, R}   -> #{error => R}
            end,
            Reply = encode_reply(CommandId, Result),
            send_raw(Reply, State);
        false ->
            State
    end;

dispatch_rust_command(<<"force_view_change">>, Args, State) ->
    ShardId = maps:get(<<"shard_id">>, Args, undefined),
    case ShardId =/= undefined of
        true ->
            case sbft_consensus_manager:get_shard_pid(ShardId) of
                {ok, Pid} -> sbft_shard_consensus:force_view_change(Pid);
                _         -> ok
            end;
        false ->
            ok
    end,
    State;

dispatch_rust_command(Command, _Args, State) ->
    error_logger:warning_msg(
        "[sbft_rust_bridge] unknown Rust command: ~p~n",
        [Command]
    ),
    State.

encode_event(Topic, Payload) ->
    Msg = #{
        msg_type  => ?MSG_TYPE_EVENT,
        topic     => atom_to_binary(Topic, utf8),
        payload   => Payload,
        timestamp => erlang:system_time(millisecond)
    },
    encode_message(Msg).

encode_command(CommandId, Command, Args) ->
    Msg = #{
        msg_type   => ?MSG_TYPE_COMMAND,
        command_id => CommandId,
        command    => atom_to_binary(Command, utf8),
        args       => Args,
        timestamp  => erlang:system_time(millisecond)
    },
    encode_message(Msg).

encode_reply(CommandId, Result) ->
    Msg = #{
        msg_type   => ?MSG_TYPE_REPLY,
        command_id => CommandId,
        result     => Result,
        timestamp  => erlang:system_time(millisecond)
    },
    encode_message(Msg).

encode_message(Msg) ->
    Encoded = term_to_binary(Msg, [compressed]),
    Len     = byte_size(Encoded),
    <<Len:32/big, Encoded/binary>>.

decode_message(Raw) ->
    try
        Decoded = binary_to_term(Raw, [safe]),
        {ok, Decoded}
    catch
        _:Reason ->
            {error, {decode_failed, Reason}}
    end.

decode_block_from_rust(BlockData) ->
    #sbft_block_record{
        hash                 = maps:get(<<"hash">>, BlockData, <<>>),
        view                 = maps:get(<<"view">>, BlockData, 0),
        height               = maps:get(<<"height">>, BlockData, 0),
        proposer             = maps:get(<<"proposer">>, BlockData, <<>>),
        transactions         = maps:get(<<"transactions">>, BlockData, []),
        parent_hash          = maps:get(<<"parent_hash">>, BlockData, <<>>),
        timestamp            = erlang:system_time(millisecond),
        signature            = maps:get(<<"signature">>, BlockData, <<>>),
        shard_id             = maps:get(<<"shard_id">>, BlockData, <<>>),
        cross_shard_receipts = [],
        state_root           = maps:get(<<"state_root">>, BlockData, <<>>),
        erasure_coded        = maps:get(<<"erasure_coded">>, BlockData, false)
    }.

decode_validator_from_rust(ValidatorData) ->
    #sbft_validator_record{
        id             = maps:get(<<"id">>, ValidatorData, <<>>),
        public_key     = maps:get(<<"public_key">>, ValidatorData, <<>>),
        pqc_public_key = maps:get(<<"pqc_public_key">>, ValidatorData, undefined),
        kem_public_key = maps:get(<<"kem_public_key">>, ValidatorData, undefined),
        sig_algorithm  = binary_to_existing_atom(
                           maps:get(<<"sig_algorithm">>, ValidatorData, <<"ed25519">>),
                           utf8
                         ),
        stake          = maps:get(<<"stake">>, ValidatorData, 0),
        is_active      = maps:get(<<"is_active">>, ValidatorData, true),
        shard_id       = maps:get(<<"shard_id">>, ValidatorData, <<>>),
        role           = replica,
        capability     = legacy,
        reputation     = 1.0,
        performance_score = 1.0,
        last_seen      = erlang:system_time(millisecond),
        last_vote_view = undefined,
        slashing_events = 0
    }.

validator_to_map(V) ->
    #{
        public_key     => V#sbft_validator_record.public_key,
        pqc_public_key => V#sbft_validator_record.pqc_public_key,
        kem_public_key => V#sbft_validator_record.kem_public_key,
        stake          => V#sbft_validator_record.stake,
        is_active      => V#sbft_validator_record.is_active,
        shard_id       => V#sbft_validator_record.shard_id,
        sig_algorithm  => V#sbft_validator_record.sig_algorithm
    }.

fail_pending_calls(PendingCalls) ->
    maps:foreach(fun(_CommandId, Pending) ->
        cancel_timer(Pending#pending_call.timeout_ref),
        gen_server:reply(Pending#pending_call.from, {error, bridge_disconnected})
    end, PendingCalls).

generate_command_id() ->
    Rand = crypto:strong_rand_bytes(8),
    TS   = erlang:system_time(microsecond),
    sbft_crypto:hash(blake2s, <<Rand/binary, TS:64/big>>).

get_node_id() ->
    case application:get_env(erl_bridge, node_id, undefined) of
        undefined -> atom_to_binary(node(), utf8);
        NodeId    -> NodeId
    end.

default_rust_topics() ->
    [
        block_finalized,
        new_view_started,
        validator_slashed,
        cross_shard_receipt,
        qc_formed,
        poc_report_received,
        drs_score_emitted,
        deploy_accepted,
        deploy_rejected
    ].

cancel_timer(undefined) -> ok;
cancel_timer(Ref)       -> erlang:cancel_timer(Ref), ok.

init_metrics() ->
    #{
        successful_connects      => 0,
        connect_failures         => 0,
        messages_sent            => 0,
        dropped_backpressure     => 0,
        dropped_overflow         => 0,
        decode_errors            => 0,
        command_timeouts         => 0,
        command_replies_received => 0
    }.

bump_metric(Key, Metrics) ->
    maps:update_with(Key, fun(V) -> V + 1 end, 1, Metrics).

bump_metric_by(Key, N, Metrics) ->
    maps:update_with(Key, fun(V) -> V + N end, N, Metrics).
