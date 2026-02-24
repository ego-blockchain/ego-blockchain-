-module(erl_bridge_app).
-behaviour(application).

-export([start/2, stop/1, get_env/2, get_env/3]).

start(_StartType, _StartArgs) ->
    ok = load_environment(),
    ok = ensure_crypto_started(),
    case erl_bridge_sup:start_link() of
        {ok, Pid} ->
            ok = maybe_load_nif(),
            ok = maybe_start_demo_shards(),
            {ok, Pid};
        {error, Reason} ->
            {error, Reason}
    end.

stop(_State) ->
    ok.

get_env(Key, Default) ->
    application:get_env(erl_bridge, Key, Default).

get_env(App, Key, Default) ->
    application:get_env(App, Key, Default).

load_environment() ->
    Defaults = [
        {rust_bridge_enabled,       false},
        {rust_bridge_transport,     tcp},
        {rust_bridge_host,          "127.0.0.1"},
        {rust_bridge_port,          14777},
        {rust_bridge_socket_path,   "/tmp/ego_sbft_bridge.sock"},
        {pqc_enabled,               true},
        {sig_algorithm,             dilithium2},
        {consensus_timeout_ms,      3000},
        {view_change_timeout_ms,    6000},
        {min_validators_per_shard,  4},
        {max_validators_per_shard,  100},
        {demo_mode,                 false},
        {node_id,                   undefined},
        {log_level,                 info}
    ],
    lists:foreach(fun({Key, Default}) ->
        case application:get_env(erl_bridge, Key) of
            undefined -> application:set_env(erl_bridge, Key, Default);
            {ok, _}   -> ok
        end
    end, Defaults),
    ok.

ensure_crypto_started() ->
    case application:ensure_started(crypto) of
        ok                          -> ok;
        {error, {already_started,_}} -> ok;
        {error, Reason}             -> {error, Reason}
    end.

maybe_load_nif() ->
    case sbft_nif:load() of
        ok -> ok;
        _  -> ok
    end.

maybe_start_demo_shards() ->
    case application:get_env(erl_bridge, demo_mode, false) of
        true  -> start_demo_shards();
        false -> ok
    end.

start_demo_shards() ->
    error_logger:info_msg("[erl_bridge_app] starting demo shards~n"),
    DemoConfig = #{
        pqc_enabled         => application:get_env(erl_bridge, pqc_enabled, true),
        consensus_timeout   => application:get_env(erl_bridge, consensus_timeout_ms, 3000),
        view_change_timeout => application:get_env(erl_bridge, view_change_timeout_ms, 6000)
    },
    Shards = application:get_env(erl_bridge, demo_shards, [<<"shard_001">>]),
    lists:foreach(fun(ShardId) ->
        case sbft_consensus_manager:start_shard_consensus(ShardId, DemoConfig) of
            {ok, _Pid} ->
                error_logger:info_msg(
                    "[erl_bridge_app] demo shard ~p started~n", [ShardId]
                );
            {error, Reason} ->
                error_logger:warning_msg(
                    "[erl_bridge_app] demo shard ~p failed: ~p~n", [ShardId, Reason]
                )
        end
    end, Shards),
    ok.
