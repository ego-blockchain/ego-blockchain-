-module(erl_bridge_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).
-export([start_child_shard/2, stop_child_shard/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_child_shard(ShardId, Config) ->
    ChildSpec = shard_child_spec(ShardId, Config),
    supervisor:start_child(?SERVER, ChildSpec).

stop_child_shard(ShardId) ->
    ChildId = shard_child_id(ShardId),
    case supervisor:terminate_child(?SERVER, ChildId) of
        ok -> supervisor:delete_child(?SERVER, ChildId);
        {error, Reason} -> {error, Reason}
    end.

init([]) ->
    SupFlags = #{
        strategy  => rest_for_one,
        intensity => 10,
        period    => 60
    },
    ChildSpecs = [
        #{
            id       => sbft_event_bus,
            start    => {sbft_event_bus, start_link, []},
            restart  => permanent,
            shutdown => 5000,
            type     => worker,
            modules  => [sbft_event_bus]
        },
        #{
            id       => sbft_nif,
            start    => {sbft_nif_server, start_link, []},
            restart  => permanent,
            shutdown => 3000,
            type     => worker,
            modules  => [sbft_nif_server]
        },
        #{
            id       => sbft_validator_manager,
            start    => {sbft_validator_manager, start_link, []},
            restart  => permanent,
            shutdown => 10000,
            type     => worker,
            modules  => [sbft_validator_manager]
        },
        #{
            id       => sbft_slashing,
            start    => {sbft_slashing, start_link, []},
            restart  => permanent,
            shutdown => 5000,
            type     => worker,
            modules  => [sbft_slashing]
        },
        #{
            id       => sbft_cross_shard,
            start    => {sbft_cross_shard, start_link, []},
            restart  => permanent,
            shutdown => 10000,
            type     => worker,
            modules  => [sbft_cross_shard]
        },
        #{
            id       => sbft_consensus_manager,
            start    => {sbft_consensus_manager, start_link, []},
            restart  => permanent,
            shutdown => 30000,
            type     => worker,
            modules  => [sbft_consensus_manager]
        },
        #{
            id       => sbft_rust_bridge,
            start    => {sbft_rust_bridge, start_link, []},
            restart  => permanent,
            shutdown => 5000,
            type     => worker,
            modules  => [sbft_rust_bridge]
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.

shard_child_spec(ShardId, Config) ->
    ChildId = shard_child_id(ShardId),
    #{
        id       => ChildId,
        start    => {sbft_shard_consensus, start_link, [ShardId, Config]},
        restart  => transient,
        shutdown => 10000,
        type     => worker,
        modules  => [sbft_shard_consensus]
    }.

shard_child_id(ShardId) ->
    binary_to_atom(<<"sbft_shard_", ShardId/binary>>, utf8).
