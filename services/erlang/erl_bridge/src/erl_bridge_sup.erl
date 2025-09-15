-module(erl_bridge_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },
    ChildSpecs = [
        #{
            id => sbft_consensus_manager,
            start => {sbft_consensus_manager, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [sbft_consensus_manager]
        },
        #{
            id => sbft_cross_shard,
            start => {sbft_cross_shard, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [sbft_cross_shard]
        },
        #{
            id => sbft_validator_manager,
            start => {sbft_validator_manager, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [sbft_validator_manager]
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.
