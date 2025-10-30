%%%-------------------------------------------------------------------
%%% @doc TxRollup Supervisor
%%% Manages TxRollup servers for L1 shard integration
%%% Handles transaction batching, commitments, and challenge resolution
%%% @end
%%%-------------------------------------------------------------------

-module(tx_rollup_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_rollup/2, stop_rollup/1]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

-spec start_rollup(RollupId :: binary(), Config :: map()) -> 
    {ok, Pid :: pid()} | {error, Reason :: term()}.
start_rollup(RollupId, Config) ->
    ChildSpec = #{
        id => {tx_rollup, RollupId},
        start => {tx_rollup_server, start_link, [RollupId, Config]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [tx_rollup_server]
    },
    supervisor:start_child(?SERVER, ChildSpec).

-spec stop_rollup(RollupId :: binary()) -> ok | {error, not_found}.
stop_rollup(RollupId) ->
    case supervisor:terminate_child(?SERVER, {tx_rollup, RollupId}) of
        ok ->
            supervisor:delete_child(?SERVER, {tx_rollup, RollupId});
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

-spec init(Args :: term()) ->
    {ok, {SupFlags :: supervisor:sup_flags(),
          [ChildSpec :: supervisor:child_spec()]}} | ignore.
init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },
    
    RegistrySpec = #{
        id => tx_rollup_registry,
        start => {tx_rollup_registry, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [tx_rollup_registry]
    },
    
    {ok, {SupFlags, [RegistrySpec]}}.
