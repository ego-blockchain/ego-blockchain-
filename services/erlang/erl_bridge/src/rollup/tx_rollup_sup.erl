%%%-------------------------------------------------------------------
%%% @doc TxRollup Supervisor
%%% Manages TxRollup servers for L1 shard integration.
%%% Handles transaction batching, commitments, and challenge resolution.
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

%%--------------------------------------------------------------------
%% @doc Start the supervisor
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | {error, any()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%--------------------------------------------------------------------
%% @doc Start a new TxRollup server instance and register it
%%--------------------------------------------------------------------
-spec start_rollup(binary(), map()) -> {ok, pid()} | {error, term()}.
start_rollup(RollupId, Config) ->
    ChildSpec = #{
        id => {tx_rollup, RollupId},
        start => {tx_rollup_server, start_link, [RollupId, Config]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [tx_rollup_server]
    },
    case supervisor:start_child(?SERVER, ChildSpec) of
        {ok, Pid} ->
            io:format("[TxRollup] Started for ~p (pid=~p)~n", [RollupId, Pid]),
            tx_rollup_registry:register(RollupId, Pid),
            {ok, Pid};
        Error ->
            Error
    end.

%%--------------------------------------------------------------------
%% @doc Stop a TxRollup server instance and unregister it
%%--------------------------------------------------------------------
-spec stop_rollup(binary()) -> ok | {error, term()}.
stop_rollup(RollupId) ->
    tx_rollup_registry:unregister(RollupId),
    case supervisor:terminate_child(?SERVER, {tx_rollup, RollupId}) of
        ok ->
            supervisor:delete_child(?SERVER, {tx_rollup, RollupId});
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% Initialize supervisor strategy and start the registry
%%--------------------------------------------------------------------
-spec init(term()) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}} | ignore.
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
