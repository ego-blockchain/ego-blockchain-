%%%-------------------------------------------------------------------
%%% @doc ProofRollup Supervisor
%%% Manages ProofRollup servers for L1 shard integration.
%%% Handles PoC/PoSt/PoRep evidence aggregation and commitment acceptance.
%%%-------------------------------------------------------------------

-module(proof_rollup_sup).

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
%% @doc Starts the supervisor
%%--------------------------------------------------------------------
-spec start_link() -> {ok, Pid :: pid()} | {error, Reason :: term()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%--------------------------------------------------------------------
%% @doc Start a new ProofRollup server instance and register it
%%--------------------------------------------------------------------
-spec start_rollup(RollupId :: binary(), Config :: map()) ->
    {ok, Pid :: pid()} | {error, Reason :: term()}.
start_rollup(RollupId, Config) ->
    ChildSpec = #{
        id => {proof_rollup, RollupId},
        start => {proof_rollup_server, start_link, [RollupId, Config]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [proof_rollup_server]
    },
    case supervisor:start_child(?SERVER, ChildSpec) of
        {ok, Pid} ->
            proof_rollup_registry:register(RollupId, Pid),
            io:format("[ProofRollupSup] Registered rollup ~p -> ~p~n", [RollupId, Pid]),
            {ok, Pid};
        {error, Reason} ->
            io:format("[ProofRollupSup] Failed to start rollup ~p: ~p~n", [RollupId, Reason]),
            {error, Reason}
    end.

%%--------------------------------------------------------------------
%% @doc Stop and unregister a ProofRollup server instance
%%--------------------------------------------------------------------
-spec stop_rollup(RollupId :: binary()) -> ok | {error, not_found}.
stop_rollup(RollupId) ->
    proof_rollup_registry:unregister(RollupId),
    case supervisor:terminate_child(?SERVER, {proof_rollup, RollupId}) of
        ok ->
            supervisor:delete_child(?SERVER, {proof_rollup, RollupId});
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Initialize supervisor and start registry
%%--------------------------------------------------------------------
-spec init(Args :: term()) ->
    {ok, {SupFlags :: supervisor:sup_flags(),
          [ChildSpec :: supervisor:child_spec()]}} | ignore.
init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },

    %% Start the ProofRollup registry
    RegistrySpec = #{
        id => proof_rollup_registry,
        start => {proof_rollup_registry, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [proof_rollup_registry]
    },

    {ok, {SupFlags, [RegistrySpec]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
