%%%-------------------------------------------------------------------
%%% @doc ProofRollup Supervisor
%%% Manages ProofRollup servers for L1 shard integration
%%% Handles PoC/PoSt/PoRep evidence aggregation and commitment acceptance
%%% @end
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
%% @doc
%% Starts the supervisor
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, Pid :: pid()} | {error, Reason :: term()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%--------------------------------------------------------------------
%% @doc
%% Start a new ProofRollup server instance
%% @end
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
    supervisor:start_child(?SERVER, ChildSpec).

%%--------------------------------------------------------------------
%% @doc
%% Stop a ProofRollup server instance
%% @end
%%--------------------------------------------------------------------
-spec stop_rollup(RollupId :: binary()) -> ok | {error, not_found}.
stop_rollup(RollupId) ->
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
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart intensity, and child
%% specifications.
%% @end
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
