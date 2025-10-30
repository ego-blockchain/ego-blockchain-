%%%-------------------------------------------------------------------
%%% @doc TxRollup Registry
%%% Keeps track of active TxRollup servers managed by tx_rollup_sup.
%%% Allows registration, lookup, unregistration, and listing of rollups.
%%%-------------------------------------------------------------------

-module(tx_rollup_registry).
-behaviour(gen_server).

%% API
-export([start_link/0, register/2, unregister/1, whereis/1, list/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%%%===================================================================
%%% API FUNCTIONS
%%%===================================================================

-spec start_link() -> {ok, pid()} | {error, any()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Register a rollup ID with its process PID
-spec register(binary(), pid()) -> ok.
register(RollupId, Pid) ->
    gen_server:call(?MODULE, {register, RollupId, Pid}).

%% Unregister a rollup ID
-spec unregister(binary()) -> ok.
unregister(RollupId) ->
    gen_server:call(?MODULE, {unregister, RollupId}).

%% Lookup rollup PID by RollupId
-spec whereis(binary()) -> {ok, pid()} | not_found.
whereis(RollupId) ->
    gen_server:call(?MODULE, {whereis, RollupId}).

%% List all registered rollups
-spec list() -> [{binary(), pid()}].
list() ->
    gen_server:call(?MODULE, list).

%%%===================================================================
%%% GEN_SERVER CALLBACKS
%%%===================================================================

init([]) ->
    io:format("[TxRollupRegistry] started~n"),
    {ok, #{}}.

handle_call({register, RollupId, Pid}, _From, State) ->
    io:format("[TxRollupRegistry] Registering ~p -> ~p~n", [RollupId, Pid]),
    {reply, ok, maps:put(RollupId, Pid, State)};

handle_call({unregister, RollupId}, _From, State) ->
    io:format("[TxRollupRegistry] Unregistering ~p~n", [RollupId]),
    {reply, ok, maps:remove(RollupId, State)};

handle_call({whereis, RollupId}, _From, State) ->
    case maps:get(RollupId, State, undefined) of
        undefined ->
            {reply, not_found, State};
        Pid ->
            {reply, {ok, Pid}, State}
    end;

handle_call(list, _From, State) ->
    {reply, maps:to_list(State), State};

handle_call(_Msg, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
