-module(sbft_nif_server).
-behaviour(gen_server).

-export([start_link/0, reload/0, status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(nif_server_state, {
    loaded          = false :: boolean(),
    capabilities    = #{}   :: map(),
    loaded_at       :: non_neg_integer() | undefined
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

reload() ->
    gen_server:call(?SERVER, reload).

status() ->
    gen_server:call(?SERVER, status).

init([]) ->
    LoadResult   = sbft_nif:load(),
    Loaded       = LoadResult =:= ok,
    Capabilities = sbft_nif:capabilities(),
    error_logger:info_msg(
        "[sbft_nif_server] NIF load result: ~p capabilities: ~p~n",
        [LoadResult, Capabilities]
    ),
    {ok, #nif_server_state{
        loaded       = Loaded,
        capabilities = Capabilities,
        loaded_at    = erlang:system_time(millisecond)
    }}.

handle_call(reload, _From, State) ->
    LoadResult   = sbft_nif:load(),
    Loaded       = LoadResult =:= ok,
    Capabilities = sbft_nif:capabilities(),
    NewState     = State#nif_server_state{
        loaded       = Loaded,
        capabilities = Capabilities,
        loaded_at    = erlang:system_time(millisecond)
    },
    {reply, {ok, Capabilities}, NewState};

handle_call(status, _From, State) ->
    Status = #{
        loaded       => State#nif_server_state.loaded,
        capabilities => State#nif_server_state.capabilities,
        loaded_at    => State#nif_server_state.loaded_at
    },
    {reply, {ok, Status}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
