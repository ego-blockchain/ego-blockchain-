%%%-------------------------------------------------------------------
%% @doc erl_bridge public API
%% @end
%%%-------------------------------------------------------------------

-module(erl_bridge_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    erl_bridge_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
