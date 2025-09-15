-module(sbft_consensus_manager).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([start_link/0, start_shard_consensus/2, stop_shard_consensus/1,
         get_shard_status/1, get_all_shards/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(manager_state, {
    active_shards = #{} :: #{shard_id() => pid()},
    shard_configs = #{} :: #{shard_id() => map()},
    metrics = #{} :: map()
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

start_shard_consensus(ShardId, Config) ->
    gen_server:call(?SERVER, {start_shard, ShardId, Config}).

stop_shard_consensus(ShardId) ->
    gen_server:call(?SERVER, {stop_shard, ShardId}).

get_shard_status(ShardId) ->
    gen_server:call(?SERVER, {get_shard_status, ShardId}).

get_all_shards() ->
    gen_server:call(?SERVER, get_all_shards).

init([]) ->
    process_flag(trap_exit, true),
    {ok, #manager_state{}}.

handle_call({start_shard, ShardId, Config}, _From, State) ->
    case maps:get(ShardId, State#manager_state.active_shards, undefined) of
        undefined ->
            case sbft_shard_consensus:start_link(ShardId, Config) of
                {ok, Pid} ->
                    NewActiveShards = maps:put(ShardId, Pid, State#manager_state.active_shards),
                    NewConfigs = maps:put(ShardId, Config, State#manager_state.shard_configs),
                    NewState = State#manager_state{
                        active_shards = NewActiveShards,
                        shard_configs = NewConfigs
                    },
                    {reply, {ok, Pid}, NewState};
                {error, Reason} ->
                    {reply, {error, Reason}, State}
            end;
        Pid ->
            {reply, {ok, Pid}, State}
    end;

handle_call({stop_shard, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.active_shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Pid ->
            sbft_shard_consensus:stop(Pid),
            NewActiveShards = maps:remove(ShardId, State#manager_state.active_shards),
            NewConfigs = maps:remove(ShardId, State#manager_state.shard_configs),
            NewState = State#manager_state{
                active_shards = NewActiveShards,
                shard_configs = NewConfigs
            },
            {reply, ok, NewState}
    end;

handle_call({get_shard_status, ShardId}, _From, State) ->
    case maps:get(ShardId, State#manager_state.active_shards, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Pid ->
            Status = sbft_shard_consensus:get_status(Pid),
            {reply, {ok, Status}, State}
    end;

handle_call(get_all_shards, _From, State) ->
    Shards = maps:keys(State#manager_state.active_shards),
    {reply, {ok, Shards}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, State) ->
    case find_shard_by_pid(Pid, State#manager_state.active_shards) of
        {ok, ShardId} ->
            error_logger:error_msg("Shard ~p consensus crashed: ~p~n", [ShardId, Reason]),
            NewActiveShards = maps:remove(ShardId, State#manager_state.active_shards),
            NewState = State#manager_state{active_shards = NewActiveShards},
            {noreply, NewState};
        not_found ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    maps:fold(fun(_ShardId, Pid, _Acc) ->
        sbft_shard_consensus:stop(Pid)
    end, ok, State#manager_state.active_shards),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

find_shard_by_pid(Pid, ActiveShards) ->
    case maps:fold(fun(ShardId, ShardPid, Acc) ->
        case ShardPid of
            Pid -> {found, ShardId};
            _ -> Acc
        end
    end, not_found, ActiveShards) of
        {found, ShardId} -> {ok, ShardId};
        not_found -> not_found
    end.
