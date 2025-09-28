-module(sbft_cross_shard).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([start_link/0, send_receipt/3, get_pending_receipts/1,
         process_receipt/1, register_shard/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(cross_shard_state, {
    pending_receipts = #{} :: #{shard_id() => [#cross_shard_receipt{}]},
    processed_receipts = #{} :: #{binary() => #cross_shard_receipt{}},
    registered_shards = [] :: [shard_id()],
    receipt_timeout = 30000 :: non_neg_integer()
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

send_receipt(FromShard, ToShard, ReceiptData) ->
    gen_server:cast(?SERVER, {send_receipt, FromShard, ToShard, ReceiptData}).

get_pending_receipts(ShardId) ->
    gen_server:call(?SERVER, {get_pending_receipts, ShardId}).

process_receipt(Receipt) ->
    gen_server:cast(?SERVER, {process_receipt, Receipt}).

register_shard(ShardId) ->
    gen_server:call(?SERVER, {register_shard, ShardId}).

init([]) ->
    {ok, #cross_shard_state{}}.

handle_call({get_pending_receipts, ShardId}, _From, State) ->
    Receipts = maps:get(ShardId, State#cross_shard_state.pending_receipts, []),
    {reply, {ok, Receipts}, State};

handle_call({register_shard, ShardId}, _From, State) ->
    case lists:member(ShardId, State#cross_shard_state.registered_shards) of
        true ->
            {reply, {error, already_registered}, State};
        false ->
            NewShards = [ShardId | State#cross_shard_state.registered_shards],
            NewState = State#cross_shard_state{registered_shards = NewShards},
            {reply, ok, NewState}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({send_receipt, FromShard, ToShard, ReceiptData}, State) ->
    Receipt = #cross_shard_receipt{
        from_shard = FromShard,
        to_shard = ToShard,
        transaction_hash = crypto:hash(sha256, ReceiptData),
        receipt_data = ReceiptData,
        timestamp = erlang:system_time(millisecond)
    },

    CurrentReceipts = maps:get(ToShard, State#cross_shard_state.pending_receipts, []),
    NewReceipts = [Receipt | CurrentReceipts],
    NewPendingReceipts = maps:put(ToShard, NewReceipts, State#cross_shard_state.pending_receipts),

    NewState = State#cross_shard_state{pending_receipts = NewPendingReceipts},
    {noreply, NewState};

handle_cast({process_receipt, Receipt}, State) ->
    ReceiptHash = Receipt#cross_shard_receipt.transaction_hash,
    NewProcessedReceipts = maps:put(ReceiptHash, Receipt, State#cross_shard_state.processed_receipts),

    ToShard = Receipt#cross_shard_receipt.to_shard,
    CurrentReceipts = maps:get(ToShard, State#cross_shard_state.pending_receipts, []),
    FilteredReceipts = lists:filter(fun(R) ->
        R#cross_shard_receipt.transaction_hash =/= ReceiptHash
    end, CurrentReceipts),

    NewPendingReceipts = maps:put(ToShard, FilteredReceipts, State#cross_shard_state.pending_receipts),

    NewState = State#cross_shard_state{
        processed_receipts = NewProcessedReceipts,
        pending_receipts = NewPendingReceipts
    },
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
