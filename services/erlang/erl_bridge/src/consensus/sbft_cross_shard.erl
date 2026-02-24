-module(sbft_cross_shard).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([
    start_link/0,
    register_shard/1,
    unregister_shard/1,
    send_receipt/3,
    send_receipt/4,
    get_pending_receipts/1,
    get_processed_receipts/1,
    process_receipt/1,
    process_all_pending/1,
    verify_receipt/1,
    build_receipt_tree/1,
    get_receipt_root/1,
    get_registered_shards/0,
    get_metrics/0,
    expire_stale_receipts/0,
    retry_failed_receipts/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(SERVER,                 ?MODULE).
-define(RECEIPTS_TABLE,         sbft_receipts_table).
-define(PROCESSED_TABLE,        sbft_processed_receipts).
-define(EXPIRY_CHECK_INTERVAL,  15000).
-define(RETRY_INTERVAL,         10000).
-define(MAX_RECEIPT_RETRIES,    ?MAX_RETRIES).

-record(cross_shard_state, {
    registered_shards   = []  :: [shard_id()],
    pending_receipts    = #{} :: #{shard_id() => [#cross_shard_receipt{}]},
    receipt_roots       = #{} :: #{shard_id() => merkle_root()},
    metrics             = #{} :: map(),
    expiry_timer        :: reference() | undefined,
    retry_timer         :: reference() | undefined
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

register_shard(ShardId) ->
    gen_server:call(?SERVER, {register_shard, ShardId}).

unregister_shard(ShardId) ->
    gen_server:call(?SERVER, {unregister_shard, ShardId}).

send_receipt(FromShard, ToShard, ReceiptData) ->
    send_receipt(FromShard, ToShard, ReceiptData, #{}).

send_receipt(FromShard, ToShard, ReceiptData, Opts) ->
    gen_server:cast(?SERVER, {send_receipt, FromShard, ToShard, ReceiptData, Opts}).

get_pending_receipts(ShardId) ->
    gen_server:call(?SERVER, {get_pending_receipts, ShardId}).

get_processed_receipts(ShardId) ->
    gen_server:call(?SERVER, {get_processed_receipts, ShardId}).

process_receipt(Receipt) ->
    gen_server:cast(?SERVER, {process_receipt, Receipt}).

process_all_pending(ShardId) ->
    gen_server:cast(?SERVER, {process_all_pending, ShardId}).

verify_receipt(Receipt) ->
    gen_server:call(?SERVER, {verify_receipt, Receipt}).

build_receipt_tree(ShardId) ->
    gen_server:call(?SERVER, {build_receipt_tree, ShardId}).

get_receipt_root(ShardId) ->
    gen_server:call(?SERVER, {get_receipt_root, ShardId}).

get_registered_shards() ->
    gen_server:call(?SERVER, get_registered_shards).

get_metrics() ->
    gen_server:call(?SERVER, get_metrics).

expire_stale_receipts() ->
    gen_server:cast(?SERVER, expire_stale_receipts).

retry_failed_receipts(ShardId) ->
    gen_server:cast(?SERVER, {retry_failed_receipts, ShardId}).

init([]) ->
    ets:new(?RECEIPTS_TABLE, [
        named_table, bag, protected,
        {keypos, #cross_shard_receipt.to_shard}
    ]),
    ets:new(?PROCESSED_TABLE, [
        named_table, set, protected,
        {keypos, #cross_shard_receipt.receipt_id}
    ]),
    ExpiryTimer = erlang:send_after(?EXPIRY_CHECK_INTERVAL, self(), check_expiry),
    RetryTimer  = erlang:send_after(?RETRY_INTERVAL, self(), retry_failed),
    {ok, #cross_shard_state{
        expiry_timer = ExpiryTimer,
        retry_timer  = RetryTimer,
        metrics      = init_metrics()
    }}.

handle_call({register_shard, ShardId}, _From, State) ->
    case lists:member(ShardId, State#cross_shard_state.registered_shards) of
        true ->
            {reply, {error, already_registered}, State};
        false ->
            NewShards  = [ShardId | State#cross_shard_state.registered_shards],
            NewPending = maps:put(ShardId, [], State#cross_shard_state.pending_receipts),
            NewState   = State#cross_shard_state{
                registered_shards = NewShards,
                pending_receipts  = NewPending
            },
            {reply, ok, NewState}
    end;

handle_call({unregister_shard, ShardId}, _From, State) ->
    NewShards  = lists:delete(ShardId, State#cross_shard_state.registered_shards),
    NewPending = maps:remove(ShardId, State#cross_shard_state.pending_receipts),
    NewRoots   = maps:remove(ShardId, State#cross_shard_state.receipt_roots),
    ets:match_delete(?RECEIPTS_TABLE, #cross_shard_receipt{to_shard = ShardId, _ = '_'}),
    NewState = State#cross_shard_state{
        registered_shards = NewShards,
        pending_receipts  = NewPending,
        receipt_roots     = NewRoots
    },
    {reply, ok, NewState};

handle_call({get_pending_receipts, ShardId}, _From, State) ->
    Receipts = maps:get(ShardId, State#cross_shard_state.pending_receipts, []),
    {reply, {ok, Receipts}, State};

handle_call({get_processed_receipts, ShardId}, _From, State) ->
    Processed = ets:match_object(?PROCESSED_TABLE,
                                  #cross_shard_receipt{to_shard = ShardId, _ = '_'}),
    {reply, {ok, Processed}, State};

handle_call({verify_receipt, Receipt}, _From, State) ->
    Result = do_verify_receipt(Receipt),
    {reply, Result, State};

handle_call({build_receipt_tree, ShardId}, _From, State) ->
    Receipts = maps:get(ShardId, State#cross_shard_state.pending_receipts, []),
    case Receipts of
        [] ->
            {reply, {ok, <<>>, []}, State};
        _ ->
            {Root, Proofs} = build_merkle_tree(Receipts),
            NewRoots       = maps:put(ShardId, Root, State#cross_shard_state.receipt_roots),
            NewState       = State#cross_shard_state{receipt_roots = NewRoots},
            {reply, {ok, Root, Proofs}, NewState}
    end;

handle_call({get_receipt_root, ShardId}, _From, State) ->
    Root = maps:get(ShardId, State#cross_shard_state.receipt_roots, undefined),
    {reply, {ok, Root}, State};

handle_call(get_registered_shards, _From, State) ->
    {reply, {ok, State#cross_shard_state.registered_shards}, State};

handle_call(get_metrics, _From, State) ->
    {reply, {ok, State#cross_shard_state.metrics}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({send_receipt, FromShard, ToShard, ReceiptData, Opts}, State) ->
    case lists:member(ToShard, State#cross_shard_state.registered_shards) of
        false ->
            Metrics = bump_metric(receipts_dropped_unknown_shard,
                                  State#cross_shard_state.metrics),
            {noreply, State#cross_shard_state{metrics = Metrics}};
        true ->
            Receipt  = build_receipt(FromShard, ToShard, ReceiptData, Opts),
            NewState = intake_receipt(Receipt, State),
            {noreply, NewState}
    end;

handle_cast({process_receipt, Receipt}, State) ->
    NewState = do_process_receipt(Receipt, State),
    {noreply, NewState};

handle_cast({process_all_pending, ShardId}, State) ->
    Receipts = maps:get(ShardId, State#cross_shard_state.pending_receipts, []),
    NewState = lists:foldl(fun(R, AccState) ->
        do_process_receipt(R, AccState)
    end, State, Receipts),
    {noreply, NewState};

handle_cast(expire_stale_receipts, State) ->
    NewState = do_expire_stale(State),
    {noreply, NewState};

handle_cast({retry_failed_receipts, ShardId}, State) ->
    NewState = do_retry_failed(ShardId, State),
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(check_expiry, State) ->
    NewState    = do_expire_stale(State),
    ExpiryTimer = erlang:send_after(?EXPIRY_CHECK_INTERVAL, self(), check_expiry),
    {noreply, NewState#cross_shard_state{expiry_timer = ExpiryTimer}};

handle_info(retry_failed, State) ->
    NewState = lists:foldl(fun(ShardId, AccState) ->
        do_retry_failed(ShardId, AccState)
    end, State, State#cross_shard_state.registered_shards),
    RetryTimer = erlang:send_after(?RETRY_INTERVAL, self(), retry_failed),
    {noreply, NewState#cross_shard_state{retry_timer = RetryTimer}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timer(State#cross_shard_state.expiry_timer),
    cancel_timer(State#cross_shard_state.retry_timer),
    ets:delete(?RECEIPTS_TABLE),
    ets:delete(?PROCESSED_TABLE),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

build_receipt(FromShard, ToShard, ReceiptData, Opts) ->
    Now      = erlang:system_time(millisecond),
    Expiry   = maps:get(expiry_ms, Opts, Now + ?RECEIPT_EXPIRY_MS),
    TxHash   = sbft_crypto:hash(blake2s, ReceiptData),
    ReceiptId = sbft_crypto:hash(blake2s, <<TxHash/binary,
                                             FromShard/binary,
                                             ToShard/binary,
                                             Now:64/big>>),
    #cross_shard_receipt{
        receipt_id       = ReceiptId,
        from_shard       = FromShard,
        to_shard         = ToShard,
        transaction_hash = TxHash,
        receipt_data     = ReceiptData,
        merkle_proof     = undefined,
        merkle_root      = undefined,
        status           = pending,
        timestamp        = Now,
        expiry_timestamp = Expiry,
        retry_count      = 0,
        signature        = undefined,
        pqc_signature    = undefined
    }.

intake_receipt(Receipt, State) ->
    ToShard  = Receipt#cross_shard_receipt.to_shard,
    Current  = maps:get(ToShard, State#cross_shard_state.pending_receipts, []),
    Ordered  = insert_ordered(Receipt, Current),
    NewPending = maps:put(ToShard, Ordered, State#cross_shard_state.pending_receipts),
    ets:insert(?RECEIPTS_TABLE, Receipt),
    {Root, ReceiptsWithProofs} = build_merkle_tree(Ordered),
    NewRoots   = maps:put(ToShard, Root, State#cross_shard_state.receipt_roots),
    UpdatedReceipts = attach_proofs(ReceiptsWithProofs, NewPending, ToShard),
    Metrics    = bump_metric(receipts_received, State#cross_shard_state.metrics),
    NewState   = State#cross_shard_state{
        pending_receipts = UpdatedReceipts,
        receipt_roots    = NewRoots,
        metrics          = Metrics
    },
    sbft_event_bus:publish(cross_shard_receipt, #{
        receipt_id       => Receipt#cross_shard_receipt.receipt_id,
        from_shard       => Receipt#cross_shard_receipt.from_shard,
        to_shard         => Receipt#cross_shard_receipt.to_shard,
        transaction_hash => Receipt#cross_shard_receipt.transaction_hash,
        status           => pending
    }),
    NewState.

insert_ordered(Receipt, Receipts) ->
    lists:sort(fun(A, B) ->
        A#cross_shard_receipt.timestamp =< B#cross_shard_receipt.timestamp
    end, [Receipt | Receipts]).

do_process_receipt(Receipt, State) ->
    case is_already_processed(Receipt) of
        true ->
            State;
        false ->
            case do_verify_receipt(Receipt) of
                {ok, valid} ->
                    process_valid_receipt(Receipt, State);
                {error, Reason} ->
                    handle_invalid_receipt(Receipt, Reason, State)
            end
    end.

is_already_processed(Receipt) ->
    case ets:lookup(?PROCESSED_TABLE, Receipt#cross_shard_receipt.receipt_id) of
        []  -> false;
        [_] -> true
    end.

do_verify_receipt(Receipt) ->
    Checks = [
        fun() -> verify_receipt_not_expired(Receipt) end,
        fun() -> verify_receipt_hash(Receipt) end,
        fun() -> verify_receipt_merkle_proof(Receipt) end,
        fun() -> verify_receipt_signature(Receipt) end
    ],
    run_checks(Checks).

run_checks([]) ->
    {ok, valid};
run_checks([Check | Rest]) ->
    case Check() of
        ok             -> run_checks(Rest);
        {error, _} = E -> E
    end.

verify_receipt_not_expired(Receipt) ->
    case Receipt#cross_shard_receipt.expiry_timestamp of
        undefined -> ok;
        Expiry    ->
            Now = erlang:system_time(millisecond),
            case Now > Expiry of
                true  -> {error, receipt_expired};
                false -> ok
            end
    end.

verify_receipt_hash(Receipt) ->
    Expected = sbft_crypto:hash(blake2s, Receipt#cross_shard_receipt.receipt_data),
    Actual   = Receipt#cross_shard_receipt.transaction_hash,
    case sbft_crypto:constant_time_compare(Expected, Actual) of
        true  -> ok;
        false -> {error, hash_mismatch}
    end.

verify_receipt_merkle_proof(Receipt) ->
    case Receipt#cross_shard_receipt.merkle_proof of
        undefined -> ok;
        []        -> ok;
        Proof     ->
            case Receipt#cross_shard_receipt.merkle_root of
                undefined -> ok;
                Root      ->
                    Leaf = receipt_leaf_hash(Receipt),
                    case verify_merkle_proof(Leaf, Proof, Root) of
                        true  -> ok;
                        false -> {error, invalid_merkle_proof}
                    end
            end
    end.

verify_receipt_signature(Receipt) ->
    case Receipt#cross_shard_receipt.pqc_signature of
        undefined -> ok;
        PQCSig    ->
            Payload = sbft_crypto:receipt_signing_payload(Receipt),
            case get_shard_public_key(Receipt#cross_shard_receipt.from_shard) of
                {ok, PK} ->
                    case sbft_crypto:verify_pqc_signature(PQCSig, PK, Payload) of
                        true  -> ok;
                        false -> {error, invalid_signature}
                    end;
                {error, _} ->
                    ok
            end
    end.

process_valid_receipt(Receipt, State) ->
    ToShard    = Receipt#cross_shard_receipt.to_shard,
    Processed  = Receipt#cross_shard_receipt{status = processed},
    ets:insert(?PROCESSED_TABLE, Processed),
    ets:match_delete(?RECEIPTS_TABLE,
                     #cross_shard_receipt{
                         receipt_id = Receipt#cross_shard_receipt.receipt_id,
                         _ = '_'
                     }),
    Current    = maps:get(ToShard, State#cross_shard_state.pending_receipts, []),
    Remaining  = lists:filter(fun(R) ->
        R#cross_shard_receipt.receipt_id =/= Receipt#cross_shard_receipt.receipt_id
    end, Current),
    NewPending = maps:put(ToShard, Remaining, State#cross_shard_state.pending_receipts),
    Metrics    = bump_metric(receipts_processed, State#cross_shard_state.metrics),
    NewState   = State#cross_shard_state{
        pending_receipts = NewPending,
        metrics          = Metrics
    },
    sbft_event_bus:publish(cross_shard_receipt, #{
        receipt_id       => Receipt#cross_shard_receipt.receipt_id,
        from_shard       => Receipt#cross_shard_receipt.from_shard,
        to_shard         => ToShard,
        transaction_hash => Receipt#cross_shard_receipt.transaction_hash,
        status           => processed
    }),
    NewState.

handle_invalid_receipt(Receipt, Reason, State) ->
    error_logger:warning_msg(
        "[sbft_cross_shard] invalid receipt ~p from ~p to ~p: ~p~n",
        [Receipt#cross_shard_receipt.receipt_id,
         Receipt#cross_shard_receipt.from_shard,
         Receipt#cross_shard_receipt.to_shard,
         Reason]
    ),
    case Reason of
        receipt_expired ->
            mark_receipt_expired(Receipt, State);
        _ ->
            maybe_retry_receipt(Receipt, State)
    end.

mark_receipt_expired(Receipt, State) ->
    ToShard    = Receipt#cross_shard_receipt.to_shard,
    Expired    = Receipt#cross_shard_receipt{status = expired},
    ets:insert(?PROCESSED_TABLE, Expired),
    Current    = maps:get(ToShard, State#cross_shard_state.pending_receipts, []),
    Remaining  = lists:filter(fun(R) ->
        R#cross_shard_receipt.receipt_id =/= Receipt#cross_shard_receipt.receipt_id
    end, Current),
    NewPending = maps:put(ToShard, Remaining, State#cross_shard_state.pending_receipts),
    Metrics    = bump_metric(receipts_expired, State#cross_shard_state.metrics),
    State#cross_shard_state{
        pending_receipts = NewPending,
        metrics          = Metrics
    }.

maybe_retry_receipt(Receipt, State) ->
    RetryCount = Receipt#cross_shard_receipt.retry_count,
    case RetryCount >= ?MAX_RECEIPT_RETRIES of
        true ->
            ToShard   = Receipt#cross_shard_receipt.to_shard,
            Failed    = Receipt#cross_shard_receipt{status = failed},
            ets:insert(?PROCESSED_TABLE, Failed),
            Current   = maps:get(ToShard, State#cross_shard_state.pending_receipts, []),
            Remaining = lists:filter(fun(R) ->
                R#cross_shard_receipt.receipt_id =/= Receipt#cross_shard_receipt.receipt_id
            end, Current),
            NewPending = maps:put(ToShard, Remaining, State#cross_shard_state.pending_receipts),
            Metrics    = bump_metric(receipts_failed, State#cross_shard_state.metrics),
            State#cross_shard_state{
                pending_receipts = NewPending,
                metrics          = Metrics
            };
        false ->
            Updated    = Receipt#cross_shard_receipt{retry_count = RetryCount + 1},
            ToShard    = Receipt#cross_shard_receipt.to_shard,
            Current    = maps:get(ToShard, State#cross_shard_state.pending_receipts, []),
            Replaced   = lists:map(fun(R) ->
                case R#cross_shard_receipt.receipt_id =:=
                     Receipt#cross_shard_receipt.receipt_id of
                    true  -> Updated;
                    false -> R
                end
            end, Current),
            NewPending = maps:put(ToShard, Replaced, State#cross_shard_state.pending_receipts),
            Metrics    = bump_metric(receipts_retried, State#cross_shard_state.metrics),
            State#cross_shard_state{
                pending_receipts = NewPending,
                metrics          = Metrics
            }
    end.

do_expire_stale(State) ->
    Now      = erlang:system_time(millisecond),
    NewState = maps:fold(fun(ShardId, Receipts, AccState) ->
        {Expired, Remaining} = lists:partition(fun(R) ->
            case R#cross_shard_receipt.expiry_timestamp of
                undefined -> false;
                Expiry    -> Now > Expiry
            end
        end, Receipts),
        lists:foreach(fun(R) ->
            ExpiredR = R#cross_shard_receipt{status = expired},
            ets:insert(?PROCESSED_TABLE, ExpiredR),
            ets:match_delete(?RECEIPTS_TABLE,
                             #cross_shard_receipt{
                                 receipt_id = R#cross_shard_receipt.receipt_id,
                                 _ = '_'
                             })
        end, Expired),
        ExpiredCount = length(Expired),
        Metrics = bump_metric_by(receipts_expired, ExpiredCount,
                                  AccState#cross_shard_state.metrics),
        NewPending = maps:put(ShardId, Remaining,
                              AccState#cross_shard_state.pending_receipts),
        AccState#cross_shard_state{
            pending_receipts = NewPending,
            metrics          = Metrics
        }
    end, State, State#cross_shard_state.pending_receipts),
    NewState.

do_retry_failed(ShardId, State) ->
    Receipts = maps:get(ShardId, State#cross_shard_state.pending_receipts, []),
    lists:foldl(fun(Receipt, AccState) ->
        case Receipt#cross_shard_receipt.retry_count > 0 of
            true  -> do_process_receipt(Receipt, AccState);
            false -> AccState
        end
    end, State, Receipts).

build_merkle_tree([]) ->
    {<<>>, []};
build_merkle_tree(Receipts) ->
    Leaves = lists:map(fun(R) -> receipt_leaf_hash(R) end, Receipts),
    Root   = merkle_root_from_leaves(Leaves),
    Proofs = lists:map(fun(R) ->
        Leaf  = receipt_leaf_hash(R),
        Proof = generate_merkle_proof(Leaf, Leaves),
        {R#cross_shard_receipt.receipt_id, Proof}
    end, Receipts),
    {Root, Proofs}.

receipt_leaf_hash(Receipt) ->
    sbft_crypto:hash(blake2s, term_to_binary({
        Receipt#cross_shard_receipt.receipt_id,
        Receipt#cross_shard_receipt.from_shard,
        Receipt#cross_shard_receipt.to_shard,
        Receipt#cross_shard_receipt.transaction_hash,
        Receipt#cross_shard_receipt.timestamp
    })).

merkle_root_from_leaves([]) ->
    sbft_crypto:hash(blake2s, <<>>);
merkle_root_from_leaves([Single]) ->
    Single;
merkle_root_from_leaves(Leaves) ->
    Paired = pair_leaves(Leaves),
    Parents = lists:map(fun({L, R}) ->
        sbft_crypto:hash(blake2s, <<L/binary, R/binary>>)
    end, Paired),
    merkle_root_from_leaves(Parents).

pair_leaves([]) ->
    [];
pair_leaves([Single]) ->
    [{Single, Single}];
pair_leaves([L, R | Rest]) ->
    [{L, R} | pair_leaves(Rest)].

generate_merkle_proof(Leaf, AllLeaves) ->
    generate_proof(Leaf, AllLeaves, []).

generate_proof(_Leaf, [_Single], Acc) ->
    lists:reverse(Acc);
generate_proof(Leaf, Leaves, Acc) ->
    Paired    = pair_leaves(Leaves),
    {Sibling, IsLeft} = find_sibling(Leaf, Paired),
    Parents   = lists:map(fun({L, R}) ->
        sbft_crypto:hash(blake2s, <<L/binary, R/binary>>)
    end, Paired),
    ParentHash = case IsLeft of
        true  -> sbft_crypto:hash(blake2s, <<Leaf/binary, Sibling/binary>>);
        false -> sbft_crypto:hash(blake2s, <<Sibling/binary, Leaf/binary>>)
    end,
    generate_proof(ParentHash, Parents, [{Sibling, IsLeft} | Acc]).

find_sibling(Leaf, Pairs) ->
    find_sibling(Leaf, Pairs, undefined).

find_sibling(_Leaf, [], _) ->
    {<<>>, true};
find_sibling(Leaf, [{L, R} | _], _) when L =:= Leaf ->
    {R, true};
find_sibling(Leaf, [{L, R} | _], _) when R =:= Leaf ->
    {L, false};
find_sibling(Leaf, [_ | Rest], Acc) ->
    find_sibling(Leaf, Rest, Acc).

verify_merkle_proof(Leaf, Proof, Root) ->
    Computed = lists:foldl(fun({Sibling, IsLeft}, Current) ->
        case IsLeft of
            true  -> sbft_crypto:hash(blake2s, <<Current/binary, Sibling/binary>>);
            false -> sbft_crypto:hash(blake2s, <<Sibling/binary, Current/binary>>)
        end
    end, Leaf, Proof),
    sbft_crypto:constant_time_compare(Computed, Root).

attach_proofs(ReceiptsWithProofs, PendingMap, ToShard) ->
    ProofMap = maps:from_list(ReceiptsWithProofs),
    Current  = maps:get(ToShard, PendingMap, []),
    Updated  = lists:map(fun(R) ->
        Proof = maps:get(R#cross_shard_receipt.receipt_id, ProofMap, undefined),
        R#cross_shard_receipt{merkle_proof = Proof}
    end, Current),
    maps:put(ToShard, Updated, PendingMap).

get_shard_public_key(ShardId) ->
    case sbft_consensus_manager:get_shard_status(ShardId) of
        {ok, _Status} -> {ok, undefined};
        {error, R}    -> {error, R}
    end.

cancel_timer(undefined) -> ok;
cancel_timer(Ref)       -> erlang:cancel_timer(Ref), ok.

init_metrics() ->
    #{
        receipts_received              => 0,
        receipts_processed             => 0,
        receipts_expired               => 0,
        receipts_failed                => 0,
        receipts_retried               => 0,
        receipts_dropped_unknown_shard => 0
    }.

bump_metric(Key, Metrics) ->
    maps:update_with(Key, fun(V) -> V + 1 end, 1, Metrics).

bump_metric_by(Key, N, Metrics) when N > 0 ->
    maps:update_with(Key, fun(V) -> V + N end, N, Metrics);
bump_metric_by(_Key, _N, Metrics) ->
    Metrics.
