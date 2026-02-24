-module(sbft_slashing).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([
    start_link/0,
    report/1,
    report_double_vote/3,
    report_invalid_block/3,
    report_unavailability/2,
    report_invalid_poc/2,
    report_storage_fault/2,
    get_slashing_history/0,
    get_slashing_history/1,
    get_slash_count/1,
    is_slashed/1,
    get_pending_evidence/0,
    process_pending/0
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(SERVER,               ?MODULE).
-define(SLASHING_TABLE,       sbft_slashing_table).
-define(EVIDENCE_TABLE,       sbft_evidence_table).
-define(MAX_EVIDENCE_AGE_MS,  300000).
-define(DEDUP_WINDOW_MS,      60000).

-record(slashing_state, {
    pending_evidence    = [] :: [#slashing_evidence{}],
    processed_hashes    = #{} :: #{binary() => timestamp_ms()},
    total_slashed       = 0  :: non_neg_integer(),
    slash_counts        = #{} :: #{validator_id() => non_neg_integer()}
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

report(Evidence) ->
    gen_server:cast(?SERVER, {report_evidence, Evidence}).

report_double_vote(ValidatorId, Vote1, Vote2) ->
    Evidence = #slashing_evidence{
        validator_id   = ValidatorId,
        reason         = double_voting,
        evidence_votes = [Vote1, Vote2],
        evidence_block = undefined,
        reported_at    = erlang:system_time(millisecond),
        shard_id       = Vote1#sbft_vote_record.shard_id,
        stake_at_slash = 0
    },
    gen_server:cast(?SERVER, {report_evidence, Evidence}).

report_invalid_block(ValidatorId, Block, ShardId) ->
    Evidence = #slashing_evidence{
        validator_id   = ValidatorId,
        reason         = invalid_block,
        evidence_votes = [],
        evidence_block = Block,
        reported_at    = erlang:system_time(millisecond),
        shard_id       = ShardId,
        stake_at_slash = 0
    },
    gen_server:cast(?SERVER, {report_evidence, Evidence}).

report_unavailability(ValidatorId, ShardId) ->
    Evidence = #slashing_evidence{
        validator_id   = ValidatorId,
        reason         = unavailability,
        evidence_votes = [],
        evidence_block = undefined,
        reported_at    = erlang:system_time(millisecond),
        shard_id       = ShardId,
        stake_at_slash = 0
    },
    gen_server:cast(?SERVER, {report_evidence, Evidence}).

report_invalid_poc(ValidatorId, ShardId) ->
    Evidence = #slashing_evidence{
        validator_id   = ValidatorId,
        reason         = invalid_poc,
        evidence_votes = [],
        evidence_block = undefined,
        reported_at    = erlang:system_time(millisecond),
        shard_id       = ShardId,
        stake_at_slash = 0
    },
    gen_server:cast(?SERVER, {report_evidence, Evidence}).

report_storage_fault(ValidatorId, ShardId) ->
    Evidence = #slashing_evidence{
        validator_id   = ValidatorId,
        reason         = storage_fault,
        evidence_votes = [],
        evidence_block = undefined,
        reported_at    = erlang:system_time(millisecond),
        shard_id       = ShardId,
        stake_at_slash = 0
    },
    gen_server:cast(?SERVER, {report_evidence, Evidence}).

get_slashing_history() ->
    gen_server:call(?SERVER, get_slashing_history).

get_slashing_history(ValidatorId) ->
    gen_server:call(?SERVER, {get_slashing_history, ValidatorId}).

get_slash_count(ValidatorId) ->
    gen_server:call(?SERVER, {get_slash_count, ValidatorId}).

is_slashed(ValidatorId) ->
    gen_server:call(?SERVER, {is_slashed, ValidatorId}).

get_pending_evidence() ->
    gen_server:call(?SERVER, get_pending_evidence).

process_pending() ->
    gen_server:cast(?SERVER, process_pending).

init([]) ->
    ets:new(?SLASHING_TABLE, [
        named_table, bag, protected,
        {keypos, #slashing_evidence.validator_id}
    ]),
    ets:new(?EVIDENCE_TABLE, [
        named_table, set, protected
    ]),
    erlang:send_after(?MAX_EVIDENCE_AGE_MS, self(), cleanup_old_evidence),
    {ok, #slashing_state{}}.

handle_call(get_slashing_history, _From, State) ->
    History = ets:tab2list(?SLASHING_TABLE),
    {reply, {ok, History}, State};

handle_call({get_slashing_history, ValidatorId}, _From, State) ->
    History = ets:lookup(?SLASHING_TABLE, ValidatorId),
    {reply, {ok, History}, State};

handle_call({get_slash_count, ValidatorId}, _From, State) ->
    Count = maps:get(ValidatorId, State#slashing_state.slash_counts, 0),
    {reply, {ok, Count}, State};

handle_call({is_slashed, ValidatorId}, _From, State) ->
    Count  = maps:get(ValidatorId, State#slashing_state.slash_counts, 0),
    Result = Count > 0,
    {reply, {ok, Result}, State};

handle_call(get_pending_evidence, _From, State) ->
    {reply, {ok, State#slashing_state.pending_evidence}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({report_evidence, Evidence}, State) ->
    EvidenceHash = compute_evidence_hash(Evidence),
    case is_duplicate(EvidenceHash, State) of
        true ->
            {noreply, State};
        false ->
            NewState = intake_evidence(Evidence, EvidenceHash, State),
            FinalState = maybe_process_immediately(Evidence, NewState),
            {noreply, FinalState}
    end;

handle_cast(process_pending, State) ->
    NewState = process_all_pending(State),
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(cleanup_old_evidence, State) ->
    NewState = cleanup_dedup_window(State),
    erlang:send_after(?MAX_EVIDENCE_AGE_MS, self(), cleanup_old_evidence),
    {noreply, NewState};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ets:delete(?SLASHING_TABLE),
    ets:delete(?EVIDENCE_TABLE),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

compute_evidence_hash(Evidence) ->
    Payload = term_to_binary({
        Evidence#slashing_evidence.validator_id,
        Evidence#slashing_evidence.reason,
        Evidence#slashing_evidence.shard_id,
        truncate_to_window(Evidence#slashing_evidence.reported_at)
    }),
    sbft_crypto:hash(blake2s, Payload).

truncate_to_window(TimestampMs) ->
    (TimestampMs div ?DEDUP_WINDOW_MS) * ?DEDUP_WINDOW_MS.

is_duplicate(EvidenceHash, State) ->
    maps:is_key(EvidenceHash, State#slashing_state.processed_hashes).

intake_evidence(Evidence, EvidenceHash, State) ->
    Now         = erlang:system_time(millisecond),
    NewHashes   = maps:put(EvidenceHash, Now, State#slashing_state.processed_hashes),
    NewPending  = [Evidence | State#slashing_state.pending_evidence],
    State#slashing_state{
        processed_hashes = NewHashes,
        pending_evidence = NewPending
    }.

maybe_process_immediately(Evidence, State) ->
    case requires_immediate_action(Evidence#slashing_evidence.reason) of
        true  -> process_evidence(Evidence, State);
        false -> State
    end.

requires_immediate_action(double_voting)  -> true;
requires_immediate_action(equivocation)   -> true;
requires_immediate_action(invalid_block)  -> true;
requires_immediate_action(unavailability) -> false;
requires_immediate_action(invalid_poc)    -> false;
requires_immediate_action(storage_fault)  -> false.

process_all_pending(State) ->
    lists:foldl(fun(Evidence, AccState) ->
        process_evidence(Evidence, AccState)
    end, State#slashing_state{pending_evidence = []},
    State#slashing_state.pending_evidence).

process_evidence(Evidence, State) ->
    ValidatorId = Evidence#slashing_evidence.validator_id,
    case fetch_validator_stake(ValidatorId) of
        {ok, CurrentStake} ->
            EvidenceWithStake = Evidence#slashing_evidence{stake_at_slash = CurrentStake},
            State1 = apply_slash(EvidenceWithStake, CurrentStake, State),
            record_evidence(EvidenceWithStake),
            emit_slash_event(EvidenceWithStake),
            State1;
        {error, not_found} ->
            error_logger:warning_msg(
                "[sbft_slashing] cannot slash unknown validator ~p~n",
                [ValidatorId]
            ),
            State
    end.

fetch_validator_stake(ValidatorId) ->
    case sbft_validator_manager:get_validator(ValidatorId) of
        {ok, Validator} -> {ok, Validator#sbft_validator_record.stake};
        {error, Reason} -> {error, Reason}
    end.

apply_slash(Evidence, CurrentStake, State) ->
    ValidatorId  = Evidence#slashing_evidence.validator_id,
    SlashAmount  = compute_slash_amount(Evidence#slashing_evidence.reason, CurrentStake, State),
    NewStake     = max(0, CurrentStake - SlashAmount),
    State1       = update_slash_counts(ValidatorId, State),
    SlashCount   = maps:get(ValidatorId, State1#slashing_state.slash_counts, 0),
    ok = apply_stake_reduction(ValidatorId, NewStake, SlashCount),
    State1#slashing_state{total_slashed = State1#slashing_state.total_slashed + SlashAmount}.

compute_slash_amount(double_voting, Stake, _State) ->
    trunc(Stake * 1.0);
compute_slash_amount(equivocation, Stake, _State) ->
    trunc(Stake * 1.0);
compute_slash_amount(invalid_block, Stake, _State) ->
    trunc(Stake * 0.5);
compute_slash_amount(unavailability, Stake, State) ->
    Count = maps:get(unavailability, State#slashing_state.slash_counts, 0),
    Fraction = min(0.1 * (Count + 1), 0.5),
    trunc(Stake * Fraction);
compute_slash_amount(invalid_poc, Stake, _State) ->
    trunc(Stake * 0.25);
compute_slash_amount(storage_fault, Stake, _State) ->
    trunc(Stake * 0.3);
compute_slash_amount(_, Stake, _State) ->
    trunc(Stake * 0.1).

apply_stake_reduction(ValidatorId, NewStake, SlashCount) ->
    case NewStake =:= 0 orelse SlashCount >= 1 of
        true ->
            ok = sbft_validator_manager:slash_validator(ValidatorId, deactivated),
            ok;
        false ->
            ok = sbft_validator_manager:update_stake(ValidatorId, NewStake),
            ok
    end.

update_slash_counts(ValidatorId, State) ->
    Counts    = State#slashing_state.slash_counts,
    NewCounts = maps:update_with(ValidatorId, fun(C) -> C + 1 end, 1, Counts),
    State#slashing_state{slash_counts = NewCounts}.

record_evidence(Evidence) ->
    ets:insert(?SLASHING_TABLE, Evidence).

emit_slash_event(Evidence) ->
    sbft_event_bus:publish(validator_slashed, #{
        validator_id   => Evidence#slashing_evidence.validator_id,
        reason         => Evidence#slashing_evidence.reason,
        shard_id       => Evidence#slashing_evidence.shard_id,
        stake_slashed  => Evidence#slashing_evidence.stake_at_slash,
        reported_at    => Evidence#slashing_evidence.reported_at
    }).

cleanup_dedup_window(State) ->
    Now        = erlang:system_time(millisecond),
    Cutoff     = Now - ?MAX_EVIDENCE_AGE_MS,
    NewHashes  = maps:filter(fun(_Hash, Timestamp) ->
        Timestamp > Cutoff
    end, State#slashing_state.processed_hashes),
    State#slashing_state{processed_hashes = NewHashes}.
