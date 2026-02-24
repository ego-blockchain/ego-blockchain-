-module(sbft_shard_consensus).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([
    start_link/2,
    stop/1,
    propose_block/2,
    submit_vote/2,
    submit_view_change/2,
    get_status/1,
    get_committed_block/2,
    get_high_qc/1,
    add_validator/2,
    remove_validator/2,
    update_validator_stake/3,
    inject_cross_shard_receipt/2,
    get_pending_receipts/1,
    force_view_change/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

start_link(ShardId, Config) ->
    gen_server:start_link(?MODULE, {ShardId, Config}, []).

stop(Pid) ->
    gen_server:call(Pid, stop).

propose_block(Pid, Block) ->
    gen_server:cast(Pid, {propose_block, Block}).

submit_vote(Pid, Vote) ->
    gen_server:cast(Pid, {submit_vote, Vote}).

submit_view_change(Pid, ViewChangeMsg) ->
    gen_server:cast(Pid, {submit_view_change, ViewChangeMsg}).

get_status(Pid) ->
    gen_server:call(Pid, get_status).

get_committed_block(Pid, View) ->
    gen_server:call(Pid, {get_committed_block, View}).

get_high_qc(Pid) ->
    gen_server:call(Pid, get_high_qc).

add_validator(Pid, Validator) ->
    gen_server:call(Pid, {add_validator, Validator}).

remove_validator(Pid, ValidatorId) ->
    gen_server:call(Pid, {remove_validator, ValidatorId}).

update_validator_stake(Pid, ValidatorId, NewStake) ->
    gen_server:call(Pid, {update_validator_stake, ValidatorId, NewStake}).

inject_cross_shard_receipt(Pid, Receipt) ->
    gen_server:cast(Pid, {inject_cross_shard_receipt, Receipt}).

get_pending_receipts(Pid) ->
    gen_server:call(Pid, get_pending_receipts).

force_view_change(Pid) ->
    gen_server:cast(Pid, force_view_change).

init({ShardId, Config}) ->
    process_flag(trap_exit, true),

    Validators      = maps:get(validators, Config, []),
    ConsTimeout     = maps:get(consensus_timeout, Config, ?DEFAULT_CONSENSUS_TIMEOUT),
    VCTimeout       = maps:get(view_change_timeout, Config, ?DEFAULT_VIEW_CHANGE_TIMEOUT),
    PQCEnabled      = maps:get(pqc_enabled, Config, true),
    SigAlgorithm    = maps:get(sig_algorithm, Config, dilithium2),

    ValidatorWeights = calculate_validator_weights(Validators),
    TotalStake       = calculate_total_stake(Validators),

    State = #sbft_consensus_state{
        shard_id             = ShardId,
        validators           = Validators,
        validator_weights    = ValidatorWeights,
        total_stake          = TotalStake,
        consensus_timeout    = ConsTimeout,
        view_change_timeout  = VCTimeout,
        current_leader       = select_leader(0, Validators),
        pqc_enabled          = PQCEnabled,
        sig_algorithm        = SigAlgorithm,
        metrics              = init_metrics()
    },

    TimeoutRef = schedule_consensus_timeout(ConsTimeout),
    {ok, State#sbft_consensus_state{timeout_ref = TimeoutRef}}.

handle_call(get_status, _From, State) ->
    Status = build_status(State),
    {reply, Status, State};

handle_call({get_committed_block, View}, _From, State) ->
    Result = maps:get(View, State#sbft_consensus_state.committed_blocks, undefined),
    case Result of
        undefined -> {reply, {error, not_found}, State};
        Block     -> {reply, {ok, Block}, State}
    end;

handle_call(get_high_qc, _From, State) ->
    {reply, State#sbft_consensus_state.high_qc, State};

handle_call({add_validator, Validator}, _From, State) ->
    ValidatorId = Validator#sbft_validator_record.id,
    Existing    = State#sbft_consensus_state.validators,
    case lists:keyfind(ValidatorId, #sbft_validator_record.id, Existing) of
        false ->
            NewValidators    = [Validator | Existing],
            NewWeights       = calculate_validator_weights(NewValidators),
            NewTotalStake    = calculate_total_stake(NewValidators),
            NewState = State#sbft_consensus_state{
                validators        = NewValidators,
                validator_weights = NewWeights,
                total_stake       = NewTotalStake
            },
            {reply, ok, NewState};
        _ ->
            {reply, {error, already_exists}, State}
    end;

handle_call({remove_validator, ValidatorId}, _From, State) ->
    Existing     = State#sbft_consensus_state.validators,
    NewValidators = lists:keydelete(ValidatorId, #sbft_validator_record.id, Existing),
    case length(NewValidators) < length(Existing) of
        false ->
            {reply, {error, not_found}, State};
        true ->
            case length(NewValidators) < ?MIN_VALIDATORS_PER_SHARD of
                true ->
                    {reply, {error, below_minimum_validators}, State};
                false ->
                    NewWeights    = calculate_validator_weights(NewValidators),
                    NewTotalStake = calculate_total_stake(NewValidators),
                    NewState = State#sbft_consensus_state{
                        validators        = NewValidators,
                        validator_weights = NewWeights,
                        total_stake       = NewTotalStake
                    },
                    {reply, ok, NewState}
            end
    end;

handle_call({update_validator_stake, ValidatorId, NewStake}, _From, State) ->
    Existing = State#sbft_consensus_state.validators,
    case lists:keyfind(ValidatorId, #sbft_validator_record.id, Existing) of
        false ->
            {reply, {error, not_found}, State};
        Validator ->
            Updated       = Validator#sbft_validator_record{stake = NewStake},
            NewValidators = lists:keyreplace(ValidatorId, #sbft_validator_record.id, Existing, Updated),
            NewWeights    = calculate_validator_weights(NewValidators),
            NewTotalStake = calculate_total_stake(NewValidators),
            NewState = State#sbft_consensus_state{
                validators        = NewValidators,
                validator_weights = NewWeights,
                total_stake       = NewTotalStake
            },
            {reply, ok, NewState}
    end;

handle_call(get_pending_receipts, _From, State) ->
    {reply, State#sbft_consensus_state.cross_shard_receipts, State};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({propose_block, Block}, State) ->
    NewState = handle_block_proposal(Block, State),
    {noreply, NewState};

handle_cast({submit_vote, Vote}, State) ->
    NewState = handle_vote(Vote, State),
    {noreply, NewState};

handle_cast({submit_view_change, ViewChangeMsg}, State) ->
    NewState = handle_view_change_message(ViewChangeMsg, State),
    {noreply, NewState};

handle_cast({inject_cross_shard_receipt, Receipt}, State) ->
    Current    = State#sbft_consensus_state.cross_shard_receipts,
    NewReceipts = [Receipt | Current],
    {noreply, State#sbft_consensus_state{cross_shard_receipts = NewReceipts}};

handle_cast(force_view_change, State) ->
    NewState = initiate_view_change(State),
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(consensus_timeout, State) ->
    NewState = handle_consensus_timeout(State),
    {noreply, NewState};

handle_info(view_change_timeout, State) ->
    NewState = handle_view_change_timeout(State),
    {noreply, NewState};

handle_info({'EXIT', _Pid, Reason}, State) ->
    error_logger:error_msg(
        "[sbft_shard_consensus] shard=~p linked process exited: ~p~n",
        [State#sbft_consensus_state.shard_id, Reason]
    ),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timer(State#sbft_consensus_state.timeout_ref),
    cancel_timer(State#sbft_consensus_state.view_change_timer),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_block_proposal(Block, State) ->
    case State#sbft_consensus_state.phase of
        prepare ->
            case validate_block_proposal(Block, State) of
                {ok, ValidatedBlock} ->
                    process_valid_proposal(ValidatedBlock, State);
                {error, Reason} ->
                    error_logger:warning_msg(
                        "[sbft_shard_consensus] shard=~p invalid block proposal: ~p~n",
                        [State#sbft_consensus_state.shard_id, Reason]
                    ),
                    State
            end;
        _ ->
            State
    end.

validate_block_proposal(Block, State) ->
    Checks = [
        fun() -> check_proposer_is_leader(Block, State) end,
        fun() -> check_block_view(Block, State) end,
        fun() -> check_parent_hash(Block, State) end,
        fun() -> check_shard_id(Block, State) end,
        fun() -> check_liveness_rule(Block, State) end
    ],
    run_checks(Checks, Block).

run_checks([], Block) ->
    {ok, Block};
run_checks([Check | Rest], Block) ->
    case Check() of
        ok             -> run_checks(Rest, Block);
        {error, _} = E -> E
    end.

check_proposer_is_leader(Block, State) ->
    Leader   = State#sbft_consensus_state.current_leader,
    Proposer = Block#sbft_block_record.proposer,
    case Proposer =:= Leader of
        true  -> ok;
        false -> {error, {not_leader, Proposer, Leader}}
    end.

check_block_view(Block, State) ->
    BlockView = Block#sbft_block_record.view,
    StateView = State#sbft_consensus_state.view,
    case BlockView =:= StateView of
        true  -> ok;
        false -> {error, {view_mismatch, BlockView, StateView}}
    end.

check_parent_hash(Block, State) ->
    case State#sbft_consensus_state.last_finalized_hash of
        undefined -> ok;
        LastHash  ->
            case Block#sbft_block_record.parent_hash =:= LastHash of
                true  -> ok;
                false -> {error, {invalid_parent_hash,
                                  Block#sbft_block_record.parent_hash,
                                  LastHash}}
            end
    end.

check_shard_id(Block, State) ->
    BlockShard = Block#sbft_block_record.shard_id,
    StateShard = State#sbft_consensus_state.shard_id,
    case BlockShard =:= StateShard of
        true  -> ok;
        false -> {error, {shard_mismatch, BlockShard, StateShard}}
    end.

check_liveness_rule(Block, State) ->
    case State#sbft_consensus_state.locked_block of
        undefined ->
            ok;
        LockedBlock ->
            LockedView = State#sbft_consensus_state.locked_view,
            BlockView  = Block#sbft_block_record.view,
            BlockHash  = Block#sbft_block_record.hash,
            LockedHash = LockedBlock#sbft_block_record.hash,
            case BlockHash =:= LockedHash orelse BlockView > LockedView of
                true  -> ok;
                false -> {error, {violates_liveness_rule, BlockView, LockedView}}
            end
    end.

process_valid_proposal(Block, State) ->
    NewState1 = State#sbft_consensus_state{
        current_block      = Block,
        current_block_hash = Block#sbft_block_record.hash,
        votes              = #{}
    },
    PreparedBlocks = maps:put(
        State#sbft_consensus_state.view,
        Block,
        State#sbft_consensus_state.prepared_blocks
    ),
    NewState2 = NewState1#sbft_consensus_state{prepared_blocks = PreparedBlocks},
    Metrics   = bump_metric(blocks_proposed, NewState2#sbft_consensus_state.metrics),
    NewState3 = NewState2#sbft_consensus_state{metrics = Metrics},
    cast_self_prepare_vote(NewState3),
    NewState3.

cast_self_prepare_vote(State) ->
    Vote = build_internal_vote(prepare, State),
    gen_server:cast(self(), {submit_vote, Vote}).

build_internal_vote(VoteType, State) ->
    BlockHash = case State#sbft_consensus_state.current_block_hash of
        undefined -> <<>>;
        H         -> H
    end,
    #sbft_vote_record{
        validator_id = State#sbft_consensus_state.current_leader,
        view         = State#sbft_consensus_state.view,
        block_hash   = BlockHash,
        vote_type    = VoteType,
        signature    = build_vote_signature(VoteType, State),
        pqc_signature = undefined,
        timestamp    = erlang:system_time(millisecond),
        shard_id     = State#sbft_consensus_state.shard_id
    }.

build_vote_signature(VoteType, State) ->
    Payload = term_to_binary({
        VoteType,
        State#sbft_consensus_state.view,
        State#sbft_consensus_state.current_block_hash,
        State#sbft_consensus_state.shard_id
    }),
    sbft_crypto:hash(blake2s, Payload).

handle_vote(Vote, State) ->
    case validate_vote(Vote, State) of
        {ok, _} ->
            State1 = check_equivocation(Vote, State),
            State2 = record_vote(Vote, State1),
            check_consensus_progress(State2);
        {error, Reason} ->
            error_logger:warning_msg(
                "[sbft_shard_consensus] shard=~p invalid vote from ~p: ~p~n",
                [State#sbft_consensus_state.shard_id,
                 Vote#sbft_vote_record.validator_id,
                 Reason]
            ),
            State
    end.

validate_vote(Vote, State) ->
    Checks = [
        fun() -> check_vote_shard(Vote, State) end,
        fun() -> check_vote_view(Vote, State) end,
        fun() -> check_validator_active(Vote, State) end,
        fun() -> check_vote_phase_match(Vote, State) end
    ],
    run_checks(Checks, Vote).

check_vote_shard(Vote, State) ->
    case Vote#sbft_vote_record.shard_id =:= State#sbft_consensus_state.shard_id of
        true  -> ok;
        false -> {error, wrong_shard}
    end.

check_vote_view(Vote, State) ->
    VoteView  = Vote#sbft_vote_record.view,
    StateView = State#sbft_consensus_state.view,
    case VoteView =:= StateView of
        true  -> ok;
        false -> {error, {wrong_view, VoteView, StateView}}
    end.

check_validator_active(Vote, State) ->
    ValidatorId = Vote#sbft_vote_record.validator_id,
    Validators  = State#sbft_consensus_state.validators,
    case lists:keyfind(ValidatorId, #sbft_validator_record.id, Validators) of
        false     -> {error, {unknown_validator, ValidatorId}};
        Validator ->
            case Validator#sbft_validator_record.is_active of
                true  -> ok;
                false -> {error, {validator_inactive, ValidatorId}}
            end
    end.

check_vote_phase_match(Vote, State) ->
    VoteType     = Vote#sbft_vote_record.vote_type,
    CurrentPhase = State#sbft_consensus_state.phase,
    case {VoteType, CurrentPhase} of
        {prepare,     prepare}     -> ok;
        {commit,      commit}      -> ok;
        {view_change, view_change} -> ok;
        {new_view,    view_change} -> ok;
        _                          -> {error, {phase_mismatch, VoteType, CurrentPhase}}
    end.

check_equivocation(Vote, State) ->
    ValidatorId = Vote#sbft_vote_record.validator_id,
    DoubleLog   = State#sbft_consensus_state.double_vote_log,
    ExistingVotes = maps:get(ValidatorId, DoubleLog, []),
    Equivocations = lists:filtermap(fun(ExistingVote) ->
        case sbft_crypto:detect_equivocation(Vote, ExistingVote) of
            {equivocation_detected, Id} ->
                {true, {Id, ExistingVote, Vote}};
            no_equivocation ->
                false
        end
    end, ExistingVotes),
    case Equivocations of
        [] ->
            NewLog      = maps:put(ValidatorId, [Vote | ExistingVotes], DoubleLog),
            Metrics     = bump_metric(equivocations_detected,
                                      State#sbft_consensus_state.metrics),
            State#sbft_consensus_state{
                double_vote_log = NewLog,
                metrics         = Metrics
            };
        [_|_] ->
            lists:foreach(fun({Id, V1, V2}) ->
                report_equivocation(Id, V1, V2, State)
            end, Equivocations),
            NewLog  = maps:put(ValidatorId, [Vote | ExistingVotes], DoubleLog),
            Metrics = bump_metric(equivocations_detected,
                                  State#sbft_consensus_state.metrics),
            State#sbft_consensus_state{
                double_vote_log = NewLog,
                metrics         = Metrics
            }
    end.

report_equivocation(ValidatorId, Vote1, Vote2, State) ->
    Evidence = #slashing_evidence{
        validator_id   = ValidatorId,
        reason         = equivocation,
        evidence_votes = [Vote1, Vote2],
        evidence_block = undefined,
        reported_at    = erlang:system_time(millisecond),
        shard_id       = State#sbft_consensus_state.shard_id,
        stake_at_slash = get_validator_stake(ValidatorId, State)
    },
    sbft_slashing:report(Evidence).

get_validator_stake(ValidatorId, State) ->
    maps:get(ValidatorId, State#sbft_consensus_state.validator_weights, 0).

record_vote(Vote, State) ->
    ValidatorId = Vote#sbft_vote_record.validator_id,
    NewVotes    = maps:put(ValidatorId, Vote, State#sbft_consensus_state.votes),
    State#sbft_consensus_state{votes = NewVotes}.

check_consensus_progress(State) ->
    case State#sbft_consensus_state.phase of
        prepare     -> check_prepare_phase(State);
        commit      -> check_commit_phase(State);
        view_change -> check_view_change_phase(State);
        _           -> State
    end.

check_prepare_phase(State) ->
    WeightedVotes   = count_weighted_votes(prepare, State),
    RequiredWeight  = required_weight(State#sbft_consensus_state.total_stake),
    case WeightedVotes >= RequiredWeight of
        true ->
            QC       = form_quorum_certificate(prepare, State),
            NewState = advance_to_commit(QC, State),
            NewState;
        false ->
            State
    end.

check_commit_phase(State) ->
    WeightedVotes  = count_weighted_votes(commit, State),
    RequiredWeight = required_weight(State#sbft_consensus_state.total_stake),
    case WeightedVotes >= RequiredWeight of
        true ->
            QC       = form_quorum_certificate(commit, State),
            NewState = finalize_block(QC, State),
            NewState;
        false ->
            State
    end.

check_view_change_phase(State) ->
    View           = State#sbft_consensus_state.view,
    PendingVC      = State#sbft_consensus_state.pending_view_changes,
    VCVotes        = maps:get(View, PendingVC, #{}),
    WeightedVotes  = count_weighted_votes_from_map(view_change, VCVotes, State),
    RequiredWeight = required_weight(State#sbft_consensus_state.total_stake),
    case WeightedVotes >= RequiredWeight of
        true  -> start_new_view(State);
        false -> State
    end.

advance_to_commit(QC, State) ->
    NewState1 = update_high_qc(QC, State),
    NewState2 = NewState1#sbft_consensus_state{
        phase  = commit,
        votes  = #{}
    },
    NewState3 = reset_consensus_timer(NewState2),
    cast_self_commit_vote(NewState3),
    NewState3.

cast_self_commit_vote(State) ->
    Vote = build_internal_vote(commit, State),
    gen_server:cast(self(), {submit_vote, Vote}).

update_high_qc(QC, State) ->
    CurrentHighQC = State#sbft_consensus_state.high_qc,
    case CurrentHighQC of
        undefined ->
            State#sbft_consensus_state{high_qc = QC};
        Existing ->
            case QC#quorum_certificate.view > Existing#quorum_certificate.view of
                true  -> State#sbft_consensus_state{high_qc = QC};
                false -> State
            end
    end.

finalize_block(QC, State) ->
    View    = State#sbft_consensus_state.view,
    Block   = State#sbft_consensus_state.current_block,
    NewCommitted = maps:put(View, Block, State#sbft_consensus_state.committed_blocks),
    Metrics = bump_metric(blocks_committed, State#sbft_consensus_state.metrics),
    NewView = View + 1,
    NewState1 = State#sbft_consensus_state{
        view                 = NewView,
        height               = State#sbft_consensus_state.height + 1,
        phase                = prepare,
        current_block        = undefined,
        current_block_hash   = undefined,
        votes                = #{},
        committed_blocks     = NewCommitted,
        current_leader       = select_leader(NewView, State#sbft_consensus_state.validators),
        last_finalized_view  = View,
        last_finalized_hash  = Block#sbft_block_record.hash,
        locked_block         = Block,
        locked_view          = View,
        high_qc              = QC,
        cross_shard_receipts = [],
        metrics              = Metrics
    },
    notify_finalization(Block, QC, NewState1),
    reset_consensus_timer(NewState1).

notify_finalization(Block, QC, State) ->
    sbft_event_bus:publish(block_finalized, #{
        shard_id   => State#sbft_consensus_state.shard_id,
        block_hash => Block#sbft_block_record.hash,
        view       => Block#sbft_block_record.view,
        height     => State#sbft_consensus_state.height,
        qc         => QC,
        receipts   => State#sbft_consensus_state.cross_shard_receipts
    }).

form_quorum_certificate(VoteType, State) ->
    Votes = maps:values(maps:filter(fun(_K, V) ->
        V#sbft_vote_record.vote_type =:= VoteType
    end, State#sbft_consensus_state.votes)),
    {ok, AggSig} = sbft_crypto:aggregate_signatures(Votes),
    #quorum_certificate{
        view          = State#sbft_consensus_state.view,
        block_hash    = State#sbft_consensus_state.current_block_hash,
        shard_id      = State#sbft_consensus_state.shard_id,
        votes         = Votes,
        aggregate_sig = AggSig,
        formed_at     = erlang:system_time(millisecond)
    }.

handle_view_change_message(ViewChangeMsg, State) ->
    NewView     = ViewChangeMsg#view_change_message.new_view,
    ValidatorId = ViewChangeMsg#view_change_message.validator_id,
    HighQC      = ViewChangeMsg#view_change_message.high_qc,
    PendingVC   = State#sbft_consensus_state.pending_view_changes,
    ViewVotes   = maps:get(NewView, PendingVC, #{}),
    VCVote = #sbft_vote_record{
        validator_id = ValidatorId,
        view         = NewView,
        block_hash   = case HighQC of
                           undefined -> <<>>;
                           QC        -> QC#quorum_certificate.block_hash
                       end,
        vote_type    = view_change,
        signature    = ViewChangeMsg#view_change_message.signature,
        timestamp    = ViewChangeMsg#view_change_message.timestamp,
        shard_id     = State#sbft_consensus_state.shard_id
    },
    NewViewVotes = maps:put(ValidatorId, VCVote, ViewVotes),
    NewPendingVC = maps:put(NewView, NewViewVotes, PendingVC),
    NewState1    = State#sbft_consensus_state{pending_view_changes = NewPendingVC},
    NewState2    = maybe_update_high_qc_from_view_change(HighQC, NewState1),
    case State#sbft_consensus_state.phase =:= view_change of
        true  -> check_view_change_phase(NewState2);
        false -> NewState2
    end.

maybe_update_high_qc_from_view_change(undefined, State) ->
    State;
maybe_update_high_qc_from_view_change(QC, State) ->
    update_high_qc(QC, State).

initiate_view_change(State) ->
    cancel_timer(State#sbft_consensus_state.timeout_ref),
    NewState1 = State#sbft_consensus_state{
        phase   = view_change,
        votes   = #{}
    },
    VCTimerRef = schedule_view_change_timeout(State#sbft_consensus_state.view_change_timeout),
    NewState2  = NewState1#sbft_consensus_state{view_change_timer = VCTimerRef},
    Metrics    = bump_metric(view_changes, NewState2#sbft_consensus_state.metrics),
    NewState2#sbft_consensus_state{metrics = Metrics}.

start_new_view(State) ->
    cancel_timer(State#sbft_consensus_state.view_change_timer),
    NewView    = State#sbft_consensus_state.view + 1,
    NewLeader  = select_leader(NewView, State#sbft_consensus_state.validators),
    NewState   = State#sbft_consensus_state{
        view           = NewView,
        phase          = prepare,
        current_block  = undefined,
        current_block_hash = undefined,
        votes          = #{},
        current_leader = NewLeader,
        view_change_timer = undefined
    },
    notify_new_view(NewView, NewLeader, NewState),
    reset_consensus_timer(NewState).

notify_new_view(NewView, NewLeader, State) ->
    sbft_event_bus:publish(new_view_started, #{
        shard_id   => State#sbft_consensus_state.shard_id,
        new_view   => NewView,
        new_leader => NewLeader,
        high_qc    => State#sbft_consensus_state.high_qc
    }).

handle_consensus_timeout(State) ->
    error_logger:warning_msg(
        "[sbft_shard_consensus] shard=~p consensus timeout in phase=~p view=~p~n",
        [State#sbft_consensus_state.shard_id,
         State#sbft_consensus_state.phase,
         State#sbft_consensus_state.view]
    ),
    case State#sbft_consensus_state.phase of
        finalized -> State;
        _         -> initiate_view_change(State)
    end.

handle_view_change_timeout(State) ->
    error_logger:warning_msg(
        "[sbft_shard_consensus] shard=~p view change timeout, forcing new view~n",
        [State#sbft_consensus_state.shard_id]
    ),
    start_new_view(State).

count_weighted_votes(VoteType, State) ->
    Votes   = State#sbft_consensus_state.votes,
    Weights = State#sbft_consensus_state.validator_weights,
    maps:fold(fun(ValidatorId, Vote, Acc) ->
        case Vote#sbft_vote_record.vote_type =:= VoteType of
            true  -> Acc + maps:get(ValidatorId, Weights, 0);
            false -> Acc
        end
    end, 0, Votes).

count_weighted_votes_from_map(VoteType, VotesMap, State) ->
    Weights = State#sbft_consensus_state.validator_weights,
    maps:fold(fun(ValidatorId, Vote, Acc) ->
        case Vote#sbft_vote_record.vote_type =:= VoteType of
            true  -> Acc + maps:get(ValidatorId, Weights, 0);
            false -> Acc
        end
    end, 0, VotesMap).

required_weight(TotalStake) ->
    trunc(TotalStake * ?REQUIRED_VOTE_FRACTION) + 1.

select_leader(_View, []) ->
    undefined;
select_leader(View, Validators) ->
    Active = lists:filter(fun(V) -> V#sbft_validator_record.is_active end, Validators),
    case Active of
        [] ->
            undefined;
        _ ->
            Index     = View rem length(Active),
            Validator = lists:nth(Index + 1, Active),
            Validator#sbft_validator_record.id
    end.

calculate_validator_weights(Validators) ->
    lists:foldl(fun(V, Acc) ->
        maps:put(V#sbft_validator_record.id, V#sbft_validator_record.stake, Acc)
    end, #{}, Validators).

calculate_total_stake(Validators) ->
    lists:foldl(fun(V, Acc) ->
        Acc + V#sbft_validator_record.stake
    end, 0, Validators).

schedule_consensus_timeout(Timeout) ->
    erlang:send_after(Timeout, self(), consensus_timeout).

schedule_view_change_timeout(Timeout) ->
    erlang:send_after(Timeout, self(), view_change_timeout).

cancel_timer(undefined) ->
    ok;
cancel_timer(Ref) ->
    erlang:cancel_timer(Ref),
    ok.

reset_consensus_timer(State) ->
    cancel_timer(State#sbft_consensus_state.timeout_ref),
    Timeout = State#sbft_consensus_state.consensus_timeout,
    NewRef  = schedule_consensus_timeout(Timeout),
    State#sbft_consensus_state{timeout_ref = NewRef}.

init_metrics() ->
    #{
        blocks_proposed              => 0,
        blocks_committed             => 0,
        view_changes                 => 0,
        equivocations_detected       => 0,
        cross_shard_receipts_processed => 0,
        last_finality_time           => undefined
    }.

bump_metric(Key, Metrics) ->
    maps:update_with(Key, fun(V) -> V + 1 end, 1, Metrics).

build_status(State) ->
    #{
        shard_id            => State#sbft_consensus_state.shard_id,
        view                => State#sbft_consensus_state.view,
        height              => State#sbft_consensus_state.height,
        phase               => State#sbft_consensus_state.phase,
        current_leader      => State#sbft_consensus_state.current_leader,
        validators_count    => length(State#sbft_consensus_state.validators),
        total_stake         => State#sbft_consensus_state.total_stake,
        last_finalized_view => State#sbft_consensus_state.last_finalized_view,
        last_finalized_hash => State#sbft_consensus_state.last_finalized_hash,
        locked_view         => State#sbft_consensus_state.locked_view,
        high_qc_view        => case State#sbft_consensus_state.high_qc of
                                   undefined -> undefined;
                                   QC        -> QC#quorum_certificate.view
                               end,
        pending_receipts    => length(State#sbft_consensus_state.cross_shard_receipts),
        pqc_enabled         => State#sbft_consensus_state.pqc_enabled,
        metrics             => State#sbft_consensus_state.metrics
    }.
