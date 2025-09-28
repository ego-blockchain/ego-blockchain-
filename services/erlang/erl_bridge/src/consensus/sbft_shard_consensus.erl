-module(sbft_shard_consensus).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([start_link/2, stop/1, propose_block/2, submit_vote/2,
         get_status/1, add_validator/2, remove_validator/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

start_link(ShardId, Config) ->
    gen_server:start_link(?MODULE, {ShardId, Config}, []).

stop(Pid) ->
    gen_server:call(Pid, stop).

propose_block(Pid, Block) ->
    gen_server:cast(Pid, {propose_block, Block}).

submit_vote(Pid, Vote) ->
    gen_server:cast(Pid, {submit_vote, Vote}).

get_status(Pid) ->
    gen_server:call(Pid, get_status).

add_validator(Pid, Validator) ->
    gen_server:call(Pid, {add_validator, Validator}).

remove_validator(Pid, ValidatorId) ->
    gen_server:call(Pid, {remove_validator, ValidatorId}).

init({ShardId, Config}) ->
    Validators = maps:get(validators, Config, []),
    ConsensusTimeout = maps:get(consensus_timeout, Config, 3000),
    ViewChangeTimeout = maps:get(view_change_timeout, Config, 5000),

    ValidatorWeights = calculate_validator_weights(Validators),
    TotalStake = calculate_total_stake(Validators),

    State = #sbft_consensus_state{
        shard_id = ShardId,
        validators = Validators,
        validator_weights = ValidatorWeights,
        total_stake = TotalStake,
        consensus_timeout = ConsensusTimeout,
        view_change_timeout = ViewChangeTimeout,
        current_leader = select_leader(0, Validators),
        metrics = #{
            blocks_proposed => 0,
            blocks_committed => 0,
            view_changes => 0
        }
    },

    TimeoutRef = erlang:send_after(ConsensusTimeout, self(), consensus_timeout),
    NewState = State#sbft_consensus_state{timeout_ref = TimeoutRef},

    {ok, NewState}.

handle_call(get_status, _From, State) ->
    Status = #{
        shard_id => State#sbft_consensus_state.shard_id,
        view => State#sbft_consensus_state.view,
        phase => State#sbft_consensus_state.phase,
        current_leader => State#sbft_consensus_state.current_leader,
        validators_count => length(State#sbft_consensus_state.validators),
        total_stake => State#sbft_consensus_state.total_stake,
        last_finalized_view => State#sbft_consensus_state.last_finalized_view,
        metrics => State#sbft_consensus_state.metrics
    },
    {reply, Status, State};

handle_call({add_validator, Validator}, _From, State) ->
    case lists:keyfind(Validator#sbft_validator_record.id, #sbft_validator_record.id,
                      State#sbft_consensus_state.validators) of
        false ->
            NewValidators = [Validator | State#sbft_consensus_state.validators],
            NewWeights = calculate_validator_weights(NewValidators),
            NewTotalStake = calculate_total_stake(NewValidators),
            NewState = State#sbft_consensus_state{
                validators = NewValidators,
                validator_weights = NewWeights,
                total_stake = NewTotalStake
            },
            {reply, ok, NewState};
        _ ->
            {reply, {error, already_exists}, State}
    end;

handle_call({remove_validator, ValidatorId}, _From, State) ->
    NewValidators = lists:keydelete(ValidatorId, #sbft_validator_record.id,
                                   State#sbft_consensus_state.validators),
    case length(NewValidators) < length(State#sbft_consensus_state.validators) of
        true ->
            NewWeights = calculate_validator_weights(NewValidators),
            NewTotalStake = calculate_total_stake(NewValidators),
            NewState = State#sbft_consensus_state{
                validators = NewValidators,
                validator_weights = NewWeights,
                total_stake = NewTotalStake
            },
            {reply, ok, NewState};
        false ->
            {reply, {error, not_found}, State}
    end;

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({propose_block, Block}, State) ->
    case State#sbft_consensus_state.phase of
        prepare ->
            NewState = handle_block_proposal(Block, State),
            {noreply, NewState};
        _ ->
            {noreply, State}
    end;

handle_cast({submit_vote, Vote}, State) ->
    NewState = handle_vote_submission(Vote, State),
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(consensus_timeout, State) ->
    NewState = handle_consensus_timeout(State),
    {noreply, NewState};

handle_info(view_change_timeout, State) ->
    NewState = handle_view_change_timeout(State),
    {noreply, NewState};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    case State#sbft_consensus_state.timeout_ref of
        undefined -> ok;
        Ref -> erlang:cancel_timer(Ref)
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_block_proposal(Block, State) ->
    case validate_block_proposal(Block, State) of
        true ->
            NewState = State#sbft_consensus_state{
                current_block = Block,
                current_block_hash = Block#sbft_block_record.hash,
                phase = prepare
            },

            broadcast_prepare_vote(NewState),

            Metrics = State#sbft_consensus_state.metrics,
            NewMetrics = maps:update_with(blocks_proposed, fun(X) -> X + 1 end, 1, Metrics),
            NewState#sbft_consensus_state{metrics = NewMetrics};
        false ->
            State
    end.

handle_vote_submission(Vote, State) ->
    case validate_vote(Vote, State) of
        true ->
            ValidatorId = Vote#sbft_vote_record.validator_id,
            NewVotes = maps:put(ValidatorId, Vote, State#sbft_consensus_state.votes),
            NewState = State#sbft_consensus_state{votes = NewVotes},

            check_consensus_progress(NewState);
        false ->
            State
    end.

check_consensus_progress(State) ->
    case State#sbft_consensus_state.phase of
        prepare ->
            check_prepare_phase(State);
        commit ->
            check_commit_phase(State);
        view_change ->
            check_view_change_phase(State)
    end.

check_prepare_phase(State) ->
    PrepareVotes = count_votes_by_type(prepare, State),
    RequiredVotes = calculate_required_votes(State#sbft_consensus_state.total_stake),

    if PrepareVotes >= RequiredVotes ->
        NewState = State#sbft_consensus_state{phase = commit, votes = #{}},
        broadcast_commit_vote(NewState),
        reset_consensus_timer(NewState);
    true ->
        State
    end.

check_commit_phase(State) ->
    CommitVotes = count_votes_by_type(commit, State),
    RequiredVotes = calculate_required_votes(State#sbft_consensus_state.total_stake),

    if CommitVotes >= RequiredVotes ->
        finalize_block(State);
    true ->
        State
    end.

check_view_change_phase(State) ->
    ViewChangeVotes = count_votes_by_type(view_change, State),
    RequiredVotes = calculate_required_votes(State#sbft_consensus_state.total_stake),

    if ViewChangeVotes >= RequiredVotes ->
        start_new_view(State);
    true ->
        State
    end.

finalize_block(State) ->
    View = State#sbft_consensus_state.view,
    Block = State#sbft_consensus_state.current_block,

    NewCommittedBlocks = maps:put(View, Block, State#sbft_consensus_state.committed_blocks),

    Metrics = State#sbft_consensus_state.metrics,
    NewMetrics = maps:update_with(blocks_committed, fun(X) -> X + 1 end, 1, Metrics),

    NewView = View + 1,
    NewLeader = select_leader(NewView, State#sbft_consensus_state.validators),

    NewState = State#sbft_consensus_state{
        view = NewView,
        phase = prepare,
        current_block = undefined,
        current_block_hash = undefined,
        votes = #{},
        committed_blocks = NewCommittedBlocks,
        current_leader = NewLeader,
        last_finalized_view = View,
        metrics = NewMetrics
    },

    reset_consensus_timer(NewState).

start_new_view(State) ->
    NewView = State#sbft_consensus_state.view + 1,
    NewLeader = select_leader(NewView, State#sbft_consensus_state.validators),

    Metrics = State#sbft_consensus_state.metrics,
    NewMetrics = maps:update_with(view_changes, fun(X) -> X + 1 end, 1, Metrics),

    NewState = State#sbft_consensus_state{
        view = NewView,
        phase = prepare,
        current_block = undefined,
        current_block_hash = undefined,
        votes = #{},
        current_leader = NewLeader,
        metrics = NewMetrics
    },

    reset_consensus_timer(NewState).

handle_consensus_timeout(State) ->
    case State#sbft_consensus_state.phase of
        prepare ->
            State#sbft_consensus_state{phase = view_change, votes = #{}};
        commit ->
            State#sbft_consensus_state{phase = view_change, votes = #{}};
        view_change ->
            State
    end.

handle_view_change_timeout(State) ->
    start_new_view(State).

validate_block_proposal(_Block, _State) ->
    true.

validate_vote(_Vote, _State) ->
    true.

broadcast_prepare_vote(_State) ->
    ok.

broadcast_commit_vote(_State) ->
    ok.

count_votes_by_type(VoteType, State) ->
    maps:fold(fun(_ValidatorId, Vote, Acc) ->
        case Vote#sbft_vote_record.vote_type of
            VoteType -> Acc + 1;
            _ -> Acc
        end
    end, 0, State#sbft_consensus_state.votes).

calculate_required_votes(TotalStake) ->
    (TotalStake * 2) div 3 + 1.

calculate_validator_weights(Validators) ->
    lists:foldl(fun(Validator, Acc) ->
        maps:put(Validator#sbft_validator_record.id,
                Validator#sbft_validator_record.stake, Acc)
    end, #{}, Validators).

calculate_total_stake(Validators) ->
    lists:foldl(fun(Validator, Acc) ->
        Acc + Validator#sbft_validator_record.stake
    end, 0, Validators).

select_leader(View, Validators) ->
    case Validators of
        [] -> undefined;
        _ ->
            Index = View rem length(Validators),
            Validator = lists:nth(Index + 1, Validators),
            Validator#sbft_validator_record.id
    end.

reset_consensus_timer(State) ->
    case State#sbft_consensus_state.timeout_ref of
        undefined -> ok;
        Ref -> erlang:cancel_timer(Ref)
    end,
    Timeout = State#sbft_consensus_state.consensus_timeout,
    NewRef = erlang:send_after(Timeout, self(), consensus_timeout),
    State#sbft_consensus_state{timeout_ref = NewRef}.
