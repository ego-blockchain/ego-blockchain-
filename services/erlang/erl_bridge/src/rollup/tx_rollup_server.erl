%%%-------------------------------------------------------------------
%%% @doc TxRollup Server
%%% L1 shard server for TxRollup commitments
%%% Handles transaction batches, state transitions, challenges, and finalization
%%% @end
%%%-------------------------------------------------------------------

-module(tx_rollup_server).

-behaviour(gen_server).

%% API
-export([start_link/2,
         submit_commitment/2,
         challenge_commitment/3,
         defend_challenge/3,
         finalize_commitment/2,
         get_commitment/2,
         get_state/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {
    rollup_id :: binary(),
    region_id :: non_neg_integer(),
    config :: map(),
    commitments :: map(),
    challenges :: map(),
    current_epoch :: non_neg_integer(),
    current_window :: non_neg_integer(),
    current_state_root :: binary(),
    shard_id :: non_neg_integer(),
    consensus_pid :: pid() | undefined
}).

-record(tx_commitment, {
    commitment_hash :: binary(),
    rollup_id :: binary(),
    region_id :: non_neg_integer(),
    epoch :: non_neg_integer(),
    window_id :: non_neg_integer(),
    tx_root :: binary(),
    state_root :: binary(),
    da_root :: binary(),
    count_tx :: non_neg_integer(),
    blob_bytes :: non_neg_integer(),
    block_range_start :: non_neg_integer(),
    block_range_end :: non_neg_integer(),
    min_validity_proof :: atom(),
    alg_sig_id :: non_neg_integer(),
    operator_addr :: binary(),
    operator_sig :: binary(),
    status :: pending | challenged | finalized | slashed,
    submitted_at :: non_neg_integer(),
    finalize_at :: non_neg_integer()
}).

-record(tx_challenge, {
    challenge_hash :: binary(),
    commitment_hash :: binary(),
    challenger :: binary(),
    challenge_type :: da_unavailable | invalid_state_transition | 
                      invalid_inclusion | timeout,
    fraud_proof :: map() | undefined,
    submitted_at :: non_neg_integer(),
    deadline :: non_neg_integer(),
    status :: pending | defended | proven | expired
}).

-define(CHALLENGE_PERIOD, 1000).
-define(RESPONSE_WINDOW, 100).

%%%===================================================================
%%% API
%%%===================================================================

start_link(RollupId, Config) ->
    gen_server:start_link(?MODULE, [RollupId, Config], []).

-spec submit_commitment(Pid :: pid(), Commitment :: map()) ->
    {ok, CommitmentHash :: binary()} | {error, Reason :: term()}.
submit_commitment(Pid, Commitment) ->
    gen_server:call(Pid, {submit_commitment, Commitment}).

-spec challenge_commitment(Pid :: pid(), CommitmentHash :: binary(),
                           FraudProof :: map()) ->
    {ok, ChallengeHash :: binary()} | {error, Reason :: term()}.
challenge_commitment(Pid, CommitmentHash, FraudProof) ->
    gen_server:call(Pid, {challenge_commitment, CommitmentHash, FraudProof}).

-spec defend_challenge(Pid :: pid(), ChallengeHash :: binary(),
                       Defense :: map()) ->
    ok | {error, Reason :: term()}.
defend_challenge(Pid, ChallengeHash, Defense) ->
    gen_server:call(Pid, {defend_challenge, ChallengeHash, Defense}).

-spec finalize_commitment(Pid :: pid(), CommitmentHash :: binary()) ->
    ok | {error, Reason :: term()}.
finalize_commitment(Pid, CommitmentHash) ->
    gen_server:call(Pid, {finalize_commitment, CommitmentHash}).

-spec get_commitment(Pid :: pid(), CommitmentHash :: binary()) ->
    {ok, map()} | {error, not_found}.
get_commitment(Pid, CommitmentHash) ->
    gen_server:call(Pid, {get_commitment, CommitmentHash}).

-spec get_state(Pid :: pid()) -> {ok, map()}.
get_state(Pid) ->
    gen_server:call(Pid, get_state).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([RollupId, Config]) ->
    process_flag(trap_exit, true),
    
    RegionId = maps:get(region_id, Config, 0),
    ShardId = maps:get(shard_id, Config, 0),
    
    ConsensusPid = case maps:get(consensus_enabled, Config, false) of
        true ->
            {ok, Pid} = sbft_shard_consensus:start_link(ShardId, #{}),
            Pid;
        false ->
            undefined
    end,
    
    erlang:send_after(1000, self(), check_challenge_windows),
    
    io:format("[TxRollup] Started for rollup ~p, region ~p, shard ~p~n",
              [RollupId, RegionId, ShardId]),
    
    {ok, #state{
        rollup_id = RollupId,
        region_id = RegionId,
        config = Config,
        commitments = #{},
        challenges = #{},
        current_epoch = 0,
        current_window = 0,
        current_state_root = crypto:strong_rand_bytes(32),
        shard_id = ShardId,
        consensus_pid = ConsensusPid
    }}.

handle_call({submit_commitment, CommitmentMap}, _From, State) ->
    #state{commitments = Commitments,
           current_epoch = Epoch,
           current_state_root = StateRoot,
           consensus_pid = ConsensusPid} = State,
    
    case verify_dilithium_signature(CommitmentMap) of
        {ok, true} ->
            CommitmentHash = compute_commitment_hash(CommitmentMap),
            
            %% Verify state transition
            PrevStateRoot = maps:get(prev_state_root, CommitmentMap, StateRoot),
            NewStateRoot = maps:get(state_root, CommitmentMap),
            
            case verify_state_transition(PrevStateRoot, NewStateRoot, CommitmentMap) of
                {ok, valid} ->
                    Commitment = #tx_commitment{
                        commitment_hash = CommitmentHash,
                        rollup_id = maps:get(rollup_id, CommitmentMap),
                        region_id = maps:get(region_id, CommitmentMap),
                        epoch = maps:get(epoch, CommitmentMap),
                        window_id = maps:get(window_id, CommitmentMap),
                        tx_root = maps:get(tx_root, CommitmentMap),
                        state_root = NewStateRoot,
                        da_root = maps:get(da_root, CommitmentMap),
                        count_tx = maps:get(count_tx, CommitmentMap),
                        blob_bytes = maps:get(blob_bytes, CommitmentMap),
                        block_range_start = maps:get(block_range_start, CommitmentMap),
                        block_range_end = maps:get(block_range_end, CommitmentMap),
                        min_validity_proof = maps:get(min_validity_proof, CommitmentMap),
                        alg_sig_id = maps:get(alg_sig_id, CommitmentMap),
                        operator_addr = maps:get(operator_addr, CommitmentMap),
                        operator_sig = maps:get(operator_sig, CommitmentMap),
                        status = pending,
                        submitted_at = erlang:system_time(millisecond),
                        finalize_at = erlang:system_time(millisecond) +
                                      (?CHALLENGE_PERIOD * 1000)
                    },
                    
                    NewCommitments = maps:put(CommitmentHash, Commitment, Commitments),
                    
                    case ConsensusPid of
                        undefined -> ok;
                        Pid ->
                            sbft_shard_consensus:propose_transaction(Pid,
                                #{type => tx_rollup_commit,
                                  data => CommitmentMap})
                    end,
                    
                    io:format("[TxRollup] Accepted commitment ~p (epoch=~p, txs=~p)~n",
                              [CommitmentHash, Epoch, Commitment#tx_commitment.count_tx]),
                    
                    {reply, {ok, CommitmentHash},
                     State#state{commitments = NewCommitments,
                                 current_state_root = NewStateRoot}};
                
                {error, Reason} ->
                    {reply, {error, {invalid_state_transition, Reason}}, State}
            end;
        
        {ok, false} ->
            {reply, {error, invalid_signature}, State};
        
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({challenge_commitment, CommitmentHash, FraudProof},
            {ChallengerPid, _}, State) ->
    #state{commitments = Commitments,
           challenges = Challenges} = State,
    
    case maps:get(CommitmentHash, Commitments, undefined) of
        undefined ->
            {reply, {error, commitment_not_found}, State};
        
        Commitment when Commitment#tx_commitment.status =:= pending ->
            ChallengeHash = crypto:strong_rand_bytes(32),
            ChallengeType = maps:get(challenge_type, FraudProof, da_unavailable),
            
            Challenge = #tx_challenge{
                challenge_hash = ChallengeHash,
                commitment_hash = CommitmentHash,
                challenger = term_to_binary(ChallengerPid),
                challenge_type = ChallengeType,
                fraud_proof = FraudProof,
                submitted_at = erlang:system_time(millisecond),
                deadline = erlang:system_time(millisecond) +
                           (?RESPONSE_WINDOW * 1000),
                status = pending
            },
            
            UpdatedCommitment = Commitment#tx_commitment{status = challenged},
            NewCommitments = maps:put(CommitmentHash, UpdatedCommitment,
                                      Commitments),
            NewChallenges = maps:put(ChallengeHash, Challenge, Challenges),
            
            io:format("[TxRollup] Challenge ~p (~p) for commitment ~p~n",
                      [ChallengeHash, ChallengeType, CommitmentHash]),
            
            {reply, {ok, ChallengeHash},
             State#state{commitments = NewCommitments,
                         challenges = NewChallenges}};
        
        _ ->
            {reply, {error, commitment_not_pending}, State}
    end;

handle_call({defend_challenge, ChallengeHash, Defense}, _From, State) ->
    #state{challenges = Challenges,
           commitments = Commitments} = State,
    
    case maps:get(ChallengeHash, Challenges, undefined) of
        undefined ->
            {reply, {error, challenge_not_found}, State};
        
        Challenge when Challenge#tx_challenge.status =:= pending ->
            %% Verify defense based on challenge type
            case verify_defense(Challenge, Defense) of
                {ok, valid} ->
                    UpdatedChallenge = Challenge#tx_challenge{status = defended},
                    NewChallenges = maps:put(ChallengeHash, UpdatedChallenge,
                                             Challenges),
                    
                    %% Update commitment status back to pending
                    CommitmentHash = Challenge#tx_challenge.commitment_hash,
                    case maps:get(CommitmentHash, Commitments, undefined) of
                        undefined ->
                            {reply, {error, commitment_not_found}, State};
                        Commitment ->
                            UpdatedCommitment = Commitment#tx_commitment{status = pending},
                            NewCommitments = maps:put(CommitmentHash,
                                                      UpdatedCommitment,
                                                      Commitments),
                            
                            io:format("[TxRollup] Challenge ~p defended~n",
                                      [ChallengeHash]),
                            
                            {reply, ok,
                             State#state{challenges = NewChallenges,
                                         commitments = NewCommitments}}
                    end;
                
                {error, Reason} ->
                    %% Defense failed, slash operator
                    UpdatedChallenge = Challenge#tx_challenge{status = proven},
                    NewChallenges = maps:put(ChallengeHash, UpdatedChallenge,
                                             Challenges),
                    
                    CommitmentHash = Challenge#tx_challenge.commitment_hash,
                    case maps:get(CommitmentHash, Commitments, undefined) of
                        undefined ->
                            {reply, {error, commitment_not_found}, State};
                        Commitment ->
                            UpdatedCommitment = Commitment#tx_commitment{status = slashed},
                            NewCommitments = maps:put(CommitmentHash,
                                                      UpdatedCommitment,
                                                      Commitments),
                            
                            io:format("[TxRollup] Challenge ~p proven, operator slashed~n",
                                      [ChallengeHash]),
                            
                            {reply, {error, {defense_failed, Reason}},
                             State#state{challenges = NewChallenges,
                                         commitments = NewCommitments}}
                    end
            end;
        
        _ ->
            {reply, {error, challenge_not_pending}, State}
    end;

handle_call({finalize_commitment, CommitmentHash}, _From, State) ->
    #state{commitments = Commitments} = State,
    
    case maps:get(CommitmentHash, Commitments, undefined) of
        undefined ->
            {reply, {error, commitment_not_found}, State};
        
        Commitment ->
            Now = erlang:system_time(millisecond),
            
            case {Commitment#tx_commitment.status,
                  Now >= Commitment#tx_commitment.finalize_at} of
                {pending, true} ->
                    UpdatedCommitment = Commitment#tx_commitment{status = finalized},
                    NewCommitments = maps:put(CommitmentHash, UpdatedCommitment,
                                              Commitments),
                    
                    io:format("[TxRollup] Finalized commitment ~p~n",
                              [CommitmentHash]),
                    
                    {reply, ok, State#state{commitments = NewCommitments}};
                
                {pending, false} ->
                    {reply, {error, challenge_period_not_expired}, State};
                
                {Status, _} ->
                    {reply, {error, {invalid_status, Status}}, State}
            end
    end;

handle_call({get_commitment, CommitmentHash}, _From, State) ->
    #state{commitments = Commitments} = State,
    
    case maps:get(CommitmentHash, Commitments, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Commitment ->
            CommitmentMap = tx_commitment_to_map(Commitment),
            {reply, {ok, CommitmentMap}, State}
    end;

handle_call(get_state, _From, State) ->
    #state{rollup_id = RollupId,
           current_epoch = Epoch,
           current_window = Window,
           current_state_root = StateRoot,
           commitments = Commitments} = State,
    
    StateMap = #{
        rollup_id => RollupId,
        current_epoch => Epoch,
        current_window => Window,
        current_state_root => StateRoot,
        total_commitments => maps:size(Commitments),
        pending_commitments => count_by_status(Commitments, pending),
        finalized_commitments => count_by_status(Commitments, finalized),
        slashed_commitments => count_by_status(Commitments, slashed)
    },
    
    {reply, {ok, StateMap}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(check_challenge_windows, State) ->
    #state{commitments = Commitments,
           challenges = Challenges} = State,
    
    Now = erlang:system_time(millisecond),
    
    NewCommitments = maps:map(
        fun(_Hash, Commitment) ->
            case {Commitment#tx_commitment.status,
                  Now >= Commitment#tx_commitment.finalize_at} of
                {pending, true} ->
                    io:format("[TxRollup] Auto-finalizing commitment ~p~n",
                              [Commitment#tx_commitment.commitment_hash]),
                    Commitment#tx_commitment{status = finalized};
                _ ->
                    Commitment
            end
        end,
        Commitments
    ),
    
    NewChallenges = maps:map(
        fun(_Hash, Challenge) ->
            case {Challenge#tx_challenge.status,
                  Now >= Challenge#tx_challenge.deadline} of
                {pending, true} ->
                    Challenge#tx_challenge{status = expired};
                _ ->
                    Challenge
            end
        end,
        Challenges
    ),
    
    erlang:send_after(5000, self(), check_challenge_windows),
    
    {noreply, State#state{commitments = NewCommitments,
                          challenges = NewChallenges}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

verify_dilithium_signature(CommitmentMap) ->
    %% TODO: Implement Dilithium-2 verification
    _OperatorSig = maps:get(operator_sig, CommitmentMap),
    _AlgSigId = maps:get(alg_sig_id, CommitmentMap),
    {ok, true}.

compute_commitment_hash(CommitmentMap) ->
    Data = term_to_binary(CommitmentMap),
    crypto:hash(blake2s, Data).

verify_state_transition(_PrevStateRoot, _NewStateRoot, _CommitmentMap) ->
    %% TODO: Implement actual state transition verification
    %% For now, accept all transitions
    {ok, valid}.

verify_defense(Challenge, Defense) ->
    case Challenge#tx_challenge.challenge_type of
        da_unavailable ->
            %% Verify DA chunks provided
            case maps:get(da_chunks, Defense, undefined) of
                undefined -> {error, missing_da_chunks};
                _Chunks -> {ok, valid}
            end;
        
        invalid_state_transition ->
            %% Verify state witness
            case maps:get(state_witness, Defense, undefined) of
                undefined -> {error, missing_state_witness};
                _Witness -> {ok, valid}
            end;
        
        invalid_inclusion ->
            %% Verify inclusion proofs
            case maps:get(inclusion_proofs, Defense, undefined) of
                undefined -> {error, missing_inclusion_proofs};
                _Proofs -> {ok, valid}
            end;
        
        timeout ->
            {error, cannot_defend_timeout}
    end.

tx_commitment_to_map(#tx_commitment{} = C) ->
    #{
        commitment_hash => C#tx_commitment.commitment_hash,
        rollup_id => C#tx_commitment.rollup_id,
        region_id => C#tx_commitment.region_id,
        epoch => C#tx_commitment.epoch,
        window_id => C#tx_commitment.window_id,
        tx_root => C#tx_commitment.tx_root,
        state_root => C#tx_commitment.state_root,
        da_root => C#tx_commitment.da_root,
        count_tx => C#tx_commitment.count_tx,
        blob_bytes => C#tx_commitment.blob_bytes,
        block_range => {C#tx_commitment.block_range_start,
                        C#tx_commitment.block_range_end},
        status => C#tx_commitment.status,
        submitted_at => C#tx_commitment.submitted_at,
        finalize_at => C#tx_commitment.finalize_at
    }.

count_by_status(Commitments, Status) ->
    maps:fold(
        fun(_Hash, Commitment, Count) ->
            case Commitment#tx_commitment.status of
                Status -> Count + 1;
                _ -> Count
            end
        end,
        0,
        Commitments
    ).
