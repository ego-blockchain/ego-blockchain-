%%%-------------------------------------------------------------------
%%% @doc ProofRollup Server
%%% L1 shard server for ProofRollup commitments
%%% Accepts commitments, enforces challenge windows, finalizes or slashes
%%% Integrates with SBFT consensus for deterministic rollup state
%%% @end
%%%-------------------------------------------------------------------

-module(proof_rollup_server).

-behaviour(gen_server).

%% API
-export([start_link/2, 
         submit_commitment/2,
         challenge_commitment/3,
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
    shard_id :: non_neg_integer(),
    consensus_pid :: pid() | undefined
}).

-record(commitment, {
    commitment_hash :: binary(),
    rollup_id :: binary(),
    region_id :: non_neg_integer(),
    epoch :: non_neg_integer(),
    window_id :: non_neg_integer(),
    proofs_root :: binary(),
    da_root :: binary(),
    count_proofs :: non_neg_integer(),
    blob_bytes :: non_neg_integer(),
    min_validity_proof :: atom(),
    alg_sig_id :: non_neg_integer(),
    operator_addr :: binary(),
    operator_sig :: binary(),
    status :: pending | challenged | finalized | slashed,
    submitted_at :: non_neg_integer(),
    finalize_at :: non_neg_integer()
}).

-record(challenge, {
    challenge_hash :: binary(),
    commitment_hash :: binary(),
    challenger :: binary(),
    challenge_type :: atom(),
    submitted_at :: non_neg_integer(),
    deadline :: non_neg_integer(),
    status :: pending | resolved | expired
}).

-define(CHALLENGE_PERIOD, 1000).  %% blocks
-define(RESPONSE_WINDOW, 100).    %% blocks

%%%===================================================================
%%% API
%%%===================================================================

start_link(RollupId, Config) ->
    gen_server:start_link(?MODULE, [RollupId, Config], []).

%%--------------------------------------------------------------------
%% @doc Submit a ProofRollup commitment to L1 shard
%% @end
%%--------------------------------------------------------------------
-spec submit_commitment(Pid :: pid(), Commitment :: map()) ->
    {ok, CommitmentHash :: binary()} | {error, Reason :: term()}.
submit_commitment(Pid, Commitment) ->
    gen_server:call(Pid, {submit_commitment, Commitment}).

%%--------------------------------------------------------------------
%% @doc Challenge a commitment with fraud proof
%% @end
%%--------------------------------------------------------------------
-spec challenge_commitment(Pid :: pid(), CommitmentHash :: binary(), 
                           FraudProof :: map()) ->
    {ok, ChallengeHash :: binary()} | {error, Reason :: term()}.
challenge_commitment(Pid, CommitmentHash, FraudProof) ->
    gen_server:call(Pid, {challenge_commitment, CommitmentHash, FraudProof}).

%%--------------------------------------------------------------------
%% @doc Finalize a commitment after challenge window expires
%% @end
%%--------------------------------------------------------------------
-spec finalize_commitment(Pid :: pid(), CommitmentHash :: binary()) ->
    ok | {error, Reason :: term()}.
finalize_commitment(Pid, CommitmentHash) ->
    gen_server:call(Pid, {finalize_commitment, CommitmentHash}).

%%--------------------------------------------------------------------
%% @doc Get commitment details
%% @end
%%--------------------------------------------------------------------
-spec get_commitment(Pid :: pid(), CommitmentHash :: binary()) ->
    {ok, map()} | {error, not_found}.
get_commitment(Pid, CommitmentHash) ->
    gen_server:call(Pid, {get_commitment, CommitmentHash}).

%%--------------------------------------------------------------------
%% @doc Get rollup state
%% @end
%%--------------------------------------------------------------------
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
    
    %% Link to SBFT consensus
    ConsensusPid = case maps:get(consensus_enabled, Config, false) of
        true ->
            {ok, Pid} = sbft_shard_consensus:start_link(ShardId, #{}),
            Pid;
        false ->
            undefined
    end,
    
    %% Start challenge window timer
    erlang:send_after(1000, self(), check_challenge_windows),
    
    io:format("[ProofRollup] Started for rollup ~p, region ~p, shard ~p~n", 
              [RollupId, RegionId, ShardId]),
    
    {ok, #state{
        rollup_id = RollupId,
        region_id = RegionId,
        config = Config,
        commitments = #{},
        challenges = #{},
        current_epoch = 0,
        current_window = 0,
        shard_id = ShardId,
        consensus_pid = ConsensusPid
    }}.

%%--------------------------------------------------------------------
%% @private
%% @doc Handle submit_commitment call
%% @end
%%--------------------------------------------------------------------
handle_call({submit_commitment, CommitmentMap}, _From, State) ->
    #state{commitments = Commitments, 
           current_epoch = Epoch,
           consensus_pid = ConsensusPid} = State,
    
    %% Verify Dilithium-2 signature
    case verify_dilithium_signature(CommitmentMap) of
        {ok, true} ->
            CommitmentHash = compute_commitment_hash(CommitmentMap),
            
            %% Create commitment record
            Commitment = #commitment{
                commitment_hash = CommitmentHash,
                rollup_id = maps:get(rollup_id, CommitmentMap),
                region_id = maps:get(region_id, CommitmentMap),
                epoch = maps:get(epoch, CommitmentMap),
                window_id = maps:get(window_id, CommitmentMap),
                proofs_root = maps:get(proofs_root, CommitmentMap),
                da_root = maps:get(da_root, CommitmentMap),
                count_proofs = maps:get(count_proofs, CommitmentMap),
                blob_bytes = maps:get(blob_bytes, CommitmentMap),
                min_validity_proof = maps:get(min_validity_proof, CommitmentMap),
                alg_sig_id = maps:get(alg_sig_id, CommitmentMap),
                operator_addr = maps:get(operator_addr, CommitmentMap),
                operator_sig = maps:get(operator_sig, CommitmentMap),
                status = pending,
                submitted_at = erlang:system_time(millisecond),
                finalize_at = erlang:system_time(millisecond) + 
                              (?CHALLENGE_PERIOD * 1000)
            },
            
            %% Store commitment
            NewCommitments = maps:put(CommitmentHash, Commitment, Commitments),
            
            %% Propagate to consensus if enabled
            case ConsensusPid of
                undefined -> ok;
                Pid -> 
                    sbft_shard_consensus:propose_transaction(Pid, 
                        #{type => proof_rollup_commit, 
                          data => CommitmentMap})
            end,
            
            io:format("[ProofRollup] Accepted commitment ~p (epoch=~p, window=~p)~n",
                      [CommitmentHash, Epoch, Commitment#commitment.window_id]),
            
            {reply, {ok, CommitmentHash}, 
             State#state{commitments = NewCommitments}};
        
        {ok, false} ->
            {reply, {error, invalid_signature}, State};
        
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc Handle challenge_commitment call
%% @end
%%--------------------------------------------------------------------
handle_call({challenge_commitment, CommitmentHash, FraudProof}, 
            {ChallengerPid, _}, State) ->
    #state{commitments = Commitments, 
           challenges = Challenges} = State,
    
    case maps:get(CommitmentHash, Commitments, undefined) of
        undefined ->
            {reply, {error, commitment_not_found}, State};
        
        Commitment when Commitment#commitment.status =:= pending ->
            ChallengeHash = crypto:strong_rand_bytes(32),
            
            Challenge = #challenge{
                challenge_hash = ChallengeHash,
                commitment_hash = CommitmentHash,
                challenger = term_to_binary(ChallengerPid),
                challenge_type = maps:get(challenge_type, FraudProof, da_unavailable),
                submitted_at = erlang:system_time(millisecond),
                deadline = erlang:system_time(millisecond) + 
                           (?RESPONSE_WINDOW * 1000),
                status = pending
            },
            
            %% Update commitment status
            UpdatedCommitment = Commitment#commitment{status = challenged},
            NewCommitments = maps:put(CommitmentHash, UpdatedCommitment, 
                                      Commitments),
            NewChallenges = maps:put(ChallengeHash, Challenge, Challenges),
            
            io:format("[ProofRollup] Challenge ~p submitted for commitment ~p~n",
                      [ChallengeHash, CommitmentHash]),
            
            {reply, {ok, ChallengeHash}, 
             State#state{commitments = NewCommitments, 
                         challenges = NewChallenges}};
        
        _ ->
            {reply, {error, commitment_not_pending}, State}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc Handle finalize_commitment call
%% @end
%%--------------------------------------------------------------------
handle_call({finalize_commitment, CommitmentHash}, _From, State) ->
    #state{commitments = Commitments} = State,
    
    case maps:get(CommitmentHash, Commitments, undefined) of
        undefined ->
            {reply, {error, commitment_not_found}, State};
        
        Commitment ->
            Now = erlang:system_time(millisecond),
            
            case {Commitment#commitment.status, 
                  Now >= Commitment#commitment.finalize_at} of
                {pending, true} ->
                    %% Finalize commitment
                    UpdatedCommitment = Commitment#commitment{status = finalized},
                    NewCommitments = maps:put(CommitmentHash, UpdatedCommitment, 
                                              Commitments),
                    
                    io:format("[ProofRollup] Finalized commitment ~p~n", 
                              [CommitmentHash]),
                    
                    {reply, ok, State#state{commitments = NewCommitments}};
                
                {pending, false} ->
                    {reply, {error, challenge_period_not_expired}, State};
                
                {Status, _} ->
                    {reply, {error, {invalid_status, Status}}, State}
            end
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc Handle get_commitment call
%% @end
%%--------------------------------------------------------------------
handle_call({get_commitment, CommitmentHash}, _From, State) ->
    #state{commitments = Commitments} = State,
    
    case maps:get(CommitmentHash, Commitments, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Commitment ->
            CommitmentMap = commitment_to_map(Commitment),
            {reply, {ok, CommitmentMap}, State}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc Handle get_state call
%% @end
%%--------------------------------------------------------------------
handle_call(get_state, _From, State) ->
    #state{rollup_id = RollupId,
           current_epoch = Epoch,
           current_window = Window,
           commitments = Commitments} = State,
    
    StateMap = #{
        rollup_id => RollupId,
        current_epoch => Epoch,
        current_window => Window,
        total_commitments => maps:size(Commitments),
        pending_commitments => count_by_status(Commitments, pending),
        finalized_commitments => count_by_status(Commitments, finalized)
    },
    
    {reply, {ok, StateMap}, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc Handle async messages
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc Handle timer and other messages
%% @end
%%--------------------------------------------------------------------
handle_info(check_challenge_windows, State) ->
    #state{commitments = Commitments, 
           challenges = Challenges} = State,
    
    %% Check for expired challenge windows and finalize
    Now = erlang:system_time(millisecond),
    
    NewCommitments = maps:map(
        fun(_Hash, Commitment) ->
            case {Commitment#commitment.status, 
                  Now >= Commitment#commitment.finalize_at} of
                {pending, true} ->
                    io:format("[ProofRollup] Auto-finalizing commitment ~p~n",
                              [Commitment#commitment.commitment_hash]),
                    Commitment#commitment{status = finalized};
                _ ->
                    Commitment
            end
        end,
        Commitments
    ),
    
    %% Check for expired challenges
    NewChallenges = maps:map(
        fun(_Hash, Challenge) ->
            case {Challenge#challenge.status, 
                  Now >= Challenge#challenge.deadline} of
                {pending, true} ->
                    Challenge#challenge{status = expired};
                _ ->
                    Challenge
            end
        end,
        Challenges
    ),
    
    %% Schedule next check
    erlang:send_after(5000, self(), check_challenge_windows),
    
    {noreply, State#state{commitments = NewCommitments, 
                          challenges = NewChallenges}};

handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc Cleanup on termination
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc Handle code changes
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

verify_dilithium_signature(CommitmentMap) ->
    %% TODO: Implement actual Dilithium-2 signature verification
    %% For now, accept all signatures
    _OperatorSig = maps:get(operator_sig, CommitmentMap),
    _AlgSigId = maps:get(alg_sig_id, CommitmentMap),
    {ok, true}.

compute_commitment_hash(CommitmentMap) ->
    %% Compute BLAKE2s hash of commitment data
    Data = term_to_binary(CommitmentMap),
    crypto:hash(blake2s, Data).

commitment_to_map(#commitment{} = C) ->
    #{
        commitment_hash => C#commitment.commitment_hash,
        rollup_id => C#commitment.rollup_id,
        region_id => C#commitment.region_id,
        epoch => C#commitment.epoch,
        window_id => C#commitment.window_id,
        proofs_root => C#commitment.proofs_root,
        da_root => C#commitment.da_root,
        count_proofs => C#commitment.count_proofs,
        blob_bytes => C#commitment.blob_bytes,
        status => C#commitment.status,
        submitted_at => C#commitment.submitted_at,
        finalize_at => C#commitment.finalize_at
    }.

count_by_status(Commitments, Status) ->
    maps:fold(
        fun(_Hash, Commitment, Count) ->
            case Commitment#commitment.status of
                Status -> Count + 1;
                _ -> Count
            end
        end,
        0,
        Commitments
    ).
