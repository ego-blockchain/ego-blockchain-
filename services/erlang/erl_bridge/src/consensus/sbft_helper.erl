-module(sbft_helper).

-include("../include/sbft.hrl").

-export([create_validator/4, create_block/6, create_vote/6,
         create_config/2, start_demo/0]).

create_validator(Id, PublicKey, Stake, ShardId) ->
    #sbft_validator_record{
        id = Id,
        public_key = PublicKey,
        stake = Stake,
        is_active = true,
        shard_id = ShardId,
        last_seen = erlang:system_time(millisecond)
    }.

create_block(Hash, View, Proposer, Transactions, ParentHash, ShardId) ->
    #sbft_block_record{
        hash = Hash,
        view = View,
        proposer = Proposer,
        transactions = Transactions,
        parent_hash = ParentHash,
        timestamp = erlang:system_time(millisecond),
        signature = <<"dummy_signature">>,
        shard_id = ShardId,
        cross_shard_receipts = [],
        state_root = <<"dummy_state_root">>
    }.

create_vote(ValidatorId, View, BlockHash, VoteType, ShardId, Signature) ->
    #sbft_vote_record{
        validator_id = ValidatorId,
        view = View,
        block_hash = BlockHash,
        vote_type = VoteType,
        signature = Signature,
        timestamp = erlang:system_time(millisecond),
        shard_id = ShardId
    }.

create_config(Validators, Timeout) ->
    #{
        validators => Validators,
        consensus_timeout => Timeout,
        view_change_timeout => Timeout + 2000
    }.

start_demo() ->
    ShardId = <<"shard_001">>,

    Validator1 = create_validator(<<"validator_1">>, <<"pubkey_1">>, 1000, ShardId),
    Validator2 = create_validator(<<"validator_2">>, <<"pubkey_2">>, 1500, ShardId),
    Validator3 = create_validator(<<"validator_3">>, <<"pubkey_3">>, 2000, ShardId),

    Config = create_config([Validator1, Validator2, Validator3], 3000),

    case sbft_consensus_manager:start_shard_consensus(ShardId, Config) of
        {ok, Pid} ->
            io:format("Shard consensus started successfully with PID: ~p~n", [Pid]),

            timer:sleep(1000),

            {ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
            io:format("Shard status: ~p~n", [Status]),

            Block = create_block(<<"block_hash_1">>, 0, <<"validator_1">>,
                               [<<"tx1">>, <<"tx2">>], <<"genesis">>, ShardId),

            sbft_shard_consensus:propose_block(Pid, Block),
            io:format("Block proposed~n"),

            timer:sleep(1000),

            {ok, FinalStatus} = sbft_consensus_manager:get_shard_status(ShardId),
            io:format("Final shard status: ~p~n", [FinalStatus]),

            {ok, Pid};
        {error, Reason} ->
            io:format("Failed to start shard consensus: ~p~n", [Reason]),
            {error, Reason}
    end.
