-type validator_id() :: binary().
-type shard_id() :: binary().
-type block_hash() :: binary().
-type view_number() :: non_neg_integer().
-type vote_type() :: prepare | commit | view_change.
-type consensus_phase() :: prepare | commit | view_change.

-record(cross_shard_receipt, {
    from_shard :: shard_id(),
    to_shard :: shard_id(),
    transaction_hash :: binary(),
    receipt_data :: binary(),
    timestamp :: non_neg_integer()
}).

-record(sbft_validator_record, {
    id :: validator_id(),
    public_key :: binary(),
    stake :: non_neg_integer(),
    is_active = true :: boolean(),
    shard_id :: shard_id(),
    last_seen :: non_neg_integer()
}).

-record(sbft_vote_record, {
    validator_id :: validator_id(),
    view :: view_number(),
    block_hash :: block_hash(),
    vote_type :: vote_type(),
    signature :: binary(),
    timestamp :: non_neg_integer(),
    shard_id :: shard_id()
}).

-record(sbft_block_record, {
    hash :: block_hash(),
    view :: view_number(),
    proposer :: validator_id(),
    transactions :: [binary()],
    parent_hash :: block_hash(),
    timestamp :: non_neg_integer(),
    signature :: binary(),
    shard_id :: shard_id(),
    cross_shard_receipts :: [#cross_shard_receipt{}],
    state_root :: binary()
}).

-record(sbft_consensus_state, {
    shard_id :: shard_id(),
    view = 0 :: view_number(),
    phase = prepare :: consensus_phase(),
    current_block :: #sbft_block_record{} | undefined,
    current_block_hash :: block_hash() | undefined,
    votes = #{} :: #{validator_id() => #sbft_vote_record{}},
    prepared_blocks = #{} :: #{view_number() => #sbft_block_record{}},
    committed_blocks = #{} :: #{view_number() => #sbft_block_record{}},
    validators = [] :: [#sbft_validator_record{}],
    validator_weights = #{} :: #{validator_id() => non_neg_integer()},
    total_stake = 0 :: non_neg_integer(),
    current_leader :: validator_id() | undefined,
    timeout_ref :: reference() | undefined,
    consensus_timeout = 3000 :: non_neg_integer(),
    view_change_timeout = 5000 :: non_neg_integer(),
    last_finalized_view = -1 :: integer(),
    metrics = #{} :: map(),
    cross_shard_receipts = [] :: [#cross_shard_receipt{}],
    pending_transactions = [] :: [binary()]
}).

-record(view_change_message, {
    validator_id :: validator_id(),
    new_view :: view_number(),
    last_prepared_view :: view_number(),
    prepared_blocks :: [#sbft_block_record{}],
    signature :: binary(),
    timestamp :: non_neg_integer()
}).

-record(consensus_metrics, {
    total_blocks_proposed = 0 :: non_neg_integer(),
    total_blocks_committed = 0 :: non_neg_integer(),
    average_consensus_time = 0 :: float(),
    view_changes = 0 :: non_neg_integer(),
    last_finality_time :: non_neg_integer() | undefined
}).
