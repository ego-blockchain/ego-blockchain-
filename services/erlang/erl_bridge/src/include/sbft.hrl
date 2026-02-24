-ifndef(SBFT_HRL).
-define(SBFT_HRL, true).

-type validator_id()    :: binary().
-type shard_id()        :: binary().
-type block_hash()      :: binary().
-type view_number()     :: non_neg_integer().
-type stake_amount()    :: non_neg_integer().
-type timestamp_ms()    :: non_neg_integer().
-type merkle_root()     :: binary().
-type public_key()      :: binary().
-type signature()       :: binary().
-type epoch_number()    :: non_neg_integer().
-type h3_index()        :: binary().

-type vote_type()       :: prepare | commit | view_change | new_view.
-type consensus_phase() :: prepare | commit | view_change | finalized | idle.
-type validator_role()  :: leader | replica | observer.
-type receipt_status()  :: pending | processed | expired | failed.
-type node_capability() :: pqc_primary | pqc_hybrid | legacy.
-type network_type()    :: wifi | fiveg | ethernet | lte.

-type sig_algorithm()   :: dilithium2 | ed25519 | hybrid.
-type kem_algorithm()   :: mlkem768 | x25519 | hybrid_kem.
-type hash_algorithm()  :: blake2s | sha256 | sha3_256.

-type slash_reason()    ::
    double_voting       |
    equivocation        |
    unavailability      |
    invalid_block       |
    invalid_proof       |
    invalid_poc         |
    storage_fault.

-record(pqc_signature, {
    algorithm           :: sig_algorithm(),
    signer_id           :: validator_id(),
    payload_hash        :: binary(),
    signature_bytes     :: binary(),
    timestamp           :: timestamp_ms()
}).

-record(pqc_keypair, {
    algorithm           :: sig_algorithm(),
    public_key          :: public_key(),
    secret_key          :: binary(),
    kem_algorithm       :: kem_algorithm(),
    kem_public_key      :: public_key(),
    kem_secret_key      :: binary(),
    created_at          :: timestamp_ms(),
    rotation_due_at     :: timestamp_ms()
}).

-record(hybrid_session_key, {
    session_id          :: binary(),
    kem_ciphertext      :: binary(),
    shared_secret       :: binary(),
    cipher              :: xchacha20_poly1305,
    hkdf_algorithm      :: blake2s,
    created_at          :: timestamp_ms(),
    peer_id             :: binary()
}).

-record(cross_shard_receipt, {
    receipt_id          :: binary(),
    from_shard          :: shard_id(),
    to_shard            :: shard_id(),
    transaction_hash    :: binary(),
    receipt_data        :: binary(),
    merkle_proof        :: [binary()] | undefined,
    merkle_root         :: merkle_root() | undefined,
    status              = pending :: receipt_status(),
    timestamp           :: timestamp_ms(),
    expiry_timestamp    :: timestamp_ms() | undefined,
    retry_count         = 0 :: non_neg_integer(),
    signature           :: signature() | undefined,
    pqc_signature       :: #pqc_signature{} | undefined
}).

-record(sbft_validator_record, {
    id                  :: validator_id(),
    public_key          :: public_key(),
    pqc_public_key      :: public_key() | undefined,
    kem_public_key      :: public_key() | undefined,
    sig_algorithm       = ed25519 :: sig_algorithm(),
    stake               :: stake_amount(),
    is_active           = true :: boolean(),
    shard_id            :: shard_id(),
    role                = replica :: validator_role(),
    capability          = legacy :: node_capability(),
    reputation          = 1.0 :: float(),
    performance_score   = 1.0 :: float(),
    last_seen           :: timestamp_ms(),
    last_vote_view      :: view_number() | undefined,
    slashing_events     = 0 :: non_neg_integer()
}).

-record(sbft_vote_record, {
    validator_id        :: validator_id(),
    view                :: view_number(),
    block_hash          :: block_hash(),
    vote_type           :: vote_type(),
    signature           :: signature(),
    pqc_signature       :: #pqc_signature{} | undefined,
    timestamp           :: timestamp_ms(),
    shard_id            :: shard_id(),
    justified_view      :: view_number() | undefined
}).

-record(sbft_block_record, {
    hash                :: block_hash(),
    view                :: view_number(),
    height              = 0 :: non_neg_integer(),
    proposer            :: validator_id(),
    transactions        :: [binary()],
    parent_hash         :: block_hash(),
    timestamp           :: timestamp_ms(),
    signature           :: signature(),
    pqc_signature       :: #pqc_signature{} | undefined,
    shard_id            :: shard_id(),
    cross_shard_receipts :: [#cross_shard_receipt{}],
    state_root          :: merkle_root(),
    receipt_root        :: merkle_root() | undefined,
    tx_root             :: merkle_root() | undefined,
    gas_used            = 0 :: non_neg_integer(),
    size_bytes          = 0 :: non_neg_integer(),
    erasure_coded       = false :: boolean()
}).

-record(quorum_certificate, {
    view                :: view_number(),
    block_hash          :: block_hash(),
    shard_id            :: shard_id(),
    votes               :: [#sbft_vote_record{}],
    aggregate_sig       :: binary() | undefined,
    formed_at           :: timestamp_ms()
}).

-record(sbft_consensus_state, {
    shard_id                :: shard_id(),
    view                    = 0 :: view_number(),
    phase                   = prepare :: consensus_phase(),
    height                  = 0 :: non_neg_integer(),
    current_block           :: #sbft_block_record{} | undefined,
    current_block_hash      :: block_hash() | undefined,
    votes                   = #{} :: #{validator_id() => #sbft_vote_record{}},
    prepared_blocks         = #{} :: #{view_number() => #sbft_block_record{}},
    committed_blocks        = #{} :: #{view_number() => #sbft_block_record{}},
    pending_view_changes    = #{} :: #{view_number() => #{validator_id() => #sbft_vote_record{}}},
    validators              = [] :: [#sbft_validator_record{}],
    validator_weights       = #{} :: #{validator_id() => stake_amount()},
    total_stake             = 0 :: stake_amount(),
    current_leader          :: validator_id() | undefined,
    timeout_ref             :: reference() | undefined,
    view_change_timer       :: reference() | undefined,
    consensus_timeout       = 3000 :: non_neg_integer(),
    view_change_timeout     = 5000 :: non_neg_integer(),
    last_finalized_view     = -1 :: integer(),
    last_finalized_hash     :: block_hash() | undefined,
    high_qc                 :: #quorum_certificate{} | undefined,
    locked_block            :: #sbft_block_record{} | undefined,
    locked_view             :: view_number() | undefined,
    metrics                 = #{} :: map(),
    cross_shard_receipts    = [] :: [#cross_shard_receipt{}],
    pending_transactions    = [] :: [binary()],
    double_vote_log         = #{} :: #{validator_id() => [#sbft_vote_record{}]},
    pqc_enabled             = true :: boolean(),
    sig_algorithm           = dilithium2 :: sig_algorithm()
}).

-record(view_change_message, {
    validator_id        :: validator_id(),
    new_view            :: view_number(),
    last_prepared_view  :: view_number(),
    prepared_blocks     :: [#sbft_block_record{}],
    high_qc             :: #quorum_certificate{} | undefined,
    signature           :: signature(),
    pqc_signature       :: #pqc_signature{} | undefined,
    timestamp           :: timestamp_ms()
}).

-record(new_view_message, {
    new_view            :: view_number(),
    new_leader          :: validator_id(),
    shard_id            :: shard_id(),
    view_change_votes   :: [#sbft_vote_record{}],
    high_qc             :: #quorum_certificate{} | undefined,
    signature           :: signature(),
    pqc_signature       :: #pqc_signature{} | undefined,
    timestamp           :: timestamp_ms()
}).

-record(consensus_metrics, {
    total_blocks_proposed               = 0 :: non_neg_integer(),
    total_blocks_committed              = 0 :: non_neg_integer(),
    average_consensus_time              = 0.0 :: float(),
    view_changes                        = 0 :: non_neg_integer(),
    last_finality_time                  :: timestamp_ms() | undefined,
    equivocations_detected              = 0 :: non_neg_integer(),
    cross_shard_receipts_processed      = 0 :: non_neg_integer()
}).

-record(slashing_evidence, {
    validator_id        :: validator_id(),
    reason              :: slash_reason(),
    evidence_votes      :: [#sbft_vote_record{}],
    evidence_block      :: #sbft_block_record{} | undefined,
    reported_at         :: timestamp_ms(),
    shard_id            :: shard_id(),
    stake_at_slash      :: stake_amount()
}).

-record(poc_report, {
    node_id             :: binary(),
    shard_id            :: shard_id(),
    rsrp                :: float(),
    rsrq                :: float(),
    sinr                :: float(),
    timing_advance      :: non_neg_integer(),
    gps_lat             :: float(),
    gps_lon             :: float(),
    h3_index            :: h3_index(),
    geohash             :: binary(),
    timestamp           :: timestamp_ms(),
    signature           :: signature(),
    pqc_signature       :: #pqc_signature{} | undefined
}).

-record(drs_score_event, {
    node_id             :: binary(),
    shard_id            :: shard_id(),
    raw_score           :: float(),
    bounded_multiplier  :: float(),
    epoch               :: epoch_number(),
    component_scores    :: map(),
    emitted_at          :: timestamp_ms()
}).

-record(deploy_policy, {
    staker_free_quota   :: non_neg_integer(),
    pob_credits         :: non_neg_integer(),
    deploy_bond         :: stake_amount(),
    hard_cap            :: non_neg_integer(),
    size_kb_limit       :: non_neg_integer(),
    epoch               :: epoch_number()
}).

-record(bandwidth_slot, {
    owner_id            :: binary(),
    shard_id            :: shard_id(),
    bytes_available     :: non_neg_integer(),
    bytes_used          = 0 :: non_neg_integer(),
    price_per_mb        :: float(),
    expiry              :: timestamp_ms(),
    network_type        :: network_type(),
    region              :: binary(),
    active              = true :: boolean()
}).

-define(MAX_BYZANTINE_FRACTION,             0.33).
-define(REQUIRED_VOTE_FRACTION,             0.67).
-define(DEFAULT_CONSENSUS_TIMEOUT,          3000).
-define(DEFAULT_VIEW_CHANGE_TIMEOUT,        6000).
-define(MAX_RETRIES,                        3).
-define(RECEIPT_EXPIRY_MS,                  30000).
-define(MAX_VALIDATORS_PER_SHARD,           100).
-define(MIN_VALIDATORS_PER_SHARD,           4).
-define(BLAKE2S_DIGEST_SIZE,                32).
-define(DILITHIUM2_SIG_SIZE,                2420).
-define(ED25519_SIG_SIZE,                   64).
-define(MLKEM768_CT_SIZE,                   1088).
-define(MLKEM768_PK_SIZE,                   1184).
-define(MAX_VIEW_CHANGE_ROUNDS,             10).
-define(DRS_MAX_MULTIPLIER,                 2.0).
-define(DRS_MIN_MULTIPLIER,                 0.0).
-define(DEPLOY_FREE_QUOTA_PER_EPOCH,        5).

-endif.
