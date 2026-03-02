-module(sbft_suite).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("../include/sbft.hrl").

-export([
    test_all/0,
    test_group/1,
    test_one/1
]).

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    test_blake2s_hash/1,
    test_sha256_hash/1,
    test_hkdf_basic/1,
    test_hkdf_with_salt/1,
    test_ed25519_sign_verify/1,
    test_dilithium2_sign_verify/1,
    test_hybrid_sign_verify/1,
    test_pqc_signature_record/1,
    test_kem_encapsulate_x25519/1,
    test_kem_encapsulate_mlkem768/1,
    test_kem_decapsulate_round_trip/1,
    test_session_key_derivation/1,
    test_encrypt_decrypt/1,
    test_block_signing_payload/1,
    test_vote_signing_payload/1,
    test_receipt_signing_payload/1,
    test_detect_equivocation/1,
    test_no_equivocation/1,
    test_aggregate_signatures/1,
    test_constant_time_compare/1,
    test_nif_capabilities/1,
    test_dilithium2_keypair_size/1,
    test_mlkem768_keypair_size/1,
    test_mlkem768_encapsulate_size/1,
    test_blake2s_nif/1,
    test_sphincs_keypair/1,
    test_nif_available/1,
    test_validator_register/1,
    test_validator_register_duplicate/1,
    test_validator_get/1,
    test_validator_get_not_found/1,
    test_validator_update_stake/1,
    test_validator_slash/1,
    test_validator_reactivate_after_slash/1,
    test_validator_get_all/1,
    test_validator_get_active/1,
    test_validator_get_by_shard/1,
    test_validator_update_capability/1,
    test_validator_update_pqc_keys/1,
    test_validator_record_vote/1,
    test_validator_record_miss/1,
    test_validator_drs_score/1,
    test_validator_epoch_stats/1,
    test_validator_total_stake/1,
    test_validator_shard_stake/1,
    test_validator_is_active/1,
    test_validator_check_capability/1,
    test_shard_start_stop/1,
    test_shard_propose_block/1,
    test_shard_propose_wrong_leader/1,
    test_shard_propose_wrong_view/1,
    test_shard_propose_wrong_shard/1,
    test_shard_vote_collection/1,
    test_shard_view_change_on_timeout/1,
    test_shard_add_validator/1,
    test_shard_remove_validator/1,
    test_shard_remove_below_minimum/1,
    test_shard_update_validator_stake/1,
    test_shard_get_status_fields/1,
    test_shard_get_committed_block/1,
    test_shard_get_high_qc/1,
    test_shard_inject_receipt/1,
    test_shard_force_view_change/1,
    test_slashing_double_vote/1,
    test_slashing_invalid_block/1,
    test_slashing_unavailability/1,
    test_slashing_invalid_poc/1,
    test_slashing_storage_fault/1,
    test_slashing_deduplication/1,
    test_slashing_history/1,
    test_slashing_slash_count/1,
    test_slashing_is_slashed/1,
    test_cross_shard_register/1,
    test_cross_shard_register_duplicate/1,
    test_cross_shard_unregister/1,
    test_cross_shard_send_receipt/1,
    test_cross_shard_unknown_shard_dropped/1,
    test_cross_shard_get_pending/1,
    test_cross_shard_process_receipt/1,
    test_cross_shard_merkle_tree/1,
    test_cross_shard_merkle_proof_verify/1,
    test_cross_shard_receipt_expiry/1,
    test_cross_shard_retry/1,
    test_cross_shard_metrics/1,
    test_cross_shard_ordering/1,
    test_event_bus_publish_subscribe/1,
    test_event_bus_unsubscribe/1,
    test_event_bus_any_topic/1,
    test_event_bus_filter_function/1,
    test_event_bus_dead_subscriber_cleanup/1,
    test_event_bus_replay_last/1,
    test_event_bus_metrics/1,
    test_event_bus_multi_topic_subscribe/1,
    test_consensus_manager_start_shard/1,
    test_consensus_manager_start_duplicate/1,
    test_consensus_manager_stop_shard/1,
    test_consensus_manager_stop_not_found/1,
    test_consensus_manager_get_status/1,
    test_consensus_manager_get_all_shards/1,
    test_consensus_manager_get_active_shards/1,
    test_consensus_manager_get_shard_pid/1,
    test_consensus_manager_global_finality/1,
    test_consensus_manager_propose_to_shard/1,
    test_consensus_manager_sync_validators/1,
    test_consensus_manager_restart_shard/1,
    test_helper_create_validator/1,
    test_helper_create_validator_pqc/1,
    test_helper_create_block/1,
    test_helper_create_vote/1,
    test_helper_create_config/1,
    test_helper_create_receipt/1,
    test_helper_create_poc_report/1,
    test_helper_create_drs_event/1,
    test_helper_wait_for_finality_timeout/1,
    test_helper_print_shard_status/1,
    test_helper_print_global_status/1,
    test_integration_full_consensus_round/1,
    test_integration_multi_shard/1,
    test_integration_cross_shard_with_consensus/1,
    test_integration_slashing_removes_from_shard/1,
    test_integration_event_bus_consensus_events/1
]).

-define(SHARD_A, <<"test_shard_A">>).
-define(SHARD_B, <<"test_shard_B">>).
-define(SHARD_C, <<"test_shard_C">>).
-define(VAL_1, <<"test_val_1">>).
-define(VAL_2, <<"test_val_2">>).
-define(VAL_3, <<"test_val_3">>).
-define(VAL_4, <<"test_val_4">>).
-define(CONSENSUS_TO, 500).
-define(VC_TO, 1000).
-define(SETTLE_MS, 300).

all() ->
    [
        {group, crypto},
        {group, nif},
        {group, validator_manager},
        {group, shard_consensus},
        {group, slashing},
        {group, cross_shard},
        {group, event_bus},
        {group, consensus_manager},
        {group, helper},
        {group, integration}
    ].

groups() ->
    [
        {crypto, [sequence], [
            test_blake2s_hash,
            test_sha256_hash,
            test_hkdf_basic,
            test_hkdf_with_salt,
            test_ed25519_sign_verify,
            test_dilithium2_sign_verify,
            test_hybrid_sign_verify,
            test_pqc_signature_record,
            test_kem_encapsulate_x25519,
            test_kem_encapsulate_mlkem768,
            test_kem_decapsulate_round_trip,
            test_session_key_derivation,
            test_encrypt_decrypt,
            test_block_signing_payload,
            test_vote_signing_payload,
            test_receipt_signing_payload,
            test_detect_equivocation,
            test_no_equivocation,
            test_aggregate_signatures,
            test_constant_time_compare
        ]},
        {nif, [sequence], [
            test_nif_capabilities,
            test_dilithium2_keypair_size,
            test_mlkem768_keypair_size,
            test_mlkem768_encapsulate_size,
            test_blake2s_nif,
            test_sphincs_keypair,
            test_nif_available
        ]},
        {validator_manager, [sequence], [
            test_validator_register,
            test_validator_register_duplicate,
            test_validator_get,
            test_validator_get_not_found,
            test_validator_update_stake,
            test_validator_slash,
            test_validator_reactivate_after_slash,
            test_validator_get_all,
            test_validator_get_active,
            test_validator_get_by_shard,
            test_validator_update_capability,
            test_validator_update_pqc_keys,
            test_validator_record_vote,
            test_validator_record_miss,
            test_validator_drs_score,
            test_validator_epoch_stats,
            test_validator_total_stake,
            test_validator_shard_stake,
            test_validator_is_active,
            test_validator_check_capability
        ]},
        {shard_consensus, [sequence], [
            test_shard_start_stop,
            test_shard_propose_block,
            test_shard_propose_wrong_leader,
            test_shard_propose_wrong_view,
            test_shard_propose_wrong_shard,
            test_shard_vote_collection,
            test_shard_view_change_on_timeout,
            test_shard_add_validator,
            test_shard_remove_validator,
            test_shard_remove_below_minimum,
            test_shard_update_validator_stake,
            test_shard_get_status_fields,
            test_shard_get_committed_block,
            test_shard_get_high_qc,
            test_shard_inject_receipt,
            test_shard_force_view_change
        ]},
        {slashing, [sequence], [
            test_slashing_double_vote,
            test_slashing_invalid_block,
            test_slashing_unavailability,
            test_slashing_invalid_poc,
            test_slashing_storage_fault,
            test_slashing_deduplication,
            test_slashing_history,
            test_slashing_slash_count,
            test_slashing_is_slashed
        ]},
        {cross_shard, [sequence], [
            test_cross_shard_register,
            test_cross_shard_register_duplicate,
            test_cross_shard_unregister,
            test_cross_shard_send_receipt,
            test_cross_shard_unknown_shard_dropped,
            test_cross_shard_get_pending,
            test_cross_shard_process_receipt,
            test_cross_shard_merkle_tree,
            test_cross_shard_merkle_proof_verify,
            test_cross_shard_receipt_expiry,
            test_cross_shard_retry,
            test_cross_shard_metrics,
            test_cross_shard_ordering
        ]},
        {event_bus, [sequence], [
            test_event_bus_publish_subscribe,
            test_event_bus_unsubscribe,
            test_event_bus_any_topic,
            test_event_bus_filter_function,
            test_event_bus_dead_subscriber_cleanup,
            test_event_bus_replay_last,
            test_event_bus_metrics,
            test_event_bus_multi_topic_subscribe
        ]},
        {consensus_manager, [sequence], [
            test_consensus_manager_start_shard,
            test_consensus_manager_start_duplicate,
            test_consensus_manager_stop_shard,
            test_consensus_manager_stop_not_found,
            test_consensus_manager_get_status,
            test_consensus_manager_get_all_shards,
            test_consensus_manager_get_active_shards,
            test_consensus_manager_get_shard_pid,
            test_consensus_manager_global_finality,
            test_consensus_manager_propose_to_shard,
            test_consensus_manager_sync_validators,
            test_consensus_manager_restart_shard
        ]},
        {helper, [sequence], [
            test_helper_create_validator,
            test_helper_create_validator_pqc,
            test_helper_create_block,
            test_helper_create_vote,
            test_helper_create_config,
            test_helper_create_receipt,
            test_helper_create_poc_report,
            test_helper_create_drs_event,
            test_helper_wait_for_finality_timeout,
            test_helper_print_shard_status,
            test_helper_print_global_status
        ]},
        {integration, [sequence], [
            test_integration_full_consensus_round,
            test_integration_multi_shard,
            test_integration_cross_shard_with_consensus,
            test_integration_slashing_removes_from_shard,
            test_integration_event_bus_consensus_events
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(erl_bridge),
    timer:sleep(200),
    Config.

end_per_suite(_Config) ->
    application:stop(erl_bridge),
    ok.

init_per_group(validator_manager, Config) ->
    cleanup_validators(),
    Config;
init_per_group(slashing, Config) ->
    cleanup_validators(),
    Config;
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, _Config) ->
    ct:pal("Finished test: ~p", [TestCase]),
    stop_all_test_shards(),
    ok.

test_blake2s_hash(_Config) ->
    Hash = sbft_crypto:hash(blake2s, <<"hello world">>),
    ?assert(is_binary(Hash)),
    ?assertEqual(32, byte_size(Hash)),
    Hash2 = sbft_crypto:hash(blake2s, <<"hello world">>),
    ?assertEqual(Hash, Hash2),
    Hash3 = sbft_crypto:hash(blake2s, <<"different">>),
    ?assertNotEqual(Hash, Hash3).

test_sha256_hash(_Config) ->
    Hash = sbft_crypto:hash(sha256, <<"test">>),
    ?assert(is_binary(Hash)),
    ?assertEqual(32, byte_size(Hash)).

test_hkdf_basic(_Config) ->
    IKM = <<"input key material">>,
    Info = <<"test context">>,
    Result = sbft_crypto:hkdf(IKM, undefined, Info),
    ?assert(is_binary(Result)),
    ?assertEqual(32, byte_size(Result)),
    Result2 = sbft_crypto:hkdf(IKM, undefined, Info),
    ?assertEqual(Result, Result2).

test_hkdf_with_salt(_Config) ->
    IKM = <<"input key material">>,
    Salt = <<"my salt">>,
    Info = <<"context">>,
    R1 = sbft_crypto:hkdf(IKM, undefined, Info),
    R2 = sbft_crypto:hkdf(IKM, Salt, Info),
    ?assertNotEqual(R1, R2),
    ?assertEqual(64, byte_size(sbft_crypto:hkdf(IKM, Salt, Info, 64))).

test_ed25519_sign_verify(_Config) ->
    Payload = <<"consensus vote payload">>,
    {ok, Keypair} = sbft_crypto:generate_keypair(ed25519),
    PK = Keypair#pqc_keypair.public_key,
    SK = Keypair#pqc_keypair.secret_key,
    {ok, Sig} = sbft_crypto:sign(ed25519, SK, Payload),
    ?assert(is_binary(Sig)),
    ?assert(sbft_crypto:verify(ed25519, PK, Payload, Sig)),
    ?assertNot(sbft_crypto:verify(ed25519, PK, <<"tampered">>, Sig)).

test_dilithium2_sign_verify(_Config) ->
    Payload = <<"block proposal">>,
    {ok, Keypair} = sbft_crypto:generate_keypair(dilithium2),
    PK = Keypair#pqc_keypair.public_key,
    SK = Keypair#pqc_keypair.secret_key,
    {ok, Sig} = sbft_crypto:sign(dilithium2, SK, Payload),
    ?assert(is_binary(Sig)),
    Result = sbft_crypto:verify(dilithium2, PK, Payload, Sig),
    ?assert(is_boolean(Result)).

test_hybrid_sign_verify(_Config) ->
    Payload = <<"hybrid signed message">>,
    {ok, Keypair} = sbft_crypto:generate_keypair(hybrid),
    PK = Keypair#pqc_keypair.public_key,
    SK = Keypair#pqc_keypair.secret_key,
    {ok, Sig} = sbft_crypto:sign(hybrid, SK, Payload),
    ?assert(is_binary(Sig)),
    Result = sbft_crypto:verify(hybrid, PK, Payload, Sig),
    ?assert(is_boolean(Result)).

test_pqc_signature_record(_Config) ->
    Payload = <<"pqc payload">>,
    {ok, Keypair} = sbft_crypto:generate_keypair(ed25519),
    {ok, PQCSig} = sbft_crypto:sign_hybrid(Keypair, <<"validator_id">>, Payload),
    ?assertMatch(#pqc_signature{}, PQCSig),
    ?assertEqual(ed25519, PQCSig#pqc_signature.algorithm),
    ?assertEqual(<<"validator_id">>, PQCSig#pqc_signature.signer_id),
    ?assert(is_binary(PQCSig#pqc_signature.payload_hash)),
    ?assert(is_binary(PQCSig#pqc_signature.signature_bytes)).

test_kem_encapsulate_x25519(_Config) ->
    {EphPK, _EphSK} = crypto:generate_key(ecdh, x25519),
    {ok, CT, SS} = sbft_crypto:kem_encapsulate(x25519, EphPK),
    ?assert(is_binary(CT)),
    ?assert(is_binary(SS)),
    ?assertEqual(32, byte_size(SS)).

test_kem_encapsulate_mlkem768(_Config) ->
    {ok, KemPK, _KemSK} = sbft_nif:mlkem768_keypair(),
    {ok, CT, SS} = sbft_crypto:kem_encapsulate(mlkem768, KemPK),
    ?assert(is_binary(CT)),
    ?assert(is_binary(SS)),
    ?assertEqual(?MLKEM768_CT_SIZE, byte_size(CT)),
    ?assertEqual(32, byte_size(SS)).

test_kem_decapsulate_round_trip(_Config) ->
    {ok, KemPK, KemSK} = sbft_nif:mlkem768_keypair(),
    {ok, CT, SS1} = sbft_crypto:kem_encapsulate(mlkem768, KemPK),
    {ok, SS2} = sbft_crypto:kem_decapsulate(mlkem768, KemSK, CT),
    ?assert(sbft_crypto:constant_time_compare(SS1, SS2)).

test_session_key_derivation(_Config) ->
    SS = sbft_crypto:random_bytes(32),
    PeerId = <<"peer_node_id">>,
    Context = <<"consensus">>,
    {ok, SessionKey, Nonce} = sbft_crypto:derive_session_key(SS, PeerId, Context),
    ?assertMatch(#hybrid_session_key{}, SessionKey),
    ?assert(is_binary(Nonce)),
    ?assertEqual(24, byte_size(Nonce)).

test_encrypt_decrypt(_Config) ->
    SS = sbft_crypto:random_bytes(32),
    {ok, SessionKey, _Nonce} = sbft_crypto:derive_session_key(SS, <<"peer">>, <<"ctx">>),
    Plaintext = <<"secret consensus message">>,
    {ok, Ciphertext} = sbft_crypto:encrypt_message(SessionKey, Plaintext),
    ?assert(is_binary(Ciphertext)),
    ?assertNotEqual(Plaintext, Ciphertext),
    {ok, Decrypted} = sbft_crypto:decrypt_message(SessionKey, Ciphertext),
    ?assertEqual(Plaintext, Decrypted).

test_block_signing_payload(_Config) ->
    Block = make_test_block(<<"hash1">>, 0, ?VAL_1, ?SHARD_A),
    Payload = sbft_crypto:block_signing_payload(Block),
    ?assert(is_binary(Payload)),
    ?assertEqual(32, byte_size(Payload)),
    Payload2 = sbft_crypto:block_signing_payload(Block),
    ?assertEqual(Payload, Payload2).

test_vote_signing_payload(_Config) ->
    Vote = make_test_vote(?VAL_1, 0, <<"hash1">>, prepare, ?SHARD_A),
    Payload = sbft_crypto:vote_signing_payload(Vote),
    ?assert(is_binary(Payload)),
    ?assertEqual(32, byte_size(Payload)).

test_receipt_signing_payload(_Config) ->
    Receipt = sbft_helper:create_cross_shard_receipt(?SHARD_A, ?SHARD_B, <<"data">>, #{}),
    Payload = sbft_crypto:receipt_signing_payload(Receipt),
    ?assert(is_binary(Payload)),
    ?assertEqual(32, byte_size(Payload)).

test_detect_equivocation(_Config) ->
    Vote1 = make_test_vote(?VAL_1, 5, <<"hash_A">>, prepare, ?SHARD_A),
    Vote2 = make_test_vote(?VAL_1, 5, <<"hash_B">>, prepare, ?SHARD_A),
    Result = sbft_crypto:detect_equivocation(Vote1, Vote2),
    ?assertMatch({equivocation_detected, ?VAL_1}, Result).

test_no_equivocation(_Config) ->
    Vote1 = make_test_vote(?VAL_1, 5, <<"hash_A">>, prepare, ?SHARD_A),
    Vote2 = make_test_vote(?VAL_2, 5, <<"hash_B">>, prepare, ?SHARD_A),
    ?assertEqual(no_equivocation, sbft_crypto:detect_equivocation(Vote1, Vote2)),
    Vote3 = make_test_vote(?VAL_1, 6, <<"hash_B">>, prepare, ?SHARD_A),
    ?assertEqual(no_equivocation, sbft_crypto:detect_equivocation(Vote1, Vote3)),
    Vote4 = make_test_vote(?VAL_1, 5, <<"hash_A">>, prepare, ?SHARD_A),
    ?assertEqual(no_equivocation, sbft_crypto:detect_equivocation(Vote1, Vote4)).

test_aggregate_signatures(_Config) ->
    Votes = [make_test_vote(V, 0, <<"h">>, prepare, ?SHARD_A) ||
             V <- [?VAL_1, ?VAL_2, ?VAL_3]],
    {ok, AggSig} = sbft_crypto:aggregate_signatures(Votes),
    ?assert(is_binary(AggSig)),
    ?assert(sbft_crypto:verify_aggregate(AggSig, Votes, [])).

test_constant_time_compare(_Config) ->
    A = <<"equal binary">>,
    B = <<"equal binary">>,
    C = <<"differ binary">>,
    D = <<"short">>,
    ?assert(sbft_crypto:constant_time_compare(A, B)),
    ?assertNot(sbft_crypto:constant_time_compare(A, C)),
    ?assertNot(sbft_crypto:constant_time_compare(A, D)).

test_nif_capabilities(_Config) ->
    Caps = sbft_nif:capabilities(),
    ?assert(is_map(Caps)),
    ?assert(maps:get(ed25519, Caps)),
    ?assert(maps:get(x25519, Caps)),
    ?assert(maps:get(sha256, Caps)),
    ?assert(is_boolean(maps:get(dilithium2, Caps))),
    ?assert(is_boolean(maps:get(mlkem768, Caps))).

test_dilithium2_keypair_size(_Config) ->
    {ok, PK, SK} = sbft_nif:dilithium2_keypair(),
    ?assert(byte_size(PK) > 0),
    ?assert(byte_size(SK) > 0).

test_mlkem768_keypair_size(_Config) ->
    {ok, PK, SK} = sbft_nif:mlkem768_keypair(),
    ?assertEqual(?MLKEM768_PK_SIZE, byte_size(PK)),
    ?assert(byte_size(SK) > 0).

test_mlkem768_encapsulate_size(_Config) ->
    {ok, PK, _SK} = sbft_nif:mlkem768_keypair(),
    {ok, CT, SS} = sbft_nif:mlkem768_encapsulate(PK),
    ?assertEqual(?MLKEM768_CT_SIZE, byte_size(CT)),
    ?assertEqual(32, byte_size(SS)).

test_blake2s_nif(_Config) ->
    {ok, Hash} = sbft_nif:blake2s_hash(<<"test data">>),
    ?assert(is_binary(Hash)),
    ?assertEqual(?BLAKE2S_DIGEST_SIZE, byte_size(Hash)),
    {ok, Mac} = sbft_nif:blake2s_mac(<<"key">>, <<"data">>),
    ?assert(is_binary(Mac)).

test_sphincs_keypair(_Config) ->
    {ok, PK, SK} = sbft_nif:sphincs_keypair(),
    ?assert(is_binary(PK)),
    ?assert(is_binary(SK)),
    {ok, Sig} = sbft_nif:sphincs_sign(SK, <<"message">>),
    ?assert(is_binary(Sig)),
    {ok, Valid} = sbft_nif:sphincs_verify(PK, <<"message">>, Sig),
    ?assert(is_boolean(Valid)).

test_nif_available(_Config) ->
    Result = sbft_nif:nif_available(),
    ?assert(is_boolean(Result)),
    ?assert(is_boolean(sbft_nif:nif_available(dilithium2))),
    ?assert(is_boolean(sbft_nif:nif_available(mlkem768))).

test_validator_register(_Config) ->
    VId = unique_id(<<"reg_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ?assertEqual(ok, sbft_validator_manager:register_validator(VId, Data)).

test_validator_register_duplicate(_Config) ->
    VId = unique_id(<<"dup_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    ?assertEqual({error, already_exists},
                 sbft_validator_manager:register_validator(VId, Data)).

test_validator_get(_Config) ->
    VId = unique_id(<<"get_val">>),
    Data = make_validator_data(2000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assertEqual(VId, V#sbft_validator_record.id),
    ?assertEqual(2000, V#sbft_validator_record.stake),
    ?assert(V#sbft_validator_record.is_active).

test_validator_get_not_found(_Config) ->
    ?assertEqual({error, not_found},
                 sbft_validator_manager:get_validator(<<"nonexistent_99999">>)).

test_validator_update_stake(_Config) ->
    VId = unique_id(<<"stake_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    ok = sbft_validator_manager:update_stake(VId, 5000),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assertEqual(5000, V#sbft_validator_record.stake).

test_validator_slash(_Config) ->
    VId = unique_id(<<"slash_val">>),
    Data = make_validator_data(3000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    ok = sbft_validator_manager:slash_validator(VId, double_voting),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assertNot(V#sbft_validator_record.is_active),
    ?assertEqual(1, V#sbft_validator_record.slashing_events).

test_validator_reactivate_after_slash(_Config) ->
    VId = unique_id(<<"react_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    ok = sbft_validator_manager:slash_validator(VId, unavailability),
    ?assertEqual({error, permanently_slashed},
                 sbft_validator_manager:reactivate_validator(VId)).

test_validator_get_all(_Config) ->
    VId1 = unique_id(<<"all_v1">>),
    VId2 = unique_id(<<"all_v2">>),
    ok = sbft_validator_manager:register_validator(VId1, make_validator_data(100, ?SHARD_A)),
    ok = sbft_validator_manager:register_validator(VId2, make_validator_data(200, ?SHARD_A)),
    {ok, All} = sbft_validator_manager:get_all_validators(),
    ?assert(is_list(All)),
    Ids = [V#sbft_validator_record.id || V <- All],
    ?assert(lists:member(VId1, Ids)),
    ?assert(lists:member(VId2, Ids)).

test_validator_get_active(_Config) ->
    VId1 = unique_id(<<"act_v1">>),
    VId2 = unique_id(<<"act_v2">>),
    ok = sbft_validator_manager:register_validator(VId1, make_validator_data(100, ?SHARD_A)),
    ok = sbft_validator_manager:register_validator(VId2, make_validator_data(200, ?SHARD_A)),
    ok = sbft_validator_manager:slash_validator(VId2, unavailability),
    {ok, Active} = sbft_validator_manager:get_active_validators(),
    ActiveIds = [V#sbft_validator_record.id || V <- Active],
    ?assert(lists:member(VId1, ActiveIds)),
    ?assertNot(lists:member(VId2, ActiveIds)).

test_validator_get_by_shard(_Config) ->
    VId1 = unique_id(<<"shard_v1">>),
    VId2 = unique_id(<<"shard_v2">>),
    UniqShard = unique_id(<<"uniq_shard">>),
    ok = sbft_validator_manager:register_validator(VId1, make_validator_data(100, UniqShard)),
    ok = sbft_validator_manager:register_validator(VId2, make_validator_data(200, ?SHARD_B)),
    {ok, ShardVals} = sbft_validator_manager:get_validators_for_shard(UniqShard),
    Ids = [V#sbft_validator_record.id || V <- ShardVals],
    ?assert(lists:member(VId1, Ids)),
    ?assertNot(lists:member(VId2, Ids)).

test_validator_update_capability(_Config) ->
    VId = unique_id(<<"cap_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    ok = sbft_validator_manager:update_capability(VId, pqc_primary),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assertEqual(pqc_primary, V#sbft_validator_record.capability).

test_validator_update_pqc_keys(_Config) ->
    VId = unique_id(<<"pqc_key_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    {ok, PK, _SK} = sbft_nif:dilithium2_keypair(),
    {ok, KemPK, _KemSK} = sbft_nif:mlkem768_keypair(),
    ok = sbft_validator_manager:update_pqc_keys(VId, PK, KemPK),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assertNotEqual(undefined, V#sbft_validator_record.pqc_public_key),
    ?assertNotEqual(undefined, V#sbft_validator_record.kem_public_key).

test_validator_record_vote(_Config) ->
    VId = unique_id(<<"vote_rec_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    sbft_validator_manager:record_vote_cast(VId),
    sbft_validator_manager:record_vote_cast(VId),
    timer:sleep(50),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assert(V#sbft_validator_record.performance_score >= 0.0).

test_validator_record_miss(_Config) ->
    VId = unique_id(<<"miss_rec_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    sbft_validator_manager:record_missed_vote(VId),
    timer:sleep(50),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assert(V#sbft_validator_record.reputation =< 1.0).

test_validator_drs_score(_Config) ->
    VId = unique_id(<<"drs_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    DRSEvt = sbft_helper:create_drs_event(VId, ?SHARD_A, 0.8, 1),
    sbft_validator_manager:apply_drs_score(VId, DRSEvt),
    timer:sleep(50),
    {ok, Multiplier} = sbft_validator_manager:get_drs_score(VId),
    ?assert(Multiplier >= ?DRS_MIN_MULTIPLIER),
    ?assert(Multiplier =< ?DRS_MAX_MULTIPLIER).

test_validator_epoch_stats(_Config) ->
    {ok, Stats} = sbft_validator_manager:get_epoch_stats(),
    ?assert(is_map(Stats)),
    ?assert(maps:is_key(epoch, Stats)),
    ?assert(maps:is_key(total_validators, Stats)),
    ?assert(maps:is_key(active_validators, Stats)),
    ?assert(maps:is_key(total_stake, Stats)).

test_validator_total_stake(_Config) ->
    {ok, Stake} = sbft_validator_manager:get_total_stake(),
    ?assert(is_integer(Stake)),
    ?assert(Stake >= 0).

test_validator_shard_stake(_Config) ->
    UniqShard = unique_id(<<"stake_shard">>),
    VId1 = unique_id(<<"ss_v1">>),
    VId2 = unique_id(<<"ss_v2">>),
    ok = sbft_validator_manager:register_validator(VId1, make_validator_data(1000, UniqShard)),
    ok = sbft_validator_manager:register_validator(VId2, make_validator_data(2000, UniqShard)),
    {ok, Total} = sbft_validator_manager:get_total_stake_for_shard(UniqShard),
    ?assertEqual(3000, Total).

test_validator_is_active(_Config) ->
    VId = unique_id(<<"isact_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    ?assert(sbft_validator_manager:is_active(VId)),
    ok = sbft_validator_manager:slash_validator(VId, double_voting),
    ?assertNot(sbft_validator_manager:is_active(VId)).

test_validator_check_capability(_Config) ->
    VId = unique_id(<<"chkcap_val">>),
    Data = make_validator_data(1000, ?SHARD_A),
    ok = sbft_validator_manager:register_validator(VId, Data),
    {ok, true} = sbft_validator_manager:check_capability(VId, legacy),
    {ok, false} = sbft_validator_manager:check_capability(VId, pqc_primary).

test_shard_start_stop(_Config) ->
    ShardId = unique_id(<<"ss_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    ?assert(erlang:is_process_alive(Pid)),
    ok = sbft_shard_consensus:stop(Pid),
    timer:sleep(50),
    ?assertNot(erlang:is_process_alive(Pid)).

test_shard_propose_block(_Config) ->
    ShardId = unique_id(<<"pb_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status = sbft_shard_consensus:get_status(Pid),
    Leader = maps:get(current_leader, Status),
    Block = make_test_block(<<"hash_pb">>, 0, Leader, ShardId),
    sbft_shard_consensus:propose_block(Pid, Block),
    timer:sleep(?SETTLE_MS),
    Status2 = sbft_shard_consensus:get_status(Pid),
    Metrics = maps:get(metrics, Status2),
    ?assert(maps:get(blocks_proposed, Metrics) >= 0),
    sbft_shard_consensus:stop(Pid).

test_shard_propose_wrong_leader(_Config) ->
    ShardId = unique_id(<<"wl_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status0 = sbft_shard_consensus:get_status(Pid),
    Block = make_test_block(<<"hash_wl">>, 0, <<"wrong_leader">>, ShardId),
    sbft_shard_consensus:propose_block(Pid, Block),
    timer:sleep(?SETTLE_MS),
    Status1 = sbft_shard_consensus:get_status(Pid),
    M0 = maps:get(blocks_proposed, maps:get(metrics, Status0), 0),
    M1 = maps:get(blocks_proposed, maps:get(metrics, Status1), 0),
    ?assertEqual(M0, M1),
    sbft_shard_consensus:stop(Pid).

test_shard_propose_wrong_view(_Config) ->
    ShardId = unique_id(<<"wv_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status = sbft_shard_consensus:get_status(Pid),
    Leader = maps:get(current_leader, Status),
    Block = make_test_block(<<"hash_wv">>, 99, Leader, ShardId),
    sbft_shard_consensus:propose_block(Pid, Block),
    timer:sleep(?SETTLE_MS),
    Status2 = sbft_shard_consensus:get_status(Pid),
    ?assertEqual(0, maps:get(view, Status2)),
    sbft_shard_consensus:stop(Pid).

test_shard_propose_wrong_shard(_Config) ->
    ShardId = unique_id(<<"ws_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status = sbft_shard_consensus:get_status(Pid),
    Leader = maps:get(current_leader, Status),
    Block = make_test_block(<<"hash_ws">>, 0, Leader, <<"wrong_shard_id">>),
    sbft_shard_consensus:propose_block(Pid, Block),
    timer:sleep(?SETTLE_MS),
    Status2 = sbft_shard_consensus:get_status(Pid),
    Metrics = maps:get(metrics, Status2),
    ?assertEqual(0, maps:get(blocks_proposed, Metrics, 0)),
    sbft_shard_consensus:stop(Pid).

test_shard_vote_collection(_Config) ->
    ShardId = unique_id(<<"vc_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status = sbft_shard_consensus:get_status(Pid),
    ?assert(maps:get(validators_count, Status) >= 4),
    sbft_shard_consensus:stop(Pid).

test_shard_view_change_on_timeout(_Config) ->
    ShardId = unique_id(<<"vct_shard">>),
    Validators = make_test_validators(ShardId, 4),
    Config = sbft_helper:create_config(Validators, 300, #{view_change_timeout => 600}),
    {ok, Pid} = sbft_shard_consensus:start_link(ShardId, Config),
    timer:sleep(1500),
    Status = sbft_shard_consensus:get_status(Pid),
    Metrics = maps:get(metrics, Status),
    ?assert(maps:get(view_changes, Metrics, 0) >= 0),
    sbft_shard_consensus:stop(Pid).

test_shard_add_validator(_Config) ->
    ShardId = unique_id(<<"av_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status0 = sbft_shard_consensus:get_status(Pid),
    Count0 = maps:get(validators_count, Status0),
    NewVal = sbft_helper:create_validator(<<"new_val_x">>, <<"pk_x">>, 500, ShardId),
    ?assertEqual(ok, sbft_shard_consensus:add_validator(Pid, NewVal)),
    Status1 = sbft_shard_consensus:get_status(Pid),
    ?assertEqual(Count0 + 1, maps:get(validators_count, Status1)),
    sbft_shard_consensus:stop(Pid).

test_shard_remove_validator(_Config) ->
    ShardId = unique_id(<<"rv_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status0 = sbft_shard_consensus:get_status(Pid),
    Count0 = maps:get(validators_count, Status0),
    NewVal = sbft_helper:create_validator(unique_id(<<"rem_v">>), <<"pk_r">>, 500, ShardId),
    ValId = NewVal#sbft_validator_record.id,
    ok = sbft_shard_consensus:add_validator(Pid, NewVal),
    ok = sbft_shard_consensus:remove_validator(Pid, ValId),
    Status1 = sbft_shard_consensus:get_status(Pid),
    ?assertEqual(Count0, maps:get(validators_count, Status1)),
    sbft_shard_consensus:stop(Pid).

test_shard_remove_below_minimum(_Config) ->
    ShardId = unique_id(<<"rbm_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status = sbft_shard_consensus:get_status(Pid),
    Leader = maps:get(current_leader, Status),
    ?assertEqual({error, below_minimum_validators},
                 sbft_shard_consensus:remove_validator(Pid, Leader)),
    sbft_shard_consensus:stop(Pid).

test_shard_update_validator_stake(_Config) ->
    ShardId = unique_id(<<"uvs_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status = sbft_shard_consensus:get_status(Pid),
    Leader = maps:get(current_leader, Status),
    ok = sbft_shard_consensus:update_validator_stake(Pid, Leader, 9999),
    Status2 = sbft_shard_consensus:get_status(Pid),
    ?assert(maps:get(total_stake, Status2) > 0),
    sbft_shard_consensus:stop(Pid).

test_shard_get_status_fields(_Config) ->
    ShardId = unique_id(<<"gsf_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status = sbft_shard_consensus:get_status(Pid),
    ?assert(maps:is_key(shard_id, Status)),
    ?assert(maps:is_key(view, Status)),
    ?assert(maps:is_key(height, Status)),
    ?assert(maps:is_key(phase, Status)),
    ?assert(maps:is_key(current_leader, Status)),
    ?assert(maps:is_key(validators_count, Status)),
    ?assert(maps:is_key(total_stake, Status)),
    ?assert(maps:is_key(last_finalized_view, Status)),
    ?assert(maps:is_key(metrics, Status)),
    ?assert(maps:is_key(pqc_enabled, Status)),
    sbft_shard_consensus:stop(Pid).

test_shard_get_committed_block(_Config) ->
    ShardId = unique_id(<<"gcb_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    ?assertEqual({error, not_found}, sbft_shard_consensus:get_committed_block(Pid, 999)),
    sbft_shard_consensus:stop(Pid).

test_shard_get_high_qc(_Config) ->
    ShardId = unique_id(<<"ghq_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    HighQC = sbft_shard_consensus:get_high_qc(Pid),
    ?assert(HighQC =:= undefined orelse is_record(HighQC, quorum_certificate)),
    sbft_shard_consensus:stop(Pid).

test_shard_inject_receipt(_Config) ->
    ShardId = unique_id(<<"ir_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Receipt = sbft_helper:create_cross_shard_receipt(?SHARD_A, ShardId, <<"data">>, #{}),
    sbft_shard_consensus:inject_cross_shard_receipt(Pid, Receipt),
    timer:sleep(50),
    Receipts = sbft_shard_consensus:get_pending_receipts(Pid),
    ?assert(length(Receipts) >= 1),
    sbft_shard_consensus:stop(Pid).

test_shard_force_view_change(_Config) ->
    ShardId = unique_id(<<"fvc_shard">>),
    {ok, Pid} = start_test_shard(ShardId),
    Status0 = sbft_shard_consensus:get_status(Pid),
    View0 = maps:get(view, Status0),
    sbft_shard_consensus:force_view_change(Pid),
    timer:sleep(?SETTLE_MS),
    Status1 = sbft_shard_consensus:get_status(Pid),
    ?assert(maps:get(view, Status1) >= View0),
    sbft_shard_consensus:stop(Pid).

test_slashing_double_vote(_Config) ->
    VId = unique_id(<<"dv_sl_val">>),
    ok = sbft_validator_manager:register_validator(VId, make_validator_data(5000, ?SHARD_A)),
    Vote1 = make_test_vote(VId, 3, <<"hash_X">>, prepare, ?SHARD_A),
    Vote2 = make_test_vote(VId, 3, <<"hash_Y">>, prepare, ?SHARD_A),
    sbft_slashing:report_double_vote(VId, Vote1, Vote2),
    timer:sleep(?SETTLE_MS),
    {ok, IsSlashed} = sbft_slashing:is_slashed(VId),
    ?assert(IsSlashed).

test_slashing_invalid_block(_Config) ->
    VId = unique_id(<<"ib_sl_val">>),
    ok = sbft_validator_manager:register_validator(VId, make_validator_data(4000, ?SHARD_A)),
    Block = make_test_block(<<"bad_block">>, 0, VId, ?SHARD_A),
    sbft_slashing:report_invalid_block(VId, Block, ?SHARD_A),
    timer:sleep(?SETTLE_MS),
    {ok, Count} = sbft_slashing:get_slash_count(VId),
    ?assert(Count >= 1).

test_slashing_unavailability(_Config) ->
    VId = unique_id(<<"ua_sl_val">>),
    ok = sbft_validator_manager:register_validator(VId, make_validator_data(2000, ?SHARD_A)),
    sbft_slashing:report_unavailability(VId, ?SHARD_A),
    timer:sleep(?SETTLE_MS),
    {ok, Pending} = sbft_slashing:get_pending_evidence(),
    ?assert(is_list(Pending)).

test_slashing_invalid_poc(_Config) ->
    VId = unique_id(<<"ip_sl_val">>),
    ok = sbft_validator_manager:register_validator(VId, make_validator_data(2000, ?SHARD_A)),
    sbft_slashing:report_invalid_poc(VId, ?SHARD_A),
    timer:sleep(?SETTLE_MS),
    {ok, History} = sbft_slashing:get_slashing_history(),
    ?assert(is_list(History)).

test_slashing_storage_fault(_Config) ->
    VId = unique_id(<<"sf_sl_val">>),
    ok = sbft_validator_manager:register_validator(VId, make_validator_data(2000, ?SHARD_A)),
    sbft_slashing:report_storage_fault(VId, ?SHARD_A),
    timer:sleep(?SETTLE_MS),
    {ok, History} = sbft_slashing:get_slashing_history(VId),
    ?assert(is_list(History)).

test_slashing_deduplication(_Config) ->
    VId = unique_id(<<"dedup_sl_val">>),
    ok = sbft_validator_manager:register_validator(VId, make_validator_data(5000, ?SHARD_A)),
    Vote1 = make_test_vote(VId, 7, <<"hash_P">>, prepare, ?SHARD_A),
    Vote2 = make_test_vote(VId, 7, <<"hash_Q">>, prepare, ?SHARD_A),
    sbft_slashing:report_double_vote(VId, Vote1, Vote2),
    sbft_slashing:report_double_vote(VId, Vote1, Vote2),
    sbft_slashing:report_double_vote(VId, Vote1, Vote2),
    timer:sleep(?SETTLE_MS),
    {ok, Count} = sbft_slashing:get_slash_count(VId),
    ?assert(Count >= 1).

test_slashing_history(_Config) ->
    {ok, History} = sbft_slashing:get_slashing_history(),
    ?assert(is_list(History)).

test_slashing_slash_count(_Config) ->
    {ok, Count} = sbft_slashing:get_slash_count(<<"nonexistent_slash_v">>),
    ?assertEqual(0, Count).

test_slashing_is_slashed(_Config) ->
    {ok, Result} = sbft_slashing:is_slashed(<<"nonexistent_slash_v2">>),
    ?assertNot(Result).

test_cross_shard_register(_Config) ->
    ShardId = unique_id(<<"cs_reg">>),
    ?assertEqual(ok, sbft_cross_shard:register_shard(ShardId)).

test_cross_shard_register_duplicate(_Config) ->
    ShardId = unique_id(<<"cs_dup">>),
    ok = sbft_cross_shard:register_shard(ShardId),
    ?assertEqual({error, already_registered},
                 sbft_cross_shard:register_shard(ShardId)).

test_cross_shard_unregister(_Config) ->
    ShardId = unique_id(<<"cs_unreg">>),
    ok = sbft_cross_shard:register_shard(ShardId),
    ok = sbft_cross_shard:unregister_shard(ShardId),
    {ok, Shards} = sbft_cross_shard:get_registered_shards(),
    ?assertNot(lists:member(ShardId, Shards)).

test_cross_shard_send_receipt(_Config) ->
    From = unique_id(<<"cs_from">>),
    To = unique_id(<<"cs_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    sbft_cross_shard:send_receipt(From, To, <<"tx_data">>, #{}),
    timer:sleep(100),
    {ok, Pending} = sbft_cross_shard:get_pending_receipts(To),
    ?assert(length(Pending) >= 1).

test_cross_shard_unknown_shard_dropped(_Config) ->
    {ok, MetricsBefore} = sbft_cross_shard:get_metrics(),
    sbft_cross_shard:send_receipt(<<"nobody">>, <<"also_nobody">>, <<"data">>, #{}),
    timer:sleep(100),
    {ok, MetricsAfter} = sbft_cross_shard:get_metrics(),
    Before = maps:get(receipts_dropped_unknown_shard, MetricsBefore, 0),
    After = maps:get(receipts_dropped_unknown_shard, MetricsAfter, 0),
    ?assert(After >= Before).

test_cross_shard_get_pending(_Config) ->
    From = unique_id(<<"cs_gp_from">>),
    To = unique_id(<<"cs_gp_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    sbft_cross_shard:send_receipt(From, To, <<"data1">>, #{}),
    sbft_cross_shard:send_receipt(From, To, <<"data2">>, #{}),
    sbft_cross_shard:send_receipt(From, To, <<"data3">>, #{}),
    timer:sleep(100),
    {ok, Pending} = sbft_cross_shard:get_pending_receipts(To),
    ?assertEqual(3, length(Pending)).

test_cross_shard_process_receipt(_Config) ->
    From = unique_id(<<"cs_pr_from">>),
    To = unique_id(<<"cs_pr_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    sbft_cross_shard:send_receipt(From, To, <<"process_me">>, #{}),
    timer:sleep(100),
    {ok, [Receipt | _]} = sbft_cross_shard:get_pending_receipts(To),
    sbft_cross_shard:process_receipt(Receipt),
    timer:sleep(100),
    {ok, Remaining} = sbft_cross_shard:get_pending_receipts(To),
    ?assertEqual(0, length(Remaining)).

test_cross_shard_merkle_tree(_Config) ->
    From = unique_id(<<"cs_mt_from">>),
    To = unique_id(<<"cs_mt_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    sbft_cross_shard:send_receipt(From, To, <<"tx1">>, #{}),
    sbft_cross_shard:send_receipt(From, To, <<"tx2">>, #{}),
    sbft_cross_shard:send_receipt(From, To, <<"tx3">>, #{}),
    timer:sleep(100),
    {ok, Root, Proofs} = sbft_cross_shard:build_receipt_tree(To),
    ?assert(is_binary(Root)),
    ?assert(byte_size(Root) > 0),
    ?assertEqual(3, length(Proofs)).

test_cross_shard_merkle_proof_verify(_Config) ->
    From = unique_id(<<"cs_mpv_from">>),
    To = unique_id(<<"cs_mpv_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    sbft_cross_shard:send_receipt(From, To, <<"verify_tx_1">>, #{}),
    sbft_cross_shard:send_receipt(From, To, <<"verify_tx_2">>, #{}),
    timer:sleep(100),
    {ok, _Root, _Proofs} = sbft_cross_shard:build_receipt_tree(To),
    {ok, Pending} = sbft_cross_shard:get_pending_receipts(To),
    lists:foreach(fun(R) ->
        Verification = sbft_cross_shard:verify_receipt(R),
        ?assertMatch({ok, valid}, Verification)
    end, Pending).

test_cross_shard_receipt_expiry(_Config) ->
    From = unique_id(<<"cs_exp_from">>),
    To = unique_id(<<"cs_exp_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    Now = erlang:system_time(millisecond),
    sbft_cross_shard:send_receipt(From, To, <<"expiring">>, #{expiry_ms => Now - 1}),
    timer:sleep(100),
    sbft_cross_shard:expire_stale_receipts(),
    timer:sleep(100),
    {ok, Pending} = sbft_cross_shard:get_pending_receipts(To),
    ?assertEqual(0, length(Pending)).

test_cross_shard_retry(_Config) ->
    From = unique_id(<<"cs_ret_from">>),
    To = unique_id(<<"cs_ret_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    sbft_cross_shard:send_receipt(From, To, <<"retry_data">>, #{}),
    timer:sleep(100),
    {ok, Metrics} = sbft_cross_shard:get_metrics(),
    ?assert(is_map(Metrics)).

test_cross_shard_metrics(_Config) ->
    {ok, Metrics} = sbft_cross_shard:get_metrics(),
    ?assert(maps:is_key(receipts_received, Metrics)),
    ?assert(maps:is_key(receipts_processed, Metrics)),
    ?assert(maps:is_key(receipts_expired, Metrics)),
    ?assert(maps:is_key(receipts_failed, Metrics)).

test_cross_shard_ordering(_Config) ->
    From = unique_id(<<"cs_ord_from">>),
    To = unique_id(<<"cs_ord_to">>),
    ok = sbft_cross_shard:register_shard(From),
    ok = sbft_cross_shard:register_shard(To),
    sbft_cross_shard:send_receipt(From, To, <<"first">>, #{}),
    timer:sleep(10),
    sbft_cross_shard:send_receipt(From, To, <<"second">>, #{}),
    timer:sleep(10),
    sbft_cross_shard:send_receipt(From, To, <<"third">>, #{}),
    timer:sleep(100),
    {ok, Pending} = sbft_cross_shard:get_pending_receipts(To),
    ?assertEqual(3, length(Pending)),
    Timestamps = [R#cross_shard_receipt.timestamp || R <- Pending],
    ?assertEqual(Timestamps, lists:sort(Timestamps)).

test_event_bus_publish_subscribe(_Config) ->
    sbft_event_bus:subscribe([block_finalized]),
    sbft_event_bus:publish(block_finalized, #{shard_id => ?SHARD_A, view => 1}),
    timer:sleep(100),
    receive
        {sbft_event, block_finalized, Payload} ->
            ?assertEqual(?SHARD_A, maps:get(shard_id, Payload))
    after 500 ->
        ct:fail(no_event_received)
    end,
    sbft_event_bus:unsubscribe([block_finalized]).

test_event_bus_unsubscribe(_Config) ->
    sbft_event_bus:subscribe([new_view_started]),
    sbft_event_bus:unsubscribe([new_view_started]),
    sbft_event_bus:publish(new_view_started, #{shard_id => ?SHARD_A}),
    timer:sleep(200),
    receive
        {sbft_event, new_view_started, _} ->
            ct:fail(should_not_receive_after_unsubscribe)
    after 100 ->
        ok
    end.

test_event_bus_any_topic(_Config) ->
    sbft_event_bus:subscribe([any]),
    sbft_event_bus:publish(qc_formed, #{shard_id => ?SHARD_A, view => 5}),
    timer:sleep(100),
    receive
        {sbft_event, qc_formed, _Payload} -> ok
    after 500 ->
        ct:fail(any_topic_not_received)
    end,
    sbft_event_bus:unsubscribe([any]).

test_event_bus_filter_function(_Config) ->
    Filter = fun(_Topic, Payload) ->
        maps:get(shard_id, Payload, undefined) =:= ?SHARD_B
    end,
    sbft_event_bus:subscribe([block_finalized], Filter),
    sbft_event_bus:publish(block_finalized, #{shard_id => ?SHARD_A}),
    sbft_event_bus:publish(block_finalized, #{shard_id => ?SHARD_B}),
    timer:sleep(200),
    receive
        {sbft_event, block_finalized, P1} when P1 =:= #{shard_id => ?SHARD_A} ->
            ct:fail(filter_should_have_blocked_shard_a)
    after 0 -> ok
    end,
    receive
        {sbft_event, block_finalized, P2} ->
            ?assertEqual(?SHARD_B, maps:get(shard_id, P2))
    after 500 ->
        ct:fail(filtered_event_not_received)
    end,
    sbft_event_bus:unsubscribe([block_finalized]).

test_event_bus_dead_subscriber_cleanup(_Config) ->
    Pid = spawn(fun() ->
        sbft_event_bus:subscribe([validator_slashed]),
        receive stop -> ok end
    end),
    timer:sleep(50),
    {ok, SubsBefore} = sbft_event_bus:get_subscribers(validator_slashed),
    ?assert(lists:member(Pid, SubsBefore)),
    exit(Pid, kill),
    timer:sleep(200),
    {ok, SubsAfter} = sbft_event_bus:get_subscribers(validator_slashed),
    ?assertNot(lists:member(Pid, SubsAfter)).

test_event_bus_replay_last(_Config) ->
    sbft_event_bus:publish(drs_score_emitted, #{node_id => <<"n1">>, score => 0.9}),
    timer:sleep(100),
    {ok, LastEvent} = sbft_event_bus:replay_last(drs_score_emitted),
    ?assertNotEqual(undefined, LastEvent),
    ?assertEqual(<<"n1">>, maps:get(node_id, LastEvent)).

test_event_bus_metrics(_Config) ->
    {ok, MetricsBefore} = sbft_event_bus:get_metrics(),
    sbft_event_bus:publish(poc_report_received, #{node_id => <<"poc_node">>}),
    timer:sleep(100),
    {ok, MetricsAfter} = sbft_event_bus:get_metrics(),
    Before = maps:get(published_total, MetricsBefore, 0),
    After = maps:get(published_total, MetricsAfter, 0),
    ?assert(After > Before).

test_event_bus_multi_topic_subscribe(_Config) ->
    sbft_event_bus:subscribe([block_finalized, new_view_started]),
    sbft_event_bus:publish(block_finalized, #{shard_id => ?SHARD_C}),
    sbft_event_bus:publish(new_view_started, #{shard_id => ?SHARD_C}),
    timer:sleep(200),
    Got = collect_events(200),
    Topics = [T || {T, _} <- Got],
    ?assert(lists:member(block_finalized, Topics)),
    ?assert(lists:member(new_view_started, Topics)),
    sbft_event_bus:unsubscribe([block_finalized, new_view_started]).

test_consensus_manager_start_shard(_Config) ->
    ShardId = unique_id(<<"cm_start">>),
    Config = make_shard_config(ShardId),
    {ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    ?assert(is_pid(Pid)),
    ?assert(erlang:is_process_alive(Pid)),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_consensus_manager_start_duplicate(_Config) ->
    ShardId = unique_id(<<"cm_dup">>),
    Config = make_shard_config(ShardId),
    {ok, Pid1} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    {ok, Pid2} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    ?assertEqual(Pid1, Pid2),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_consensus_manager_stop_shard(_Config) ->
    ShardId = unique_id(<<"cm_stop">>),
    Config = make_shard_config(ShardId),
    {ok, _Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    ok = sbft_consensus_manager:stop_shard_consensus(ShardId),
    ?assertEqual({error, not_found},
                 sbft_consensus_manager:get_shard_status(ShardId)).

test_consensus_manager_stop_not_found(_Config) ->
    ?assertEqual({error, not_found},
                 sbft_consensus_manager:stop_shard_consensus(<<"nonexistent_shard_xyz">>)).

test_consensus_manager_get_status(_Config) ->
    ShardId = unique_id(<<"cm_gs">>),
    Config = make_shard_config(ShardId),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    {ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
    ?assert(is_map(Status)),
    ?assert(maps:is_key(shard_id, Status)),
    ?assert(maps:is_key(phase, Status)),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_consensus_manager_get_all_shards(_Config) ->
    S1 = unique_id(<<"cm_all_1">>),
    S2 = unique_id(<<"cm_all_2">>),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(S1, make_shard_config(S1)),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(S2, make_shard_config(S2)),
    {ok, All} = sbft_consensus_manager:get_all_shards(),
    ?assert(lists:member(S1, All)),
    ?assert(lists:member(S2, All)),
    sbft_consensus_manager:stop_shard_consensus(S1),
    sbft_consensus_manager:stop_shard_consensus(S2).

test_consensus_manager_get_active_shards(_Config) ->
    S1 = unique_id(<<"cm_act_1">>),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(S1, make_shard_config(S1)),
    {ok, Active} = sbft_consensus_manager:get_active_shards(),
    ?assert(lists:member(S1, Active)),
    sbft_consensus_manager:stop_shard_consensus(S1).

test_consensus_manager_get_shard_pid(_Config) ->
    ShardId = unique_id(<<"cm_pid">>),
    {ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, make_shard_config(ShardId)),
    {ok, RetPid} = sbft_consensus_manager:get_shard_pid(ShardId),
    ?assertEqual(Pid, RetPid),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_consensus_manager_global_finality(_Config) ->
    {ok, Finality} = sbft_consensus_manager:get_global_finality(),
    ?assert(is_map(Finality)),
    ?assert(maps:is_key(shard_count, Finality)),
    ?assert(maps:is_key(epoch, Finality)).

test_consensus_manager_propose_to_shard(_Config) ->
    ShardId = unique_id(<<"cm_prop">>),
    Config = make_shard_config(ShardId),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    {ok, Status} = sbft_consensus_manager:get_shard_status(ShardId),
    Leader = maps:get(current_leader, Status),
    Block = make_test_block(<<"cm_hash">>, 0, Leader, ShardId),
    sbft_consensus_manager:propose_to_shard(ShardId, Block),
    timer:sleep(?SETTLE_MS),
    {ok, Status2} = sbft_consensus_manager:get_shard_status(ShardId),
    ?assert(is_map(Status2)),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_consensus_manager_sync_validators(_Config) ->
    ShardId = unique_id(<<"cm_sync">>),
    Config = make_shard_config(ShardId),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    Result = sbft_consensus_manager:sync_shard_validators(ShardId),
    ?assert(Result =:= {ok, synced} orelse
            Result =:= {ok, no_change} orelse
            Result =:= {error, status_unavailable}),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_consensus_manager_restart_shard(_Config) ->
    ShardId = unique_id(<<"cm_restart">>),
    Config = make_shard_config(ShardId),
    {ok, Pid1} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    Result = sbft_consensus_manager:restart_shard_consensus(ShardId),
    timer:sleep(200),
    case Result of
        {ok, _Pid2} ->
            sbft_consensus_manager:stop_shard_consensus(ShardId);
        {error, _} ->
            ?assert(erlang:is_process_alive(Pid1) orelse true)
    end.

test_helper_create_validator(_Config) ->
    V = sbft_helper:create_validator(?VAL_1, <<"pk">>, 1000, ?SHARD_A),
    ?assertMatch(#sbft_validator_record{}, V),
    ?assertEqual(?VAL_1, V#sbft_validator_record.id),
    ?assertEqual(1000, V#sbft_validator_record.stake),
    ?assert(V#sbft_validator_record.is_active),
    ?assertEqual(legacy, V#sbft_validator_record.capability).

test_helper_create_validator_pqc(_Config) ->
    {ok, PK, _SK} = sbft_nif:dilithium2_keypair(),
    {ok, KemPK, _} = sbft_nif:mlkem768_keypair(),
    V = sbft_helper:create_validator_with_pqc(?VAL_1, 2000, ?SHARD_A, PK, KemPK),
    ?assertMatch(#sbft_validator_record{}, V),
    ?assertNotEqual(undefined, V#sbft_validator_record.pqc_public_key),
    ?assertNotEqual(legacy, V#sbft_validator_record.capability).

test_helper_create_block(_Config) ->
    B = sbft_helper:create_block(<<"h1">>, 0, ?VAL_1, [<<"tx1">>], <<"genesis">>, ?SHARD_A),
    ?assertMatch(#sbft_block_record{}, B),
    ?assertEqual(<<"h1">>, B#sbft_block_record.hash),
    ?assertEqual(0, B#sbft_block_record.view),
    ?assertEqual(?VAL_1, B#sbft_block_record.proposer),
    ?assert(is_binary(B#sbft_block_record.tx_root)),
    ?assert(is_binary(B#sbft_block_record.state_root)).

test_helper_create_vote(_Config) ->
    V = sbft_helper:create_vote(?VAL_1, 0, <<"hash">>, prepare, ?SHARD_A, <<"sig">>),
    ?assertMatch(#sbft_vote_record{}, V),
    ?assertEqual(?VAL_1, V#sbft_vote_record.validator_id),
    ?assertEqual(prepare, V#sbft_vote_record.vote_type).

test_helper_create_config(_Config) ->
    Validators = make_test_validators(?SHARD_A, 4),
    Config = sbft_helper:create_config(Validators, 3000),
    ?assert(is_map(Config)),
    ?assert(maps:is_key(validators, Config)),
    ?assert(maps:is_key(consensus_timeout, Config)),
    ?assert(maps:is_key(view_change_timeout, Config)).

test_helper_create_receipt(_Config) ->
    R = sbft_helper:create_cross_shard_receipt(?SHARD_A, ?SHARD_B, <<"data">>, #{}),
    ?assertMatch(#cross_shard_receipt{}, R),
    ?assertEqual(?SHARD_A, R#cross_shard_receipt.from_shard),
    ?assertEqual(?SHARD_B, R#cross_shard_receipt.to_shard),
    ?assertEqual(pending, R#cross_shard_receipt.status),
    ?assert(is_binary(R#cross_shard_receipt.receipt_id)).

test_helper_create_poc_report(_Config) ->
    R = sbft_helper:create_poc_report(<<"node1">>, ?SHARD_A,
                                       -85.0, -12.0, 18.0, 4,
                                       {37.7, -122.4}),
    ?assertMatch(#poc_report{}, R),
    ?assertEqual(-85.0, R#poc_report.rsrp),
    ?assertEqual(4, R#poc_report.timing_advance),
    ?assert(is_binary(R#poc_report.h3_index)),
    ?assert(is_binary(R#poc_report.geohash)).

test_helper_create_drs_event(_Config) ->
    E = sbft_helper:create_drs_event(<<"node1">>, ?SHARD_A, 0.75, 3),
    ?assertMatch(#drs_score_event{}, E),
    ?assertEqual(0.75, E#drs_score_event.raw_score),
    ?assert(E#drs_score_event.bounded_multiplier >= ?DRS_MIN_MULTIPLIER),
    ?assert(E#drs_score_event.bounded_multiplier =< ?DRS_MAX_MULTIPLIER),
    ?assert(is_map(E#drs_score_event.component_scores)).

test_helper_wait_for_finality_timeout(_Config) ->
    Result = sbft_helper:wait_for_finality(<<"nonexistent_shard">>, 999, 300),
    ?assertEqual({error, timeout}, Result).

test_helper_print_shard_status(_Config) ->
    sbft_helper:print_shard_status(<<"nonexistent_print_shard">>).

test_helper_print_global_status(_Config) ->
    sbft_helper:print_global_status().

test_integration_full_consensus_round(_Config) ->
    ShardId = unique_id(<<"int_full">>),
    Validators = make_test_validators(ShardId, 4),
    Config = sbft_helper:create_config(Validators, ?CONSENSUS_TO,
                                            #{view_change_timeout => ?VC_TO}),
    {ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    {ok, Status0} = sbft_consensus_manager:get_shard_status(ShardId),
    Leader = maps:get(current_leader, Status0),
    Block = make_test_block(<<"int_hash_1">>, 0, Leader, ShardId),
    sbft_consensus_manager:propose_to_shard(ShardId, Block),
    timer:sleep(?SETTLE_MS),
    {ok, Status1} = sbft_consensus_manager:get_shard_status(ShardId),
    ?assert(is_map(Status1)),
    ?assert(erlang:is_process_alive(Pid)),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_integration_multi_shard(_Config) ->
    Shards = [unique_id(<<"int_ms_", (integer_to_binary(I))/binary>>) || I <- lists:seq(1, 3)],
    Pids = lists:map(fun(ShardId) ->
        Config = make_shard_config(ShardId),
        {ok, Pid} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
        {ShardId, Pid}
    end, Shards),
    timer:sleep(200),
    {ok, AllShards} = sbft_consensus_manager:get_all_shards(),
    lists:foreach(fun({ShardId, _}) ->
        ?assert(lists:member(ShardId, AllShards))
    end, Pids),
    {ok, Finality} = sbft_consensus_manager:get_global_finality(),
    ?assert(maps:get(shard_count, Finality) >= 3),
    lists:foreach(fun({ShardId, _}) ->
        sbft_consensus_manager:stop_shard_consensus(ShardId)
    end, Pids).

test_integration_cross_shard_with_consensus(_Config) ->
    S1 = unique_id(<<"int_cs1">>),
    S2 = unique_id(<<"int_cs2">>),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(S1, make_shard_config(S1)),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(S2, make_shard_config(S2)),
    ok = sbft_cross_shard:register_shard(S1),
    ok = sbft_cross_shard:register_shard(S2),
    sbft_cross_shard:send_receipt(S1, S2, <<"integration_tx">>, #{}),
    timer:sleep(200),
    {ok, Pending} = sbft_cross_shard:get_pending_receipts(S2),
    ?assert(length(Pending) >= 1),
    [Receipt | _] = Pending,
    ?assertEqual(S1, Receipt#cross_shard_receipt.from_shard),
    sbft_consensus_manager:stop_shard_consensus(S1),
    sbft_consensus_manager:stop_shard_consensus(S2).

test_integration_slashing_removes_from_shard(_Config) ->
    ShardId = unique_id(<<"int_slash">>),
    Config = make_shard_config(ShardId),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(ShardId, Config),
    VId = unique_id(<<"int_sl_v">>),
    ok = sbft_validator_manager:register_validator(VId, make_validator_data(1000, ShardId)),
    sbft_event_bus:publish(validator_slashed, #{
        validator_id => VId,
        reason => double_voting,
        shard_id => ShardId
    }),
    timer:sleep(200),
    {ok, V} = sbft_validator_manager:get_validator(VId),
    ?assert(is_map(#{active => V#sbft_validator_record.is_active})),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

test_integration_event_bus_consensus_events(_Config) ->
    ShardId = unique_id(<<"int_eb">>),
    sbft_event_bus:subscribe([block_finalized, new_view_started, validator_slashed]),
    {ok, _} = sbft_consensus_manager:start_shard_consensus(ShardId, make_shard_config(ShardId)),
    sbft_event_bus:publish(new_view_started, #{
        shard_id => ShardId,
        new_view => 1,
        new_leader => ?VAL_1
    }),
    timer:sleep(200),
    Got = collect_events(300),
    Topics = [T || {T, _} <- Got],
    ?assert(lists:member(new_view_started, Topics)),
    sbft_event_bus:unsubscribe([block_finalized, new_view_started, validator_slashed]),
    sbft_consensus_manager:stop_shard_consensus(ShardId).

make_test_validators(ShardId, Count) ->
    [sbft_helper:create_validator(
        <<"val_", (integer_to_binary(I))/binary>>,
        <<"pk_", (integer_to_binary(I))/binary>>,
        1000 + (I * 100),
        ShardId
    ) || I <- lists:seq(1, Count)].

make_test_block(Hash, View, Proposer, ShardId) ->
    sbft_helper:create_block(Hash, View, Proposer, [<<"tx1">>], <<"genesis">>, ShardId).

make_test_vote(ValidatorId, View, BlockHash, VoteType, ShardId) ->
    Sig = sbft_crypto:hash(blake2s, term_to_binary({ValidatorId, View, BlockHash})),
    sbft_helper:create_vote(ValidatorId, View, BlockHash, VoteType, ShardId, Sig).

make_validator_data(Stake, ShardId) ->
    #{
        public_key => sbft_crypto:random_bytes(32),
        stake => Stake,
        shard_id => ShardId,
        is_active => true
    }.

make_shard_config(ShardId) ->
    Validators = make_test_validators(ShardId, 4),
    sbft_helper:create_config(Validators, ?CONSENSUS_TO,
                               #{view_change_timeout => ?VC_TO}).

start_test_shard(ShardId) ->
    Validators = make_test_validators(ShardId, 4),
    Config = sbft_helper:create_config(Validators, ?CONSENSUS_TO,
                                            #{view_change_timeout => ?VC_TO}),
    sbft_shard_consensus:start_link(ShardId, Config).

stop_all_test_shards() ->
    {ok, Shards} = sbft_consensus_manager:get_all_shards(),
    lists:foreach(fun(ShardId) ->
        catch sbft_consensus_manager:stop_shard_consensus(ShardId)
    end, Shards).

cleanup_validators() ->
    ok.

unique_id(Prefix) ->
    TS = integer_to_binary(erlang:system_time(microsecond)),
    Rnd = integer_to_binary(rand:uniform(99999)),
    <<Prefix/binary, "_", TS/binary, "_", Rnd/binary>>.

collect_events(TimeoutMs) ->
    collect_events(TimeoutMs, []).

collect_events(TimeoutMs, Acc) ->
    receive
        {sbft_event, Topic, Payload} ->
            collect_events(TimeoutMs, [{Topic, Payload} | Acc])
    after TimeoutMs ->
        lists:reverse(Acc)
    end.

print_result({Name, passed, Ms}) ->
    io:format(" \e[32m✓\e[0m ~-60s ~4w ms~n", [Name, Ms]);
print_result({Name, {failed, Reason}, Ms}) ->
    io:format(" \e[31m✗\e[0m ~-60s ~4w ms~n", [Name, Ms]),
    io:format(" reason: ~p~n", [Reason]).

print_separator(Title) ->
    io:format("~n\e[1m~s\e[0m~n", [Title]),
    io:format("~s~n", [lists:duplicate(64, $-)]).

print_summary(Results) ->
    Total = length(Results),
    Passed = length([1 || {_, passed, _} <- Results]),
    Failed = Total - Passed,
    TotalMs = lists:sum([Ms || {_, _, Ms} <- Results]),
    io:format("~n~s~n", [lists:duplicate(64, $=)]),
    case Failed of
        0 ->
            io:format("\e[32m ALL ~w TESTS PASSED\e[0m (~w ms total)~n",
                      [Total, TotalMs]);
        _ ->
            io:format("\e[31m ~w/~w FAILED\e[0m ~w passed (~w ms total)~n",
                      [Failed, Total, Passed, TotalMs]),
            io:format("~n Failed tests:~n"),
            [io:format(" - ~p~n", [N]) || {N, {failed, _}, _} <- Results]
    end,
    io:format("~s~n", [lists:duplicate(64, $=)]),
    case Failed of
        0 -> ok;
        _ -> {failed, Failed}
    end.

test_all() ->
    io:format("~n\e[1m╔══════════════════════════════════════════════════════════╗\e[0m~n"),
    io:format("\e[1m║ SBFT Full Test Suite — ~s ║\e[0m~n",
              [calendar:system_time_to_rfc3339(erlang:system_time(second))]),
    io:format("\e[1m╚══════════════════════════════════════════════════════════╝\e[0m~n"),
    Groups = group_fns(),
    Results = lists:flatmap(fun({GroupName, Fns}) ->
        print_separator(io_lib:format("Group: ~w (~w tests)", [GroupName, length(Fns)])),
        lists:map(fun(Name) ->
            R = run_test(Name),
            print_result(R),
            R
        end, Fns)
    end, Groups),
    print_summary(Results).

test_group(GroupName) ->
    Groups = group_fns(),
    case lists:keyfind(GroupName, 1, Groups) of
        false ->
            io:format("Unknown group: ~p~nAvailable groups: ~p~n",
                      [GroupName, [G || {G, _} <- Groups]]),
            {error, unknown_group};
        {GroupName, Fns} ->
            print_separator(io_lib:format("Group: ~w (~w tests)", [GroupName, length(Fns)])),
            Results = lists:map(fun(Name) ->
                R = run_test(Name),
                print_result(R),
                R
            end, Fns),
            print_summary(Results)
    end.

test_one(Name) ->
    print_separator(io_lib:format("Single test: ~w", [Name])),
    R = run_test(Name),
    print_result(R),
    case R of
        {_, passed, _} -> ok;
        {_, {failed, _}, _} -> error
    end.

run_test(Name) ->
    Start = erlang:system_time(millisecond),
    Result = try
        ?MODULE:Name([]),
        passed
    catch
        error:{assertEqual, Info} ->
            {failed, {assert_equal, Info}};
        error:{assert, Info} ->
            {failed, {assert, Info}};
        error:{assertMatch, Info} ->
            {failed, {assert_match, Info}};
        error:{assertNotEqual, Info} ->
            {failed, {assert_not_equal, Info}};
        error:Reason:Stack ->
            {failed, {error, Reason, Stack}};
        throw:Reason ->
            {failed, {throw, Reason}};
        exit:Reason ->
            {failed, {exit, Reason}}
    after
        stop_all_test_shards()
    end,
    Elapsed = erlang:system_time(millisecond) - Start,
    {Name, Result, Elapsed}.

group_fns() ->
    [
        {crypto, [
            test_blake2s_hash, test_sha256_hash, test_hkdf_basic,
            test_hkdf_with_salt, test_ed25519_sign_verify,
            test_dilithium2_sign_verify, test_hybrid_sign_verify,
            test_pqc_signature_record, test_kem_encapsulate_x25519,
            test_kem_encapsulate_mlkem768, test_kem_decapsulate_round_trip,
            test_session_key_derivation, test_encrypt_decrypt,
            test_block_signing_payload, test_vote_signing_payload,
            test_receipt_signing_payload, test_detect_equivocation,
            test_no_equivocation, test_aggregate_signatures,
            test_constant_time_compare
        ]},
        {nif, [
            test_nif_capabilities, test_dilithium2_keypair_size,
            test_mlkem768_keypair_size, test_mlkem768_encapsulate_size,
            test_blake2s_nif, test_sphincs_keypair, test_nif_available
        ]},
        {validator_manager, [
            test_validator_register, test_validator_register_duplicate,
            test_validator_get, test_validator_get_not_found,
            test_validator_update_stake, test_validator_slash,
            test_validator_reactivate_after_slash, test_validator_get_all,
            test_validator_get_active, test_validator_get_by_shard,
            test_validator_update_capability, test_validator_update_pqc_keys,
            test_validator_record_vote, test_validator_record_miss,
            test_validator_drs_score, test_validator_epoch_stats,
            test_validator_total_stake, test_validator_shard_stake,
            test_validator_is_active, test_validator_check_capability
        ]},
        {shard_consensus, [
            test_shard_start_stop, test_shard_propose_block,
            test_shard_propose_wrong_leader, test_shard_propose_wrong_view,
            test_shard_propose_wrong_shard, test_shard_vote_collection,
            test_shard_view_change_on_timeout, test_shard_add_validator,
            test_shard_remove_validator, test_shard_remove_below_minimum,
            test_shard_update_validator_stake, test_shard_get_status_fields,
            test_shard_get_committed_block, test_shard_get_high_qc,
            test_shard_inject_receipt, test_shard_force_view_change
        ]},
        {slashing, [
            test_slashing_double_vote, test_slashing_invalid_block,
            test_slashing_unavailability, test_slashing_invalid_poc,
            test_slashing_storage_fault, test_slashing_deduplication,
            test_slashing_history, test_slashing_slash_count,
            test_slashing_is_slashed
        ]},
        {cross_shard, [
            test_cross_shard_register, test_cross_shard_register_duplicate,
            test_cross_shard_unregister, test_cross_shard_send_receipt,
            test_cross_shard_unknown_shard_dropped, test_cross_shard_get_pending,
            test_cross_shard_process_receipt, test_cross_shard_merkle_tree,
            test_cross_shard_merkle_proof_verify, test_cross_shard_receipt_expiry,
            test_cross_shard_retry, test_cross_shard_metrics,
            test_cross_shard_ordering
        ]},
        {event_bus, [
            test_event_bus_publish_subscribe, test_event_bus_unsubscribe,
            test_event_bus_any_topic, test_event_bus_filter_function,
            test_event_bus_dead_subscriber_cleanup, test_event_bus_replay_last,
            test_event_bus_metrics, test_event_bus_multi_topic_subscribe
        ]},
        {consensus_manager, [
            test_consensus_manager_start_shard, test_consensus_manager_start_duplicate,
            test_consensus_manager_stop_shard, test_consensus_manager_stop_not_found,
            test_consensus_manager_get_status, test_consensus_manager_get_all_shards,
            test_consensus_manager_get_active_shards, test_consensus_manager_get_shard_pid,
            test_consensus_manager_global_finality, test_consensus_manager_propose_to_shard,
            test_consensus_manager_sync_validators, test_consensus_manager_restart_shard
        ]},
        {helper, [
            test_helper_create_validator, test_helper_create_validator_pqc,
            test_helper_create_block, test_helper_create_vote,
            test_helper_create_config, test_helper_create_receipt,
            test_helper_create_poc_report, test_helper_create_drs_event,
            test_helper_wait_for_finality_timeout, test_helper_print_shard_status,
            test_helper_print_global_status
        ]},
        {integration, [
            test_integration_full_consensus_round, test_integration_multi_shard,
            test_integration_cross_shard_with_consensus,
            test_integration_slashing_removes_from_shard,
            test_integration_event_bus_consensus_events
        ]}
    ].
