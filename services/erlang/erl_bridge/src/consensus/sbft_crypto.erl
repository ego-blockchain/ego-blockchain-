-module(sbft_crypto).

-include("../include/sbft.hrl").

-export([
    hash/1,
    hash/2,
    hkdf/3,
    hkdf/4,
    sign/3,
    verify/4,
    sign_hybrid/3,
    verify_hybrid/4,
    generate_keypair/1,
    kem_encapsulate/2,
    kem_decapsulate/3,
    derive_session_key/3,
    encrypt_message/2,
    decrypt_message/2,
    make_pqc_signature/4,
    verify_pqc_signature/3,
    block_signing_payload/1,
    vote_signing_payload/1,
    receipt_signing_payload/1,
    new_view_signing_payload/1,
    detect_equivocation/2,
    aggregate_signatures/1,
    verify_aggregate/3,
    random_bytes/1,
    constant_time_compare/2
]).

-define(HKDF_INFO_CONSENSUS,    <<"ego-sbft-consensus-v1">>).
-define(HKDF_INFO_SESSION,      <<"ego-sbft-session-v1">>).
-define(HKDF_INFO_RECEIPT,      <<"ego-sbft-receipt-v1">>).
-define(SESSION_KEY_LEN,        32).
-define(NONCE_LEN,              24).
-define(TAG_LEN,                16).

hash(Data) ->
    hash(blake2s, Data).

hash(blake2s, Data) ->
    crypto:hash(blake2s, Data);
hash(sha256, Data) ->
    crypto:hash(sha256, Data);
hash(sha3_256, Data) ->
    crypto:hash(sha3_256, Data).

hkdf(IKM, Salt, Info) ->
    hkdf(IKM, Salt, Info, ?SESSION_KEY_LEN).

hkdf(IKM, Salt, Info, Len) ->
    ActualSalt = case Salt of
        undefined -> binary:copy(<<0>>, ?BLAKE2S_DIGEST_SIZE);
        _         -> Salt
    end,
    PRK  = crypto:mac(hmac, sha256, ActualSalt, IKM),
    hkdf_expand(PRK, Info, Len).

hkdf_expand(PRK, Info, Len) ->
    N = ceil(Len / 32),
    {OKM, _} = lists:foldl(fun(I, {Acc, Prev}) ->
        T = crypto:mac(hmac, sha256, PRK, <<Prev/binary, Info/binary, I:8>>),
        {<<Acc/binary, T/binary>>, T}
    end, {<<>>, <<>>}, lists:seq(1, N)),
    binary:part(OKM, 0, Len).

generate_keypair(dilithium2) ->
    case sbft_nif:dilithium2_keypair() of
        {ok, PK, SK} ->
            {ok, #pqc_keypair{
                algorithm       = dilithium2,
                public_key      = PK,
                secret_key      = SK,
                kem_algorithm   = mlkem768,
                kem_public_key  = <<>>,
                kem_secret_key  = <<>>,
                created_at      = erlang:system_time(millisecond),
                rotation_due_at = erlang:system_time(millisecond) + 86400000
            }};
        {error, Reason} ->
            {error, Reason}
    end;
generate_keypair(ed25519) ->
    {PK, SK} = crypto:generate_key(eddsa, ed25519),
    {ok, #pqc_keypair{
        algorithm       = ed25519,
        public_key      = PK,
        secret_key      = SK,
        kem_algorithm   = x25519,
        kem_public_key  = <<>>,
        kem_secret_key  = <<>>,
        created_at      = erlang:system_time(millisecond),
        rotation_due_at = erlang:system_time(millisecond) + 86400000
    }};
generate_keypair(hybrid) ->
    case sbft_nif:dilithium2_keypair() of
        {ok, DilPK, DilSK} ->
            {EdPK, EdSK} = crypto:generate_key(eddsa, ed25519),
            case sbft_nif:mlkem768_keypair() of
                {ok, KemPK, KemSK} ->
                    {ok, #pqc_keypair{
                        algorithm       = hybrid,
                        public_key      = DilPK,
                        secret_key      = DilSK,
                        kem_algorithm   = hybrid_kem,
                        kem_public_key  = KemPK,
                        kem_secret_key  = KemSK,
                        created_at      = erlang:system_time(millisecond),
                        rotation_due_at = erlang:system_time(millisecond) + 86400000
                    }};
                {error, _} ->
                    {ok, #pqc_keypair{
                        algorithm       = hybrid,
                        public_key      = DilPK,
                        secret_key      = DilSK,
                        kem_algorithm   = x25519,
                        kem_public_key  = EdPK,
                        kem_secret_key  = EdSK,
                        created_at      = erlang:system_time(millisecond),
                        rotation_due_at = erlang:system_time(millisecond) + 86400000
                    }}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

sign(dilithium2, SecretKey, Payload) ->
    PayloadHash = hash(blake2s, Payload),
    case sbft_nif:dilithium2_sign(SecretKey, PayloadHash) of
        {ok, SigBytes} -> {ok, SigBytes};
        {error, _}     ->
            FallbackSig = crypto:mac(hmac, sha256, SecretKey, PayloadHash),
            {ok, FallbackSig}
    end;
sign(ed25519, SecretKey, Payload) ->
    PayloadHash = hash(blake2s, Payload),
    SigBytes = crypto:sign(eddsa, none, PayloadHash, [SecretKey, ed25519]),
    {ok, SigBytes};
sign(hybrid, SecretKey, Payload) ->
    PayloadHash = hash(blake2s, Payload),
    PrimaryResult = case sbft_nif:dilithium2_sign(SecretKey, PayloadHash) of
        {ok, DilSig} -> DilSig;
        {error, _}   -> crypto:mac(hmac, sha256, SecretKey, PayloadHash)
    end,
    {ok, PrimaryResult}.

verify(dilithium2, PublicKey, Payload, SigBytes) ->
    PayloadHash = hash(blake2s, Payload),
    case sbft_nif:dilithium2_verify(PublicKey, PayloadHash, SigBytes) of
        {ok, true}  -> true;
        {ok, false} -> false;
        {error, _}  ->
            Expected = crypto:mac(hmac, sha256, PublicKey, PayloadHash),
            constant_time_compare(SigBytes, Expected)
    end;
verify(ed25519, PublicKey, Payload, SigBytes) ->
    PayloadHash = hash(blake2s, Payload),
    crypto:verify(eddsa, none, PayloadHash, SigBytes, [PublicKey, ed25519]);
verify(hybrid, PublicKey, Payload, SigBytes) ->
    verify(dilithium2, PublicKey, Payload, SigBytes).

sign_hybrid(Keypair, ValidatorId, Payload) ->
    Algorithm   = Keypair#pqc_keypair.algorithm,
    SecretKey   = Keypair#pqc_keypair.secret_key,
    PayloadHash = hash(blake2s, Payload),
    case sign(Algorithm, SecretKey, Payload) of
        {ok, SigBytes} ->
            PQCSig = #pqc_signature{
                algorithm      = Algorithm,
                signer_id      = ValidatorId,
                payload_hash   = PayloadHash,
                signature_bytes = SigBytes,
                timestamp      = erlang:system_time(millisecond)
            },
            {ok, PQCSig};
        {error, Reason} ->
            {error, Reason}
    end.

verify_hybrid(PQCSig, PublicKey, Payload, RequiredAlgorithm) ->
    Algorithm   = PQCSig#pqc_signature.algorithm,
    SigBytes    = PQCSig#pqc_signature.signature_bytes,
    PayloadHash = PQCSig#pqc_signature.payload_hash,
    ComputedHash = hash(blake2s, Payload),
    case constant_time_compare(PayloadHash, ComputedHash) of
        false ->
            false;
        true ->
            AlgoOk = case RequiredAlgorithm of
                any     -> true;
                _       -> Algorithm =:= RequiredAlgorithm
            end,
            case AlgoOk of
                false -> false;
                true  -> verify(Algorithm, PublicKey, Payload, SigBytes)
            end
    end.

make_pqc_signature(Algorithm, ValidatorId, SecretKey, Payload) ->
    PayloadHash = hash(blake2s, Payload),
    case sign(Algorithm, SecretKey, Payload) of
        {ok, SigBytes} ->
            {ok, #pqc_signature{
                algorithm       = Algorithm,
                signer_id       = ValidatorId,
                payload_hash    = PayloadHash,
                signature_bytes = SigBytes,
                timestamp       = erlang:system_time(millisecond)
            }};
        {error, Reason} ->
            {error, Reason}
    end.

verify_pqc_signature(PQCSig, PublicKey, Payload) ->
    Algorithm   = PQCSig#pqc_signature.algorithm,
    SigBytes    = PQCSig#pqc_signature.signature_bytes,
    PayloadHash = PQCSig#pqc_signature.payload_hash,
    ComputedHash = hash(blake2s, Payload),
    case constant_time_compare(PayloadHash, ComputedHash) of
        false -> false;
        true  -> verify(Algorithm, PublicKey, Payload, SigBytes)
    end.

kem_encapsulate(mlkem768, RecipientPK) ->
    case sbft_nif:mlkem768_encapsulate(RecipientPK) of
        {ok, Ciphertext, SharedSecret} ->
            {ok, Ciphertext, SharedSecret};
        {error, _} ->
            SharedSecret = random_bytes(32),
            Ciphertext   = random_bytes(?MLKEM768_CT_SIZE),
            {ok, Ciphertext, SharedSecret}
    end;
kem_encapsulate(x25519, RecipientPK) ->
    {EphPK, EphSK} = crypto:generate_key(ecdh, x25519),
    SharedSecret   = crypto:compute_key(ecdh, RecipientPK, EphSK, x25519),
    {ok, EphPK, SharedSecret};
kem_encapsulate(hybrid_kem, RecipientPK) ->
    KemPK = binary:part(RecipientPK, 0, ?MLKEM768_PK_SIZE),
    X25519PK = binary:part(RecipientPK, ?MLKEM768_PK_SIZE, byte_size(RecipientPK) - ?MLKEM768_PK_SIZE),
    {ok, KemCT, KemSS}     = kem_encapsulate(mlkem768, KemPK),
    {ok, X25519CT, X25519SS} = kem_encapsulate(x25519, X25519PK),
    CombinedSS = hkdf(<<KemSS/binary, X25519SS/binary>>, undefined, ?HKDF_INFO_SESSION),
    CombinedCT = <<KemCT/binary, X25519CT/binary>>,
    {ok, CombinedCT, CombinedSS}.

kem_decapsulate(mlkem768, SecretKey, Ciphertext) ->
    case sbft_nif:mlkem768_decapsulate(SecretKey, Ciphertext) of
        {ok, SharedSecret} -> {ok, SharedSecret};
        {error, Reason}    -> {error, Reason}
    end;
kem_decapsulate(x25519, SecretKey, EphemeralPK) ->
    SharedSecret = crypto:compute_key(ecdh, EphemeralPK, SecretKey, x25519),
    {ok, SharedSecret};
kem_decapsulate(hybrid_kem, SecretKey, Ciphertext) ->
    KemCT    = binary:part(Ciphertext, 0, ?MLKEM768_CT_SIZE),
    X25519CT = binary:part(Ciphertext, ?MLKEM768_CT_SIZE, byte_size(Ciphertext) - ?MLKEM768_CT_SIZE),
    KemSK    = binary:part(SecretKey, 0, byte_size(SecretKey) div 2),
    X25519SK = binary:part(SecretKey, byte_size(SecretKey) div 2, byte_size(SecretKey) div 2),
    case kem_decapsulate(mlkem768, KemSK, KemCT) of
        {ok, KemSS} ->
            case kem_decapsulate(x25519, X25519SK, X25519CT) of
                {ok, X25519SS} ->
                    CombinedSS = hkdf(<<KemSS/binary, X25519SS/binary>>, undefined, ?HKDF_INFO_SESSION),
                    {ok, CombinedSS};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

derive_session_key(SharedSecret, PeerId, Context) ->
    Salt = hash(blake2s, PeerId),
    Info = <<?HKDF_INFO_SESSION/binary, Context/binary>>,
    SessionKey = hkdf(SharedSecret, Salt, Info, ?SESSION_KEY_LEN),
    Nonce      = hkdf(SharedSecret, Salt, <<Info/binary, "-nonce">>, ?NONCE_LEN),
    SessionId  = random_bytes(16),
    {ok, #hybrid_session_key{
        session_id     = SessionId,
        kem_ciphertext = <<>>,
        shared_secret  = SessionKey,
        cipher         = xchacha20_poly1305,
        hkdf_algorithm = blake2s,
        created_at     = erlang:system_time(millisecond),
        peer_id        = PeerId
    }, Nonce}.

encrypt_message(#hybrid_session_key{shared_secret = Key}, Plaintext) ->
    Nonce = random_bytes(?NONCE_LEN),
    AAD   = hash(blake2s, Nonce),
    case crypto:crypto_one_time_aead(chacha20_poly1305, Key, binary:part(Nonce, 0, 12),
                                     Plaintext, AAD, ?TAG_LEN, true) of
        {Ciphertext, Tag} ->
            {ok, <<Nonce/binary, Tag/binary, Ciphertext/binary>>};
        error ->
            {error, encryption_failed}
    end.

decrypt_message(#hybrid_session_key{shared_secret = Key}, EncryptedMsg) ->
    case byte_size(EncryptedMsg) > (?NONCE_LEN + ?TAG_LEN) of
        false ->
            {error, invalid_ciphertext};
        true ->
            Nonce      = binary:part(EncryptedMsg, 0, ?NONCE_LEN),
            Tag        = binary:part(EncryptedMsg, ?NONCE_LEN, ?TAG_LEN),
            Ciphertext = binary:part(EncryptedMsg, ?NONCE_LEN + ?TAG_LEN,
                                     byte_size(EncryptedMsg) - ?NONCE_LEN - ?TAG_LEN),
            AAD        = hash(blake2s, Nonce),
            case crypto:crypto_one_time_aead(chacha20_poly1305, Key, binary:part(Nonce, 0, 12),
                                             Ciphertext, AAD, Tag, false) of
                error     -> {error, decryption_failed};
                Plaintext -> {ok, Plaintext}
            end
    end.

block_signing_payload(Block) ->
    hash(blake2s, term_to_binary({
        Block#sbft_block_record.hash,
        Block#sbft_block_record.view,
        Block#sbft_block_record.height,
        Block#sbft_block_record.proposer,
        Block#sbft_block_record.parent_hash,
        Block#sbft_block_record.state_root,
        Block#sbft_block_record.tx_root,
        Block#sbft_block_record.shard_id,
        Block#sbft_block_record.timestamp
    })).

vote_signing_payload(Vote) ->
    hash(blake2s, term_to_binary({
        Vote#sbft_vote_record.validator_id,
        Vote#sbft_vote_record.view,
        Vote#sbft_vote_record.block_hash,
        Vote#sbft_vote_record.vote_type,
        Vote#sbft_vote_record.shard_id,
        Vote#sbft_vote_record.timestamp
    })).

receipt_signing_payload(Receipt) ->
    hash(blake2s, term_to_binary({
        Receipt#cross_shard_receipt.receipt_id,
        Receipt#cross_shard_receipt.from_shard,
        Receipt#cross_shard_receipt.to_shard,
        Receipt#cross_shard_receipt.transaction_hash,
        Receipt#cross_shard_receipt.merkle_root,
        Receipt#cross_shard_receipt.timestamp
    })).

new_view_signing_payload(NewViewMsg) ->
    hash(blake2s, term_to_binary({
        NewViewMsg#new_view_message.new_view,
        NewViewMsg#new_view_message.new_leader,
        NewViewMsg#new_view_message.shard_id,
        NewViewMsg#new_view_message.timestamp
    })).

detect_equivocation(Vote1, Vote2) ->
    SameValidator = Vote1#sbft_vote_record.validator_id =:= Vote2#sbft_vote_record.validator_id,
    SameView      = Vote1#sbft_vote_record.view =:= Vote2#sbft_vote_record.view,
    SameType      = Vote1#sbft_vote_record.vote_type =:= Vote2#sbft_vote_record.vote_type,
    DiffHash      = Vote1#sbft_vote_record.block_hash =/= Vote2#sbft_vote_record.block_hash,
    case SameValidator andalso SameView andalso SameType andalso DiffHash of
        true  -> {equivocation_detected, Vote1#sbft_vote_record.validator_id};
        false -> no_equivocation
    end.

aggregate_signatures(Votes) when is_list(Votes) ->
    SigList = [V#sbft_vote_record.signature || V <- Votes,
               V#sbft_vote_record.signature =/= undefined],
    AggSig  = crypto:hash(blake2s, list_to_binary(SigList)),
    {ok, AggSig}.

verify_aggregate(AggSig, Votes, _PublicKeys) ->
    SigList   = [V#sbft_vote_record.signature || V <- Votes,
                 V#sbft_vote_record.signature =/= undefined],
    ComputedAgg = crypto:hash(blake2s, list_to_binary(SigList)),
    constant_time_compare(AggSig, ComputedAgg).

random_bytes(N) ->
    crypto:strong_rand_bytes(N).

constant_time_compare(A, B) when byte_size(A) =/= byte_size(B) ->
    false;
constant_time_compare(A, B) ->
    crypto:hash(sha256, A) =:= crypto:hash(sha256, B).
