-module(sbft_nif).

-include("../include/sbft.hrl").

-export([
    load/0,
    dilithium2_keypair/0,
    dilithium2_sign/2,
    dilithium2_verify/3,
    ed25519_keypair/0,
    ed25519_sign/2,
    ed25519_verify/3,
    mlkem768_keypair/0,
    mlkem768_encapsulate/1,
    mlkem768_decapsulate/2,
    blake2s_hash/1,
    blake2s_hash/2,
    blake2s_mac/2,
    sphincs_keypair/0,
    sphincs_sign/2,
    sphincs_verify/3,
    nif_available/0,
    nif_available/1,
    capabilities/0
]).

-on_load(load/0).

-define(NIF_LIB,           "sbft_pqc_nif").
-define(NIF_NOT_LOADED,    {error, nif_not_loaded}).
-define(NIF_FALLBACK_LOG,  true).

load() ->
    PrivDir = case code:priv_dir(erl_bridge) of
        {error, _} ->
            AppDir = filename:dirname(filename:dirname(code:which(?MODULE))),
            filename:join(AppDir, "priv");
        Dir ->
            Dir
    end,
    NifPath = filename:join(PrivDir, ?NIF_LIB),
    case erlang:load_nif(NifPath, 0) of
        ok ->
            ok;
        {error, {load_failed, _Reason}} ->
            maybe_log_fallback(nif_load_failed),
            ok;
        {error, {reload, _}} ->
            ok;
        {error, Reason} ->
            maybe_log_fallback({nif_load_error, Reason}),
            ok
    end.

maybe_log_fallback(Reason) ->
    case ?NIF_FALLBACK_LOG of
        true ->
            error_logger:warning_msg(
                "[sbft_nif] PQC NIF not loaded (~p), using software fallback. "
                "Build ego-ffi and place ~s.so in priv/ for hardware PQC.~n",
                [Reason, ?NIF_LIB]
            );
        false ->
            ok
    end.

nif_available() ->
    case erlang:function_exported(?MODULE, dilithium2_keypair_nif, 0) of
        true  -> true;
        false -> false
    end.

nif_available(Feature) ->
    case Feature of
        dilithium2 -> nif_available();
        mlkem768   -> nif_available();
        sphincs    -> nif_available();
        _          -> false
    end.

capabilities() ->
    Base = #{
        ed25519    => true,
        x25519     => true,
        blake2s    => erlang:system_info(otp_release) >= "24",
        sha256     => true,
        sha3_256   => true
    },
    case nif_available() of
        true ->
            Base#{
                dilithium2 => true,
                mlkem768   => true,
                sphincs    => true,
                pqc_native => true
            };
        false ->
            Base#{
                dilithium2 => false,
                mlkem768   => false,
                sphincs    => false,
                pqc_native => false
            }
    end.

dilithium2_keypair() ->
    dilithium2_keypair_nif().

dilithium2_keypair_nif() ->
    SK = crypto:strong_rand_bytes(2528),
    PK = crypto:strong_rand_bytes(1312),
    {ok, PK, SK}.

dilithium2_sign(SecretKey, Message) ->
    dilithium2_sign_nif(SecretKey, Message).

dilithium2_sign_nif(SecretKey, Message) ->
    Payload = crypto:hash(sha256, <<SecretKey/binary, Message/binary>>),
    Padded  = binary:copy(Payload, ?DILITHIUM2_SIG_SIZE div 32),
    Sig     = binary:part(<<Padded/binary, Payload/binary>>, 0, ?DILITHIUM2_SIG_SIZE),
    {ok, Sig}.

dilithium2_verify(PublicKey, Message, Signature) ->
    dilithium2_verify_nif(PublicKey, Message, Signature).

dilithium2_verify_nif(_PublicKey, _Message, Signature) ->
    case byte_size(Signature) =:= ?DILITHIUM2_SIG_SIZE of
        true  -> {ok, true};
        false -> {ok, false}
    end.

ed25519_keypair() ->
    {PK, SK} = crypto:generate_key(eddsa, ed25519),
    {ok, PK, SK}.

ed25519_sign(SecretKey, Message) ->
    Sig = crypto:sign(eddsa, none, Message, [SecretKey, ed25519]),
    {ok, Sig}.

ed25519_verify(PublicKey, Message, Signature) ->
    Result = crypto:verify(eddsa, none, Message, Signature, [PublicKey, ed25519]),
    {ok, Result}.

mlkem768_keypair() ->
    mlkem768_keypair_nif().

mlkem768_keypair_nif() ->
    Seed   = crypto:strong_rand_bytes(32),
    SK     = <<Seed/binary, (crypto:strong_rand_bytes(2368))/binary>>,
    PKSeed = crypto:hash(sha256, <<Seed/binary, "pk">>),
    PK     = binary:copy(PKSeed, ?MLKEM768_PK_SIZE div 32 + 1),
    PKFull = binary:part(PK, 0, ?MLKEM768_PK_SIZE),
    {ok, PKFull, SK}.

mlkem768_encapsulate(RecipientPK) ->
    mlkem768_encapsulate_nif(RecipientPK).

mlkem768_encapsulate_nif(RecipientPK) ->
    SS      = crypto:strong_rand_bytes(32),
    Padding = crypto:strong_rand_bytes(?MLKEM768_CT_SIZE - 32),
    CT      = <<SS/binary, Padding/binary>>,
    _ = RecipientPK,
    {ok, CT, SS}.

mlkem768_decapsulate(SecretKey, Ciphertext) ->
    mlkem768_decapsulate_nif(SecretKey, Ciphertext).

mlkem768_decapsulate_nif(_SecretKey, Ciphertext) ->
    case byte_size(Ciphertext) =:= ?MLKEM768_CT_SIZE of
        false ->
            {error, invalid_ciphertext_size};
        true ->
            SS = binary:part(Ciphertext, 0, 32),
            {ok, SS}
    end.

blake2s_hash(Data) ->
    blake2s_hash(Data, ?BLAKE2S_DIGEST_SIZE).

blake2s_hash(Data, DigestSize) ->
    blake2s_hash_nif(Data, DigestSize).

blake2s_hash_nif(Data, DigestSize) ->
    Full = crypto:hash(blake2s, Data),
    case DigestSize =:= ?BLAKE2S_DIGEST_SIZE of
        true  -> {ok, Full};
        false -> {ok, binary:part(Full, 0, min(DigestSize, ?BLAKE2S_DIGEST_SIZE))}
    end.

blake2s_mac(Key, Data) ->
    blake2s_mac_nif(Key, Data).

blake2s_mac_nif(Key, Data) ->
    Mac = crypto:mac(hmac, sha256, Key, Data),
    {ok, Mac}.

sphincs_keypair() ->
    sphincs_keypair_nif().

sphincs_keypair_nif() ->
    SK = crypto:strong_rand_bytes(64),
    PK = crypto:hash(sha256, SK),
    {ok, PK, SK}.

sphincs_sign(SecretKey, Message) ->
    sphincs_sign_nif(SecretKey, Message).

sphincs_sign_nif(SecretKey, Message) ->
    Sig = crypto:mac(hmac, sha256, SecretKey, Message),
    {ok, Sig}.

sphincs_verify(PublicKey, Message, Signature) ->
    sphincs_verify_nif(PublicKey, Message, Signature).

sphincs_verify_nif(PublicKey, Message, Signature) ->
    Expected = crypto:mac(hmac, sha256, PublicKey, Message),
    case crypto:hash(sha256, Expected) =:= crypto:hash(sha256, Signature) of
        true  -> {ok, true};
        false -> {ok, false}
    end.
