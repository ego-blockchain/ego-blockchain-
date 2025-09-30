use ego_core::*;
use std::collections::HashMap;

#[cfg(test)]
mod pq_crypto_tests {
    use super::*;

    #[test]
    fn test_algorithm_ids() {
        assert_eq!(AlgorithmId::Ed25519.as_u16(), 0xED01);
        assert_eq!(AlgorithmId::MlDsa2.as_u16(), 0x0202);
        assert_eq!(AlgorithmId::SlhDsa.as_u16(), 0x0303);
        assert_eq!(AlgorithmId::X25519.as_u16(), 0x0101);
        assert_eq!(AlgorithmId::MlKem768.as_u16(), 0x0302);
        assert_eq!(AlgorithmId::XChaCha20Poly1305.as_u16(), 0x0401);
        assert_eq!(AlgorithmId::Blake2s256.as_u16(), 0x0501);
        assert_eq!(AlgorithmId::HkdfBlake2s.as_u16(), 0x0502);
    }

    #[test]
    fn test_algorithm_id_conversion() {
        assert_eq!(AlgorithmId::from_u16(0xED01), Some(AlgorithmId::Ed25519));
        assert_eq!(AlgorithmId::from_u16(0x0202), Some(AlgorithmId::MlDsa2));
        assert_eq!(AlgorithmId::from_u16(0x0302), Some(AlgorithmId::MlKem768));
        assert_eq!(AlgorithmId::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = crypto::KeyPair::generate();

        assert_eq!(
            keypair.dilithium_public_key().algorithm,
            AlgorithmId::MlDsa2
        );
        assert_eq!(keypair.kyber_public_key().algorithm, AlgorithmId::MlKem768);
        assert_eq!(keypair.public_key().algorithm, AlgorithmId::Ed25519);
        assert_eq!(keypair.x25519_public_key().len(), 32);
    }

    #[test]
    fn test_keypair_with_slh_dsa() {
        let keypair = crypto::KeyPair::generate_with_slh_dsa();

        assert!(keypair.slh_dsa_public_key().is_some());
        let slh_pk = keypair.slh_dsa_public_key().unwrap();
        assert_eq!(slh_pk.algorithm, AlgorithmId::SlhDsa);
    }

    #[test]
    fn test_dilithium_signature() {
        let keypair = crypto::KeyPair::generate();
        let message = b"test message for dilithium";

        let signature = keypair.sign_dilithium(message);
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa2);
        assert_eq!(signature.signature_data.len(), 2420);

        let public_key = keypair.dilithium_public_key();
        let is_valid = crypto::verify_signature(&public_key, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_ed25519_signature() {
        let keypair = crypto::KeyPair::generate();
        let message = b"test message for ed25519";

        let signature = keypair.sign_ed25519(message);
        assert_eq!(signature.algorithm, AlgorithmId::Ed25519);
        assert_eq!(signature.signature_data.len(), 64);

        let public_key = keypair.public_key();
        let is_valid = crypto::verify_signature(&public_key, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_dual_signature() {
        let keypair = crypto::KeyPair::generate();
        let message = b"test message for dual signature";

        let dual_sig = keypair.dual_sign(message);
        assert!(dual_sig.ed25519_sig.is_some());
        assert!(dual_sig.dilithium_sig.is_some());
        assert_eq!(dual_sig.protocol_version, PROTOCOL_VERSION);

        let ed25519_pk = keypair.public_key();
        let dilithium_pk = keypair.dilithium_public_key();
        let is_valid =
            crypto::verify_dual_signature(&ed25519_pk, &dilithium_pk, message, &dual_sig).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_hybrid_signature_transition_mode() {
        let keypair = crypto::KeyPair::generate();
        let message = b"test message for hybrid signature";

        let hybrid_sig = keypair.sign_hybrid(message, true);
        assert!(hybrid_sig.ed25519_sig.is_some());
        assert!(hybrid_sig.dilithium_sig.is_some());

        let pq_only_sig = keypair.sign_hybrid(message, false);
        assert!(pq_only_sig.ed25519_sig.is_none());
        assert!(pq_only_sig.dilithium_sig.is_some());
    }

    #[test]
    fn test_slh_dsa_signature() {
        let keypair = crypto::KeyPair::generate_with_slh_dsa();
        let message = b"test message for SLH-DSA";

        let signature = keypair.sign_slh_dsa(message).unwrap();
        assert_eq!(signature.algorithm, AlgorithmId::SlhDsa);
        assert!(signature.signature_data.len() >= 8192);
        assert!(signature.signature_data.len() <= 17408);

        if let Some(public_key) = keypair.slh_dsa_public_key() {
            let is_valid = crypto::verify_signature(&public_key, message, &signature).unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_kyber_encapsulation_decapsulation() {
        let keypair1 = crypto::KeyPair::generate();
        let keypair2 = crypto::KeyPair::generate();

        let kyber_pk = keypair2.kyber_public_key();
        let (shared_secret1, ciphertext) = keypair1.encapsulate_kyber(&kyber_pk.key_data).unwrap();

        assert_eq!(shared_secret1.len(), 32);
        assert_eq!(ciphertext.len(), 1088);

        let shared_secret2 = keypair2.decapsulate_kyber(&ciphertext).unwrap();
        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_hybrid_session_creation() {
        let keypair1 = crypto::KeyPair::generate();
        let keypair2 = crypto::KeyPair::generate();

        let x25519_pk = keypair2.x25519_public_key();
        let kyber_pk = keypair2.kyber_public_key();

        let stream_kind = "test_stream";
        let stream_nonce = [42u8; 32];
        let chain_id = b"test_chain_id";

        let (session_record, session_key) = keypair1
            .create_hybrid_session(
                &x25519_pk,
                &kyber_pk.key_data,
                stream_kind,
                &stream_nonce,
                chain_id,
            )
            .unwrap();

        assert_eq!(session_record.alg_kem_id, AlgorithmId::MlKem768.as_u16());
        assert_eq!(
            session_record.alg_dh_legacy_id,
            Some(AlgorithmId::X25519.as_u16())
        );
        assert_eq!(session_record.protocol_version, PROTOCOL_VERSION);
        assert!(session_record.x25519_pubkey.is_some());
        assert_eq!(session_record.kyber_ciphertext.len(), 1088);
        assert_eq!(session_key.len(), 32);
    }

    #[test]
    fn test_kyber_only_session() {
        let keypair1 = crypto::KeyPair::generate();
        let keypair2 = crypto::KeyPair::generate();

        let kyber_pk = keypair2.kyber_public_key();
        let stream_kind = "pq_only_stream";
        let stream_nonce = [99u8; 32];
        let chain_id = b"pq_chain_id";

        let (session_record, session_key) = keypair1
            .create_kyber_only_session(&kyber_pk.key_data, stream_kind, &stream_nonce, chain_id)
            .unwrap();

        assert_eq!(session_record.alg_kem_id, AlgorithmId::MlKem768.as_u16());
        assert_eq!(session_record.alg_dh_legacy_id, None);
        assert!(session_record.x25519_pubkey.is_none());
        assert_eq!(session_key.len(), 32);
    }

    #[test]
    fn test_identity_binding() {
        let keypair = crypto::KeyPair::generate();
        let peer_id = "test_peer_12345";
        let caps = b"test_capabilities";
        let chain_id = b"test_chain";

        let binding_with_ed25519 = keypair
            .create_identity_binding(peer_id, caps, chain_id, true)
            .unwrap();
        let binding_dilithium_only = keypair
            .create_identity_binding(peer_id, caps, chain_id, false)
            .unwrap();

        assert!(binding_with_ed25519.len() > binding_dilithium_only.len());

        let dilithium_pk = keypair.dilithium_public_key();
        let ed25519_pk = keypair.public_key();

        let nonce_hybrid = &binding_with_ed25519[binding_with_ed25519.len() - 32..];
        let is_valid_hybrid = crypto::verify_identity_binding(
            peer_id,
            &keypair.kyber_public_key().key_data,
            caps,
            chain_id,
            nonce_hybrid,
            &binding_with_ed25519,
            &dilithium_pk.key_data,
            Some(&ed25519_pk.key_data),
        )
        .unwrap();
        assert!(is_valid_hybrid);

        let nonce_dilithium = &binding_dilithium_only[binding_dilithium_only.len() - 32..];
        let is_valid_dilithium = crypto::verify_identity_binding(
            peer_id,
            &keypair.kyber_public_key().key_data,
            caps,
            chain_id,
            nonce_dilithium,
            &binding_dilithium_only,
            &dilithium_pk.key_data,
            None,
        )
        .unwrap();
        assert!(is_valid_dilithium);
    }

    #[test]
    fn test_stream_cipher() {
        let key = [42u8; 32];
        let stream_id = b"test_stream_123".to_vec();
        let chain_id = b"test_chain_456".to_vec();
        let alg_ids = (
            AlgorithmId::MlKem768.as_u16(),
            AlgorithmId::XChaCha20Poly1305.as_u16(),
        );

        let mut cipher1 =
            crypto::StreamCipher::new(&key, stream_id.clone(), chain_id.clone(), alg_ids).unwrap();
        let mut cipher2 = crypto::StreamCipher::new(&key, stream_id, chain_id, alg_ids).unwrap();

        let plaintext = b"Hello, post-quantum world!";
        let encrypted_frame = cipher1.encrypt_frame(plaintext, 1).unwrap();

        assert!(encrypted_frame.len() > plaintext.len());

        let decrypted = cipher2.decrypt_frame(&encrypted_frame, 1).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_batch_verifier() {
        let mut verifier = crypto::BatchVerifier::new(10000, 100);

        let keypair1 = crypto::KeyPair::generate();
        let keypair2 = crypto::KeyPair::generate();

        let message1 = b"message 1";
        let message2 = b"message 2";

        let sig1 = keypair1.sign_dilithium(message1);
        let sig2 = keypair2.sign_dilithium(message2);

        verifier
            .add_signature(keypair1.dilithium_public_key(), message1.to_vec(), sig1)
            .unwrap();
        verifier
            .add_signature(keypair2.dilithium_public_key(), message2.to_vec(), sig2)
            .unwrap();

        let results = verifier.verify_batch().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0]);
        assert!(results[1]);
    }

    #[test]
    fn test_handshake_init_creation() {
        let keypair1 = crypto::KeyPair::generate();
        let keypair2 = crypto::KeyPair::generate();

        let peer_kyber_pk = keypair2.kyber_public_key();
        let stream_kind = "consensus";
        let caps = b"node_capabilities";
        let chain_id = b"mainnet";

        let hybrid_handshake = crypto::create_handshake_init(
            &keypair1,
            &peer_kyber_pk.key_data,
            stream_kind,
            caps,
            chain_id,
            true,
        )
        .unwrap();

        assert_eq!(hybrid_handshake.version, PROTOCOL_VERSION);
        assert_eq!(hybrid_handshake.alg_kem, AlgorithmId::MlKem768.as_u16());
        assert_eq!(
            hybrid_handshake.alg_dh_legacy,
            Some(AlgorithmId::X25519.as_u16())
        );
        assert!(hybrid_handshake.x25519_c_pk.is_some());
        assert_eq!(hybrid_handshake.ct_pq_c2s.len(), 1088);

        let pq_only_handshake = crypto::create_handshake_init(
            &keypair1,
            &peer_kyber_pk.key_data,
            stream_kind,
            caps,
            chain_id,
            false,
        )
        .unwrap();

        assert_eq!(pq_only_handshake.alg_dh_legacy, None);
        assert!(pq_only_handshake.x25519_c_pk.is_none());
    }

    #[test]
    fn test_peer_capabilities() {
        let keypair = crypto::KeyPair::generate();
        let address = Address::new([1u8; 20]);

        let caps = keypair.get_peer_capabilities(address);

        assert!(caps
            .alg_sig_supported
            .contains(&AlgorithmId::MlDsa2.as_u16()));
        assert!(caps
            .alg_sig_supported
            .contains(&AlgorithmId::Ed25519.as_u16()));
        assert!(caps
            .alg_kem_supported
            .contains(&AlgorithmId::MlKem768.as_u16()));
        assert_eq!(caps.mlkem_pk.len(), 1184);
        assert!(caps.x25519_pk.is_some());
        assert_eq!(caps.account_addr, address);
        assert!(caps.cellular_safe);
    }

    #[test]
    fn test_stealth_address_derivation() {
        let receiver_keypair = crypto::KeyPair::generate();
        let sender_ephemeral = [123u8; 32];

        let receiver_kyber_pk = receiver_keypair.kyber_public_key();
        let (stealth_pubkey, spend_key) =
            crypto::derive_stealth_address(&receiver_kyber_pk.key_data, &sender_ephemeral).unwrap();

        assert_ne!(
            stealth_pubkey.key_data,
            receiver_keypair.public_key().key_data
        );
        assert_eq!(spend_key.len(), 32);
    }

    #[test]
    fn test_downgrade_protection() {
        let handshake_data = vec![
            b"handshake_init".to_vec(),
            b"handshake_response".to_vec(),
            b"capabilities".to_vec(),
        ];

        let transcript = crypto::create_authenticated_transcript(&handshake_data);
        assert_eq!(transcript.len(), 32);

        let result1 = crypto::verify_downgrade_protection(&transcript, true, true);
        assert!(result1.is_ok());

        let result2 = crypto::verify_downgrade_protection(&transcript, true, false);
        assert!(result2.is_err());
    }

    #[test]
    fn test_hkdf_blake2s() {
        let ikm = b"input_key_material";
        let salt = b"salt_value";
        let info = b"context_info";
        let length = 32;

        let output = crypto::hkdf_blake2s(ikm, salt, info, length);
        assert_eq!(output.len(), length);

        let output2 = crypto::hkdf_blake2s(ikm, salt, info, length);
        assert_eq!(output, output2);

        let output3 = crypto::hkdf_blake2s(b"different_ikm", salt, info, length);
        assert_ne!(output, output3);
    }

    #[test]
    fn test_xchacha20poly1305_encryption() {
        let key = [1u8; 32];
        let nonce = [2u8; 24];
        let plaintext = b"Secret message for encryption";
        let aad = b"additional_authenticated_data";

        let ciphertext = crypto::xchacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = crypto::xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        let wrong_aad = b"wrong_aad";
        let decrypt_result =
            crypto::xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, wrong_aad);
        assert!(decrypt_result.is_err());
    }

    #[test]
    fn test_account_pq_transition() {
        let address = Address::new([1u8; 20]);
        let mut account = Account::new_user(address);

        assert!(!account.is_pq_only_mode());
        assert!(account.supports_algorithm(AlgorithmId::MlDsa2.as_u16()));
        assert!(account.supports_algorithm(AlgorithmId::Ed25519.as_u16()));

        account.enable_pq_only_mode(100);

        assert!(account.is_pq_only_mode());
        assert!(account.supports_algorithm(AlgorithmId::MlDsa2.as_u16()));
        assert!(!account.supports_algorithm(AlgorithmId::Ed25519.as_u16()));
    }

    #[test]
    fn test_transaction_pq_signature() {
        let keypair = crypto::KeyPair::generate();
        let from_address = Address::from_public_key(&keypair.dilithium_public_key());

        let mut tx = Transaction::new(
            from_address,
            1,
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from_egoc(10),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
        );

        tx.sign(&keypair, true).unwrap();

        assert!(tx.signature.ed25519_sig.is_some());
        assert!(tx.signature.dilithium_sig.is_some());
        assert!(tx.public_keys.ed25519_pk.is_some());
        assert!(tx.public_keys.mlkem_pk.is_some());
        assert!(tx.verify_signature().unwrap());

        let mut pq_only_tx = Transaction::new(
            from_address,
            2,
            TransactionPayload::SystemOperation {
                operation_id: "test_op".to_string(),
                data: vec![],
                auth_level: 1,
                epoch_anchor: false,
            },
            ShardId::new(0).unwrap(),
            None,
        );

        pq_only_tx.sign(&keypair, false).unwrap();

        assert!(pq_only_tx.signature.ed25519_sig.is_none());
        assert!(pq_only_tx.signature.dilithium_sig.is_some());
        assert!(pq_only_tx.public_keys.ed25519_pk.is_none());
        assert!(pq_only_tx.verify_signature().unwrap());
    }

    #[test]
    fn test_block_pq_signature_counting() {
        let keypair = crypto::KeyPair::generate();
        let proposer_address = Address::from_public_key(&keypair.dilithium_public_key());

        let mut tx1 = Transaction::new(
            proposer_address,
            1,
            TransactionPayload::Transfer {
                to: Address::new([1u8; 20]),
                amount: Balance::from_egoc(5),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
        );
        tx1.sign(&keypair, true).unwrap();

        let mut tx2 = Transaction::new(
            proposer_address,
            2,
            TransactionPayload::SystemOperation {
                operation_id: "pq_op".to_string(),
                data: vec![],
                auth_level: 1,
                epoch_anchor: false,
            },
            ShardId::new(0).unwrap(),
            None,
        );
        tx2.sign(&keypair, false).unwrap();

        let mut block = Block::new(
            BlockHeight::new(1),
            Hash::ZERO,
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer_address,
            vec![tx1, tx2],
            vec![],
        );

        block.sign(&keypair, true).unwrap();

        assert_eq!(block.header.core.pq_signature_count.hybrid_sigs, 1);
        assert_eq!(block.header.core.pq_signature_count.dilithium_sigs, 1);
        assert_eq!(block.header.core.pq_signature_count.ed25519_sigs, 0);

        assert!(block.is_pq_compliant());

        let algorithm_stats = block.get_algorithm_usage_stats();
        assert_eq!(algorithm_stats[&AlgorithmId::MlDsa2.as_u16()], 1);
        assert_eq!(algorithm_stats[&AlgorithmId::Ed25519.as_u16()], 0);
    }

    #[test]
    fn test_cellular_safe_operations() {
        let address = Address::new([1u8; 20]);
        let capabilities = crate::account::DeviceCapabilities {
            bandwidth_capacity: 1_000_000,
            storage_capacity: 1024 * 1024 * 1024,
            supported_slices: vec![],
            coverage_area: None,
            hardware_specs: HashMap::new(),
            last_poc: None,
            post_stats: crate::account::PostStats::default(),
            cellular_safe: true,
            max_bandwidth_cellular: 100_000,
            monthly_data_limit_gb: 5,
            cost_awareness: crate::account::CostAwareness::default(),
        };

        let account = Account::new_device_simple(address, "test_device".to_string(), capabilities);

        assert!(account.is_cellular_safe());
        assert!(account.within_data_limits(1));
        assert!(!account.within_data_limits(10));
        assert!(account.should_use_wifi_only("heavy_compute"));
        assert!(!account.should_use_wifi_only("light_operation"));
    }

    #[test]
    fn test_pq_transition_events() {
        let mut block = Block::new(
            BlockHeight::new(100),
            Hash::ZERO,
            ShardId::new(0).unwrap(),
            EpochNumber::new(10),
            Address::new([1u8; 20]),
            vec![],
            vec![],
        );

        let pq_events = vec![
            crate::block::PQTransitionEvent {
                event_type: crate::block::PQTransitionEventType::HybridModeEnabled,
                affected_accounts: vec![Address::new([2u8; 20])],
                new_algorithms: vec![AlgorithmId::MlDsa2.as_u16(), AlgorithmId::Ed25519.as_u16()],
                epoch: 10,
                timestamp: Timestamp::now(),
            },
            crate::block::PQTransitionEvent {
                event_type: crate::block::PQTransitionEventType::PQRequiredOnTopic {
                    topic: "consensus".to_string(),
                },
                affected_accounts: vec![],
                new_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
                epoch: 10,
                timestamp: Timestamp::now(),
            },
        ];

        block.add_pq_transition_events(pq_events);

        assert_eq!(block.body.pq_transition_events.len(), 2);

        if let Some(ref pq_data) = block.header.metadata.pq_transition_data {
            assert_eq!(pq_data.transition_phase, 1);
            assert!(pq_data
                .pq_required_topics
                .contains(&"consensus".to_string()));
        }
    }
}

#[test]
fn test_full_pq_workflow() {
    let alice_keypair = crypto::KeyPair::generate();
    let bob_keypair = crypto::KeyPair::generate();

    let alice_address = Address::from_public_key(&alice_keypair.dilithium_public_key());
    let bob_address = Address::from_public_key(&bob_keypair.dilithium_public_key());

    let mut alice_account = Account::new_eoa(
        alice_address,
        alice_keypair.dilithium_public_key().key_data.clone(),
        alice_keypair.kyber_public_key().key_data.clone(),
    );
    alice_account.credit(Balance::from_egoc(100));

    let _bob_account = Account::new_eoa(
        bob_address,
        bob_keypair.dilithium_public_key().key_data.clone(),
        bob_keypair.kyber_public_key().key_data.clone(),
    );

    let mut transfer_tx = Transaction::new(
        alice_address,
        1,
        TransactionPayload::Transfer {
            to: bob_address,
            amount: Balance::from_egoc(10),
            memo: Some("PQ transfer test".to_string()),
            stealth_mode: false,
        },
        ShardId::new(0).unwrap(),
        None,
    );

    transfer_tx.sign(&alice_keypair, true).unwrap();

    assert!(transfer_tx.verify_signature().unwrap());
    assert!(transfer_tx.validate_against_account(&alice_account).is_ok());

    let session_result = alice_keypair.create_hybrid_session(
        &bob_keypair.x25519_public_key(),
        &bob_keypair.kyber_public_key().key_data,
        "transfer_session",
        &[0u8; 32],
        b"testnet",
    );

    assert!(session_result.is_ok());
    let (session_record, session_key) = session_result.unwrap();

    assert_eq!(session_record.protocol_version, PROTOCOL_VERSION);
    assert_eq!(session_key.len(), 32);

    alice_account.enable_pq_only_mode(50);

    let mut pq_only_tx = Transaction::new(
        alice_address,
        2,
        TransactionPayload::PQTransition {
            new_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
            disable_legacy: true,
            transition_epoch: 50,
        },
        ShardId::new(0).unwrap(),
        None,
    );

    pq_only_tx.sign(&alice_keypair, false).unwrap();
    assert!(pq_only_tx.signature.ed25519_sig.is_none());
    assert!(pq_only_tx.signature.dilithium_sig.is_some());

    let mut block = Block::new(
        BlockHeight::new(1),
        Hash::ZERO,
        ShardId::new(0).unwrap(),
        EpochNumber::new(1),
        alice_address,
        vec![transfer_tx, pq_only_tx],
        vec![],
    );

    block.sign(&alice_keypair, true).unwrap();

    assert!(block.validate_structure().is_ok());
    assert!(block.is_pq_compliant());

    let stats = block.get_algorithm_usage_stats();
    assert!(stats.contains_key(&AlgorithmId::MlDsa2.as_u16()));

    println!("✅ Full PQ workflow test completed successfully");
    println!("   - Alice and Bob accounts created with PQ keys");
    println!("   - Hybrid signature transaction created and verified");
    println!("   - Secure session established with hybrid KEM");
    println!("   - PQ transition transaction processed");
    println!("   - Block with PQ compliance validation passed");
}
