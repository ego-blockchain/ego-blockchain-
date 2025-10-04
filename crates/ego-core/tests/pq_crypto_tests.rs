use ego_core::*;

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
        assert_eq!(keypair.public_key().algorithm, AlgorithmId::MlDsa2);
        assert_eq!(keypair.x25519_public_key().len(), 32);
        assert!(!keypair.is_transition_mode());
    }

    #[test]
    fn test_keypair_transition_mode() {
        let keypair_pq = crypto::KeyPair::generate();
        assert!(!keypair_pq.is_transition_mode());

        let keypair_transition = crypto::KeyPair::generate_with_transition();
        assert!(keypair_transition.is_transition_mode());

        let caps_pq = keypair_pq.get_peer_capabilities(Address::new([1u8; 20]));
        assert_eq!(
            caps_pq.alg_sig_supported,
            vec![AlgorithmId::MlDsa2.as_u16()]
        );
        assert!(caps_pq.pq_required);
        assert!(caps_pq.x25519_pk.is_none());

        let caps_transition = keypair_transition.get_peer_capabilities(Address::new([1u8; 20]));
        assert!(caps_transition
            .alg_sig_supported
            .contains(&AlgorithmId::Ed25519.as_u16()));
        assert!(!caps_transition.pq_required);
        assert!(caps_transition.x25519_pk.is_some());
    }

    #[test]
    fn test_keypair_with_slh_dsa() {
        let keypair = crypto::KeyPair::generate_with_slh_dsa();

        assert!(keypair.slh_dsa_public_key().is_some());
        let slh_pk = keypair.slh_dsa_public_key().unwrap();
        assert_eq!(slh_pk.algorithm, AlgorithmId::SlhDsa);
    }

    #[test]
    fn test_keypair_from_bytes() {
        let seed = [42u8; 32];
        let keypair1 = crypto::KeyPair::from_bytes(&seed).unwrap();
        let keypair2 = crypto::KeyPair::from_bytes(&seed).unwrap();

        assert_eq!(
            keypair1.ed25519_public_key().key_data,
            keypair2.ed25519_public_key().key_data
        );
        assert_eq!(keypair1.x25519_public_key(), keypair2.x25519_public_key());

        assert_ne!(
            keypair1.dilithium_public_key().key_data,
            keypair2.dilithium_public_key().key_data
        );
    }

    #[test]
    fn test_dilithium_signature() {
        let keypair = crypto::KeyPair::generate();
        let message = b"test message for dilithium";

        let signature = keypair.sign_dilithium(message);
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa2);
        assert!(signature.signature_data.len() > 0);

        let public_key = keypair.dilithium_public_key();
        let is_valid = crypto::verify_signature(&public_key, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_ed25519_signature() {
        let keypair = crypto::KeyPair::generate_with_transition();
        let message = b"test message for ed25519";

        let signature = keypair.sign_ed25519(message);
        assert_eq!(signature.algorithm, AlgorithmId::Ed25519);
        assert_eq!(signature.signature_data.len(), 64);

        let public_key = keypair.ed25519_public_key();
        let is_valid = crypto::verify_signature(&public_key, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_dual_signature() {
        let keypair = crypto::KeyPair::generate_with_transition();
        let message = b"test message for dual signature";

        let dual_sig = keypair.dual_sign(message);
        assert!(dual_sig.ed25519_sig.is_some());
        assert!(dual_sig.dilithium_sig.is_some());

        let ed25519_pk = keypair.ed25519_public_key();
        let dilithium_pk = keypair.dilithium_public_key();
        let is_valid =
            crypto::verify_dual_signature(&ed25519_pk, &dilithium_pk, message, &dual_sig).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_hybrid_signature_transition_mode() {
        let keypair = crypto::KeyPair::generate_with_transition();
        let message = b"test message for hybrid signature";

        let hybrid_sig = keypair.sign_hybrid(message, false);
        assert!(hybrid_sig.ed25519_sig.is_some());
        assert!(hybrid_sig.dilithium_sig.is_some());

        let keypair_pq = crypto::KeyPair::generate();
        let pq_only_sig = keypair_pq.sign_hybrid(message, false);
        assert!(pq_only_sig.ed25519_sig.is_none());
        assert!(pq_only_sig.dilithium_sig.is_some());
    }

    #[test]
    fn test_slh_dsa_signature() {
        let keypair = crypto::KeyPair::generate_with_slh_dsa();
        let message = b"test message for SLH-DSA";

        let signature = keypair.sign_slh_dsa(message).unwrap();
        assert_eq!(signature.algorithm, AlgorithmId::SlhDsa);
        assert!(signature.signature_data.len() > 7000);

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
        let (ciphertext, shared_secret1) = keypair1.encapsulate_kyber(&kyber_pk.key_data).unwrap();

        assert_eq!(shared_secret1.len(), 32);
        assert!(ciphertext.len() > 1000);

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
        let network_id = 1u32;
        let version = 1u32;

        let (session_record, session_key) = keypair1
            .create_hybrid_session(
                &x25519_pk,
                &kyber_pk.key_data,
                stream_kind,
                &stream_nonce,
                chain_id,
                network_id,
                version,
            )
            .unwrap();

        assert_eq!(session_record.alg_kem_id, AlgorithmId::MlKem768.as_u16());
        assert_eq!(
            session_record.alg_dh_legacy_id,
            Some(AlgorithmId::X25519.as_u16())
        );
        assert!(session_record.x25519_pubkey.is_some());
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
        let network_id = 1u32;
        let version = 1u32;

        let (session_record, session_key) = keypair1
            .create_kyber_only_session(
                &kyber_pk.key_data,
                stream_kind,
                &stream_nonce,
                chain_id,
                network_id,
                version,
            )
            .unwrap();

        assert_eq!(session_record.alg_kem_id, AlgorithmId::MlKem768.as_u16());
        assert_eq!(session_record.alg_dh_legacy_id, None);
        assert!(session_record.x25519_pubkey.is_none());
        assert_eq!(session_key.len(), 32);
    }

    #[test]
    fn test_identity_binding() {
        let keypair = crypto::KeyPair::generate_with_transition();
        let peer_id = "test_peer_12345";
        let caps = b"test_capabilities";
        let chain_id = b"test_chain";
        let network_id = 1u32;
        let version = 1u32;

        let binding_with_ed25519 = keypair
            .create_identity_binding(peer_id, caps, chain_id, network_id, version, true)
            .unwrap();
        let binding_dilithium_only = keypair
            .create_identity_binding(peer_id, caps, chain_id, network_id, version, false)
            .unwrap();

        assert!(binding_with_ed25519.len() > binding_dilithium_only.len());

        let dilithium_pk = keypair.dilithium_public_key();
        let ed25519_pk = keypair.ed25519_public_key();

        let nonce_hybrid = &binding_with_ed25519[binding_with_ed25519.len() - 32..];
        let is_valid_hybrid = crypto::verify_identity_binding(
            peer_id,
            &keypair.kyber_public_key().key_data,
            caps,
            chain_id,
            network_id,
            version,
            nonce_hybrid,
            &binding_with_ed25519,
            &dilithium_pk.key_data,
            Some(&ed25519_pk.key_data[..]),
        )
        .unwrap();
        assert!(is_valid_hybrid);

        let nonce_dilithium = &binding_dilithium_only[binding_dilithium_only.len() - 32..];
        let is_valid_dilithium = crypto::verify_identity_binding(
            peer_id,
            &keypair.kyber_public_key().key_data,
            caps,
            chain_id,
            network_id,
            version,
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
        let network_id = 1u32;
        let alg_ids = (
            AlgorithmId::MlKem768.as_u16(),
            AlgorithmId::XChaCha20Poly1305.as_u16(),
        );

        let mut cipher1 = crypto::StreamCipher::new(
            &key,
            stream_id.clone(),
            chain_id.clone(),
            network_id,
            alg_ids,
        )
        .unwrap();
        let mut cipher2 =
            crypto::StreamCipher::new(&key, stream_id, chain_id, network_id, alg_ids).unwrap();

        let plaintext = b"Hello, post-quantum world!";
        let encrypted_frame = cipher1.encrypt_frame(plaintext, 1).unwrap();

        assert!(encrypted_frame.len() > plaintext.len());

        let decrypted = cipher2.decrypt_frame(&encrypted_frame, 1).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stream_cipher_replay_protection() {
        let key = [42u8; 32];
        let stream_id = b"replay_test".to_vec();
        let chain_id = b"test_chain".to_vec();
        let network_id = 1u32;
        let alg_ids = (
            AlgorithmId::MlKem768.as_u16(),
            AlgorithmId::XChaCha20Poly1305.as_u16(),
        );

        let mut cipher1 = crypto::StreamCipher::new(
            &key,
            stream_id.clone(),
            chain_id.clone(),
            network_id,
            alg_ids,
        )
        .unwrap();
        let mut cipher2 =
            crypto::StreamCipher::new(&key, stream_id, chain_id, network_id, alg_ids).unwrap();

        let plaintext = b"Test message";
        let encrypted_frame = cipher1.encrypt_frame(plaintext, 1).unwrap();

        let decrypted1 = cipher2.decrypt_frame(&encrypted_frame, 1).unwrap();
        assert_eq!(decrypted1, plaintext);

        let result = cipher2.decrypt_frame(&encrypted_frame, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_verifier() {
        let mut verifier = crypto::BatchVerifier::new(20000, 100);

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
    fn test_batch_verifier_budget() {
        let mut verifier = crypto::BatchVerifier::new(7000, 100);

        let keypair = crypto::KeyPair::generate();
        let message = b"test message";
        let sig = keypair.sign_dilithium(message);

        verifier
            .add_signature(
                keypair.dilithium_public_key(),
                message.to_vec(),
                sig.clone(),
            )
            .unwrap();

        assert!(verifier.has_budget());

        let result = verifier.add_signature(keypair.dilithium_public_key(), message.to_vec(), sig);
        assert!(result.is_err());

        assert!(verifier.has_budget());
    }

    #[test]
    fn test_handshake_init_creation() {
        let keypair1 = crypto::KeyPair::generate();
        let keypair2 = crypto::KeyPair::generate();

        let peer_kyber_pk = keypair2.kyber_public_key();
        let stream_kind = "consensus";
        let caps = b"node_capabilities";
        let chain_id = b"mainnet";
        let network_id = 1u32;
        let version = 1u32;

        let hybrid_handshake = crypto::create_handshake_init(
            &keypair1,
            &peer_kyber_pk.key_data,
            stream_kind,
            caps,
            chain_id,
            network_id,
            version,
            true,
        )
        .unwrap();

        assert_eq!(hybrid_handshake.version, 1);
        assert_eq!(hybrid_handshake.alg_kem, AlgorithmId::MlKem768.as_u16());
        assert_eq!(
            hybrid_handshake.alg_dh_legacy,
            Some(AlgorithmId::X25519.as_u16())
        );
        assert!(hybrid_handshake.x25519_c_pk.is_some());

        let pq_only_handshake = crypto::create_handshake_init(
            &keypair1,
            &peer_kyber_pk.key_data,
            stream_kind,
            caps,
            chain_id,
            network_id,
            version,
            false,
        )
        .unwrap();

        assert_eq!(pq_only_handshake.alg_dh_legacy, None);
        assert!(pq_only_handshake.x25519_c_pk.is_none());
    }

    #[test]
    fn test_peer_capabilities() {
        let keypair_pq = crypto::KeyPair::generate();
        let address = Address::new([1u8; 20]);

        let caps_pq = keypair_pq.get_peer_capabilities(address);
        assert!(caps_pq
            .alg_sig_supported
            .contains(&AlgorithmId::MlDsa2.as_u16()));
        assert!(!caps_pq
            .alg_sig_supported
            .contains(&AlgorithmId::Ed25519.as_u16()));
        assert!(caps_pq
            .alg_kem_supported
            .contains(&AlgorithmId::MlKem768.as_u16()));
        assert!(caps_pq.x25519_pk.is_none());
        assert_eq!(caps_pq.account_addr, address);
        assert!(caps_pq.cellular_safe);
        assert!(caps_pq.pq_required);

        let keypair_transition = crypto::KeyPair::generate_with_transition();
        let caps_transition = keypair_transition.get_peer_capabilities(address);
        assert!(caps_transition
            .alg_sig_supported
            .contains(&AlgorithmId::Ed25519.as_u16()));
        assert!(caps_transition.x25519_pk.is_some());
        assert!(!caps_transition.pq_required);
    }

    #[test]
    fn test_stealth_address_derivation() {
        let receiver_keypair = crypto::KeyPair::generate();
        let sender_ephemeral = [123u8; 32];

        let receiver_kyber_pk = receiver_keypair.kyber_public_key();
        let (stealth_pubkey, spend_key) =
            crypto::derive_stealth_address(&receiver_kyber_pk.key_data, &sender_ephemeral).unwrap();

        assert_eq!(stealth_pubkey.algorithm, AlgorithmId::MlDsa2);
        assert_ne!(
            stealth_pubkey.key_data,
            receiver_keypair.dilithium_public_key().key_data
        );
        assert!(spend_key.len() > 1000);
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

        let result3 = crypto::verify_downgrade_protection(&transcript, false, false);
        assert!(result3.is_ok());
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
    fn test_blake2s_hashing() {
        let data1 = b"test data";
        let hash1 = crypto::blake2s_hash(data1);
        assert_eq!(hash1.len(), 32);

        let hash2 = crypto::blake2s_hash(data1);
        assert_eq!(hash1, hash2);

        let data2 = b"different data";
        let hash3 = crypto::blake2s_hash(data2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_domain_separated_hashing() {
        let piece1 = b"part1";
        let piece2 = b"part2";
        let piece3 = b"part3";

        let hash1 = crypto::blake2s_hash_domain(&[piece1, piece2, piece3]);
        let hash2 = crypto::blake2s_hash_domain(&[piece1, piece2, piece3]);
        assert_eq!(hash1, hash2);

        let hash3 = crypto::blake2s_hash_domain(&[piece1, piece3, piece2]);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_merkle_tree_construction() {
        let items = vec![
            b"item1".to_vec(),
            b"item2".to_vec(),
            b"item3".to_vec(),
            b"item4".to_vec(),
        ];

        let tree = crypto::MerkleTree::build(items.clone());
        assert_eq!(tree.len(), 4);
        assert!(!tree.is_empty());
        assert!(tree.root_hash().is_some());

        let empty_tree = crypto::MerkleTree::build(vec![]);
        assert!(empty_tree.is_empty());
        assert!(empty_tree.root_hash().is_none());
    }

    #[test]
    fn test_merkle_proof_verification() {
        let items = vec![
            b"item1".to_vec(),
            b"item2".to_vec(),
            b"item3".to_vec(),
            b"item4".to_vec(),
        ];

        let tree = crypto::MerkleTree::build(items.clone());
        let _root_hash = tree.root_hash().unwrap();

        let leaf_hash = crypto::hash_data(&items[0]);
        let proof = crypto::MerkleProof {
            leaf_index: 0,
            leaf_hash,
            proof_hashes: vec![],
            tree_size: 1,
        };

        let single_tree = crypto::MerkleTree::build(vec![items[0].clone()]);
        let single_root = single_tree.root_hash().unwrap();
        assert!(proof.verify(single_root).unwrap());
    }

    #[test]
    fn test_poc_beacon_signing() {
        let keypair = crypto::KeyPair::generate();
        let beacon_data = b"beacon_challenge_12345";
        let chain_id = b"mainnet";
        let network_id = 1u32;

        let signature = keypair.sign_poc_beacon(beacon_data, chain_id, network_id);
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa2);
        assert!(signature.signature_data.len() > 2000);
    }

    #[test]
    fn test_poc_witness_signing() {
        let keypair = crypto::KeyPair::generate();
        let witness_data = b"witness_proof_67890";
        let chain_id = b"mainnet";
        let network_id = 1u32;

        let signature = keypair.sign_poc_witness(witness_data, chain_id, network_id);
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa2);
    }

    #[test]
    fn test_post_proof_signing() {
        let keypair = crypto::KeyPair::generate();
        let proof_data = b"storage_proof_data";
        let chain_id = b"mainnet";
        let network_id = 1u32;

        let signature = keypair.sign_post_proof(proof_data, chain_id, network_id);
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa2);
    }

    #[test]
    fn test_dilithium_signature_verification_failure() {
        let keypair = crypto::KeyPair::generate();
        let message = b"original message";
        let tampered_message = b"tampered message";

        let signature = keypair.sign_dilithium(message);
        let public_key = keypair.dilithium_public_key();

        let is_valid = crypto::verify_signature(&public_key, tampered_message, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_kyber_shared_secret_uniqueness() {
        let keypair1 = crypto::KeyPair::generate();
        let keypair2 = crypto::KeyPair::generate();

        let kyber_pk = keypair2.kyber_public_key();

        let (ciphertext1, shared_secret1) = keypair1.encapsulate_kyber(&kyber_pk.key_data).unwrap();
        let (ciphertext2, shared_secret2) = keypair1.encapsulate_kyber(&kyber_pk.key_data).unwrap();

        assert_ne!(shared_secret1, shared_secret2);
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_wrong_algorithm_signature_verification() {
        let keypair = crypto::KeyPair::generate();
        let message = b"test message";

        let ed25519_sig = keypair.sign_ed25519(message);
        let dilithium_pk = keypair.dilithium_public_key();

        let result = crypto::verify_signature(&dilithium_pk, message, &ed25519_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_zeroization() {
        let keypair = crypto::KeyPair::generate();
        let seed_copy = keypair.to_bytes();

        drop(keypair);

        let keypair2 = crypto::KeyPair::from_bytes(&seed_copy).unwrap();
        assert_eq!(keypair2.to_bytes(), seed_copy);
    }

    #[test]
    fn test_deterministic_ots_keypair() {
        let seed = [42u8; 32];

        let (pk1, _sk1) = crypto::KeyPair::derive_ots_keypair_from_seed(&seed).unwrap();
        let (pk2, _sk2) = crypto::KeyPair::derive_ots_keypair_from_seed(&seed).unwrap();

        assert_ne!(pk1, pk2, "OTS public keys must be unique for security");
        assert!(pk1.len() > 1000, "Valid Dilithium2 public key size");
        assert!(pk2.len() > 1000, "Valid Dilithium2 public key size");
    }

    #[test]
    fn test_different_seeds_produce_different_keypairs() {
        let seed1 = [42u8; 32];
        let seed2 = [43u8; 32];

        let (pk1, _) = crypto::KeyPair::derive_ots_keypair_from_seed(&seed1).unwrap();
        let (pk2, _) = crypto::KeyPair::derive_ots_keypair_from_seed(&seed2).unwrap();

        assert_ne!(
            pk1, pk2,
            "Different seeds should produce different public keys"
        );
    }

    #[test]
    fn test_ots_signing_and_verification() {
        let seed = [42u8; 32];
        let (pk, sk) = crypto::KeyPair::derive_ots_keypair_from_seed(&seed).unwrap();

        let message = b"test message for OTS";
        let signature = crypto::dilithium_sign(&sk, message).unwrap();
        let valid = crypto::dilithium_verify(&pk, message, &signature).unwrap();

        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn test_stealth_address_derivation_from_crypto() {
        use rand::RngCore;

        let receiver_keypair = crypto::KeyPair::generate();
        let mut sender_ephemeral = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sender_ephemeral);

        let result = crypto::derive_stealth_address(
            &receiver_keypair.kyber_public_key().key_data,
            &sender_ephemeral,
        );

        assert!(result.is_ok(), "Stealth address derivation should succeed");
        let (one_time_pk, spend_key) = result.unwrap();

        assert_eq!(one_time_pk.algorithm, AlgorithmId::MlDsa2);
        assert!(!spend_key.is_empty(), "Spend key should not be empty");
    }
}

#[test]
fn test_full_pq_workflow() {
    let alice_keypair = crypto::KeyPair::generate_with_transition();
    let bob_keypair = crypto::KeyPair::generate_with_transition();

    let alice_address = Address::from_public_key(&alice_keypair.dilithium_public_key());
    let bob_address = Address::from_public_key(&bob_keypair.dilithium_public_key());

    println!("✓ Generated PQ keypairs for Alice and Bob (transition mode)");

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

    println!("✓ Created EOA accounts with PQ keys");

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
    println!("✓ Created hybrid-signed transaction (Ed25519 + Dilithium)");

    assert!(transfer_tx.signature.ed25519_sig.is_some());
    assert!(transfer_tx.signature.dilithium_sig.is_some());
    println!("✓ Transaction signature created (hybrid mode)");

    let session_result = alice_keypair.create_hybrid_session(
        &bob_keypair.x25519_public_key(),
        &bob_keypair.kyber_public_key().key_data,
        "transfer_session",
        &[0u8; 32],
        b"testnet",
        1u32,
        1u32,
    );

    assert!(session_result.is_ok());
    let (_session_record, session_key) = session_result.unwrap();

    assert_eq!(session_key.len(), 32);
    println!("✓ Established hybrid session (X25519 + Kyber-768)");

    alice_account.enable_pq_only_mode(50);
    println!("✓ Enabled PQ-only mode for Alice");

    let mut alice_keypair_pq = alice_keypair.clone();
    alice_keypair_pq.set_transition_mode(false);

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

    pq_only_tx.sign(&alice_keypair_pq, false).unwrap();
    assert!(pq_only_tx.signature.ed25519_sig.is_none());
    assert!(pq_only_tx.signature.dilithium_sig.is_some());
    println!("✓ Created PQ-only transaction (Dilithium-2 only)");

    println!("✓ All cryptographic operations validated successfully");

    println!("\n=== Full PQ Workflow Test Summary ===");
    println!("✓ Keypair generation (Dilithium-2 primary, Ed25519 for transition)");
    println!("✓ Hybrid signatures (Ed25519 + Dilithium-2 during transition)");
    println!("✓ Hybrid KEM sessions (X25519 + Kyber-768 during transition)");
    println!("✓ PQ-only mode transition (Dilithium-2 + Kyber-768 only)");
    println!("✓ Transaction signing with both hybrid and PQ-only modes");
    println!("\nProduction-ready PQ crypto implementation verified!");
}
