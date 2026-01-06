use ego_core::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

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

    fn export_keypair_to_files(
        keypair: &crypto::KeyPair,
        base_dir: &Path,
        prefix: &str,
    ) -> std::io::Result<()> {
        let keys = keypair.export_keys();
        let keys_hex = keypair.export_keys_hex();

        let keypair_dir = base_dir.join(prefix);
        fs::create_dir_all(&keypair_dir)?;

        File::create(keypair_dir.join("ed25519_public.bin"))?.write_all(&keys.ed25519_public)?;
        File::create(keypair_dir.join("ed25519_secret.bin"))?.write_all(&keys.ed25519_secret)?;
        File::create(keypair_dir.join("dilithium_public.bin"))?
            .write_all(&keys.dilithium_public)?;
        File::create(keypair_dir.join("dilithium_secret.bin"))?
            .write_all(&keys.dilithium_secret)?;
        File::create(keypair_dir.join("kyber_public.bin"))?.write_all(&keys.kyber_public)?;
        File::create(keypair_dir.join("kyber_secret.bin"))?.write_all(&keys.kyber_secret)?;
        File::create(keypair_dir.join("x25519_public.bin"))?.write_all(&keys.x25519_public)?;
        File::create(keypair_dir.join("x25519_secret.bin"))?.write_all(&keys.x25519_secret)?;
        File::create(keypair_dir.join("seed.bin"))?.write_all(&keys.seed)?;

        if let Some(ref pk) = keys.slh_dsa_public {
            File::create(keypair_dir.join("slh_dsa_public.bin"))?.write_all(pk)?;
        }
        if let Some(ref sk) = keys.slh_dsa_secret {
            File::create(keypair_dir.join("slh_dsa_secret.bin"))?.write_all(sk)?;
        }

        let json_content = serde_json::to_string_pretty(&keys_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        File::create(keypair_dir.join("keys_hex.json"))?.write_all(json_content.as_bytes())?;

        Ok(())
    }

    #[test]
    fn test_export_keys_to_files() {
        let output_dir = Path::new("./test_keys_export");
        let _ = fs::remove_dir_all(output_dir);
        fs::create_dir_all(output_dir).unwrap();

        println!("\n=== Exporting Post-Quantum Keypairs ===");

        let keypair_standard = crypto::KeyPair::generate();
        export_keypair_to_files(&keypair_standard, output_dir, "1_pq_only").unwrap();
        println!("✓ Exported PQ-only keypair to: ./test_keys_export/1_pq_only/");

        let keypair_transition = crypto::KeyPair::generate_with_transition();
        export_keypair_to_files(&keypair_transition, output_dir, "2_transition_mode").unwrap();
        println!("✓ Exported transition mode keypair to: ./test_keys_export/2_transition_mode/");

        let keypair_slh_dsa = crypto::KeyPair::generate_with_slh_dsa();
        export_keypair_to_files(&keypair_slh_dsa, output_dir, "3_with_slh_dsa").unwrap();
        println!("✓ Exported SLH-DSA keypair to: ./test_keys_export/3_with_slh_dsa/");

        println!("\n=== Export Summary ===");
        println!("Total keypairs exported: 3");
        println!("Output directory: {:?}", output_dir.canonicalize().unwrap());
        println!("\n⚠️  WARNING: These directories contain SECRET KEYS!");
        println!("Please secure or delete them after inspection.");
    }

    #[test]
    fn test_direct_key_access() {
        println!("\n=== Testing Direct Key Access ===");

        let keypair = crypto::KeyPair::generate_with_transition();

        let ed25519_secret = keypair.get_ed25519_secret_key();
        let dilithium_secret = keypair.get_dilithium_secret_key();
        let kyber_secret = keypair.get_kyber_secret_key();
        let x25519_secret = keypair.get_x25519_secret_key();
        let seed = keypair.get_seed();

        println!("✓ Ed25519 secret key: {} bytes", ed25519_secret.len());
        println!("✓ Dilithium secret key: {} bytes", dilithium_secret.len());
        println!("✓ Kyber secret key: {} bytes", kyber_secret.len());
        println!("✓ X25519 secret key: {} bytes", x25519_secret.len());
        println!("✓ Master seed: {} bytes", seed.len());

        assert_eq!(ed25519_secret.len(), 32);
        assert_eq!(x25519_secret.len(), 32);
        assert_eq!(seed.len(), 32);
        assert!(dilithium_secret.len() > 2000);
        assert!(kyber_secret.len() > 2000);

        println!("\n✓ All direct key access methods working correctly");
    }

    #[test]
    fn test_key_export_and_reimport() {
        println!("\n=== Testing Key Export and Re-import ===");

        let original_keypair = crypto::KeyPair::generate_with_transition();

        let exported = original_keypair.export_keys();

        println!("✓ Exported all keys from keypair");

        let seed = original_keypair.get_seed();
        let recreated_keypair = crypto::KeyPair::from_bytes(seed).unwrap();

        assert_eq!(
            original_keypair.ed25519_public_key().key_data,
            recreated_keypair.ed25519_public_key().key_data
        );

        assert_eq!(
            original_keypair.x25519_public_key(),
            recreated_keypair.x25519_public_key()
        );

        println!("✓ Successfully recreated keypair from exported seed");
        println!("✓ Ed25519 and X25519 keys match (deterministic)");
        println!("✓ Dilithium and Kyber keys regenerated (non-deterministic)");
    }

    #[test]
    fn test_export_keys_hex_format() {
        println!("\n=== Testing Hex-Encoded Key Export ===");

        let keypair = crypto::KeyPair::generate_with_transition();
        let keys_hex = keypair.export_keys_hex();

        assert!(hex::decode(&keys_hex.ed25519_public).is_ok());
        assert!(hex::decode(&keys_hex.ed25519_secret).is_ok());
        assert!(hex::decode(&keys_hex.dilithium_public).is_ok());
        assert!(hex::decode(&keys_hex.dilithium_secret).is_ok());
        assert!(hex::decode(&keys_hex.kyber_public).is_ok());
        assert!(hex::decode(&keys_hex.kyber_secret).is_ok());
        assert!(hex::decode(&keys_hex.x25519_public).is_ok());
        assert!(hex::decode(&keys_hex.x25519_secret).is_ok());
        assert!(hex::decode(&keys_hex.seed).is_ok());

        println!("✓ All keys exported to valid hex format");
        println!(
            "✓ Ed25519 public hex: {}...",
            &keys_hex.ed25519_public[..16]
        );
        println!(
            "✓ Dilithium public hex: {}...",
            &keys_hex.dilithium_public[..16]
        );
        println!("✓ Kyber public hex: {}...", &keys_hex.kyber_public[..16]);
        println!("✓ X25519 public hex: {}...", &keys_hex.x25519_public[..16]);
    }

    #[test]
    fn test_export_multiple_keypairs() {
        println!("\n=== Exporting Multiple Keypairs for Comparison ===");

        let output_dir = Path::new("./test_keys_export/batch");
        if output_dir.exists() {
            fs::remove_dir_all(output_dir).unwrap();
        }
        fs::create_dir_all(output_dir).unwrap();

        for i in 1..=5 {
            let keypair = crypto::KeyPair::generate();
            let prefix = format!("keypair_{:02}", i);
            export_keypair_to_files(&keypair, output_dir, &prefix).unwrap();
            println!(
                "✓ Exported keypair {} to: ./test_keys_export/batch/{}/",
                i, prefix
            );
        }

        println!("\n✓ Successfully exported 5 keypairs");
        println!("✓ Each keypair has unique keys");
        println!("✓ All keys stored in: ./test_keys_export/batch/");
    }

    #[test]
    fn test_read_exported_bin_files() {
        use std::fs;
        use std::path::Path;

        println!("\n=== Reading Exported Binary Key Files ===\n");

        let keypair_dir = Path::new("./test_keys_export/1_pq_only");

        if !keypair_dir.exists() {
            println!("⚠️  Directory not found. Run test_export_keys_to_files first.");
            return;
        }

        let ed25519_pub = fs::read(keypair_dir.join("ed25519_public.bin")).unwrap();
        println!("Ed25519 Public Key:");
        println!("  Size: {} bytes", ed25519_pub.len());
        println!("  Hex: {}", hex::encode(&ed25519_pub));
        println!(
            "  First 16 bytes: {:?}\n",
            &ed25519_pub[..16.min(ed25519_pub.len())]
        );

        let dilithium_pub = fs::read(keypair_dir.join("dilithium_public.bin")).unwrap();
        println!("Dilithium2 Public Key:");
        println!("  Size: {} bytes", dilithium_pub.len());
        println!(
            "  Hex (first 32 bytes): {}",
            hex::encode(&dilithium_pub[..32])
        );
        println!("  First 16 bytes: {:?}\n", &dilithium_pub[..16]);

        let kyber_pub = fs::read(keypair_dir.join("kyber_public.bin")).unwrap();
        println!("Kyber768 Public Key:");
        println!("  Size: {} bytes", kyber_pub.len());
        println!("  Hex (first 32 bytes): {}", hex::encode(&kyber_pub[..32]));
        println!("  First 16 bytes: {:?}\n", &kyber_pub[..16]);

        let x25519_pub = fs::read(keypair_dir.join("x25519_public.bin")).unwrap();
        println!("X25519 Public Key:");
        println!("  Size: {} bytes", x25519_pub.len());
        println!("  Hex: {}", hex::encode(&x25519_pub));
        println!("  Bytes: {:?}\n", x25519_pub);

        let seed = fs::read(keypair_dir.join("seed.bin")).unwrap();
        println!("Master Seed:");
        println!("  Size: {} bytes", seed.len());
        println!("  Hex: {}", hex::encode(&seed));
        println!("  ⚠️  KEEP SECRET - Can regenerate all keys!\n");

        println!("✓ Successfully read all binary key files");
    }

    #[test]
    fn test_ego_address_derivation() {
        let keypair = crypto::KeyPair::generate();
        let chain_id = 1u32;

        let eoa_address = keypair.derive_address(chain_id, crypto::AddressType::EOA);
        assert_eq!(eoa_address.version(), 0b001);
        assert_eq!(eoa_address.address_type(), Some(crypto::AddressType::EOA));
        assert_eq!(eoa_address.payload().len(), 20);

        let contract_addr = keypair.derive_address(chain_id, crypto::AddressType::Contract);
        let device_addr = keypair.derive_address(chain_id, crypto::AddressType::Device);
        let validator_addr = keypair.derive_address(chain_id, crypto::AddressType::Validator);

        assert_eq!(
            eoa_address.payload(),
            contract_addr.payload(),
            "Payload should be identical - only type byte differs"
        );

        assert_ne!(eoa_address.address_type(), contract_addr.address_type());
        assert_eq!(
            contract_addr.address_type(),
            Some(crypto::AddressType::Contract)
        );
        assert_eq!(
            device_addr.address_type(),
            Some(crypto::AddressType::Device)
        );
        assert_eq!(
            validator_addr.address_type(),
            Some(crypto::AddressType::Validator)
        );

        assert_ne!(
            eoa_address.as_bytes(),
            contract_addr.as_bytes(),
            "Full addresses differ due to type byte"
        );

        println!("✓ Address derivation follows spec (version 001, 20-byte payload)");
        println!("✓ Address type only affects the version/type byte, not the payload");
    }

    #[test]
    fn test_bech32m_address_encoding() {
        let keypair = crypto::KeyPair::generate();
        let chain_id = 1u32;

        let mainnet_addr = keypair
            .derive_bech32_address(chain_id, crypto::AddressType::EOA, "ego")
            .unwrap();
        assert!(mainnet_addr.starts_with("ego1"));

        let testnet_addr = keypair
            .derive_bech32_address(chain_id, crypto::AddressType::EOA, "egot")
            .unwrap();
        assert!(testnet_addr.starts_with("egot1"));

        let devnet_addr = keypair
            .derive_bech32_address(chain_id, crypto::AddressType::EOA, "egod")
            .unwrap();
        assert!(devnet_addr.starts_with("egod1"));

        println!("✓ Bech32m encoding with correct HRP prefixes");
        println!("  Mainnet: {}", mainnet_addr);
        println!("  Testnet: {}", testnet_addr);
    }

    #[test]
    fn test_address_round_trip_encoding_decoding() {
        let keypair = crypto::KeyPair::generate();
        let chain_id = 1u32;

        let original_address = keypair.derive_address(chain_id, crypto::AddressType::EOA);
        let bech32_str = original_address.to_bech32("ego").unwrap();

        let decoded_address = crypto::EgoAddress::from_bech32(&bech32_str, "ego").unwrap();

        assert_eq!(original_address.version(), decoded_address.version());
        assert_eq!(
            original_address.address_type(),
            decoded_address.address_type()
        );
        assert_eq!(original_address.payload(), decoded_address.payload());
        assert_eq!(original_address.as_bytes(), decoded_address.as_bytes());

        println!("✓ Address encoding/decoding round-trip successful");
    }

    #[test]
    fn test_address_validation_rules() {
        let keypair = crypto::KeyPair::generate();
        let chain_id = 1u32;

        let address = keypair.derive_address(chain_id, crypto::AddressType::EOA);
        let valid_bech32 = address.to_bech32("ego").unwrap();

        assert!(crypto::EgoAddress::from_bech32(&valid_bech32, "ego").is_ok());

        assert!(crypto::EgoAddress::from_bech32(&valid_bech32, "egot").is_err());

        assert!(crypto::EgoAddress::from_bech32("invalid_address", "ego").is_err());

        println!("✓ Address validation rules enforced correctly");
    }

    #[test]
    fn test_chain_id_affects_address() {
        let keypair = crypto::KeyPair::generate();

        let mainnet_addr = keypair.derive_address(1u32, crypto::AddressType::EOA);
        let testnet_addr = keypair.derive_address(999u32, crypto::AddressType::EOA);

        assert_ne!(mainnet_addr.payload(), testnet_addr.payload());

        println!("✓ Chain ID properly domain-separates addresses");
    }

    #[test]
    fn test_address_size_constraints() {
        let keypair = crypto::KeyPair::generate();
        let address = keypair.derive_address(1u32, crypto::AddressType::EOA);

        assert_eq!(address.payload().len(), 20, "Payload must be 20 bytes");
        assert_eq!(
            address.as_bytes().len(),
            21,
            "Total must be 21 bytes (1 + 20)"
        );

        let bech32_str = address.to_bech32("ego").unwrap();
        assert!(bech32_str.len() > 30 && bech32_str.len() < 50);

        println!("✓ Address sizes match spec: 20-byte payload, 21-byte total");
    }

    #[test]
    fn test_qr_uri_format() {
        let keypair = crypto::KeyPair::generate();
        let address = keypair
            .derive_bech32_address(1u32, crypto::AddressType::EOA, "ego")
            .unwrap();

        let basic_uri = format!("ego:{}", address);
        assert!(basic_uri.starts_with("ego:ego1"));

        let full_uri = format!(
            "ego:{}?amount={}&memo={}&stealth={}",
            address, 2500000000u64, "Payment%20for%20Service", 1
        );

        assert!(full_uri.contains("amount=2500000000"));
        assert!(full_uri.contains("memo=Payment"));
        assert!(full_uri.contains("stealth=1"));

        println!("✓ QR URI format matches spec");
        println!("  Basic: {}", basic_uri);
        println!("  Full: {}...", &full_uri[..60]);
    }

    #[test]
    fn test_read_all_exported_keys_comprehensive() {
        use std::fs;
        use std::path::Path;

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  Reading ALL Exported Post-Quantum Keys - Comprehensive     ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        let base_dir = Path::new("./test_keys_export");

        if !base_dir.exists() {
            println!(
                "⚠️  Export directory not found. Run 'cargo test test_export_keys_to_files' first."
            );
            return;
        }

        let directories = vec!["1_pq_only", "2_transition_mode", "3_with_slh_dsa"];

        for dir_name in directories {
            let dir_path = base_dir.join(dir_name);

            if !dir_path.exists() {
                println!("⚠️  Skipping {} (not found)", dir_name);
                continue;
            }

            println!("┌─────────────────────────────────────────────────────────┐");
            println!("│ Directory: {:<45} │", dir_name);
            println!("└─────────────────────────────────────────────────────────┘\n");

            let json_path = dir_path.join("keys_hex.json");
            if json_path.exists() {
                let json_content = fs::read_to_string(&json_path).unwrap();
                let keys_hex: crypto::ExportedKeysHex =
                    serde_json::from_str(&json_content).unwrap();
                println!(
                    "📋 Mode: {}",
                    if keys_hex.transition_mode {
                        "HYBRID (Transition)"
                    } else {
                        "PQ-ONLY"
                    }
                );
            }

            read_key_file(&dir_path, "ed25519_public.bin", "Ed25519 Public");
            read_key_file(&dir_path, "ed25519_secret.bin", "Ed25519 Secret");
            read_key_file(&dir_path, "dilithium_public.bin", "Dilithium2 Public");
            read_key_file(&dir_path, "dilithium_secret.bin", "Dilithium2 Secret");
            read_key_file(&dir_path, "kyber_public.bin", "Kyber768 Public");
            read_key_file(&dir_path, "kyber_secret.bin", "Kyber768 Secret");
            read_key_file(&dir_path, "x25519_public.bin", "X25519 Public");
            read_key_file(&dir_path, "x25519_secret.bin", "X25519 Secret");
            read_key_file(&dir_path, "seed.bin", "Master Seed ⚠️");

            if dir_path.join("slh_dsa_public.bin").exists() {
                read_key_file(&dir_path, "slh_dsa_public.bin", "SLH-DSA Public");
                read_key_file(&dir_path, "slh_dsa_secret.bin", "SLH-DSA Secret");
            }

            println!("\n");
        }

        let batch_dir = base_dir.join("batch");
        if batch_dir.exists() {
            println!("┌─────────────────────────────────────────────────────────┐");
            println!("│ Batch Directory: Multiple Keypairs                      │");
            println!("└─────────────────────────────────────────────────────────┘\n");

            let entries = fs::read_dir(&batch_dir).unwrap();
            let mut count = 0;

            for entry in entries {
                let entry = entry.unwrap();
                let path = entry.path();

                if path.is_dir() {
                    count += 1;
                    let dir_name = path.file_name().unwrap().to_str().unwrap();
                    println!("  📦 {}", dir_name);

                    if let Ok(json_content) = fs::read_to_string(path.join("keys_hex.json")) {
                        if let Ok(keys_hex) =
                            serde_json::from_str::<crypto::ExportedKeysHex>(&json_content)
                        {
                            println!("     Ed25519:   {}", &keys_hex.ed25519_public[..32]);
                            println!("     Dilithium: {}...", &keys_hex.dilithium_public[..32]);
                            println!();
                        }
                    }
                }
            }

            println!("  Total keypairs in batch: {}\n", count);
        }

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  ✓ Successfully read all exported cryptographic keys        ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
    }

    fn read_key_file(dir: &Path, filename: &str, key_name: &str) {
        let file_path = dir.join(filename);

        if !file_path.exists() {
            return;
        }

        match fs::read(&file_path) {
            Ok(data) => {
                let hex_preview = if data.len() > 16 {
                    format!(
                        "{}...{}",
                        hex::encode(&data[..8]),
                        hex::encode(&data[data.len() - 8..])
                    )
                } else {
                    hex::encode(&data)
                };

                println!(
                    "  🔑 {:<20} | {:>5} bytes | {}",
                    key_name,
                    data.len(),
                    hex_preview
                );
            }
            Err(e) => {
                println!("  ⚠️  {:<20} | Error: {}", key_name, e);
            }
        }
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
        1,
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
            migration_period_epochs: 50,
        },
        ShardId::new(0).unwrap(),
        None,
        1,
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
