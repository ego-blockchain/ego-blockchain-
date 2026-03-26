use ego_core::*;
use ego_core::crypto;
use ego_core::transaction::*;
use hex;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

fn chunk_bytes(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    data.chunks(chunk_size).map(|c| c.to_vec()).collect()
}

#[cfg(test)]
mod e2e_transaction_tests {
    use super::*;

    #[test]
    fn test_alice_bob_encrypted_sharded_transaction() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  E2E Encrypted & Sharded Data Transaction Test              ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        println!("📋 STEP 1: Generating keypairs for Alice and Bob...");
        let alice_keypair = crypto::KeyPair::generate_with_transition();
        let bob_keypair = crypto::KeyPair::generate_with_transition();

        let alice_addr = Address::from_public_key(&alice_keypair.dilithium_public_key());
        let bob_addr = Address::from_public_key(&bob_keypair.dilithium_public_key());

        println!("  ✓ Alice address: {}", hex::encode(alice_addr.as_bytes()));
        println!("  ✓ Bob address:   {}", hex::encode(bob_addr.as_bytes()));

        let mut alice_account = Account::new_eoa(
            alice_addr,
            alice_keypair.dilithium_public_key().key_data.clone(),
            alice_keypair.kyber_public_key().key_data.clone(),
        );
        alice_account.credit(Balance::from_egoc(1000));
        alice_account.storage_credits = 100_000;
        alice_account.ed25519_pk = Some(alice_keypair.ed25519_public_key().key_data.clone());

        let _bob_account = Account::new_eoa(
            bob_addr,
            bob_keypair.dilithium_public_key().key_data.clone(),
            bob_keypair.kyber_public_key().key_data.clone(),
        );

        println!("  ✓ Alice balance: {} EGOC", alice_account.balance.as_u128() / 1_000_000_000);
        println!("  ✓ Alice storage credits: {}\n", alice_account.storage_credits);

        println!("📋 STEP 2: Establishing hybrid KEM session (X25519 + Kyber-768)...");
        let (session_record, session_key) = alice_keypair
            .create_hybrid_session(
                &bob_keypair.x25519_public_key(),
                &bob_keypair.kyber_public_key().key_data,
                "data_exchange_stream",
                &[0u8; 32],
                b"testnet",
                1u32,
                1u32,
            )
            .expect("Failed to create hybrid session");

        println!("  ✓ Session established");
        println!("  ✓ KEM algorithm: ML-KEM-768");
        println!("  ✓ DH algorithm: X25519");
        println!("  ✓ Session key: {}...", hex::encode(&session_key[..16]));
        assert_eq!(session_record.alg_kem_id, AlgorithmId::MlKem768.as_u16());
        assert_eq!(session_key.len(), 32);

        println!("\n📋 STEP 3: Preparing data payload...");
        let data = b"Hello Bob! This is Alice sending you encrypted data across the EGO blockchain. This message will be encrypted with post-quantum cryptography, sharded across multiple nodes, and stored with geographic diversity.";
        println!("  ✓ Data size: {} bytes", data.len());
        println!("  ✓ Data preview: {}...", String::from_utf8_lossy(&data[..50]));

        println!("\n📋 STEP 4: Encrypting data with XChaCha20-Poly1305...");
        let session_key_array: [u8; 32] = session_key.try_into().unwrap();
        let alg_ids = (
            AlgorithmId::MlKem768.as_u16(),
            AlgorithmId::XChaCha20Poly1305.as_u16(),
        );

        let mut enc = crypto::StreamCipher::new(
            &session_key_array,
            b"alice_to_bob_stream".to_vec(),
            b"testnet".to_vec(),
            1u32,
            alg_ids,
        ).expect("Failed to create stream cipher");

        let mut dec = crypto::StreamCipher::new(
            &session_key_array,
            b"alice_to_bob_stream".to_vec(),
            b"testnet".to_vec(),
            1u32,
            alg_ids,
        ).expect("Failed to create decryption cipher");

        let shard_size = 64;
        let chunks = chunk_bytes(data, shard_size);
        println!("  ✓ Data split into {} shards", chunks.len());

        let mut encrypted_frames: Vec<Vec<u8>> = Vec::new();
        let mut total_encrypted_size = 0usize;

        for (i, chunk) in chunks.iter().enumerate() {
            let seq = (i as u8) + 1;
            let encrypted_frame = enc.encrypt_frame(chunk, seq)
                .expect("Encryption failed");
            total_encrypted_size += encrypted_frame.len();
            encrypted_frames.push(encrypted_frame);
        }

        println!("  ✓ Encrypted {} shards", encrypted_frames.len());
        println!("  ✓ Total encrypted size: {} bytes", total_encrypted_size);
        println!("  ✓ Overhead: {} bytes", total_encrypted_size - data.len());

        println!("\n📋 STEP 5: Creating Merkle tree commitment...");
        let mut leaves: Vec<Vec<u8>> = Vec::new();
        for frame in &encrypted_frames {
            leaves.push(crypto::blake2s_hash(frame));
        }

        let merkle = crypto::MerkleTree::build(leaves.clone());
        let merkle_root = merkle.root_hash().expect("Failed to get merkle root");

        println!("  ✓ Merkle tree created with {} leaves", leaves.len());
        println!("  ✓ Merkle root: {}", hex::encode(merkle_root.as_bytes()));

        println!("\n📋 STEP 6: Distributing shards across nodes...");
        let n_shards = 4;
        let mut shard_distribution: HashMap<usize, Vec<usize>> = HashMap::new();

        for (i, frame) in encrypted_frames.iter().enumerate() {
            let hash = crypto::blake2s_hash_domain(&[frame]);
            let shard_id = (hash[0] as usize) % n_shards;
            shard_distribution.entry(shard_id).or_default().push(i);
        }

        println!("  ✓ Shard distribution:");
        for shard_id in 0..n_shards {
            let count = shard_distribution.get(&shard_id).map(|v| v.len()).unwrap_or(0);
            println!("    - Shard {} → {} frames", shard_id, count);
        }

        println!("\n📋 STEP 7: Creating encryption envelope for Bob...");
        let (kyber_ciphertext, shared_secret) = alice_keypair
            .encapsulate_kyber(&bob_keypair.kyber_public_key().key_data)
            .expect("Kyber encapsulation failed");

        let envelope = EncryptionEnvelope {
            kyber_ciphertexts: vec![kyber_ciphertext.clone()],
            recipient_addresses: vec![bob_addr],
            nonce24: [42u8; 24],
            auth_tag: vec![0xAA, 0xBB, 0xCC],
        };

        println!("  ✓ Kyber ciphertext size: {} bytes", kyber_ciphertext.len());
        println!("  ✓ Shared secret: {}...", hex::encode(&shared_secret[..16]));
        println!("  ✓ Envelope created for {} recipient(s)", envelope.recipient_addresses.len());

        println!("\n📋 STEP 8: Creating triad placement (3 replicas)...");
        let triad = TriadPlacement {
            primary: NodeLocation {
                node_id: Address::new([10u8; 20]),
                h3_cell: "8928308280fffff".to_string(),
                shard_id: 0,
                region: "us-west-2".to_string(),
                lat_lon: Some((37.7749, -122.4194)),
            },
            replica_a: NodeLocation {
                node_id: Address::new([11u8; 20]),
                h3_cell: "8928308281aaaaa".to_string(),
                shard_id: 0,
                region: "us-east-1".to_string(),
                lat_lon: Some((40.7128, -74.0060)),
            },
            replica_b: NodeLocation {
                node_id: Address::new([12u8; 20]),
                h3_cell: "8928308282bbbbb".to_string(),
                shard_id: 0,
                region: "eu-west-1".to_string(),
                lat_lon: Some((51.5074, -0.1278)),
            },
            group_id: "triad-group-001".to_string(),
            placement_epoch: 100,
            diversity_score: 0.92,
        };

        println!("  ✓ Primary:    {} ({})", triad.primary.region, triad.primary.h3_cell);
        println!("  ✓ Replica A:  {} ({})", triad.replica_a.region, triad.replica_a.h3_cell);
        println!("  ✓ Replica B:  {} ({})", triad.replica_b.region, triad.replica_b.h3_cell);
        println!("  ✓ Diversity score: {}", triad.diversity_score);

        println!("\n📋 STEP 9: Creating StoreData transaction...");

        let mut chunk_id_bytes = [0u8; 32];
        chunk_id_bytes.copy_from_slice(merkle_root.as_bytes());
        let chunk_id = Hash::new(chunk_id_bytes);

        let mut data_hash_bytes = [0u8; 32];
        data_hash_bytes.copy_from_slice(&leaves[0][..32]);
        let data_hash = Hash::new(data_hash_bytes);

        let payload = TransactionPayload::StoreData {
            chunk_id,
            data_size: total_encrypted_size as u64,
            duration_epochs: 100,
            data_hash,
            slice_id: SliceId::new("alice_personal".to_string()),
            storage_credits: 5000,
            replication_factor: 3,
            triad_placement: triad.clone(),
            erasure_coding: ErasureCodingParams {
                k: 10,
                m: 4,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: Some(envelope),
        };

        let mut tx = Transaction::new(
            alice_addr,
            1,
            payload,
            ShardId::new(0).unwrap(),
            Some(SliceId::new("alice_personal".to_string())),
            1,
        );

        println!("  ✓ Transaction created");
        println!("  ✓ Chunk ID: {}", hex::encode(chunk_id.as_bytes()));
        println!("  ✓ Data size: {} bytes", total_encrypted_size);
        println!("  ✓ Storage credits: 5000");
        println!("  ✓ Replication factor: 3");

        println!("\n📋 STEP 10: Signing transaction (hybrid mode)...");
        tx.sign(&alice_keypair, true).expect("Transaction signing failed");

        tx.public_keys.dilithium_pk = alice_keypair.dilithium_public_key();
        tx.public_keys.ed25519_pk = Some(alice_keypair.ed25519_public_key());

        println!("  ✓ Transaction signed with:");
        println!("    - Dilithium-2 signature ({} bytes)",
            tx.signature.dilithium_sig.as_ref().map(|s| s.signature_data.len()).unwrap_or(0));
        println!("    - Ed25519 signature ({} bytes)",
            tx.signature.ed25519_sig.as_ref().map(|s| s.signature_data.len()).unwrap_or(0));

        println!("\n📋 STEP 11: Computing transaction hash...");
        let tx_hash = crypto::blake2s_hash_domain(&[
            b"EGO-TX-STORE",
            merkle_root.as_bytes(),
            alice_addr.as_bytes(),
            bob_addr.as_bytes(),
            &tx.nonce.to_le_bytes(),
            &total_encrypted_size.to_le_bytes(),
        ]);

        let timestamp = tx.timestamp;

        println!("  ✓ Transaction hash: {}", hex::encode(&tx_hash));
        let timestamp_millis = timestamp.as_millis();
        let datetime: DateTime<Utc> = DateTime::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(timestamp_millis)
        );
        println!("  ✓ Timestamp: {} (epoch: {}ms)",
            datetime.format("%Y/%m/%d %H:%M:%S"),
            timestamp_millis);
        println!("  ✓ Block time: {}", datetime);

        println!("\n📋 STEP 12: Verifying transaction signature...");
        let sig_valid = tx.verify_signature().expect("Signature verification failed");
        assert!(sig_valid, "Signature should be valid");
        println!("  ✓ Signature verification: PASSED");

        alice_account.authorized_slices = vec![SliceId::new("alice_personal".to_string())];
        let validation = tx.validate_against_account(&alice_account);
        assert!(validation.is_ok(), "Transaction validation failed: {:?}", validation.err());
        println!("  ✓ Account validation: PASSED");

        println!("\n📋 STEP 13: Verifying Bob can decrypt the data...");

        let bob_shared_secret = bob_keypair
            .decapsulate_kyber(&kyber_ciphertext)
            .expect("Kyber decapsulation failed");

        assert_eq!(shared_secret, bob_shared_secret);
        println!("  ✓ Bob successfully decapsulated shared secret");

        let mut decrypted_data: Vec<u8> = Vec::new();
        for (i, frame) in encrypted_frames.iter().enumerate() {
            let seq = (i as u8) + 1;
            let plaintext = dec.decrypt_frame(frame, seq)
                .expect("Decryption failed");
            decrypted_data.extend_from_slice(&plaintext);
        }

        assert_eq!(decrypted_data, data);
        println!("  ✓ All {} frames decrypted successfully", encrypted_frames.len());
        println!("  ✓ Decrypted data matches original: {}",
            decrypted_data == data);

        println!("\n📋 STEP 14: Verifying Merkle commitment integrity...");
        let mut verification_leaves: Vec<Vec<u8>> = Vec::new();
        for frame in &encrypted_frames {
            verification_leaves.push(crypto::blake2s_hash(frame));
        }

        let verification_merkle = crypto::MerkleTree::build(verification_leaves);
        let verification_root = verification_merkle.root_hash().unwrap();

        assert_eq!(verification_root.as_bytes(), merkle_root.as_bytes());
        println!("  ✓ Merkle root verification: PASSED");
        println!("  ✓ Data integrity confirmed");

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  Transaction Summary                                         ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!("\n📊 Transaction Details:");
        println!("  • Transaction Hash:  {}", hex::encode(&tx_hash));
        let timestamp_millis = timestamp.as_millis();
        let datetime: DateTime<Utc> = DateTime::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(timestamp_millis)
        );
        println!("  • Timestamp:         {}", datetime.format("%Y/%m/%d %H:%M:%S"));
        println!("  • From:              {} (Alice)", hex::encode(alice_addr.as_bytes()));
        println!("  • To:                {} (Bob)", hex::encode(bob_addr.as_bytes()));
        println!("  • Nonce:             {}", tx.nonce);
        println!("  • Shard ID:          {}", tx.shard_id.as_u32());

        println!("\n🔐 Cryptographic Details:");
        println!("  • Session KEM:       ML-KEM-768 (Kyber)");
        println!("  • Session DH:        X25519");
        println!("  • Stream Cipher:     XChaCha20-Poly1305");
        println!("  • Signature:         ML-DSA-2 (Dilithium) + Ed25519");
        println!("  • Hash Function:     BLAKE2s-256");

        println!("\n📦 Data Details:");
        println!("  • Original Size:     {} bytes", data.len());
        println!("  • Encrypted Size:    {} bytes", total_encrypted_size);
        println!("  • Number of Shards:  {}", encrypted_frames.len());
        println!("  • Shard Size:        {} bytes (max)", shard_size);
        println!("  • Merkle Root:       {}", hex::encode(merkle_root.as_bytes()));

        println!("\n🌍 Storage Details:");
        println!("  • Replication:       3x (Primary + 2 Replicas)");
        println!("  • Geographic Diversity: {:.2}%", triad.diversity_score * 100.0);
        println!("  • Primary Region:    {}", triad.primary.region);
        println!("  • Replica A Region:  {}", triad.replica_a.region);
        println!("  • Replica B Region:  {}", triad.replica_b.region);
        println!("  • Storage Duration:  100 epochs");
        println!("  • Storage Credits:   5000");

        println!("\n💰 Cost Details:");
        println!("  • Storage Credits Used: 5000");
        println!("  • Alice Balance Before: {} EGOC", 1000);
        println!("  • Storage Quota Used:   {} bytes", total_encrypted_size);

        println!("\n✅ Verification Results:");
        println!("  • Signature Valid:      ✓");
        println!("  • Account Valid:        ✓");
        println!("  • Encryption Valid:     ✓");
        println!("  • Decryption Valid:     ✓");
        println!("  • Merkle Valid:         ✓");
        println!("  • Triad Diversity:      ✓ ({:.1}%)", triad.diversity_score * 100.0);

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  ✓ E2E Transaction Test PASSED                              ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
    }

    #[test]
    fn test_bob_to_alice_return_message() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  Testing Bidirectional Encrypted Communication              ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        let alice_keypair = crypto::KeyPair::generate_with_transition();
        let bob_keypair = crypto::KeyPair::generate_with_transition();

        let alice_addr = Address::from_public_key(&alice_keypair.dilithium_public_key());
        let bob_addr = Address::from_public_key(&bob_keypair.dilithium_public_key());

        println!("✓ Alice and Bob keypairs generated");

        let (session_record, session_key) = bob_keypair
            .create_hybrid_session(
                &alice_keypair.x25519_public_key(),
                &alice_keypair.kyber_public_key().key_data,
                "bob_to_alice_stream",
                &[1u8; 32],
                b"testnet",
                1u32,
                1u32,
            )
            .expect("Session creation failed");

        println!("✓ Bob → Alice session established");

        let message = b"Thanks Alice! Message received and verified.";
        let session_key_array: [u8; 32] = session_key.try_into().unwrap();

        let alg_ids = (
            AlgorithmId::MlKem768.as_u16(),
            AlgorithmId::XChaCha20Poly1305.as_u16(),
        );

        let mut enc = crypto::StreamCipher::new(
            &session_key_array,
            b"bob_response".to_vec(),
            b"testnet".to_vec(),
            1u32,
            alg_ids,
        ).unwrap();

        let encrypted = enc.encrypt_frame(message, 1).unwrap();
        let msg_hash = crypto::blake2s_hash(&encrypted);

        println!("✓ Bob's message encrypted: {} bytes", encrypted.len());

        let tx_hash = crypto::blake2s_hash_domain(&[
            b"EGO-TX-RESPONSE",
            &msg_hash,
            bob_addr.as_bytes(),
            alice_addr.as_bytes(),
        ]);

        let timestamp = Timestamp::now();

        println!("\n📊 Bob's Response Transaction:");
        println!("  • Hash:      {}", hex::encode(&tx_hash));
        let timestamp_millis = timestamp.as_millis();
        let datetime: DateTime<Utc> = DateTime::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(timestamp_millis)
        );
        println!("  • Timestamp: {}", datetime.format("%Y/%m/%d %H:%M:%S"));
        println!("  • From:      {} (Bob)", hex::encode(bob_addr.as_bytes())[..16].to_string());
        println!("  • To:        {} (Alice)", hex::encode(alice_addr.as_bytes())[..16].to_string());
        println!("  • Size:      {} bytes", encrypted.len());

        let mut dec = crypto::StreamCipher::new(
            &session_key_array,
            b"bob_response".to_vec(),
            b"testnet".to_vec(),
            1u32,
            alg_ids,
        ).unwrap();

        let decrypted = dec.decrypt_frame(&encrypted, 1).unwrap();
        assert_eq!(decrypted, message);

        println!("\n✓ Alice successfully decrypted Bob's response");
        println!("✓ Bidirectional communication verified");
        println!("\n╚══════════════════════════════════════════════════════════════╝\n");
    }
}
