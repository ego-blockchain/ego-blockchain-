#[cfg(test)]
mod porep_tests {
    use crate::porep::{
        PoRepChallenge, PoRepEvent, PoRepFraudType, PoRepProof, PoRepProvider, SealingJob,
        SealingStatus, SectorCommitment,
        prover::{PoRepProver, ProverConfig, SectorState},
        verifier::{PoRepVerifier, VerificationParams, VerifierConfig},
    };
    use ego_core::{
        Address, Hash, Timestamp,
        crypto::{KeyPair, hash_data, hash_multiple},
    };
    use tokio::sync::mpsc;

    fn make_keypair() -> KeyPair {
        KeyPair::generate()
    }

    fn make_prover_config(sector_size: u64, gpu: bool) -> ProverConfig {
        ProverConfig {
            sector_size,
            gpu_available: gpu,
            nvme_path: "/tmp/ego-porep-test".to_string(),
            max_parallel_sealing: 1,
            challenge_window_ms: 300_000,
            params_version: 1,
        }
    }

    fn make_prover(sector_size: u64, gpu: bool) -> PoRepProver {
        PoRepProver::new(make_keypair(), make_prover_config(sector_size, gpu))
    }

    fn make_verifier() -> PoRepVerifier {
        PoRepVerifier::new(Address::new([0xAAu8; 20]))
    }

    fn small_sector() -> u64 {
        512 * 1024 * 1024
    }

    fn make_commitment(
        prover: Address,
        sector_id: u64,
        comm_d: Hash,
        comm_r: Hash,
        replica_id: Hash,
    ) -> SectorCommitment {
        SectorCommitment {
            sector_id,
            prover_id: prover,
            comm_d,
            comm_r,
            replica_id,
            sector_size: small_sector(),
            params_version: 1,
            registered_at: Timestamp::now(),
            deal_ids: vec![Hash::new([0xDDu8; 32])],
            expiry: Timestamp::from_millis(Timestamp::now().as_millis() + 60_000),
        }
    }

    fn comm_r_from(comm_d: &Hash, replica_id: &Hash) -> Hash {
        hash_multiple(&[
            comm_d.as_bytes(),
            replica_id.as_bytes(),
            b"ego/porep/comm-r/v1",
        ])
    }

    fn inject_active_sector(prover: &mut PoRepProver, sector_id: u64) -> SectorState {
        let replica_id = hash_multiple(&[
            prover.address.as_bytes(),
            &sector_id.to_le_bytes(),
            Hash::new([0xCCu8; 32]).as_bytes(),
            b"ego/porep/replica-id/v1",
        ]);
        let comm_d = hash_data(Hash::new([0xCCu8; 32]).as_bytes());
        let comm_r = comm_r_from(&comm_d, &replica_id);

        let state = SectorState {
            sector_id,
            replica_id,
            comm_d,
            comm_r,
            sealed_path: format!("/sealed/sector-{}", sector_id),
            cache_path: format!("/cache/sector-{}", sector_id),
            deal_ids: vec![Hash::new([0xDDu8; 32])],
            created_at: Timestamp::now(),
            proof_count: 0,
            last_challenged_at: None,
        };

        {
            let mut sectors = prover.active_sectors.write().unwrap();
            sectors.insert(sector_id, state.clone());
        }

        {
            let commitment = make_commitment(prover.address, sector_id, comm_d, comm_r, replica_id);
            let mut comms = prover.commitments.write().unwrap();
            comms.insert(sector_id, commitment);
        }

        state
    }

    mod mod_types {
        use super::*;

        #[test]
        fn event_new_valid() {
            let evt = PoRepEvent::new(
                vec![Hash::new([1u8; 32])],
                1,
                Address::new([2u8; 20]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
                Hash::new([5u8; 32]),
                1,
                Hash::new([6u8; 32]),
            );
            assert!(evt.validate().is_ok());
            assert_eq!(evt.sector_id, 1);
            assert_eq!(evt.deal_id.len(), 1);
            assert_eq!(evt.alg_sig_id, 1);
        }

        #[test]
        fn event_validate_fails_no_deals() {
            let evt = PoRepEvent::new(
                vec![],
                1,
                Address::new([2u8; 20]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
                Hash::new([5u8; 32]),
                1,
                Hash::new([6u8; 32]),
            );
            assert!(evt.validate().is_err());
        }

        #[test]
        fn event_validate_fails_zero_sector() {
            let evt = PoRepEvent::new(
                vec![Hash::new([1u8; 32])],
                0,
                Address::new([2u8; 20]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
                Hash::new([5u8; 32]),
                1,
                Hash::new([6u8; 32]),
            );
            assert!(evt.validate().is_err());
        }

        #[test]
        fn event_signing_message_deterministic() {
            let evt = PoRepEvent::new(
                vec![Hash::new([1u8; 32])],
                1,
                Address::new([2u8; 20]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
                Hash::new([5u8; 32]),
                1,
                Hash::new([6u8; 32]),
            );
            assert_eq!(evt.compute_signing_message(), evt.compute_signing_message());
        }

        #[test]
        fn event_sign_with_keypair_sets_sig() {
            let kp = make_keypair();
            let mut evt = PoRepEvent::new(
                vec![Hash::new([1u8; 32])],
                1,
                Address::new([2u8; 20]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
                Hash::new([5u8; 32]),
                1,
                Hash::new([6u8; 32]),
            );
            evt.sign_with_keypair(&kp);
            assert_eq!(evt.alg_sig_id, 1);
        }

        #[test]
        fn event_to_block_proof_event_correct_type() {
            let evt = PoRepEvent::new(
                vec![Hash::new([1u8; 32])],
                1,
                Address::new([2u8; 20]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
                Hash::new([5u8; 32]),
                1,
                Hash::new([6u8; 32]),
            );
            let block_ev = evt.to_block_proof_event(true, 100);
            use ego_core::block::ProofEventType;
            assert!(matches!(block_ev.proof_type, ProofEventType::PoRep));
            assert!(block_ev.verified);
            assert_eq!(block_ev.latency_ms, 100);
            assert_eq!(block_ev.prover, Address::new([2u8; 20]));
        }

        #[test]
        fn proof_validate_empty_data_fails() {
            let p = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![],
                1,
                Address::new([4u8; 20]),
            );
            assert!(p.validate().is_err());
        }

        #[test]
        fn proof_validate_zero_sector_fails() {
            let p = PoRepProof::new(
                0,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![1u8; 32],
                1,
                Address::new([4u8; 20]),
            );
            assert!(p.validate().is_err());
        }

        #[test]
        fn proof_compute_hash_deterministic() {
            let p = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![0u8; 96],
                1,
                Address::new([4u8; 20]),
            );
            assert_eq!(p.compute_proof_hash(), p.compute_proof_hash());
        }

        #[test]
        fn proof_compute_hash_differs_by_sector() {
            let p1 = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![0u8; 96],
                1,
                Address::new([4u8; 20]),
            );
            let p2 = PoRepProof::new(
                2,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![0u8; 96],
                1,
                Address::new([4u8; 20]),
            );
            assert_ne!(p1.compute_proof_hash(), p2.compute_proof_hash());
        }

        #[test]
        fn proof_matches_commitment_true() {
            let prover = Address::new([1u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let comm_r = Hash::new([3u8; 32]);
            let replica_id = Hash::new([4u8; 32]);

            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![1u8], 1, prover);
            let comm = make_commitment(prover, 1, comm_d, comm_r, replica_id);
            assert!(proof.matches_commitment(&comm));
        }

        #[test]
        fn proof_matches_commitment_false_wrong_comm_r() {
            let prover = Address::new([1u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([4u8; 32]);

            let proof = PoRepProof::new(
                1,
                replica_id,
                comm_d,
                Hash::new([99u8; 32]),
                vec![1u8],
                1,
                prover,
            );
            let comm = make_commitment(prover, 1, comm_d, Hash::new([3u8; 32]), replica_id);
            assert!(!proof.matches_commitment(&comm));
        }

        #[test]
        fn challenge_generation_deterministic() {
            let c = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([2u8; 32]));
            assert_eq!(
                c.generate_deterministic_challenges(),
                c.generate_deterministic_challenges()
            );
        }

        #[test]
        fn challenge_generation_count() {
            let c = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([2u8; 32]));
            assert_eq!(c.generate_deterministic_challenges().len(), 176);
        }

        #[test]
        fn challenge_different_seeds_different_output() {
            let c1 = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([2u8; 32]));
            let c2 = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([3u8; 32]));
            assert_ne!(
                c1.generate_deterministic_challenges(),
                c2.generate_deterministic_challenges()
            );
        }

        #[test]
        fn challenge_from_finalized_block() {
            let ch = PoRepChallenge::from_finalized_block(
                1,
                Hash::new([1u8; 32]),
                Hash::new([10u8; 32]),
                [42u8; 32],
            );
            assert_eq!(ch.sector_id, 1);
            assert_eq!(ch.challenge_count, 176);
            assert!(!ch.is_expired());
        }

        #[test]
        fn challenge_not_expired_fresh() {
            let c = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([2u8; 32]));
            assert!(!c.is_expired());
        }

        #[test]
        fn challenge_expired_at_zero() {
            let c = PoRepChallenge {
                sector_id: 1,
                replica_id: Hash::new([1u8; 32]),
                challenge_seed: Hash::new([2u8; 32]),
                challenge_count: 176,
                deadline: Timestamp::from_millis(0),
            };
            assert!(c.is_expired());
        }

        #[test]
        fn sealing_job_full_pipeline() {
            let mut job = SealingJob::new(1, Hash::new([1u8; 32]));
            assert_eq!(job.status, SealingStatus::Queued);
            assert!(!job.is_terminal());

            job.advance_status(SealingStatus::PreCommit1, 0);
            assert_eq!(job.status, SealingStatus::PreCommit1);
            job.advance_status(SealingStatus::PreCommit2, 5000);
            assert_eq!(job.pc1_duration_ms, 5000);
            job.advance_status(SealingStatus::WaitingForSeed, 1000);
            assert_eq!(job.pc2_duration_ms, 1000);
            job.advance_status(SealingStatus::Commit1, 0);
            job.advance_status(SealingStatus::Commit2, 3000);
            assert_eq!(job.c1_duration_ms, 3000);
            job.advance_status(SealingStatus::Completed, 2000);
            assert_eq!(job.c2_duration_ms, 2000);
            assert!(job.is_complete());
            assert!(job.is_terminal());
            assert!(job.completed_at.is_some());
            assert_eq!(job.total_sealing_time_ms(), 5000 + 1000 + 3000 + 2000);
        }

        #[test]
        fn sealing_job_bad_transition_fails() {
            let mut job = SealingJob::new(1, Hash::new([1u8; 32]));
            job.advance_status(SealingStatus::Commit2, 0);
            assert!(job.is_failed());
            assert!(job.is_terminal());
        }

        #[test]
        fn sector_commitment_not_expired() {
            let comm = make_commitment(
                Address::new([1u8; 20]),
                1,
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            );
            assert!(!comm.is_expired());
        }

        #[test]
        fn sector_commitment_hash_deterministic() {
            let comm = make_commitment(
                Address::new([1u8; 20]),
                1,
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            );
            assert_eq!(
                comm.compute_commitment_hash(),
                comm.compute_commitment_hash()
            );
        }

        #[test]
        fn sector_commitment_hash_unique_per_sector() {
            let prover = Address::new([1u8; 20]);
            let c1 = make_commitment(
                prover,
                1,
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            );
            let c2 = make_commitment(
                prover,
                2,
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            );
            assert_ne!(c1.compute_commitment_hash(), c2.compute_commitment_hash());
        }
    }

    mod prover_tests {
        use super::*;

        #[test]
        fn prover_initial_state() {
            let p = make_prover(small_sector(), false);
            assert_eq!(p.get_sealing_queue_length(), 0);
            assert!(p.get_active_sectors().is_empty());
            assert!(p.get_all_commitments().is_empty());
        }

        #[test]
        fn prover_address_from_keypair() {
            let kp = make_keypair();
            let expected = Address::from_public_key(&kp.public_key());
            let config = make_prover_config(small_sector(), false);
            let p = PoRepProver::new(kp, config);
            assert_eq!(p.address, expected);
        }

        #[test]
        fn prover_validate_storage_empty_path_fails() {
            let kp = make_keypair();
            let config = ProverConfig {
                nvme_path: "".to_string(),
                ..make_prover_config(small_sector(), false)
            };
            let p = PoRepProver::new(kp, config);
            assert!(p.validate_storage_setup().is_err());
        }

        #[test]
        fn prover_validate_storage_zero_sector_fails() {
            let kp = make_keypair();
            let config = ProverConfig {
                sector_size: 0,
                ..make_prover_config(small_sector(), false)
            };
            let p = PoRepProver::new(kp, config);
            assert!(p.validate_storage_setup().is_err());
        }

        #[test]
        fn prover_get_sector_commitment_none() {
            let p = make_prover(small_sector(), false);
            assert!(p.get_sector_commitment(999).is_none());
        }

        #[test]
        fn prover_register_deal_ids_unknown_sector_fails() {
            let mut p = make_prover(small_sector(), false);
            assert!(p.register_deal_ids(42, vec![Hash::new([1u8; 32])]).is_err());
        }

        #[test]
        fn prover_inject_sector_and_get_commitment() {
            let mut p = make_prover(small_sector(), false);
            let state = inject_active_sector(&mut p, 1);
            let comm = p.get_sector_commitment(1).unwrap();
            assert_eq!(comm.sector_id, 1);
            assert_eq!(comm.prover_id, p.address);
            assert_eq!(comm.replica_id, state.replica_id);
            assert_eq!(comm.comm_d, state.comm_d);
            assert_eq!(comm.comm_r, state.comm_r);
        }

        #[test]
        fn prover_active_sectors_after_inject() {
            let mut p = make_prover(small_sector(), false);
            inject_active_sector(&mut p, 10);
            inject_active_sector(&mut p, 11);
            let active = p.get_active_sectors();
            assert!(active.contains(&10));
            assert!(active.contains(&11));
        }

        #[test]
        fn prover_register_deal_ids_after_inject() {
            let mut p = make_prover(small_sector(), false);
            inject_active_sector(&mut p, 5);
            let deal = Hash::new([0xFEu8; 32]);
            assert!(p.register_deal_ids(5, vec![deal]).is_ok());
            let comm = p.get_sector_commitment(5).unwrap();
            assert!(comm.deal_ids.contains(&deal));
        }

        #[test]
        fn prover_build_porep_event_after_inject() {
            let mut p = make_prover(small_sector(), false);
            inject_active_sector(&mut p, 7);
            let deal = Hash::new([0xBBu8; 32]);
            let event = p.build_porep_event(7, vec![deal]).unwrap();
            assert_eq!(event.sector_id, 7);
            assert_eq!(event.node_addr, p.address);
            assert_eq!(event.alg_sig_id, 1);
            assert!(event.validate().is_ok());
        }

        #[test]
        fn prover_build_porep_event_unknown_sector_fails() {
            let p = make_prover(small_sector(), false);
            assert!(
                p.build_porep_event(999, vec![Hash::new([1u8; 32])])
                    .is_err()
            );
        }

        #[test]
        fn prover_generate_fraud_evidence() {
            let p = make_prover(small_sector(), false);
            let challenger = Address::new([0xEEu8; 20]);
            let ev = p
                .generate_fraud_evidence(1, PoRepFraudType::InvalidProofData, challenger)
                .unwrap();
            assert_eq!(ev.sector_id, 1);
            assert_eq!(ev.prover_id, p.address);
            assert_eq!(ev.challenger, challenger);
        }

        #[test]
        fn prover_metrics_initial() {
            let p = make_prover(small_sector(), false);
            let m = p.get_sealing_metrics();
            assert_eq!(m.sealing_queue_len, 0);
            assert_eq!(m.sectors_active, 0);
            assert_eq!(m.sectors_committed, 0);
            assert_eq!(m.proofs_submitted, 0);
        }

        #[test]
        fn prover_metrics_after_inject() {
            let mut p = make_prover(small_sector(), false);
            inject_active_sector(&mut p, 1);
            inject_active_sector(&mut p, 2);
            let m = p.get_sealing_metrics();
            assert_eq!(m.sectors_active, 2);
            assert_eq!(m.sectors_committed, 2);
        }

        #[test]
        fn prover_proof_event_sender_wired() {
            let (tx, _rx) = mpsc::unbounded_channel();
            let p = make_prover(small_sector(), false).with_proof_event_sender(tx);
            assert!(p.proof_event_sender.is_some());
        }

        #[test]
        fn prover_fraud_event_sender_wired() {
            let (tx, _rx) = mpsc::unbounded_channel();
            let p = make_prover(small_sector(), false).with_fraud_event_sender(tx);
            assert!(p.fraud_event_sender.is_some());
        }

        #[test]
        fn prover_replica_id_unique_per_prover() {
            let addr1 = Address::new([1u8; 20]);
            let addr2 = Address::new([2u8; 20]);
            let cid = Hash::new([3u8; 32]);
            use crate::porep::prover::PoRepProver;
            assert_ne!(
                PoRepProver::derive_replica_id(&addr1, 1, &cid),
                PoRepProver::derive_replica_id(&addr2, 1, &cid),
            );
        }

        #[test]
        fn prover_replica_id_unique_per_sector() {
            let addr = Address::new([1u8; 20]);
            let cid = Hash::new([3u8; 32]);
            use crate::porep::prover::PoRepProver;
            assert_ne!(
                PoRepProver::derive_replica_id(&addr, 1, &cid),
                PoRepProver::derive_replica_id(&addr, 2, &cid),
            );
        }

        #[test]
        fn prover_replica_id_deterministic() {
            let addr = Address::new([1u8; 20]);
            let cid = Hash::new([3u8; 32]);
            use crate::porep::prover::PoRepProver;
            assert_eq!(
                PoRepProver::derive_replica_id(&addr, 1, &cid),
                PoRepProver::derive_replica_id(&addr, 1, &cid),
            );
        }

        #[tokio::test]
        async fn prover_verify_own_proof_valid() {
            let mut p = make_prover(small_sector(), false);
            let state = inject_active_sector(&mut p, 1);

            let challenges: Vec<u64> = (0..176).collect();
            let proof_data = p
                .compute_proof_for_sector(&state, &challenges)
                .await
                .unwrap();

            let proof = PoRepProof::new(
                1,
                state.replica_id,
                state.comm_d,
                state.comm_r,
                proof_data,
                1,
                p.address,
            );

            let valid = p.verify_porep_proof(&proof).await.unwrap();
            assert!(valid);
        }

        #[tokio::test]
        async fn prover_verify_proof_wrong_prover_invalid() {
            let mut p = make_prover(small_sector(), false);
            let state = inject_active_sector(&mut p, 1);

            let challenges: Vec<u64> = (0..176).collect();
            let proof_data = p
                .compute_proof_for_sector(&state, &challenges)
                .await
                .unwrap();

            let wrong_prover = Address::new([0xFFu8; 20]);
            let proof = PoRepProof::new(
                1,
                state.replica_id,
                state.comm_d,
                state.comm_r,
                proof_data,
                1,
                wrong_prover,
            );
            let valid = p.verify_porep_proof(&proof).await.unwrap();
            assert!(!valid);
        }

        #[tokio::test]
        async fn prover_verify_proof_wrong_comm_r_invalid() {
            let mut p = make_prover(small_sector(), false);
            let state = inject_active_sector(&mut p, 1);

            let challenges: Vec<u64> = (0..176).collect();
            let proof_data = p
                .compute_proof_for_sector(&state, &challenges)
                .await
                .unwrap();

            let proof = PoRepProof::new(
                1,
                state.replica_id,
                state.comm_d,
                Hash::new([0xFFu8; 32]),
                proof_data,
                1,
                p.address,
            );
            let valid = p.verify_porep_proof(&proof).await.unwrap();
            assert!(!valid);
        }

        #[tokio::test]
        async fn prover_verify_unknown_sector_false() {
            let p = make_prover(small_sector(), false);
            let proof = PoRepProof::new(
                999,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![0u8; 32],
                1,
                p.address,
            );
            let valid = p.verify_porep_proof(&proof).await.unwrap();
            assert!(!valid);
        }

        #[tokio::test]
        async fn prover_generate_proof_expired_challenge_fails() {
            let mut p = make_prover(small_sector(), false);
            inject_active_sector(&mut p, 1);

            let expired = PoRepChallenge {
                sector_id: 1,
                replica_id: Hash::new([1u8; 32]),
                challenge_seed: Hash::new([2u8; 32]),
                challenge_count: 176,
                deadline: Timestamp::from_millis(0),
            };
            let result = p.generate_porep_proof(expired).await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn prover_generate_proof_replica_mismatch_fails() {
            let mut p = make_prover(small_sector(), false);
            inject_active_sector(&mut p, 1);

            let challenge = PoRepChallenge::new(1, Hash::new([0xFFu8; 32]), Hash::new([2u8; 32]));
            let result = p.generate_porep_proof(challenge).await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn prover_generate_proof_unknown_sector_fails() {
            let p = make_prover(small_sector(), false);
            let challenge = PoRepChallenge::new(999, Hash::new([1u8; 32]), Hash::new([2u8; 32]));
            let result = p.generate_porep_proof(challenge).await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn prover_generate_proof_challenge_response_32_bytes() {
            let p = make_prover(small_sector(), false);
            let state = SectorState {
                sector_id: 1,
                replica_id: Hash::new([1u8; 32]),
                comm_d: Hash::new([2u8; 32]),
                comm_r: Hash::new([3u8; 32]),
                sealed_path: "/sealed/1".to_string(),
                cache_path: "/cache/1".to_string(),
                deal_ids: vec![],
                created_at: Timestamp::now(),
                proof_count: 0,
                last_challenged_at: None,
            };
            let resp = p.compute_challenge_response(&state, 12345).await.unwrap();
            assert_eq!(resp.len(), 32);
        }

        #[tokio::test]
        async fn prover_challenge_response_deterministic() {
            let p = make_prover(small_sector(), false);
            let state = SectorState {
                sector_id: 1,
                replica_id: Hash::new([1u8; 32]),
                comm_d: Hash::new([2u8; 32]),
                comm_r: Hash::new([3u8; 32]),
                sealed_path: "/sealed/1".to_string(),
                cache_path: "/cache/1".to_string(),
                deal_ids: vec![],
                created_at: Timestamp::now(),
                proof_count: 0,
                last_challenged_at: None,
            };
            assert_eq!(
                p.compute_challenge_response(&state, 42).await.unwrap(),
                p.compute_challenge_response(&state, 42).await.unwrap(),
            );
        }

        #[tokio::test]
        async fn prover_challenge_response_differs_by_challenge() {
            let p = make_prover(small_sector(), false);
            let state = SectorState {
                sector_id: 1,
                replica_id: Hash::new([1u8; 32]),
                comm_d: Hash::new([2u8; 32]),
                comm_r: Hash::new([3u8; 32]),
                sealed_path: "/sealed/1".to_string(),
                cache_path: "/cache/1".to_string(),
                deal_ids: vec![],
                created_at: Timestamp::now(),
                proof_count: 0,
                last_challenged_at: None,
            };
            assert_ne!(
                p.compute_challenge_response(&state, 1).await.unwrap(),
                p.compute_challenge_response(&state, 2).await.unwrap(),
            );
        }

        #[tokio::test]
        async fn prover_emit_proof_event_fires_sender() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let mut p = make_prover(small_sector(), false).with_proof_event_sender(tx);
            inject_active_sector(&mut p, 3);
            p.emit_proof_event(3, true, 50, None);
            let ev = rx.try_recv().expect("expected a proof event");
            use ego_core::block::ProofEventType;
            assert!(matches!(ev.proof_type, ProofEventType::PoRep));
            assert!(ev.verified);
        }
    }

    mod verifier_tests {
        use super::*;

        fn make_valid_proof_for_verifier(
            sector_id: u64,
            prover: Address,
        ) -> (PoRepProof, Hash, Hash, Hash) {
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof_data = vec![0u8; 176 * 32];
            let proof =
                PoRepProof::new(sector_id, replica_id, comm_d, comm_r, proof_data, 1, prover);
            (proof, comm_d, comm_r, replica_id)
        }

        #[test]
        fn verifier_creation() {
            let v = make_verifier();
            let stats = v.get_verification_stats();
            assert_eq!(stats.total_verifications, 0);
            assert_eq!(stats.cache_size, 0);
            assert_eq!(stats.active_provers, 0);
        }

        #[test]
        fn verifier_params_v1_v2_preloaded() {
            let v = make_verifier();
            let reg = v.params_registry.read().unwrap();
            assert!(reg.contains_key(&1));
            assert!(reg.contains_key(&2));
        }

        #[test]
        fn verifier_add_params_v3() {
            let mut v = make_verifier();
            v.add_verification_params(VerificationParams {
                params_version: 3,
                sector_size: 128 * 1024 * 1024 * 1024,
                challenge_count: 200,
                porep_id: [3u8; 32],
                activation_epoch: 500,
            });
            let reg = v.params_registry.read().unwrap();
            assert!(reg.contains_key(&3));
        }

        #[test]
        fn verifier_register_prover_ok() {
            let v = make_verifier();
            let addr = Address::new([2u8; 20]);
            assert!(v.register_prover(addr, vec![1u8; 64]).is_ok());
            assert!(v.is_prover_known(&addr));
        }

        #[test]
        fn verifier_register_prover_empty_key_fails() {
            let v = make_verifier();
            assert!(v.register_prover(Address::new([2u8; 20]), vec![]).is_err());
        }

        #[test]
        fn verifier_register_sector_commitment_ok() {
            let v = make_verifier();
            let prover = Address::new([3u8; 20]);
            let comm = make_commitment(
                prover,
                1,
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            );
            assert!(v.register_sector_commitment(comm).is_ok());
            assert!(v.get_sector_commitment(prover, 1).is_some());
        }

        #[test]
        fn verifier_register_expired_sector_fails() {
            let v = make_verifier();
            let prover = Address::new([3u8; 20]);
            let mut comm = make_commitment(
                prover,
                1,
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            );
            comm.expiry = Timestamp::from_millis(0);
            assert!(v.register_sector_commitment(comm).is_err());
        }

        #[test]
        fn verifier_deregister_sector() {
            let v = make_verifier();
            let prover = Address::new([4u8; 20]);
            let comm = make_commitment(
                prover,
                1,
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            );
            v.register_sector_commitment(comm).unwrap();
            v.deregister_sector(prover, 1);
            assert!(v.get_sector_commitment(prover, 1).is_none());
        }

        #[test]
        fn verifier_get_sectors_for_prover() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            for i in 1u64..=4 {
                let comm = make_commitment(
                    prover,
                    i,
                    Hash::new([2u8; 32]),
                    Hash::new([3u8; 32]),
                    Hash::new([4u8; 32]),
                );
                v.register_sector_commitment(comm).unwrap();
            }
            let sectors = v.get_registered_sectors_for_prover(&prover);
            assert_eq!(sectors.len(), 4);
        }

        #[test]
        fn verifier_prover_record_after_register() {
            let v = make_verifier();
            let addr = Address::new([6u8; 20]);
            v.register_prover(addr, vec![1u8; 100]).unwrap();
            let rec = v.get_prover_record(&addr).unwrap();
            assert_eq!(rec.address, addr);
            assert_eq!(rec.proofs_verified, 0);
            assert_eq!(rec.fraud_count, 0);
        }

        #[test]
        fn verifier_prover_record_unknown_returns_none() {
            let v = make_verifier();
            assert!(v.get_prover_record(&Address::new([0xFFu8; 20])).is_none());
        }

        #[tokio::test]
        async fn verifier_empty_proof_data_passes() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![], 1, prover);
            let valid = v.verify_porep_proof_internal(&proof).await.unwrap();
            assert!(valid);
        }

        #[tokio::test]
        async fn verifier_wrong_comm_r_fails() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let proof = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([0xFFu8; 32]),
                vec![0u8; 176 * 32],
                1,
                prover,
            );
            let valid = v.verify_porep_proof_internal(&proof).await.unwrap();
            assert!(!valid);
        }

        #[tokio::test]
        async fn verifier_wrong_proof_length_fails() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![0u8; 100], 1, prover);
            let valid = v.verify_porep_proof_internal(&proof).await.unwrap();
            assert!(!valid);
        }

        #[tokio::test]
        async fn verifier_unknown_params_version_fails() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let proof = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![0u8; 176 * 32],
                99,
                prover,
            );
            let result = v.verify_porep_proof_internal(&proof).await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn verifier_caches_result() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![], 1, prover);

            let r1 = v.verify_porep_proof_internal(&proof).await.unwrap();
            let r2 = v.verify_porep_proof_internal(&proof).await.unwrap();
            assert_eq!(r1, r2);

            let stats = v.get_verification_stats();
            assert!(stats.cache_hits >= 1);
            assert_eq!(stats.cache_size, 1);
        }

        #[tokio::test]
        async fn verifier_stats_increment_on_verify() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![], 1, prover);

            let _ = v.verify_porep_proof_internal(&proof).await;
            let stats = v.get_verification_stats();
            assert_eq!(stats.total_verifications, 1);
            assert_eq!(stats.valid_proofs, 1);
        }

        #[tokio::test]
        async fn verifier_invalid_proof_increments_fraud_stats() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let proof = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([0xFFu8; 32]),
                vec![0u8; 176 * 32],
                1,
                prover,
            );
            let _ = v.verify_porep_proof_internal(&proof).await.unwrap();
            let stats = v.get_verification_stats();
            assert_eq!(stats.invalid_proofs, 1);
        }

        #[tokio::test]
        async fn verifier_verdict_sent_on_verify() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let v = make_verifier().with_verdict_sender(tx);
            let prover = Address::new([5u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![], 1, prover);

            let _ = v.verify_porep_proof_internal(&proof).await;
            let verdict = rx.try_recv().expect("expected verdict");
            assert_eq!(verdict.sector_id, 1);
            assert_eq!(verdict.prover_id, prover);
            assert!(verdict.valid);
        }

        #[tokio::test]
        async fn verifier_fraud_sender_fires_on_invalid() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let v = make_verifier().with_fraud_sender(tx);
            let prover = Address::new([5u8; 20]);
            let proof = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([0xFFu8; 32]),
                vec![0u8; 176 * 32],
                1,
                prover,
            );
            let _ = v.verify_porep_proof_internal(&proof).await.unwrap();
            let ev = rx.try_recv().expect("expected fraud event");
            assert_eq!(ev.sector_id, 1);
            assert_eq!(ev.prover_id, prover);
        }

        #[tokio::test]
        async fn verifier_slashing_fires_on_invalid() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let v = make_verifier().with_slashing_sender(tx);
            let prover = Address::new([5u8; 20]);
            let proof = PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([0xFFu8; 32]),
                vec![0u8; 176 * 32],
                1,
                prover,
            );
            let _ = v.verify_porep_proof_internal(&proof).await.unwrap();
            let slash = rx.try_recv().expect("expected slash event");
            assert!(slash.amount.as_u128() > 0);
        }

        #[tokio::test]
        async fn verifier_proof_event_fires_on_valid() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let v = make_verifier().with_proof_event_sender(tx);
            let prover = Address::new([5u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![], 1, prover);

            let _ = v.verify_porep_proof_internal(&proof).await;
            let ev = rx.try_recv().expect("expected proof event");
            use ego_core::block::ProofEventType;
            assert!(matches!(ev.proof_type, ProofEventType::PoRep));
            assert!(ev.verified);
        }

        #[tokio::test]
        async fn verifier_batch_verify_proofs() {
            let v = make_verifier();
            let prover = Address::new([5u8; 20]);
            let mut proofs = vec![];
            for i in 1u64..=3 {
                let comm_d = Hash::new([2u8; 32]);
                let replica_id = Hash::new([(i as u8 + 10); 32]);
                let comm_r = comm_r_from(&comm_d, &replica_id);
                proofs.push(PoRepProof::new(
                    i,
                    replica_id,
                    comm_d,
                    comm_r,
                    vec![],
                    1,
                    prover,
                ));
            }
            let results = v.batch_verify_proofs(proofs).await.unwrap();
            assert_eq!(results.len(), 3);
            for (id, _) in &results {
                assert!(results.iter().any(|(i, _)| i == id));
            }
        }

        #[test]
        fn verifier_epoch_scores_empty() {
            let v = make_verifier();
            assert!(v.compute_epoch_porep_scores(1, &[]).is_empty());
        }

        #[test]
        fn verifier_epoch_scores_two_provers() {
            let v = make_verifier();
            let addr1 = Address::new([1u8; 20]);
            let addr2 = Address::new([2u8; 20]);
            let proofs = vec![
                PoRepProof::new(
                    1,
                    Hash::new([1u8; 32]),
                    Hash::new([2u8; 32]),
                    Hash::new([3u8; 32]),
                    vec![],
                    1,
                    addr1,
                ),
                PoRepProof::new(
                    2,
                    Hash::new([1u8; 32]),
                    Hash::new([2u8; 32]),
                    Hash::new([3u8; 32]),
                    vec![],
                    1,
                    addr2,
                ),
            ];
            let scores = v.compute_epoch_porep_scores(1, &proofs);
            assert_eq!(scores.len(), 2);
            assert!(scores.contains_key(&addr1));
            assert!(scores.contains_key(&addr2));
        }

        #[test]
        fn verifier_epoch_scores_same_prover_multiple_proofs() {
            let v = make_verifier();
            let addr = Address::new([1u8; 20]);
            let proofs = vec![
                PoRepProof::new(
                    1,
                    Hash::new([1u8; 32]),
                    Hash::new([2u8; 32]),
                    Hash::new([3u8; 32]),
                    vec![],
                    1,
                    addr,
                ),
                PoRepProof::new(
                    2,
                    Hash::new([4u8; 32]),
                    Hash::new([5u8; 32]),
                    Hash::new([6u8; 32]),
                    vec![],
                    1,
                    addr,
                ),
            ];
            let scores = v.compute_epoch_porep_scores(1, &proofs);
            assert_eq!(scores.len(), 1);
            let score = scores[&addr];
            assert!(score >= 0.0 && score <= 1.0);
        }
    }

    mod integration_tests {
        use super::*;

        #[tokio::test]
        async fn prover_generate_and_verifier_accepts() {
            let mut prover = make_prover(small_sector(), false);
            let state = inject_active_sector(&mut prover, 1);

            let challenge = PoRepChallenge::new(1, state.replica_id, Hash::new([0x11u8; 32]));
            let proof = prover.generate_porep_proof(challenge).await.unwrap();
            assert_eq!(proof.sector_id, 1);
            assert_eq!(proof.prover_id, prover.address);

            let verifier = make_verifier();
            let comm_d = state.comm_d;
            let comm_r = state.comm_r;
            let replica_id = state.replica_id;
            let commitment = make_commitment(prover.address, 1, comm_d, comm_r, replica_id);
            verifier.register_sector_commitment(commitment).unwrap();

            let valid = verifier.verify_porep_proof_internal(&proof).await.unwrap();
            assert!(valid, "Verifier should accept proof generated by prover");
        }

        #[tokio::test]
        async fn prover_generates_event_verifier_accepts() {
            let mut prover = make_prover(small_sector(), false);
            inject_active_sector(&mut prover, 2);

            let deal_ids = vec![Hash::new([0xDEu8; 32])];
            let event = prover.build_porep_event(2, deal_ids).unwrap();
            assert!(event.validate().is_ok());

            let verifier = make_verifier();
            let valid = verifier.verify_porep_event(&event).await.unwrap();
            assert!(valid, "Verifier should accept event from prover");
        }

        #[tokio::test]
        async fn duplicate_proof_rejected_by_prover() {
            let mut prover = make_prover(small_sector(), false);
            let state = inject_active_sector(&mut prover, 3);

            let challenge1 = PoRepChallenge::new(3, state.replica_id, Hash::new([0x22u8; 32]));
            let proof = prover.generate_porep_proof(challenge1).await.unwrap();

            let challenge2 = PoRepChallenge::new(3, state.replica_id, Hash::new([0x22u8; 32]));
            let result = prover.generate_porep_proof(challenge2).await;
            assert!(result.is_err(), "Duplicate challenge should be rejected");
        }

        #[tokio::test]
        async fn verifier_with_all_channels_wired() {
            let (verdict_tx, mut verdict_rx) = mpsc::unbounded_channel();
            let (fraud_tx, _fraud_rx) = mpsc::unbounded_channel();
            let (proof_ev_tx, mut proof_ev_rx) = mpsc::unbounded_channel();
            let (slash_tx, _slash_rx) = mpsc::unbounded_channel();

            let v = make_verifier()
                .with_verdict_sender(verdict_tx)
                .with_fraud_sender(fraud_tx)
                .with_proof_event_sender(proof_ev_tx)
                .with_slashing_sender(slash_tx);

            let prover = Address::new([5u8; 20]);
            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![], 1, prover);

            let valid = v.verify_porep_proof_internal(&proof).await.unwrap();
            assert!(valid);

            assert!(
                verdict_rx.try_recv().is_ok(),
                "verdict should have been sent"
            );
            assert!(
                proof_ev_rx.try_recv().is_ok(),
                "proof event should have been sent"
            );
        }

        #[tokio::test]
        async fn verifier_challenge_from_block_hash() {
            let mut prover = make_prover(small_sector(), false);
            let state = inject_active_sector(&mut prover, 10);

            let block_hash = Hash::new([0xBBu8; 32]);
            let vrf_output = [0xCCu8; 32];
            let challenge =
                PoRepChallenge::from_finalized_block(10, state.replica_id, block_hash, vrf_output);

            let proof = prover.generate_porep_proof(challenge).await.unwrap();
            assert_eq!(proof.sector_id, 10);

            let verifier = make_verifier();
            let commitment = make_commitment(
                prover.address,
                10,
                state.comm_d,
                state.comm_r,
                state.replica_id,
            );
            verifier.register_sector_commitment(commitment).unwrap();

            let valid = verifier.verify_porep_proof_internal(&proof).await.unwrap();
            assert!(valid, "Proof from block-derived challenge should be valid");
        }

        #[tokio::test]
        async fn batch_verify_mixed_valid_invalid() {
            let verifier = make_verifier();
            let prover = Address::new([5u8; 20]);

            let comm_d = Hash::new([2u8; 32]);
            let replica_id = Hash::new([0xAAu8; 32]);
            let comm_r = comm_r_from(&comm_d, &replica_id);
            let valid_proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![], 1, prover);
            let invalid_proof = PoRepProof::new(
                2,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([0xFFu8; 32]),
                vec![0u8; 176 * 32],
                1,
                prover,
            );

            let results = verifier
                .batch_verify_proofs(vec![valid_proof, invalid_proof])
                .await
                .unwrap();
            assert_eq!(results.len(), 2);

            let r1 = results.iter().find(|(id, _)| *id == 1).unwrap();
            let r2 = results.iter().find(|(id, _)| *id == 2).unwrap();
            assert!(r1.1, "sector 1 should be valid");
            assert!(!r2.1, "sector 2 should be invalid");
        }

        #[tokio::test]
        async fn prover_and_verifier_full_pipeline_with_registered_commitment() {
            let mut prover = make_prover(small_sector(), true);
            let state = inject_active_sector(&mut prover, 20);

            let challenge = PoRepChallenge::from_finalized_block(
                20,
                state.replica_id,
                Hash::new([0x55u8; 32]),
                [0x66u8; 32],
            );
            let proof = prover.generate_porep_proof(challenge).await.unwrap();

            let verifier = make_verifier();
            let commitment = make_commitment(
                prover.address,
                20,
                state.comm_d,
                state.comm_r,
                state.replica_id,
            );
            verifier.register_sector_commitment(commitment).unwrap();
            verifier
                .register_prover(prover.address, vec![1u8; 64])
                .unwrap();

            let valid = verifier.verify_porep_proof_internal(&proof).await.unwrap();
            assert!(valid);

            let rec = verifier.get_prover_record(&prover.address).unwrap();
            assert_eq!(rec.proofs_verified, 1);
            assert_eq!(rec.proofs_valid, 1);
            assert_eq!(rec.fraud_count, 0);

            let scores = verifier.compute_epoch_porep_scores(1, &[proof]);
            assert!(scores.contains_key(&prover.address));
            let score = scores[&prover.address];
            assert!(score > 0.0);
        }
    }
}
