use super::{SealingJob, SealingStatus, SectorCommitment};
use crate::error::{PoCError, PoCResult};
use super::prover::SectorState;
use ego_core::{Address, Hash, Timestamp};
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, Options};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn, error};

const CF_SECTORS: &str = "sectors";
const CF_SEALING_JOBS: &str = "sealing_jobs";
const CF_COMMITMENTS: &str = "commitments";
const CF_SUBMITTED_PROOFS: &str = "submitted_proofs";
const CF_METADATA: &str = "metadata";

#[derive(Debug)]
pub struct PoRepPersistence {
    db: Arc<DB>,
    prover_id: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PersistentSectorState {
    pub sector_id: u64,
    pub replica_id: Hash,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub sealed_path: String,
    pub cache_path: String,
    pub deal_ids: Vec<Hash>,
    pub created_at: Timestamp,
    pub proof_count: u32,
    pub last_challenged_at: Option<Timestamp>,
}

impl From<SectorState> for PersistentSectorState {
    fn from(state: SectorState) -> Self {
        Self {
            sector_id: state.sector_id,
            replica_id: state.replica_id,
            comm_d: state.comm_d,
            comm_r: state.comm_r,
            sealed_path: state.sealed_path,
            cache_path: state.cache_path,
            deal_ids: state.deal_ids,
            created_at: state.created_at,
            proof_count: state.proof_count,
            last_challenged_at: state.last_challenged_at,
        }
    }
}

impl From<PersistentSectorState> for SectorState {
    fn from(persistent: PersistentSectorState) -> Self {
        Self {
            sector_id: persistent.sector_id,
            replica_id: persistent.replica_id,
            comm_d: persistent.comm_d,
            comm_r: persistent.comm_r,
            sealed_path: persistent.sealed_path,
            cache_path: persistent.cache_path,
            deal_ids: persistent.deal_ids,
            created_at: persistent.created_at,
            proof_count: persistent.proof_count,
            last_challenged_at: persistent.last_challenged_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoRepMetadata {
    pub prover_id: Address,
    pub last_backup: Timestamp,
    pub version: u32,
    pub total_sectors: u64,
    pub active_sectors: u64,
}

impl PoRepPersistence {

    pub fn new<P: AsRef<Path>>(db_path: P, prover_id: Address) -> PoCResult<Self> {
        info!("Initializing PoRep persistence at path: {:?}", db_path.as_ref());

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(1000);
        db_opts.set_use_fsync(false);
        db_opts.set_bytes_per_sync(1048576);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_SECTORS, Options::default()),
            ColumnFamilyDescriptor::new(CF_SEALING_JOBS, Options::default()),
            ColumnFamilyDescriptor::new(CF_COMMITMENTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_SUBMITTED_PROOFS, Options::default()),
            ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&db_opts, db_path, cfs)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to open RocksDB: {}", e)))?;

        let persistence = Self {
            db: Arc::new(db),
            prover_id,
        };

        persistence.initialize_metadata()?;

        info!("✅ PoRep persistence initialized successfully");
        Ok(persistence)
    }

    fn initialize_metadata(&self) -> PoCResult<()> {
        let cf = self.get_cf(CF_METADATA)?;
        let key = b"metadata";

        let metadata = match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {

                let existing: PoRepMetadata = bincode::decode_from_slice(&data, bincode::config::standard()).map(|(v, _)| v)
                    .map_err(|e| PoCError::SerializationError(format!("Failed to decode metadata: {}", e)))?;

                if existing.prover_id != self.prover_id {
                    warn!("Prover ID mismatch! Existing: {}, Expected: {}",
                          existing.prover_id, self.prover_id);
                }
                existing
            }
            Ok(None) => {

                PoRepMetadata {
                    prover_id: self.prover_id,
                    last_backup: Timestamp::now(),
                    version: 1,
                    total_sectors: 0,
                    active_sectors: 0,
                }
            }
            Err(e) => {
                return Err(PoCError::EvidenceStorageFailed(format!("Failed to read metadata: {}", e)));
            }
        };

        let updated_metadata = PoRepMetadata {
            last_backup: Timestamp::now(),
            ..metadata
        };

        let encoded = bincode::encode_to_vec(&updated_metadata, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to encode metadata: {}", e)))?;

        self.db.put_cf(cf, key, encoded)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to write metadata: {}", e)))?;

        debug!("Metadata initialized: version={}, prover_id={}",
               updated_metadata.version, updated_metadata.prover_id);
        Ok(())
    }

    fn get_cf(&self, cf_name: &str) -> PoCResult<&ColumnFamily> {
        self.db.cf_handle(cf_name)
            .ok_or_else(|| PoCError::EvidenceStorageFailed(
                format!("Column family '{}' not found", cf_name)
            ))
    }

    pub fn save_sector_state(&self, sector_state: &SectorState) -> PoCResult<()> {
        let cf = self.get_cf(CF_SECTORS)?;
        let key = sector_state.sector_id.to_le_bytes();

        let persistent_state = PersistentSectorState::from(sector_state.clone());
        let encoded = bincode::encode_to_vec(&persistent_state, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to encode sector state: {}", e)))?;

        self.db.put_cf(cf, key, encoded)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to save sector state: {}", e)))?;

        debug!("💾 Saved sector state: sector_id={}", sector_state.sector_id);
        Ok(())
    }

    pub fn load_sector_state(&self, sector_id: u64) -> PoCResult<Option<SectorState>> {
        let cf = self.get_cf(CF_SECTORS)?;
        let key = sector_id.to_le_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let persistent: PersistentSectorState = bincode::decode_from_slice(&data, bincode::config::standard()).map(|(v, _)| v)
                    .map_err(|e| PoCError::SerializationError(format!("Failed to decode sector state: {}", e)))?;

                debug!("📂 Loaded sector state: sector_id={}", sector_id);
                Ok(Some(SectorState::from(persistent)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(PoCError::EvidenceStorageFailed(format!("Failed to load sector state: {}", e))),
        }
    }

    pub fn delete_sector_state(&self, sector_id: u64) -> PoCResult<()> {
        let cf = self.get_cf(CF_SECTORS)?;
        let key = sector_id.to_le_bytes();

        self.db.delete_cf(cf, key)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to delete sector state: {}", e)))?;

        debug!("🗑️ Deleted sector state: sector_id={}", sector_id);
        Ok(())
    }

    pub fn load_all_sector_states(&self) -> PoCResult<HashMap<u64, SectorState>> {
        let cf = self.get_cf(CF_SECTORS)?;
        let mut sectors = HashMap::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key_bytes, value_bytes) = item
                .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to iterate sectors: {}", e)))?;

            let sector_id = u64::from_le_bytes(
                key_bytes.as_ref().try_into()
                    .map_err(|e| PoCError::SerializationError(format!("Invalid sector key: {:?}", e)))?
            );

            let persistent: PersistentSectorState = bincode::decode_from_slice(&value_bytes, bincode::config::standard()).map(|(v, _)| v)
                .map_err(|e| PoCError::SerializationError(format!("Failed to decode sector: {}", e)))?;

            sectors.insert(sector_id, SectorState::from(persistent));
        }

        info!("📂 Loaded {} sector states from storage", sectors.len());
        Ok(sectors)
    }

    pub fn save_sealing_queue(&self, queue: &VecDeque<SealingJob>) -> PoCResult<()> {
        let cf = self.get_cf(CF_SEALING_JOBS)?;
        let key = b"sealing_queue";

        let queue_vec: Vec<&SealingJob> = queue.iter().collect();
        let encoded = bincode::encode_to_vec(&queue_vec, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to encode sealing queue: {}", e)))?;

        self.db.put_cf(cf, key, encoded)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to save sealing queue: {}", e)))?;

        debug!("💾 Saved sealing queue with {} jobs", queue.len());
        Ok(())
    }

    pub fn load_sealing_queue(&self) -> PoCResult<VecDeque<SealingJob>> {
        let cf = self.get_cf(CF_SEALING_JOBS)?;
        let key = b"sealing_queue";

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let queue_vec: Vec<SealingJob> = bincode::decode_from_slice(&data, bincode::config::standard()).map(|(v, _)| v)
                    .map_err(|e| PoCError::SerializationError(format!("Failed to decode sealing queue: {}", e)))?;

                let queue = VecDeque::from(queue_vec);
                info!("📂 Loaded sealing queue with {} jobs", queue.len());
                Ok(queue)
            }
            Ok(None) => {
                debug!("No sealing queue found in storage, starting with empty queue");
                Ok(VecDeque::new())
            }
            Err(e) => Err(PoCError::EvidenceStorageFailed(format!("Failed to load sealing queue: {}", e))),
        }
    }

    pub fn save_commitment(&self, sector_id: u64, commitment: &SectorCommitment) -> PoCResult<()> {
        let cf = self.get_cf(CF_COMMITMENTS)?;
        let key = sector_id.to_le_bytes();

        let encoded = bincode::encode_to_vec(commitment, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to encode commitment: {}", e)))?;

        self.db.put_cf(cf, key, encoded)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to save commitment: {}", e)))?;

        debug!("💾 Saved commitment: sector_id={}", sector_id);
        Ok(())
    }

    pub fn load_all_commitments(&self) -> PoCResult<HashMap<u64, SectorCommitment>> {
        let cf = self.get_cf(CF_COMMITMENTS)?;
        let mut commitments = HashMap::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key_bytes, value_bytes) = item
                .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to iterate commitments: {}", e)))?;

            let sector_id = u64::from_le_bytes(
                key_bytes.as_ref().try_into()
                    .map_err(|e| PoCError::SerializationError(format!("Invalid commitment key: {:?}", e)))?
            );

            let commitment: SectorCommitment = bincode::decode_from_slice(&value_bytes, bincode::config::standard()).map(|(v, _)| v)
                .map_err(|e| PoCError::SerializationError(format!("Failed to decode commitment: {}", e)))?;

            commitments.insert(sector_id, commitment);
        }

        info!("📂 Loaded {} commitments from storage", commitments.len());
        Ok(commitments)
    }

    pub fn save_submitted_proofs(&self, submitted: &HashSet<Hash>) -> PoCResult<()> {
        let cf = self.get_cf(CF_SUBMITTED_PROOFS)?;
        let key = b"submitted_proofs";

        let proofs_vec: Vec<&Hash> = submitted.iter().collect();
        let encoded = bincode::encode_to_vec(&proofs_vec, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to encode submitted proofs: {}", e)))?;

        self.db.put_cf(cf, key, encoded)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to save submitted proofs: {}", e)))?;

        debug!("💾 Saved {} submitted proof hashes", submitted.len());
        Ok(())
    }

    pub fn load_submitted_proofs(&self) -> PoCResult<HashSet<Hash>> {
        let cf = self.get_cf(CF_SUBMITTED_PROOFS)?;
        let key = b"submitted_proofs";

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let proofs_vec: Vec<Hash> = bincode::decode_from_slice(&data, bincode::config::standard()).map(|(v, _)| v)
                    .map_err(|e| PoCError::SerializationError(format!("Failed to decode submitted proofs: {}", e)))?;

                let submitted: HashSet<Hash> = proofs_vec.into_iter().collect();
                info!("📂 Loaded {} submitted proof hashes", submitted.len());
                Ok(submitted)
            }
            Ok(None) => {
                debug!("No submitted proofs found in storage, starting with empty set");
                Ok(HashSet::new())
            }
            Err(e) => Err(PoCError::EvidenceStorageFailed(format!("Failed to load submitted proofs: {}", e))),
        }
    }

    pub fn backup_state(
        &self,
        active_sectors: &HashMap<u64, SectorState>,
        sealing_queue: &VecDeque<SealingJob>,
        commitments: &HashMap<u64, SectorCommitment>,
        submitted_proofs: &HashSet<Hash>,
    ) -> PoCResult<()> {
        info!("🔄 Starting periodic state backup...");

        for (sector_id, sector_state) in active_sectors {
            if let Err(e) = self.save_sector_state(sector_state) {
                error!("Failed to backup sector {}: {}", sector_id, e);
            }
        }

        if let Err(e) = self.save_sealing_queue(sealing_queue) {
            error!("Failed to backup sealing queue: {}", e);
        }

        for (sector_id, commitment) in commitments {
            if let Err(e) = self.save_commitment(*sector_id, commitment) {
                error!("Failed to backup commitment for sector {}: {}", sector_id, e);
            }
        }

        if let Err(e) = self.save_submitted_proofs(submitted_proofs) {
            error!("Failed to backup submitted proofs: {}", e);
        }

        self.update_backup_metadata(active_sectors.len() as u64)?;

        info!("✅ State backup completed successfully");
        Ok(())
    }

    fn update_backup_metadata(&self, active_sectors: u64) -> PoCResult<()> {
        let cf = self.get_cf(CF_METADATA)?;
        let key = b"metadata";

        let metadata = PoRepMetadata {
            prover_id: self.prover_id,
            last_backup: Timestamp::now(),
            version: 1,
            total_sectors: active_sectors,
            active_sectors,
        };

        let encoded = bincode::encode_to_vec(&metadata, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to encode backup metadata: {}", e)))?;

        self.db.put_cf(cf, key, encoded)
            .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to update backup metadata: {}", e)))?;

        Ok(())
    }

    pub fn restore_state(&self) -> PoCResult<PoRepRestoredState> {
        info!("🔄 Restoring PoRep state from persistent storage...");

        let active_sectors = self.load_all_sector_states()?;
        let sealing_queue = self.load_sealing_queue()?;
        let commitments = self.load_all_commitments()?;
        let submitted_proofs = self.load_submitted_proofs()?;

        let restored_state = PoRepRestoredState {
            active_sectors,
            sealing_queue,
            commitments,
            submitted_proofs,
        };

        info!("✅ State restoration completed: {} sectors, {} jobs, {} commitments, {} proofs",
              restored_state.active_sectors.len(),
              restored_state.sealing_queue.len(),
              restored_state.commitments.len(),
              restored_state.submitted_proofs.len());

        Ok(restored_state)
    }

    pub fn cleanup_completed_sectors(&self, older_than: Timestamp) -> PoCResult<u32> {
        info!("🧹 Cleaning up completed sectors older than {}", older_than);
        let cf = self.get_cf(CF_SECTORS)?;
        let mut deleted_count = 0;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut sectors_to_delete = Vec::new();

        for item in iter {
            let (key_bytes, value_bytes) = item
                .map_err(|e| PoCError::EvidenceStorageFailed(format!("Failed to iterate for cleanup: {}", e)))?;

            let sector_id = u64::from_le_bytes(
                key_bytes.as_ref().try_into()
                    .map_err(|e| PoCError::SerializationError(format!("Invalid sector key during cleanup: {:?}", e)))?
            );

            let persistent: PersistentSectorState = bincode::decode_from_slice(&value_bytes, bincode::config::standard()).map(|(v, _)| v)
                .map_err(|e| PoCError::SerializationError(format!("Failed to decode sector during cleanup: {}", e)))?;

            if persistent.created_at < older_than && persistent.proof_count > 100 {
                sectors_to_delete.push(sector_id);
            }
        }

        for sector_id in sectors_to_delete {
            if let Err(e) = self.delete_sector_state(sector_id) {
                warn!("Failed to delete old sector {}: {}", sector_id, e);
            } else {
                deleted_count += 1;
            }
        }

        info!("🧹 Cleanup completed: deleted {} old sectors", deleted_count);
        Ok(deleted_count)
    }

    pub fn get_stats(&self) -> PoCResult<PoRepStorageStats> {
        let sectors_cf = self.get_cf(CF_SECTORS)?;
        let commitments_cf = self.get_cf(CF_COMMITMENTS)?;

        let mut stats = PoRepStorageStats {
            total_sectors: 0,
            total_commitments: 0,
            database_size_bytes: 0,
            last_backup: Timestamp::now(),
        };

        let sectors_iter = self.db.iterator_cf(&sectors_cf, rocksdb::IteratorMode::Start);
        for item in sectors_iter {
            if item.is_ok() {
                stats.total_sectors += 1;
            }
        }

        let commitments_iter = self.db.iterator_cf(&commitments_cf, rocksdb::IteratorMode::Start);
        for item in commitments_iter {
            if item.is_ok() {
                stats.total_commitments += 1;
            }
        }

        if let Ok(cf) = self.get_cf(CF_METADATA) {
            if let Ok(Some(data)) = self.db.get_cf(cf, b"metadata") {
                if let Ok((metadata, _)) = bincode::decode_from_slice::<PoRepMetadata, _>(&data, bincode::config::standard()) {
                    stats.last_backup = metadata.last_backup;
                }
            }
        }

        Ok(stats)
    }
}

#[derive(Debug)]
pub struct PoRepRestoredState {
    pub active_sectors: HashMap<u64, SectorState>,
    pub sealing_queue: VecDeque<SealingJob>,
    pub commitments: HashMap<u64, SectorCommitment>,
    pub submitted_proofs: HashSet<Hash>,
}

#[derive(Debug, Clone)]
pub struct PoRepStorageStats {
    pub total_sectors: u64,
    pub total_commitments: u64,
    pub database_size_bytes: u64,
    pub last_backup: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::crypto::KeyPair;
    use tempfile::TempDir;

    #[test]
    fn test_persistence_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public_key());

        let persistence = PoRepPersistence::new(temp_dir.path(), address);
        assert!(persistence.is_ok());
    }

    #[test]
    fn test_sector_state_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public_key());
        let persistence = PoRepPersistence::new(temp_dir.path(), address).unwrap();

        let sector_state = SectorState {
            sector_id: 12345,
            replica_id: Hash::new([1u8; 32]),
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            sealed_path: "/tmp/sealed".to_string(),
            cache_path: "/tmp/cache".to_string(),
            deal_ids: vec![Hash::new([4u8; 32])],
            created_at: Timestamp::now(),
            proof_count: 5,
            last_challenged_at: Some(Timestamp::now()),
        };

        persistence.save_sector_state(&sector_state).unwrap();
        let loaded = persistence.load_sector_state(12345).unwrap().unwrap();

        assert_eq!(loaded.sector_id, sector_state.sector_id);
        assert_eq!(loaded.replica_id, sector_state.replica_id);
        assert_eq!(loaded.proof_count, sector_state.proof_count);
    }

    #[test]
    fn test_sealing_queue_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public_key());
        let persistence = PoRepPersistence::new(temp_dir.path(), address).unwrap();

        let mut queue = VecDeque::new();
        let sealing_job = SealingJob::new(1, Hash::new([1u8; 32]));
        queue.push_back(sealing_job);

        persistence.save_sealing_queue(&queue).unwrap();
        let loaded_queue = persistence.load_sealing_queue().unwrap();

        assert_eq!(loaded_queue.len(), 1);
        assert_eq!(loaded_queue.front().unwrap().sector_id, 1);
    }
}
