use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::error::VmError;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ContractState {

    pub data: HashMap<String, HashMap<String, String>>,
}

impl ContractState {
    pub fn get(&self, prefix: &str, key: &str) -> Option<Vec<u8>> {
        self.data.get(prefix)?.get(key)
            .and_then(|v| hex::decode(v).ok())
    }

    pub fn set(&mut self, prefix: &str, key: &str, value: Vec<u8>) {
        self.data
            .entry(prefix.to_string())
            .or_default()
            .insert(key.to_string(), hex::encode(&value));
    }

    pub fn del(&mut self, prefix: &str, key: &str) {
        if let Some(map) = self.data.get_mut(prefix) {
            map.remove(key);
        }
    }
}

pub struct StateStore {
    pub base_dir: PathBuf,
}

impl StateStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn contract_dir(&self, addr: &str) -> PathBuf {
        self.base_dir.join("contracts").join(addr)
    }

    pub fn store_code(&self, addr: &str, wasm_bytes: &[u8]) -> Result<(), VmError> {
        let dir = self.contract_dir(addr);
        std::fs::create_dir_all(&dir)
            .map_err(|e| VmError::StorageError(e.to_string()))?;
        std::fs::write(dir.join("code.wasm"), wasm_bytes)
            .map_err(|e| VmError::StorageError(e.to_string()))
    }

    pub fn load_code(&self, addr: &str) -> Result<Vec<u8>, VmError> {
        std::fs::read(self.contract_dir(addr).join("code.wasm"))
            .map_err(|e| VmError::StorageError(format!("Code not found for {}: {}", addr, e)))
    }

    pub fn load_state(&self, addr: &str) -> ContractState {
        let path = self.contract_dir(addr).join("state.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save_state(&self, addr: &str, state: &ContractState) -> Result<(), VmError> {
        let dir = self.contract_dir(addr);
        std::fs::create_dir_all(&dir)
            .map_err(|e| VmError::StorageError(e.to_string()))?;
        let data = serde_json::to_string_pretty(state)
            .map_err(|e| VmError::StorageError(e.to_string()))?;
        // Atomic write: write to a temp file then rename to avoid partial-write corruption.
        let final_path = dir.join("state.json");
        let tmp_path   = dir.join("state.json.tmp");
        std::fs::write(&tmp_path, &data)
            .map_err(|e| VmError::StorageError(e.to_string()))?;
        std::fs::rename(&tmp_path, &final_path)
            .map_err(|e| VmError::StorageError(e.to_string()))
    }

    pub fn store_manifest(&self, addr: &str, manifest: &crate::types::ContractManifest) -> Result<(), VmError> {
        let dir = self.contract_dir(addr);
        std::fs::create_dir_all(&dir)
            .map_err(|e| VmError::StorageError(e.to_string()))?;
        let data = serde_json::to_string_pretty(manifest)
            .map_err(|e| VmError::StorageError(e.to_string()))?;
        std::fs::write(dir.join("manifest.json"), data)
            .map_err(|e| VmError::StorageError(e.to_string()))
    }

    pub fn load_manifest(&self, addr: &str) -> Option<crate::types::ContractManifest> {
        let path = self.contract_dir(addr).join("manifest.json");
        std::fs::read_to_string(path).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn contract_exists(&self, addr: &str) -> bool {
        self.contract_dir(addr).join("code.wasm").exists()
    }
}
