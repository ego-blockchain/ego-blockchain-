use serde::{Deserialize, Serialize};

pub const DEFAULT_CALL_FUEL:   u64 = 10_000_000;
pub const DEFAULT_DEPLOY_FUEL: u64 = 50_000_000;
pub const MAX_MEMORY_PAGES:    u32 = 256;
pub const MAX_CODE_SIZE:       usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractAddress(pub [u8; 20]);

impl ContractAddress {
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 20 { return None; }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Some(ContractAddress(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ContractAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

/// Result of deploying a contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub contract_address: String,
    pub code_hash:        String,
    pub ru_used:          u64,
    pub events:           Vec<ContractEvent>,
}

/// Result of calling a contract entrypoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallResult {
    pub success:    bool,
    pub return_val: Vec<u8>,   // raw bytes returned by contract
    pub ru_used:    u64,
    pub events:     Vec<ContractEvent>,
    pub error:      Option<String>,
}

/// An event emitted by a contract via `events.emit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEvent {
    pub contract:  String,  // contract address (hex)
    pub topic:     String,  // event topic (utf-8 or hex)
    pub payload:   Vec<u8>, // CBOR or raw bytes
    pub height:    u64,
    pub timestamp: i64,
}

/// Manifest stored alongside deployed contract code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractManifest {
    pub name:           String,
    pub version:        String,
    pub code_hash:      String,   // blake3 hex of WASM bytes
    pub deployer:       String,   // Ego address of deployer
    pub deployed_at:    i64,
    pub upgrade_policy: UpgradePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradePolicy {
    Immutable,
    Proxy { timelock_secs: u64 },
}
