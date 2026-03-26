use crate::error::{EgoDesktopError, EgoResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub keystore_path: PathBuf,
    pub storage_path: PathBuf,
    pub testnet_mode: bool,
    pub auto_start: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("EgoDesktop");

        Self {
            database_path: data_dir.join("app.db"),
            keystore_path: data_dir.join("keystore"),
            storage_path: data_dir.join("storage"),
            data_dir,
            testnet_mode: true,
            auto_start: false,
        }
    }
}

impl AppConfig {
    pub fn load() -> EgoResult<Self> {
        let config_path = dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("EgoDesktop")
            .join("config.json");

        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)
                .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to read config: {}", e)))?;

            serde_json::from_str(&content)
                .map_err(|e| EgoDesktopError::ConfigError(format!("Failed to parse config: {}", e)))
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> EgoResult<()> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("EgoDesktop");

        std::fs::create_dir_all(&config_dir)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to create config dir: {}", e)))?;

        let config_path = config_dir.join("config.json");
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| EgoDesktopError::SerializationError(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(config_path, content)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to write config: {}", e)))?;

        Ok(())
    }
}
