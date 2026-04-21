use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayloadId(pub u64);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PayloadStatus {
    Valid,
    Invalid,
    Syncing,
    Accepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineTransaction {
    pub tx_hash: String,
    pub from:    String,
    pub to:      String,
    pub amount:  u64,
    pub data:    Vec<u8>,
    pub fuel:    u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPayload {
    pub payload_id:   Option<PayloadId>,
    pub block_height: u64,
    pub timestamp:    i64,
    pub state_root:   String,
    pub parent_hash:  String,
    pub block_hash:   String,
    pub transactions: Vec<EngineTransaction>,
    pub gas_used:     u64,
    pub extra_data:   Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkChoiceState {
    pub head_block_hash:      String,
    pub safe_block_hash:      String,
    pub finalized_block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAttributes {
    pub timestamp:               i64,
    pub suggested_fee_recipient: String,
    pub transactions:            Vec<EngineTransaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkChoiceUpdatedResult {
    pub payload_status: PayloadStatus,
    pub payload_id:     Option<PayloadId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewPayloadResult {
    pub status:             PayloadStatus,
    pub latest_valid_hash:  Option<String>,
    pub validation_error:   Option<String>,
}

#[async_trait::async_trait]
pub trait EngineApi: Send + Sync {

    async fn fork_choice_updated(
        &self,
        state:      ForkChoiceState,
        attributes: Option<PayloadAttributes>,
    ) -> Result<ForkChoiceUpdatedResult, EngineError>;

    async fn new_payload(&self, payload: ExecutionPayload) -> Result<NewPayloadResult, EngineError>;

    async fn get_payload(&self, payload_id: PayloadId) -> Result<ExecutionPayload, EngineError>;

    async fn exchange_capabilities(
        &self,
        capabilities: Vec<String>,
    ) -> Result<Vec<String>, EngineError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("unknown payload: {0:?}")]
    UnknownPayload(PayloadId),
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct EgoExecutionEngine {

    pending_payloads: Mutex<std::collections::HashMap<u64, ExecutionPayload>>,

    next_payload_id: Mutex<u64>,

    head_hash: Mutex<String>,
}

impl EgoExecutionEngine {
    pub fn new() -> Arc<Self> {
        let initial_head = crate::store::load_fork_choice()
            .map(|s| s.head_block_hash)
            .unwrap_or_default();
        Arc::new(Self {
            pending_payloads: Mutex::new(std::collections::HashMap::new()),
            next_payload_id:  Mutex::new(1),
            head_hash:        Mutex::new(initial_head),
        })
    }
}

#[async_trait::async_trait]
impl EngineApi for EgoExecutionEngine {
    async fn fork_choice_updated(
        &self,
        state:      ForkChoiceState,
        attributes: Option<PayloadAttributes>,
    ) -> Result<ForkChoiceUpdatedResult, EngineError> {

        *self.head_hash.lock().await = state.head_block_hash.clone();
        crate::store::save_fork_choice(&state);

        let payload_id = if let Some(attrs) = attributes {

            let mut id_lock = self.next_payload_id.lock().await;
            let id = *id_lock;
            *id_lock += 1;
            drop(id_lock);

            let payload = ExecutionPayload {
                payload_id:   Some(PayloadId(id)),
                block_height: 0,
                timestamp:    attrs.timestamp,
                state_root:   state.head_block_hash.clone(),
                parent_hash:  state.head_block_hash.clone(),
                block_hash:   format!("pending_{}", id),
                transactions: attrs.transactions,
                gas_used:     0,
                extra_data:   vec![],
            };
            self.pending_payloads.lock().await.insert(id, payload);
            Some(PayloadId(id))
        } else {
            None
        };

        Ok(ForkChoiceUpdatedResult {
            payload_status: PayloadStatus::Valid,
            payload_id,
        })
    }

    async fn new_payload(
        &self,
        payload: ExecutionPayload,
    ) -> Result<NewPayloadResult, EngineError> {

        if payload.block_hash.is_empty() {
            return Ok(NewPayloadResult {
                status:           PayloadStatus::Invalid,
                latest_valid_hash: None,
                validation_error:  Some("empty block hash".into()),
            });
        }
        Ok(NewPayloadResult {
            status:           PayloadStatus::Valid,
            latest_valid_hash: Some(payload.block_hash.clone()),
            validation_error:  None,
        })
    }

    async fn get_payload(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayload, EngineError> {
        self.pending_payloads
            .lock()
            .await
            .get(&payload_id.0)
            .cloned()
            .ok_or(EngineError::UnknownPayload(payload_id))
    }

    async fn exchange_capabilities(
        &self,
        _capabilities: Vec<String>,
    ) -> Result<Vec<String>, EngineError> {
        Ok(vec![
            "engine_newPayloadV1".into(),
            "engine_forkchoiceUpdatedV1".into(),
            "engine_getPayloadV1".into(),
            "engine_exchangeCapabilities".into(),
        ])
    }
}
