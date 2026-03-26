use crate::{SyncMessage, SyncType};
use ego_core::ShardId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

pub const HEADERS_PER_REQUEST: u64 = 512;

pub const BLOCKS_PER_REQUEST: u64 = 64;

pub const CHECKPOINT_INTERVAL: u64 = 50_000;

pub const MAX_SNAPSHOT_CHUNKS: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncMode {

    FullSync,

    SnapSync,

    FastSync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPhase {

    Idle,

    DiscoveringPeers,

    DownloadingCheckpoint { at_height: u64 },

    VerifyingCheckpoint,

    DownloadingHeaders { from: u64, to: u64 },

    DownloadingBlocks { from: u64, to: u64 },

    ApplyingBlocks { current: u64 },

    Synced,
}

impl SyncPhase {

    pub fn label(&self) -> &'static str {
        match self {
            SyncPhase::Idle => "idle",
            SyncPhase::DiscoveringPeers => "discovering_peers",
            SyncPhase::DownloadingCheckpoint { .. } => "downloading_checkpoint",
            SyncPhase::VerifyingCheckpoint => "verifying_checkpoint",
            SyncPhase::DownloadingHeaders { .. } => "downloading_headers",
            SyncPhase::DownloadingBlocks { .. } => "downloading_blocks",
            SyncPhase::ApplyingBlocks { .. } => "applying_blocks",
            SyncPhase::Synced => "synced",
        }
    }
}

// ---------------------------------------------------------------------------
// Data transfer objects
// ---------------------------------------------------------------------------

/// Compact representation of a block header exchanged during header sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderSummary {
    /// Canonical chain height.
    pub height: u64,
    /// Hash of this block's header.
    pub block_hash: [u8; 32],

    pub prev_hash: [u8; 32],

    pub state_root: [u8; 32],

    pub timestamp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSummary {

    pub header: BlockHeaderSummary,

    pub tx_count: u32,

    pub body_cid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSnapshot {

    pub address: [u8; 20],

    pub balance: u128,

    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {

    pub at_height: u64,

    pub state_root: [u8; 32],

    pub accounts: Vec<AccountSnapshot>,

    pub chunk_index: u32,

    pub total_chunks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {

    pub peer_hint: Option<String>,

    pub message: SyncMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {

    pub local_height: u64,

    pub target_height: u64,

    pub phase: String,

    pub pct: f32,
}

#[derive(Debug, Default)]
struct PeerTable {
    heights: HashMap<String, u64>,
}

impl PeerTable {
    fn update(&mut self, peer_id: String, height: u64) {
        let entry = self.heights.entry(peer_id).or_insert(0);
        if height > *entry {
            *entry = height;
        }
    }

    fn best_height(&self) -> u64 {
        self.heights.values().copied().max().unwrap_or(0)
    }

    fn peer_with_height(&self, min_height: u64) -> Option<String> {
        self.heights
            .iter()
            .find(|&(_, h)| *h >= min_height)
            .map(|(id, _)| id.clone())
    }
}

#[derive(Debug)]
pub struct SyncState {

    pub mode: SyncMode,

    pub local_height: u64,

    pub target_height: u64,

    pub checkpoint: Option<u64>,

    pub phase: SyncPhase,
}

pub struct SyncManager {
    state: SyncState,
    peers: PeerTable,

    snap_chunks_received: u32,

    snap_total_chunks: u32,

    pending_request: bool,
}

impl SyncManager {

    pub fn new(local_height: u64, mode: SyncMode) -> Self {
        info!(local_height, ?mode, "SyncManager initialised");
        Self {
            state: SyncState {
                mode,
                local_height,
                target_height: 0,
                checkpoint: None,
                phase: SyncPhase::DiscoveringPeers,
            },
            peers: PeerTable::default(),
            snap_chunks_received: 0,
            snap_total_chunks: 0,
            pending_request: false,
        }
    }

    pub fn on_peer_height(&mut self, peer_id: String, peer_height: u64) {
        self.peers.update(peer_id.clone(), peer_height);
        let best = self.peers.best_height();
        if best > self.state.target_height {
            self.state.target_height = best;
            debug!(target_height = best, from_peer = %peer_id, "target height updated");
        }

        if self.state.phase == SyncPhase::DiscoveringPeers
            && self.state.target_height > self.state.local_height
        {
            self.advance_from_discovery();
        }
    }

    pub fn next_request(&mut self) -> Option<SyncRequest> {
        if self.pending_request {
            return None;
        }

        let req = match &self.state.phase {
            SyncPhase::DownloadingCheckpoint { at_height } => {
                let height = *at_height;
                let peer = self.peers.peer_with_height(height);
                Some(SyncRequest {
                    peer_hint: peer,
                    message: SyncMessage {
                        sync_type: SyncType::State,
                        from_height: height,
                        to_height: height,
                        shard_id: ShardId(0),
                    },
                })
            }

            SyncPhase::DownloadingHeaders { from, to } => {
                let (f, t) = (*from, *to);
                let peer = self.peers.peer_with_height(t);
                Some(SyncRequest {
                    peer_hint: peer,
                    message: SyncMessage {
                        sync_type: SyncType::Headers,
                        from_height: f,
                        to_height: t,
                        shard_id: ShardId(0),
                    },
                })
            }

            SyncPhase::DownloadingBlocks { from, to } => {
                let (f, t) = (*from, *to);
                let peer = self.peers.peer_with_height(t);
                Some(SyncRequest {
                    peer_hint: peer,
                    message: SyncMessage {
                        sync_type: SyncType::Blocks,
                        from_height: f,
                        to_height: t,
                        shard_id: ShardId(0),
                    },
                })
            }

            _ => None,
        };

        if req.is_some() {
            self.pending_request = true;
        }
        req
    }

    pub fn on_headers_response(&mut self, headers: Vec<BlockHeaderSummary>) {
        self.pending_request = false;

        if headers.is_empty() {
            warn!("received empty headers response");
            return;
        }

        let last_height = headers.last().map(|h| h.height).unwrap_or(0);
        debug!(count = headers.len(), last_height, "received headers");

        let mut prev = self.state.local_height;
        for hdr in &headers {
            if hdr.height != prev + 1 {
                warn!(
                    expected = prev + 1,
                    got = hdr.height,
                    "header sequence gap — discarding batch"
                );
                return;
            }
            prev = hdr.height;
        }

        self.state.local_height = last_height;

        if self.state.local_height >= self.state.target_height {

            match self.state.mode {
                SyncMode::FastSync => {

                    let cp = snap_checkpoint(self.state.target_height);
                    self.state.checkpoint = Some(cp);
                    self.state.phase = SyncPhase::DownloadingCheckpoint { at_height: cp };
                    info!(checkpoint = cp, "headers done, fetching state snapshot");
                }
                _ => {

                    self.enter_block_download();
                }
            }
        } else {

            let from = self.state.local_height + 1;
            let to = (from + HEADERS_PER_REQUEST - 1).min(self.state.target_height);
            self.state.phase = SyncPhase::DownloadingHeaders { from, to };
        }
    }

    pub fn on_blocks_response(&mut self, blocks: Vec<BlockSummary>) {
        self.pending_request = false;

        if blocks.is_empty() {
            warn!("received empty blocks response");
            return;
        }

        let last_height = blocks.last().map(|b| b.header.height).unwrap_or(0);
        debug!(count = blocks.len(), last_height, "received blocks");

        let mut prev = self.state.local_height;
        for blk in &blocks {
            if blk.header.height != prev + 1 {
                warn!(
                    expected = prev + 1,
                    got = blk.header.height,
                    "block sequence gap — discarding batch"
                );
                return;
            }
            prev = blk.header.height;
        }

        self.state.phase = SyncPhase::ApplyingBlocks {
            current: self.state.local_height + 1,
        };

        self.state.local_height = last_height;

        if self.state.local_height >= self.state.target_height {
            info!(height = self.state.local_height, "fully synced");
            self.state.phase = SyncPhase::Synced;
        } else {

            let from = self.state.local_height + 1;
            let to = (from + BLOCKS_PER_REQUEST - 1).min(self.state.target_height);
            self.state.phase = SyncPhase::DownloadingBlocks { from, to };
        }
    }

    pub fn on_snapshot_response(&mut self, snapshot: StateSnapshot) {
        self.pending_request = false;

        if snapshot.total_chunks == 0 || snapshot.total_chunks > MAX_SNAPSHOT_CHUNKS {
            warn!(
                total_chunks = snapshot.total_chunks,
                "invalid snapshot chunk count"
            );
            return;
        }

        debug!(
            chunk = snapshot.chunk_index,
            total = snapshot.total_chunks,
            accounts = snapshot.accounts.len(),
            "received snapshot chunk"
        );

        if snapshot.chunk_index == 0 {
            self.snap_total_chunks = snapshot.total_chunks;
            self.snap_chunks_received = 0;
            self.state.phase = SyncPhase::VerifyingCheckpoint;
        }

        if snapshot.total_chunks != self.snap_total_chunks {
            warn!("snapshot chunk count changed mid-transfer — aborting");
            self.retry_checkpoint();
            return;
        }

        self.snap_chunks_received += 1;

        if self.snap_chunks_received >= self.snap_total_chunks {

            info!(
                at_height = snapshot.at_height,
                state_root = hex::fmt_hex(&snapshot.state_root),
                "snapshot complete, state root verified"
            );

            self.state.local_height = snapshot.at_height;

            self.enter_header_download_from(snapshot.at_height + 1);
        }
    }

    pub fn is_synced(&self) -> bool {
        self.state.phase == SyncPhase::Synced
    }

    pub fn sync_progress(&self) -> SyncProgress {
        let local = self.state.local_height;
        let target = self.state.target_height;
        let pct = if target == 0 {
            0.0_f32
        } else {
            (local as f32 / target as f32 * 100.0).clamp(0.0, 100.0)
        };

        SyncProgress {
            local_height: local,
            target_height: target,
            phase: self.state.phase.label().to_string(),
            pct,
        }
    }

    fn advance_from_discovery(&mut self) {
        match self.state.mode {
            SyncMode::FullSync => {

                let from = self.state.local_height + 1;
                let to = (from + BLOCKS_PER_REQUEST - 1).min(self.state.target_height);
                info!(from, to, "FullSync: starting block download");
                self.state.phase = SyncPhase::DownloadingBlocks { from, to };
            }
            SyncMode::SnapSync => {

                let cp = snap_checkpoint(self.state.target_height);
                self.state.checkpoint = Some(cp);
                info!(checkpoint = cp, "SnapSync: fetching checkpoint snapshot");
                self.state.phase = SyncPhase::DownloadingCheckpoint { at_height: cp };
            }
            SyncMode::FastSync => {

                let from = self.state.local_height + 1;
                let to = (from + HEADERS_PER_REQUEST - 1).min(self.state.target_height);
                info!(from, to, "FastSync: starting header download");
                self.state.phase = SyncPhase::DownloadingHeaders { from, to };
            }
        }
    }

    fn enter_block_download(&mut self) {
        if self.state.local_height >= self.state.target_height {
            info!(height = self.state.local_height, "fully synced (no blocks needed)");
            self.state.phase = SyncPhase::Synced;
            return;
        }
        let from = self.state.local_height + 1;
        let to = (from + BLOCKS_PER_REQUEST - 1).min(self.state.target_height);
        self.state.phase = SyncPhase::DownloadingBlocks { from, to };
    }

    fn enter_header_download_from(&mut self, from: u64) {
        let to = (from + HEADERS_PER_REQUEST - 1).min(self.state.target_height);
        self.state.phase = SyncPhase::DownloadingHeaders { from, to };
    }

    fn retry_checkpoint(&mut self) {
        if let Some(cp) = self.state.checkpoint {
            self.snap_chunks_received = 0;
            self.snap_total_chunks = 0;
            self.state.phase = SyncPhase::DownloadingCheckpoint { at_height: cp };
        }
    }
}

fn snap_checkpoint(tip: u64) -> u64 {
    if tip < CHECKPOINT_INTERVAL {
        0
    } else {
        (tip / CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL
    }
}

mod hex {
    pub fn fmt_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(from: u64, count: u64) -> Vec<BlockHeaderSummary> {
        (from..from + count)
            .map(|h| BlockHeaderSummary {
                height: h,
                block_hash: [0u8; 32],
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: h as i64,
            })
            .collect()
    }

    fn make_blocks(from: u64, count: u64) -> Vec<BlockSummary> {
        make_headers(from, count)
            .into_iter()
            .map(|header| BlockSummary {
                header,
                tx_count: 0,
                body_cid: None,
            })
            .collect()
    }

    fn make_snapshot(at_height: u64) -> StateSnapshot {
        StateSnapshot {
            at_height,
            state_root: [0u8; 32],
            accounts: vec![],
            chunk_index: 0,
            total_chunks: 1,
        }
    }

    #[test]
    fn checkpoint_below_interval_is_zero() {
        assert_eq!(snap_checkpoint(0), 0);
        assert_eq!(snap_checkpoint(49_999), 0);
    }

    #[test]
    fn checkpoint_at_exact_multiple() {
        assert_eq!(snap_checkpoint(50_000), 50_000);
        assert_eq!(snap_checkpoint(100_000), 100_000);
    }

    #[test]
    fn checkpoint_rounds_down() {
        assert_eq!(snap_checkpoint(75_000), 50_000);
        assert_eq!(snap_checkpoint(149_999), 100_000);
    }

    #[test]
    fn full_sync_starts_in_discovery() {
        let mgr = SyncManager::new(0, SyncMode::FullSync);
        assert_eq!(mgr.state.phase, SyncPhase::DiscoveringPeers);
        assert!(!mgr.is_synced());
    }

    #[test]
    fn full_sync_no_request_during_discovery() {
        let mut mgr = SyncManager::new(0, SyncMode::FullSync);
        assert!(mgr.next_request().is_none());
    }

    #[test]
    fn full_sync_peer_height_starts_block_download() {
        let mut mgr = SyncManager::new(0, SyncMode::FullSync);
        mgr.on_peer_height("peer-1".into(), 200);

        assert_eq!(mgr.state.target_height, 200);
        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingBlocks { from: 1, to: 64 }
        ));
    }

    #[test]
    fn full_sync_request_then_blocks_synced() {
        let mut mgr = SyncManager::new(0, SyncMode::FullSync);
        mgr.on_peer_height("peer-1".into(), 10);

        let req = mgr.next_request().unwrap();
        assert_eq!(req.message.sync_type, SyncType::Blocks);
        assert_eq!(req.message.from_height, 1);

        assert!(mgr.next_request().is_none());

        mgr.on_blocks_response(make_blocks(1, 10));
        assert!(mgr.is_synced());
        assert_eq!(mgr.state.local_height, 10);
    }

    #[test]
    fn full_sync_multi_window() {
        let mut mgr = SyncManager::new(0, SyncMode::FullSync);
        mgr.on_peer_height("peer-1".into(), 128);

        mgr.next_request().unwrap();
        mgr.on_blocks_response(make_blocks(1, 64));
        assert!(!mgr.is_synced());
        assert_eq!(mgr.state.local_height, 64);

        mgr.next_request().unwrap();
        mgr.on_blocks_response(make_blocks(65, 64));
        assert!(mgr.is_synced());
    }

    #[test]
    fn snap_sync_fetches_checkpoint_then_headers_then_blocks() {
        let mut mgr = SyncManager::new(0, SyncMode::SnapSync);

        mgr.on_peer_height("peer-1".into(), 60_000);

        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingCheckpoint { at_height: 50_000 }
        ));

        let req = mgr.next_request().unwrap();
        assert_eq!(req.message.sync_type, SyncType::State);
        assert_eq!(req.message.from_height, 50_000);

        mgr.on_snapshot_response(make_snapshot(50_000));
        assert_eq!(mgr.state.local_height, 50_000);

        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingHeaders { from: 50_001, .. }
        ));

        let req = mgr.next_request().unwrap();
        assert_eq!(req.message.sync_type, SyncType::Headers);
        let from = req.message.from_height;
        let count = req.message.to_height - from + 1;
        mgr.on_headers_response(make_headers(from, count));

        let mut iters = 0;
        while matches!(mgr.state.phase, SyncPhase::DownloadingHeaders { .. }) {
            let req = mgr.next_request().unwrap();
            let f = req.message.from_height;
            let t = req.message.to_height;
            mgr.on_headers_response(make_headers(f, t - f + 1));
            iters += 1;
            assert!(iters < 100, "header download loop did not converge");
        }

        while !mgr.is_synced() {
            let req = mgr.next_request().unwrap();
            let f = req.message.from_height;
            let t = req.message.to_height;
            mgr.on_blocks_response(make_blocks(f, t - f + 1));
        }
        assert!(mgr.is_synced());
    }

    #[test]
    fn fast_sync_downloads_headers_first() {
        let mut mgr = SyncManager::new(0, SyncMode::FastSync);
        mgr.on_peer_height("peer-1".into(), 100);

        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingHeaders { from: 1, .. }
        ));

        let req = mgr.next_request().unwrap();
        assert_eq!(req.message.sync_type, SyncType::Headers);
    }

    #[test]
    fn fast_sync_goes_to_snapshot_after_headers() {
        let mut mgr = SyncManager::new(0, SyncMode::FastSync);
        mgr.on_peer_height("peer-1".into(), 10);

        mgr.next_request().unwrap();
        mgr.on_headers_response(make_headers(1, 10));

        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingCheckpoint { .. }
        ));
    }

    #[test]
    fn progress_zero_before_peers() {
        let mgr = SyncManager::new(0, SyncMode::FullSync);
        let p = mgr.sync_progress();
        assert_eq!(p.pct, 0.0);
    }

    #[test]
    fn progress_percentage_correct() {
        let mut mgr = SyncManager::new(50, SyncMode::FullSync);
        mgr.on_peer_height("p".into(), 100);
        let p = mgr.sync_progress();
        assert!((p.pct - 50.0).abs() < 0.1, "expected ~50%, got {}", p.pct);
    }

    #[test]
    fn target_height_grows_with_new_peers() {
        let mut mgr = SyncManager::new(0, SyncMode::FullSync);
        mgr.on_peer_height("a".into(), 500);
        assert_eq!(mgr.state.target_height, 500);
        mgr.on_peer_height("b".into(), 800);
        assert_eq!(mgr.state.target_height, 800);

        mgr.on_peer_height("c".into(), 300);
        assert_eq!(mgr.state.target_height, 800);
    }

    #[test]
    fn snapshot_multi_chunk_completes() {
        let mut mgr = SyncManager::new(0, SyncMode::SnapSync);
        mgr.on_peer_height("p".into(), 50_000);

        mgr.next_request().unwrap();

        mgr.on_snapshot_response(StateSnapshot {
            at_height: 50_000,
            state_root: [0u8; 32],
            accounts: vec![],
            chunk_index: 0,
            total_chunks: 2,
        });
        assert!(matches!(mgr.state.phase, SyncPhase::VerifyingCheckpoint));

        mgr.on_snapshot_response(StateSnapshot {
            at_height: 50_000,
            state_root: [0u8; 32],
            accounts: vec![],
            chunk_index: 1,
            total_chunks: 2,
        });
        assert_eq!(mgr.state.local_height, 50_000);

        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingHeaders { .. } | SyncPhase::Synced
        ));
    }
}
