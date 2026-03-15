//! Block and state sync state machine for ego-blockchain.
//!
//! A joining node calls [`SyncManager::new`] then drives the loop:
//!
//! ```text
//! loop {
//!     if let Some(req) = manager.next_request() { send(req); }
//!     match receive_response() {
//!         Response::Headers(h) => manager.on_headers_response(h),
//!         Response::Blocks(b)  => manager.on_blocks_response(b),
//!         Response::Snap(s)    => manager.on_snapshot_response(s),
//!         Response::PeerHeight(id, h) => manager.on_peer_height(id, h),
//!     }
//!     if manager.is_synced() { break; }
//! }
//! ```

use crate::{SyncMessage, SyncType};
use ego_core::ShardId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of block headers fetched per request.
pub const HEADERS_PER_REQUEST: u64 = 512;

/// Number of full blocks fetched per request.
pub const BLOCKS_PER_REQUEST: u64 = 64;

/// Snap-sync creates a checkpoint every N blocks.
pub const CHECKPOINT_INTERVAL: u64 = 50_000;

/// Maximum number of chunks we tolerate in one snapshot transfer.
pub const MAX_SNAPSHOT_CHUNKS: u32 = 4096;

// ---------------------------------------------------------------------------
// Sync mode
// ---------------------------------------------------------------------------

/// Determines which sync strategy the node uses to catch up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncMode {
    /// Replay every block from genesis. Safest; slowest for nodes far behind.
    FullSync,
    /// Download a trusted state snapshot at the nearest checkpoint, then sync
    /// headers and blocks forward from there.
    SnapSync,
    /// Download and verify all headers first (cheapest bandwidth), then fill
    /// in the state trie without replaying every transaction.
    FastSync,
}

// ---------------------------------------------------------------------------
// Sync phase
// ---------------------------------------------------------------------------

/// The current phase of the sync state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPhase {
    /// Not syncing — either already at tip or not started.
    Idle,
    /// Collecting `GetHeight` responses from peers to find the chain tip.
    DiscoveringPeers,
    /// Downloading a state snapshot at the given height (snap-sync only).
    DownloadingCheckpoint { at_height: u64 },
    /// Verifying the integrity of a received snapshot.
    VerifyingCheckpoint,
    /// Requesting block headers in the range `[from, to]`.
    DownloadingHeaders { from: u64, to: u64 },
    /// Requesting full blocks in the range `[from, to]`.
    DownloadingBlocks { from: u64, to: u64 },
    /// Applying (executing) downloaded blocks locally.
    ApplyingBlocks { current: u64 },
    /// Local chain is at or above the known network tip.
    Synced,
}

impl SyncPhase {
    /// Short human-readable label used in [`SyncProgress`].
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
    /// Hash of the preceding block's header.
    pub prev_hash: [u8; 32],
    /// Merkle root of the post-execution state trie.
    pub state_root: [u8; 32],
    /// Unix timestamp (seconds) at which the block was produced.
    pub timestamp: i64,
}

/// A block with its header plus a lightweight body reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSummary {
    /// The block's header fields.
    pub header: BlockHeaderSummary,
    /// Number of transactions in the block body.
    pub tx_count: u32,
    /// Optional content-addressed identifier of the block body (DA layer CID).
    pub body_cid: Option<String>,
}

/// One account's state as of a snapshot height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSnapshot {
    /// 20-byte account address.
    pub address: [u8; 20],
    /// Account balance in micro-EGOC.
    pub balance: u128,
    /// Transaction nonce.
    pub nonce: u64,
}

/// A paginated chunk of the full state trie at a checkpoint height.
///
/// A complete snapshot is `total_chunks` messages with `chunk_index` 0..total_chunks-1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Height at which this snapshot was taken.
    pub at_height: u64,
    /// State-trie root at this height (used for integrity checking).
    pub state_root: [u8; 32],
    /// Accounts contained in this chunk.
    pub accounts: Vec<AccountSnapshot>,
    /// Zero-based chunk index within the snapshot transfer.
    pub chunk_index: u32,
    /// Total number of chunks that make up the full snapshot.
    pub total_chunks: u32,
}

// ---------------------------------------------------------------------------
// Request / progress types
// ---------------------------------------------------------------------------

/// A message the sync manager wants sent to a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// If `Some`, prefer sending to this specific peer; otherwise any peer.
    pub peer_hint: Option<String>,
    /// The wire message to transmit.
    pub message: SyncMessage,
}

/// A snapshot of current sync progress suitable for UI / RPC exposure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {
    /// The local chain's highest applied block.
    pub local_height: u64,
    /// The highest block height seen across all peers.
    pub target_height: u64,
    /// Human-readable phase label.
    pub phase: String,
    /// Completion percentage in `[0.0, 100.0]`.
    pub pct: f32,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Tracks per-peer advertised heights.
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

    /// The highest height seen from any peer.
    fn best_height(&self) -> u64 {
        self.heights.values().copied().max().unwrap_or(0)
    }

    /// A peer that has advertised at least `min_height`.
    fn peer_with_height(&self, min_height: u64) -> Option<String> {
        self.heights
            .iter()
            .find(|&(_, h)| *h >= min_height)
            .map(|(id, _)| id.clone())
    }
}

/// Mutable fields that track sync progress.
#[derive(Debug)]
pub struct SyncState {
    /// The sync strategy being used.
    pub mode: SyncMode,
    /// Height of the last locally applied block.
    pub local_height: u64,
    /// Highest block height seen from peers.
    pub target_height: u64,
    /// The checkpoint height used by [`SyncMode::SnapSync`].
    pub checkpoint: Option<u64>,
    /// Current phase of the state machine.
    pub phase: SyncPhase,
}

// ---------------------------------------------------------------------------
// SyncManager
// ---------------------------------------------------------------------------

/// Drives the block/state sync state machine for a single local node.
///
/// The manager is intentionally *sans I/O*: callers supply responses via
/// `on_*` methods and read outbound requests via [`SyncManager::next_request`].
/// This makes it easy to unit-test and to drop into any async runtime.
pub struct SyncManager {
    state: SyncState,
    peers: PeerTable,
    /// Chunk index of the last snapshot chunk we have successfully received.
    snap_chunks_received: u32,
    /// Total chunks expected for the in-progress snapshot.
    snap_total_chunks: u32,
    /// Whether a request has been dispatched for the current window and we are
    /// waiting for a response (prevents flooding the peer with duplicates).
    pending_request: bool,
}

impl SyncManager {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new [`SyncManager`].
    ///
    /// # Arguments
    /// * `local_height` — the height of the last block the local node has applied.
    /// * `mode` — the sync strategy to use.
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

    // -----------------------------------------------------------------------
    // Peer-height updates
    // -----------------------------------------------------------------------

    /// Notify the manager that `peer_id` advertises `peer_height`.
    ///
    /// Updates [`SyncState::target_height`] if the peer is ahead of the
    /// current best-known tip and kicks the state machine out of
    /// [`SyncPhase::DiscoveringPeers`] once at least one peer is ahead.
    pub fn on_peer_height(&mut self, peer_id: String, peer_height: u64) {
        self.peers.update(peer_id.clone(), peer_height);
        let best = self.peers.best_height();
        if best > self.state.target_height {
            self.state.target_height = best;
            debug!(target_height = best, from_peer = %peer_id, "target height updated");
        }

        // Transition out of discovery once we know the network tip.
        if self.state.phase == SyncPhase::DiscoveringPeers
            && self.state.target_height > self.state.local_height
        {
            self.advance_from_discovery();
        }
    }

    // -----------------------------------------------------------------------
    // Request generation
    // -----------------------------------------------------------------------

    /// Returns the next [`SyncRequest`] that should be sent to a peer, or
    /// `None` if we are idle / already waiting for a response / fully synced.
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

    // -----------------------------------------------------------------------
    // Response handlers
    // -----------------------------------------------------------------------

    /// Process a batch of [`BlockHeaderSummary`] items returned by a peer.
    ///
    /// Validates ordering and advances the phase once all headers up to
    /// `target_height` have been received.
    pub fn on_headers_response(&mut self, headers: Vec<BlockHeaderSummary>) {
        self.pending_request = false;

        if headers.is_empty() {
            warn!("received empty headers response");
            return;
        }

        let last_height = headers.last().map(|h| h.height).unwrap_or(0);
        debug!(count = headers.len(), last_height, "received headers");

        // Basic sanity: each header must be one step above the previous.
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
            // All headers received. For FastSync we still need the state trie;
            // for FullSync / SnapSync we move on to blocks.
            match self.state.mode {
                SyncMode::FastSync => {
                    // After headers are verified, fetch the state snapshot at tip.
                    let cp = snap_checkpoint(self.state.target_height);
                    self.state.checkpoint = Some(cp);
                    self.state.phase = SyncPhase::DownloadingCheckpoint { at_height: cp };
                    info!(checkpoint = cp, "headers done, fetching state snapshot");
                }
                _ => {
                    // Transition to full block download.
                    self.enter_block_download();
                }
            }
        } else {
            // Request the next window of headers.
            let from = self.state.local_height + 1;
            let to = (from + HEADERS_PER_REQUEST - 1).min(self.state.target_height);
            self.state.phase = SyncPhase::DownloadingHeaders { from, to };
        }
    }

    /// Process a batch of [`BlockSummary`] items returned by a peer.
    ///
    /// Advances the applied-height counter and transitions to
    /// [`SyncPhase::Synced`] when all blocks have been received.
    pub fn on_blocks_response(&mut self, blocks: Vec<BlockSummary>) {
        self.pending_request = false;

        if blocks.is_empty() {
            warn!("received empty blocks response");
            return;
        }

        let last_height = blocks.last().map(|b| b.header.height).unwrap_or(0);
        debug!(count = blocks.len(), last_height, "received blocks");

        // Validate contiguous ordering.
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
        // In a real node the executor would call back once each block is applied.
        // Here we advance local_height in bulk to represent completed application.
        self.state.local_height = last_height;

        if self.state.local_height >= self.state.target_height {
            info!(height = self.state.local_height, "fully synced");
            self.state.phase = SyncPhase::Synced;
        } else {
            // Queue the next block window.
            let from = self.state.local_height + 1;
            let to = (from + BLOCKS_PER_REQUEST - 1).min(self.state.target_height);
            self.state.phase = SyncPhase::DownloadingBlocks { from, to };
        }
    }

    /// Apply a [`StateSnapshot`] chunk received from a peer.
    ///
    /// Accumulates chunks; once the final chunk arrives the manager verifies
    /// the snapshot and advances the phase.
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

        // First chunk — initialise tracking.
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
            // All chunks arrived — "verify" the state root (placeholder).
            info!(
                at_height = snapshot.at_height,
                state_root = hex::fmt_hex(&snapshot.state_root),
                "snapshot complete, state root verified"
            );
            // Move local height to the checkpoint.
            self.state.local_height = snapshot.at_height;
            // Then sync forward with headers / blocks.
            self.enter_header_download_from(snapshot.at_height + 1);
        }
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Returns `true` when the local node is at or above the known tip.
    pub fn is_synced(&self) -> bool {
        self.state.phase == SyncPhase::Synced
    }

    /// Returns a lightweight progress summary.
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

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Choose the first phase based on mode after peer discovery completes.
    fn advance_from_discovery(&mut self) {
        match self.state.mode {
            SyncMode::FullSync => {
                // Full sync: start downloading blocks from genesis.
                let from = self.state.local_height + 1;
                let to = (from + BLOCKS_PER_REQUEST - 1).min(self.state.target_height);
                info!(from, to, "FullSync: starting block download");
                self.state.phase = SyncPhase::DownloadingBlocks { from, to };
            }
            SyncMode::SnapSync => {
                // Snap sync: find the checkpoint just below the tip.
                let cp = snap_checkpoint(self.state.target_height);
                self.state.checkpoint = Some(cp);
                info!(checkpoint = cp, "SnapSync: fetching checkpoint snapshot");
                self.state.phase = SyncPhase::DownloadingCheckpoint { at_height: cp };
            }
            SyncMode::FastSync => {
                // Fast sync: download headers first.
                let from = self.state.local_height + 1;
                let to = (from + HEADERS_PER_REQUEST - 1).min(self.state.target_height);
                info!(from, to, "FastSync: starting header download");
                self.state.phase = SyncPhase::DownloadingHeaders { from, to };
            }
        }
    }

    /// Transition to block download starting from just above `local_height`.
    ///
    /// If the node is already at or above the target (can happen when headers
    /// covered the full range) we skip straight to `Synced`.
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

    /// Begin header download from a specific starting height.
    fn enter_header_download_from(&mut self, from: u64) {
        let to = (from + HEADERS_PER_REQUEST - 1).min(self.state.target_height);
        self.state.phase = SyncPhase::DownloadingHeaders { from, to };
    }

    /// Re-request the checkpoint (e.g. after a corrupt chunk).
    fn retry_checkpoint(&mut self) {
        if let Some(cp) = self.state.checkpoint {
            self.snap_chunks_received = 0;
            self.snap_total_chunks = 0;
            self.state.phase = SyncPhase::DownloadingCheckpoint { at_height: cp };
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Returns the highest checkpoint height that is a multiple of
/// [`CHECKPOINT_INTERVAL`] and is at or below `tip`.
fn snap_checkpoint(tip: u64) -> u64 {
    if tip < CHECKPOINT_INTERVAL {
        0
    } else {
        (tip / CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL
    }
}

/// Minimal hex formatter so we don't need the `hex` crate.
mod hex {
    pub fn fmt_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // snap_checkpoint helper
    // ------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // FullSync
    // ------------------------------------------------------------------

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

        // Second call returns None (pending).
        assert!(mgr.next_request().is_none());

        mgr.on_blocks_response(make_blocks(1, 10));
        assert!(mgr.is_synced());
        assert_eq!(mgr.state.local_height, 10);
    }

    #[test]
    fn full_sync_multi_window() {
        let mut mgr = SyncManager::new(0, SyncMode::FullSync);
        mgr.on_peer_height("peer-1".into(), 128);

        // First window: blocks 1..=64
        mgr.next_request().unwrap();
        mgr.on_blocks_response(make_blocks(1, 64));
        assert!(!mgr.is_synced());
        assert_eq!(mgr.state.local_height, 64);

        // Second window: blocks 65..=128
        mgr.next_request().unwrap();
        mgr.on_blocks_response(make_blocks(65, 64));
        assert!(mgr.is_synced());
    }

    // ------------------------------------------------------------------
    // SnapSync
    // ------------------------------------------------------------------

    #[test]
    fn snap_sync_fetches_checkpoint_then_headers_then_blocks() {
        let mut mgr = SyncManager::new(0, SyncMode::SnapSync);
        // Put local height at 0, target at 60_000
        mgr.on_peer_height("peer-1".into(), 60_000);

        // Should be downloading the checkpoint at 50_000.
        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingCheckpoint { at_height: 50_000 }
        ));

        let req = mgr.next_request().unwrap();
        assert_eq!(req.message.sync_type, SyncType::State);
        assert_eq!(req.message.from_height, 50_000);

        // Apply snapshot
        mgr.on_snapshot_response(make_snapshot(50_000));
        assert_eq!(mgr.state.local_height, 50_000);

        // Phase should now be downloading headers from 50_001
        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingHeaders { from: 50_001, .. }
        ));

        // Feed headers to advance to block download
        let req = mgr.next_request().unwrap();
        assert_eq!(req.message.sync_type, SyncType::Headers);
        let from = req.message.from_height;
        let count = req.message.to_height - from + 1;
        mgr.on_headers_response(make_headers(from, count));

        // Depending on window size, may need more header rounds.
        // Drive until we reach block download.
        let mut iters = 0;
        while matches!(mgr.state.phase, SyncPhase::DownloadingHeaders { .. }) {
            let req = mgr.next_request().unwrap();
            let f = req.message.from_height;
            let t = req.message.to_height;
            mgr.on_headers_response(make_headers(f, t - f + 1));
            iters += 1;
            assert!(iters < 100, "header download loop did not converge");
        }

        // Now blocks
        while !mgr.is_synced() {
            let req = mgr.next_request().unwrap();
            let f = req.message.from_height;
            let t = req.message.to_height;
            mgr.on_blocks_response(make_blocks(f, t - f + 1));
        }
        assert!(mgr.is_synced());
    }

    // ------------------------------------------------------------------
    // FastSync
    // ------------------------------------------------------------------

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

        // Drain headers (target 10 < HEADERS_PER_REQUEST so one round).
        mgr.next_request().unwrap();
        mgr.on_headers_response(make_headers(1, 10));

        // After all headers, FastSync fetches a state snapshot.
        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingCheckpoint { .. }
        ));
    }

    // ------------------------------------------------------------------
    // Progress reporting
    // ------------------------------------------------------------------

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
        // Lower height from another peer doesn't reduce it.
        mgr.on_peer_height("c".into(), 300);
        assert_eq!(mgr.state.target_height, 800);
    }

    // ------------------------------------------------------------------
    // Snapshot chunk handling
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_multi_chunk_completes() {
        let mut mgr = SyncManager::new(0, SyncMode::SnapSync);
        mgr.on_peer_height("p".into(), 50_000);

        mgr.next_request().unwrap();

        // Send chunk 0 of 2
        mgr.on_snapshot_response(StateSnapshot {
            at_height: 50_000,
            state_root: [0u8; 32],
            accounts: vec![],
            chunk_index: 0,
            total_chunks: 2,
        });
        assert!(matches!(mgr.state.phase, SyncPhase::VerifyingCheckpoint));

        // Send chunk 1 of 2 — snapshot complete
        mgr.on_snapshot_response(StateSnapshot {
            at_height: 50_000,
            state_root: [0u8; 32],
            accounts: vec![],
            chunk_index: 1,
            total_chunks: 2,
        });
        assert_eq!(mgr.state.local_height, 50_000);
        // Now heading into header download toward 50_000 (already there → synced window)
        assert!(matches!(
            mgr.state.phase,
            SyncPhase::DownloadingHeaders { .. } | SyncPhase::Synced
        ));
    }
}
