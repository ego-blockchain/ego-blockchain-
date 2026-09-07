use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_PAYLOAD: usize = 200;
pub const REASSEMBLY_TIMEOUT_SECS: i64 = 3600;
pub const MAX_PENDING_MESSAGES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Frame {
    pub v: u8,
    pub msg_id: u32,
    pub seq: u16,
    pub total: u16,
    pub crc: u32,
    pub payload: Vec<u8>,
}

pub trait SidebandTransport: Send + Sync {
    fn name(&self) -> &'static str;

    fn max_payload(&self) -> usize {
        MAX_FRAME_PAYLOAD
    }

    fn can_send(&self) -> bool {
        true
    }

    fn send_frame(&self, frame: &Frame) -> Result<(), String>;

    fn recv_frame(&self) -> Option<Frame>;
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub fn split(message: &[u8], max_payload: usize, msg_id: u32) -> Vec<Frame> {
    let chunk = max_payload.max(1);
    let checksum = crc32(message);
    let chunks: Vec<&[u8]> = message.chunks(chunk).collect();
    let total = chunks.len().min(u16::MAX as usize) as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, part)| Frame {
            v: PROTOCOL_VERSION,
            msg_id,
            seq: i as u16,
            total,
            crc: checksum,
            payload: part.to_vec(),
        })
        .collect()
}

struct Partial {
    total: u16,
    crc: u32,
    parts: HashMap<u16, Vec<u8>>,
    first_seen: i64,
}

fn pending() -> &'static Mutex<HashMap<u32, Partial>> {
    static P: OnceLock<Mutex<HashMap<u32, Partial>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn accept(frame: Frame, now: i64) -> Option<Vec<u8>> {
    if frame.v != PROTOCOL_VERSION || frame.total == 0 || frame.seq >= frame.total {
        return None;
    }

    let mut map = pending().lock().ok()?;
    map.retain(|_, p| now - p.first_seen < REASSEMBLY_TIMEOUT_SECS);

    if map.len() >= MAX_PENDING_MESSAGES && !map.contains_key(&frame.msg_id) {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, p)| p.first_seen)
            .map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
    }

    let entry = map.entry(frame.msg_id).or_insert_with(|| Partial {
        total: frame.total,
        crc: frame.crc,
        parts: HashMap::new(),
        first_seen: now,
    });

    if entry.total != frame.total || entry.crc != frame.crc {
        return None;
    }

    entry.parts.insert(frame.seq, frame.payload);
    if entry.parts.len() < entry.total as usize {
        return None;
    }

    let mut out = Vec::new();
    for i in 0..entry.total {
        out.extend_from_slice(entry.parts.get(&i)?);
    }

    let expected = entry.crc;
    map.remove(&frame.msg_id);

    if crc32(&out) != expected {
        return None;
    }
    Some(out)
}

pub fn missing_frames(msg_id: u32) -> Vec<u16> {
    let map = match pending().lock() {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    match map.get(&msg_id) {
        Some(p) => (0..p.total).filter(|s| !p.parts.contains_key(s)).collect(),
        None => Vec::new(),
    }
}

/// Frames accepted per transport per minute. A radio link is open to anyone in
/// range, so an attacker can transmit freely. Every frame costs reassembly work
/// before any signature is checked, so the cheap defence is a cap on frames, not
/// on transactions.
pub const MAX_FRAMES_PER_MINUTE: u32 = 600;

struct RateWindow {
    started: i64,
    count: u32,
}

fn rate_windows() -> &'static Mutex<HashMap<String, RateWindow>> {
    static R: OnceLock<Mutex<HashMap<String, RateWindow>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn rate_limit_ok(transport: &str, now: i64) -> bool {
    let mut map = match rate_windows().lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let w = map.entry(transport.to_string()).or_insert(RateWindow { started: now, count: 0 });
    if now - w.started >= 60 {
        w.started = now;
        w.count = 0;
    }
    w.count += 1;
    w.count <= MAX_FRAMES_PER_MINUTE
}

fn registry() -> &'static Mutex<Vec<Box<dyn SidebandTransport>>> {
    static T: OnceLock<Mutex<Vec<Box<dyn SidebandTransport>>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(Vec::new()))
}

/// True once at least one transport is registered. The send path checks this
/// before serialising anything, so a node with no sideband configured pays
/// nothing for the feature existing.
pub fn has_transport() -> bool {
    registry().lock().map(|r| !r.is_empty()).unwrap_or(false)
}

/// Names of the registered transports and whether each can transmit.
pub fn transports() -> Vec<(String, bool)> {
    match registry().lock() {
        Ok(r) => r.iter().map(|t| (t.name().to_string(), t.can_send())).collect(),
        Err(_) => Vec::new(),
    }
}

pub fn register(transport: Box<dyn SidebandTransport>) {
    if let Ok(mut v) = registry().lock() {
        eprintln!("[Sideband] registered transport: {}", transport.name());
        v.push(transport);
    }
}

/// Drain every registered transport once, reassemble what is complete, and hand
/// the result to the node through the same validation gossip uses.
pub async fn poll_once(app: Option<&tauri::AppHandle<tauri::Wry>>) {
    let now = chrono::Utc::now().timestamp();

    let drained: Vec<(&'static str, Frame)> = {
        let reg = match registry().lock() {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut out = Vec::new();
        for t in reg.iter() {
            while let Some(frame) = t.recv_frame() {
                if !rate_limit_ok(t.name(), now) {
                    eprintln!("[Sideband] {} exceeded frame rate limit, dropping", t.name());
                    break;
                }
                out.push((t.name(), frame));
            }
        }
        out
    };

    for (name, frame) in drained {
        if let Some(message) = accept(frame, now) {
            match crate::p2p::ingest_sideband_bytes(name, &message, app).await {
                Ok(()) => {}
                Err(e) => eprintln!("[Sideband] {e}"),
            }
        }
    }
}

/// Send a message out over every transport that can transmit. Receive-only
/// links, such as a satellite downlink, report can_send() false and are skipped.
pub fn broadcast(message: &[u8], msg_id: u32) -> usize {
    let reg = match registry().lock() {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let mut sent = 0usize;
    for t in reg.iter() {
        if !t.can_send() {
            continue;
        }
        let frames = split(message, t.max_payload(), msg_id);
        let total = frames.len();
        let mut ok = true;
        for frame in frames {
            if let Err(e) = t.send_frame(&frame) {
                eprintln!("[Sideband] {} send failed: {e}", t.name());
                ok = false;
                break;
            }
        }
        if ok {
            eprintln!("[Sideband] {} queued {total} frames for msg {msg_id:08x}", t.name());
            sent += 1;
        }
    }
    sent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn a_message_survives_being_split_and_reassembled() {
        let original = msg(4048);
        let frames = split(&original, 200, 7);
        assert_eq!(frames.len(), 21);
        let mut out = None;
        for f in frames {
            out = accept(f, 0);
        }
        assert_eq!(out, Some(original));
    }

    #[test]
    fn frames_arriving_out_of_order_still_reassemble() {
        let original = msg(1000);
        let mut frames = split(&original, 200, 11);
        frames.reverse();
        let mut out = None;
        for f in frames {
            out = accept(f, 0);
        }
        assert_eq!(out, Some(original));
    }

    #[test]
    fn an_incomplete_message_yields_nothing_and_reports_what_is_missing() {
        let original = msg(1000);
        let frames = split(&original, 200, 12);
        for f in frames.iter().take(3).cloned() {
            assert_eq!(accept(f, 0), None);
        }
        assert_eq!(missing_frames(12), vec![3, 4]);
    }

    #[test]
    fn a_corrupted_payload_is_rejected_rather_than_delivered() {
        let original = msg(600);
        let mut frames = split(&original, 200, 13);
        frames[1].payload[0] ^= 0xFF;
        let mut out = None;
        for f in frames {
            out = accept(f, 0);
        }
        assert_eq!(out, None, "corrupted reassembly must not be delivered");
    }

    #[test]
    fn frames_from_a_different_message_do_not_mix() {
        let a = msg(400);
        let b = msg(400);
        let fa = split(&a, 200, 20);
        let fb = split(&b, 200, 21);
        assert_eq!(accept(fa[0].clone(), 0), None);
        assert_eq!(accept(fb[0].clone(), 0), None);
        assert_eq!(accept(fa[1].clone(), 0), Some(a));
        assert_eq!(accept(fb[1].clone(), 0), Some(b));
    }

    #[test]
    fn a_stale_partial_is_dropped_rather_than_held_forever() {
        let original = msg(1000);
        let frames = split(&original, 200, 30);
        assert_eq!(accept(frames[0].clone(), 0), None);
        // arriving after the timeout starts a fresh partial, so it cannot complete
        assert_eq!(accept(frames[1].clone(), REASSEMBLY_TIMEOUT_SECS + 1), None);
        assert!(missing_frames(30).len() >= 4);
    }
}
