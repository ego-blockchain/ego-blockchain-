use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_PAYLOAD: usize = 200;
pub const REASSEMBLY_TIMEOUT_SECS: i64 = 3600;
pub const MAX_PENDING_MESSAGES: usize = 64;

pub const KIND_DATA: u8 = 0;
pub const KIND_REPEAT_REQUEST: u8 = 1;

/// How long a partial message must sit untouched before we assume the frames
/// still missing were lost rather than merely slow. An HF hop can space frames
/// minutes apart, so asking too eagerly spends the little bandwidth there is on
/// frames that were already on their way.
pub const REPAIR_IDLE_SECS: i64 = 120;
pub const MAX_REPAIR_ATTEMPTS: u8 = 3;

/// Sent frames are kept so a peer that lost a few can ask for exactly those,
/// rather than the whole transaction crossing the link again.
pub const SENT_CACHE_TTL_SECS: i64 = 3600;
pub const MAX_SENT_MESSAGES: usize = 32;

/// How many times we will answer a repeat request for the same message.
///
/// A repeat request is a few bytes and the answer can be twenty frames, so an
/// unbounded responder is an amplifier. Worse than the bandwidth: answering
/// means keying the transmitter, and on the links this exists for that is what
/// gets a person located. An attacker who can hear us must not be able to make
/// us transmit at will, so the honest case gets a few repairs and no more.
pub const MAX_REPEAT_SERVES: u8 = 6;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Frame {
    pub v: u8,
    #[serde(default)]
    pub kind: u8,
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
            kind: KIND_DATA,
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
    last_seen: i64,
    repair_attempts: u8,
}

fn pending() -> &'static Mutex<HashMap<u32, Partial>> {
    static P: OnceLock<Mutex<HashMap<u32, Partial>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn accept(frame: Frame, now: i64) -> Option<Vec<u8>> {
    if frame.v != PROTOCOL_VERSION
        || frame.kind != KIND_DATA
        || frame.total == 0
        || frame.seq >= frame.total
    {
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
        last_seen: now,
        repair_attempts: 0,
    });

    if entry.total != frame.total || entry.crc != frame.crc {
        return None;
    }

    entry.last_seen = now;
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

/// Partial messages that have gone quiet with frames still missing.
///
/// Each call counts as an attempt, so a message nobody can repair is asked
/// about a bounded number of times rather than forever.
pub fn partials_needing_repair(now: i64) -> Vec<(u32, u16, u32, Vec<u16>)> {
    let mut map = match pending().lock() {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (msg_id, p) in map.iter_mut() {
        if p.repair_attempts >= MAX_REPAIR_ATTEMPTS {
            continue;
        }
        if now - p.last_seen < REPAIR_IDLE_SECS {
            continue;
        }
        let missing: Vec<u16> = (0..p.total).filter(|s| !p.parts.contains_key(s)).collect();
        if missing.is_empty() {
            continue;
        }
        p.repair_attempts += 1;
        p.last_seen = now;
        out.push((*msg_id, p.total, p.crc, missing));
    }
    out
}

pub fn build_repeat_request(msg_id: u32, total: u16, crc: u32, missing: &[u16]) -> Frame {
    let mut payload = Vec::with_capacity(missing.len() * 2);
    for seq in missing {
        payload.extend_from_slice(&seq.to_le_bytes());
    }
    Frame {
        v: PROTOCOL_VERSION,
        kind: KIND_REPEAT_REQUEST,
        msg_id,
        seq: 0,
        total,
        crc,
        payload,
    }
}

pub fn parse_repeat_request(frame: &Frame) -> Option<Vec<u16>> {
    if frame.kind != KIND_REPEAT_REQUEST || frame.v != PROTOCOL_VERSION {
        return None;
    }
    if frame.payload.is_empty() || frame.payload.len() % 2 != 0 {
        return None;
    }
    Some(
        frame
            .payload
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect(),
    )
}

struct SentMessage {
    frames: Vec<Frame>,
    sent_at: i64,
    served: u8,
}

fn sent_cache() -> &'static Mutex<HashMap<u32, SentMessage>> {
    static S: OnceLock<Mutex<HashMap<u32, SentMessage>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_sent(msg_id: u32, frames: Vec<Frame>, now: i64) {
    let Ok(mut map) = sent_cache().lock() else { return };
    map.retain(|_, m| now - m.sent_at < SENT_CACHE_TTL_SECS);
    if map.len() >= MAX_SENT_MESSAGES && !map.contains_key(&msg_id) {
        if let Some(oldest) = map.iter().min_by_key(|(_, m)| m.sent_at).map(|(k, _)| *k) {
            map.remove(&oldest);
        }
    }
    map.insert(msg_id, SentMessage { frames, sent_at: now, served: 0 });
}

/// Frames we still hold for a message a peer is asking us to repeat.
///
/// Counts against that message's repair budget, so a peer that keeps asking
/// stops being answered rather than keying our transmitter indefinitely.
pub fn frames_for_repeat(msg_id: u32, wanted: &[u16]) -> Vec<Frame> {
    let Ok(mut map) = sent_cache().lock() else { return Vec::new() };
    let Some(msg) = map.get_mut(&msg_id) else { return Vec::new() };
    if msg.served >= MAX_REPEAT_SERVES {
        eprintln!("[Sideband] repair budget for msg {msg_id:08x} is spent, ignoring request");
        return Vec::new();
    }
    msg.served += 1;
    msg.frames
        .iter()
        .filter(|f| wanted.contains(&f.seq))
        .cloned()
        .collect()
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

fn emit(frame: &Frame) -> usize {
    let Ok(reg) = registry().lock() else { return 0 };
    let mut sent = 0;
    for t in reg.iter() {
        if !t.can_send() {
            continue;
        }
        if t.send_frame(frame).is_ok() {
            sent += 1;
        }
    }
    sent
}

/// Ask peers to resend the frames we are missing.
///
/// Only possible on a link we can transmit on. A receive-only transport has no
/// way to ask, which is why the sending side of a one-way link should raise its
/// redundancy instead.
pub fn run_repair(now: i64) {
    for (msg_id, total, crc, missing) in partials_needing_repair(now) {
        let req = build_repeat_request(msg_id, total, crc, &missing);
        if emit(&req) > 0 {
            eprintln!(
                "[Sideband] asked for {} missing frame(s) of msg {msg_id:08x}",
                missing.len()
            );
        }
    }
}

fn answer_repeat_request(frame: &Frame) {
    let Some(wanted) = parse_repeat_request(frame) else { return };
    let frames = frames_for_repeat(frame.msg_id, &wanted);
    if frames.is_empty() {
        return;
    }
    let mut sent = 0;
    for f in &frames {
        sent += emit(f);
    }
    if sent > 0 {
        eprintln!(
            "[Sideband] resent {} frame(s) of msg {:08x} on request",
            frames.len(),
            frame.msg_id
        );
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
            loop {
                if !rate_limit_ok(t.name(), now) {
                    eprintln!(
                        "[Sideband] {} hit the frame rate limit — the rest stay queued for the next poll",
                        t.name()
                    );
                    break;
                }
                match t.recv_frame() {
                    Some(frame) => out.push((t.name(), frame)),
                    None => break,
                }
            }
        }
        out
    };

    for (name, frame) in drained {
        if frame.kind == KIND_REPEAT_REQUEST {
            answer_repeat_request(&frame);
            continue;
        }
        if let Some(message) = accept(frame, now) {
            match crate::p2p::ingest_sideband_bytes(name, &message, app).await {
                Ok(()) => {}
                Err(e) => eprintln!("[Sideband] {e}"),
            }
        }
    }

    run_repair(now);
}

/// Send a message out over every transport that can transmit. Receive-only
/// links, such as a satellite downlink, report can_send() false and are skipped.
pub fn broadcast(message: &[u8], msg_id: u32) -> usize {
    let mut sent = 0usize;
    let mut retained: Option<Vec<Frame>> = None;

    {
        let reg = match registry().lock() {
            Ok(r) => r,
            Err(_) => return 0,
        };
        for t in reg.iter() {
            if !t.can_send() {
                continue;
            }
            let frames = split(message, t.max_payload(), msg_id);
            let total = frames.len();
            let mut ok = true;

            for frame in &frames {
                if let Err(e) = t.send_frame(frame) {
                    eprintln!("[Sideband] {} send failed: {e}", t.name());
                    ok = false;
                    break;
                }
            }

            if ok {
                eprintln!(
                    "[Sideband] {} queued {total} frames for msg {msg_id:08x}",
                    t.name()
                );
                sent += 1;
                if retained.is_none() {
                    retained = Some(frames);
                }
            }
        }
    }

    if let Some(frames) = retained {
        remember_sent(msg_id, frames, chrono::Utc::now().timestamp());
    }
    sent
}

/// Reassembly state is process-wide, and cargo runs tests in parallel. Any test
/// that inspects or clears that state must hold this first, or it will observe
/// another test's frames and fail intermittently.
#[cfg(test)]
fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
fn reset_state() {
    if let Ok(mut m) = pending().lock() { m.clear(); }
    if let Ok(mut m) = sent_cache().lock() { m.clear(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn a_message_survives_being_split_and_reassembled() {
        let _guard = test_guard();
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
        let _guard = test_guard();
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
        let _guard = test_guard();
        let original = msg(1000);
        let frames = split(&original, 200, 12);
        for f in frames.iter().take(3).cloned() {
            assert_eq!(accept(f, 0), None);
        }
        assert_eq!(missing_frames(12), vec![3, 4]);
    }

    #[test]
    fn a_corrupted_payload_is_rejected_rather_than_delivered() {
        let _guard = test_guard();
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
        let _guard = test_guard();
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
        let _guard = test_guard();
        let original = msg(1000);
        let frames = split(&original, 200, 30);
        assert_eq!(accept(frames[0].clone(), 0), None);
        assert_eq!(accept(frames[1].clone(), REASSEMBLY_TIMEOUT_SECS + 1), None);
        assert!(missing_frames(30).len() >= 4);
    }

    #[test]
    fn a_repeated_frame_is_harmless() {
        let _guard = test_guard();
        let original = msg(600);
        let frames = split(&original, 200, 31);
        assert_eq!(accept(frames[0].clone(), 0), None);
        assert_eq!(accept(frames[0].clone(), 0), None);
        assert_eq!(accept(frames[1].clone(), 0), None);
        assert_eq!(accept(frames[2].clone(), 0), Some(original));
    }
}

#[cfg(test)]
mod repair_tests {
    use super::*;

    fn msg(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn a_message_still_arriving_is_not_chased() {
        let _guard = test_guard();
        reset_state();
        let frames = split(&msg(1000), 200, 100);
        accept(frames[0].clone(), 0);
        assert!(
            partials_needing_repair(REPAIR_IDLE_SECS - 1).is_empty(),
            "a message that may still be in flight must not be chased"
        );
    }

    #[test]
    fn a_message_that_went_quiet_names_exactly_the_missing_frames() {
        let _guard = test_guard();
        reset_state();
        let frames = split(&msg(1000), 200, 101);
        accept(frames[0].clone(), 0);
        accept(frames[2].clone(), 0);
        accept(frames[4].clone(), 0);

        let repairs = partials_needing_repair(REPAIR_IDLE_SECS + 1);
        assert_eq!(repairs.len(), 1);
        let (msg_id, total, _crc, missing) = &repairs[0];
        assert_eq!(*msg_id, 101);
        assert_eq!(*total, 5);
        assert_eq!(missing, &vec![1u16, 3]);
    }

    #[test]
    fn a_repeat_request_round_trips_through_the_wire_format() {
        let _guard = test_guard();
        let req = build_repeat_request(202, 21, 0xdead_beef, &[1, 3, 17]);
        assert_eq!(req.kind, KIND_REPEAT_REQUEST);
        assert_eq!(parse_repeat_request(&req), Some(vec![1, 3, 17]));

        let encoded = serde_json::to_vec(&req).unwrap();
        let decoded: Frame = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(parse_repeat_request(&decoded), Some(vec![1, 3, 17]));
    }

    #[test]
    fn a_repeat_request_is_never_mistaken_for_data() {
        let _guard = test_guard();
        reset_state();
        let req = build_repeat_request(203, 4, 7, &[2]);
        assert_eq!(accept(req, 0), None, "a control frame must not enter reassembly");
        assert!(missing_frames(203).is_empty());
    }

    #[test]
    fn a_data_frame_is_never_mistaken_for_a_repeat_request() {
        let _guard = test_guard();
        let frames = split(&msg(400), 200, 204);
        assert_eq!(parse_repeat_request(&frames[0]), None);
    }

    #[test]
    fn a_frame_from_an_older_build_still_parses_as_data() {
        let _guard = test_guard();
        let legacy = br#"{"v":1,"msg_id":9,"seq":0,"total":1,"crc":0,"payload":[]}"#;
        let f: Frame = serde_json::from_slice(legacy).unwrap();
        assert_eq!(f.kind, KIND_DATA, "a frame with no kind field must mean data");
    }

    #[test]
    fn we_stop_asking_after_a_bounded_number_of_attempts() {
        let _guard = test_guard();
        reset_state();
        let frames = split(&msg(1000), 200, 105);
        accept(frames[0].clone(), 0);

        let mut now = REPAIR_IDLE_SECS + 1;
        let mut asked = 0;
        for _ in 0..(MAX_REPAIR_ATTEMPTS as usize + 3) {
            if !partials_needing_repair(now).is_empty() {
                asked += 1;
            }
            now += REPAIR_IDLE_SECS + 1;
        }
        assert_eq!(asked, MAX_REPAIR_ATTEMPTS as usize, "repair must give up eventually");
    }

    #[test]
    fn a_sender_serves_exactly_the_frames_asked_for() {
        let _guard = test_guard();
        reset_state();
        let frames = split(&msg(1000), 200, 106);
        remember_sent(106, frames, 0);

        let served = frames_for_repeat(106, &[1, 3]);
        assert_eq!(served.len(), 2);
        assert_eq!(served[0].seq, 1);
        assert_eq!(served[1].seq, 3);
    }

    #[test]
    fn a_peer_cannot_make_us_transmit_indefinitely() {
        let _guard = test_guard();
        reset_state();
        remember_sent(108, split(&msg(1000), 200, 108), 0);
        let mut answered = 0;
        for _ in 0..(MAX_REPEAT_SERVES as usize + 5) {
            if !frames_for_repeat(108, &[0, 1, 2]).is_empty() {
                answered += 1;
            }
        }
        assert_eq!(
            answered, MAX_REPEAT_SERVES as usize,
            "a repeat request must not be an unbounded way to key our transmitter"
        );
    }

    #[test]
    fn a_request_for_a_message_we_never_sent_serves_nothing() {
        let _guard = test_guard();
        reset_state();
        assert!(frames_for_repeat(9999, &[0, 1]).is_empty());
    }

    #[test]
    fn the_sent_cache_cannot_grow_without_bound() {
        let _guard = test_guard();
        reset_state();
        for i in 0..(MAX_SENT_MESSAGES as u32 + 10) {
            remember_sent(i, split(&msg(200), 200, i), 0);
        }
        let len = sent_cache().lock().unwrap().len();
        assert!(len <= MAX_SENT_MESSAGES, "sent cache grew to {len}");
    }

    #[test]
    fn repair_recovers_a_transaction_that_lost_frames_in_flight() {
        let _guard = test_guard();
        reset_state();
        let payload = msg(4048);
        let sent = split(&payload, 200, 107);
        remember_sent(107, sent.clone(), 0);

        let lost = [4u16, 9, 15];
        for f in sent.iter().filter(|f| !lost.contains(&f.seq)) {
            assert_eq!(
                accept(f.clone(), 0),
                None,
                "must not complete while frames are missing"
            );
        }

        let repairs = partials_needing_repair(REPAIR_IDLE_SECS + 1);
        assert_eq!(repairs.len(), 1);
        let (msg_id, total, crc, missing) = repairs[0].clone();
        assert_eq!(missing, lost.to_vec());

        let req = build_repeat_request(msg_id, total, crc, &missing);
        let wanted = parse_repeat_request(&req).unwrap();
        let resent = frames_for_repeat(msg_id, &wanted);
        assert_eq!(resent.len(), 3);

        let mut out = None;
        for f in resent {
            out = accept(f, REPAIR_IDLE_SECS + 2);
        }
        assert_eq!(out, Some(payload), "the transaction must survive the loss");
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::{rate_limit_ok, MAX_FRAMES_PER_MINUTE};

    #[test]
    fn the_limit_is_checked_before_a_frame_is_taken_off_the_wire() {
        let now = 1_000_000i64;
        let t = "ratetest-order";
        for i in 0..MAX_FRAMES_PER_MINUTE {
            assert!(rate_limit_ok(t, now), "frame {i} is within the limit");
        }
        assert!(
            !rate_limit_ok(t, now),
            "the call that refuses must happen before recv_frame deletes the file, or the frame              is destroyed rather than deferred and its message can never be reassembled",
        );
    }

    #[test]
    fn the_window_reopens_after_a_minute() {
        let t = "ratetest-window";
        let start = 2_000_000i64;
        for _ in 0..MAX_FRAMES_PER_MINUTE {
            assert!(rate_limit_ok(t, start));
        }
        assert!(!rate_limit_ok(t, start));
        assert!(rate_limit_ok(t, start + 60), "a new minute starts a new budget");
    }

    #[test]
    fn a_whole_transaction_fits_in_one_window() {
        assert!(
            MAX_FRAMES_PER_MINUTE >= 100,
            "one signed transaction splits into about 45 frames, so a budget under a hundred              would stall an ordinary offline payment",
        );
    }
}
