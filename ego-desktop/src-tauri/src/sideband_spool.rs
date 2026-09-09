use crate::sideband::{Frame, SidebandTransport};
use std::path::PathBuf;
use std::sync::OnceLock;

static SPOOL_ROOT: OnceLock<PathBuf> = OnceLock::new();

pub fn spool_root() -> Option<&'static PathBuf> {
    SPOOL_ROOT.get()
}

fn count_frames(dir: &PathBuf) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("frame"))
                .count()
        })
        .unwrap_or(0)
}

/// Frames waiting in the inbox and the outbox of the default spool.
pub fn queue_depths() -> (usize, usize) {
    let Some(root) = SPOOL_ROOT.get() else { return (0, 0) };
    let mine = format!("{}-", node_tag());
    let (mut waiting, mut sent) = (0usize, 0usize);
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("frame") {
                continue;
            }
            match path.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.starts_with(&mine) => sent += 1,
                Some(_) => waiting += 1,
                None => {}
            }
        }
    }
    (waiting, sent)
}

pub struct SpoolTransport {
    name: &'static str,
    inbox: PathBuf,
    outbox: PathBuf,
    send_enabled: bool,
    max_payload: usize,
}

fn spool_dir_override(var: &str) -> Option<PathBuf> {
    let raw = std::env::var(var).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

pub fn shared_spool_dir() -> PathBuf {
    if let Some(dir) = spool_dir_override("EGO_SIDEBAND_DIR") {
        return dir;
    }
    let base = std::env::var("PROGRAMDATA")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("Ego").join("sideband")
}

pub fn node_tag() -> &'static str {
    static TAG: OnceLock<String> = OnceLock::new();
    TAG.get_or_init(|| {
        let dir = crate::ledger::base_data_dir();
        let digest = ego_core::hash_data(dir.to_string_lossy().as_bytes()).to_hex();
        digest.chars().take(8).collect()
    })
}

impl SpoolTransport {
    pub fn new(name: &'static str, root: PathBuf, send_enabled: bool, max_payload: usize) -> Self {
        let inbox = root.join("inbox");
        let outbox = root.join("outbox");
        let _ = std::fs::create_dir_all(&inbox);
        let _ = std::fs::create_dir_all(&outbox);
        Self { name, inbox, outbox, send_enabled, max_payload }
    }

    pub fn default_spool() -> Self {
        let root = shared_spool_dir();
        let _ = std::fs::create_dir_all(&root);
        let _ = SPOOL_ROOT.set(root.clone());
        eprintln!("[Sideband] offline link at {} (node {})", root.display(), node_tag());
        Self { name: "spool", inbox: root.clone(), outbox: root, send_enabled: true, max_payload: 200 }
    }

    pub fn inbox(&self) -> &PathBuf {
        &self.inbox
    }

    pub fn outbox(&self) -> &PathBuf {
        &self.outbox
    }
}

impl SidebandTransport for SpoolTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn max_payload(&self) -> usize {
        self.max_payload
    }

    fn can_send(&self) -> bool {
        self.send_enabled
    }

    fn send_frame(&self, frame: &Frame) -> Result<(), String> {
        if !self.send_enabled {
            return Err("transport is receive-only".into());
        }
        let body = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
        let name = format!("{}-{:08x}-{:05}.frame", node_tag(), frame.msg_id, frame.seq);
        // Write beside the target then rename, so a bridge script never reads a
        // half-written frame.
        let tmp = self.outbox.join(format!("{name}.tmp"));
        std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.outbox.join(&name)).map_err(|e| e.to_string())
    }

    fn recv_frame(&self) -> Option<Frame> {
        let entries = std::fs::read_dir(&self.inbox).ok()?;
        let mine = format!("{}-", node_tag());
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("frame") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(&mine)) {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            // Consume the file whether or not it parses, so a malformed frame
            // cannot wedge the inbox by being retried forever.
            let _ = std::fs::remove_file(&path);
            match serde_json::from_slice::<Frame>(&bytes) {
                Ok(f) => return Some(f),
                Err(e) => {
                    eprintln!("[Sideband] {} discarded malformed frame: {e}", self.name);
                    continue;
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sideband::{accept, split};

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ego-sideband-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn a_transaction_survives_the_full_spool_round_trip() {
        let root = tmp_root("roundtrip");
        let sender = SpoolTransport::new("spool", root.clone(), true, 200);

        // 4 KB stands in for a signed Ego transaction with its Dilithium key and signature.
        let payload: Vec<u8> = (0..4048).map(|i| (i % 251) as u8).collect();
        for frame in split(&payload, sender.max_payload(), 42) {
            sender.send_frame(&frame).expect("write frame");
        }

        // The carrier, whatever it is, moves outbox to the other side's inbox.
        let receiver_root = tmp_root("roundtrip-rx");
        let receiver = SpoolTransport::new("spool", receiver_root, true, 200);
        for entry in std::fs::read_dir(sender.outbox()).unwrap().flatten() {
            let name = entry.file_name();
            let as_seen_from_elsewhere = name
                .to_string_lossy()
                .replacen(node_tag(), "beefcafe", 1);
            std::fs::copy(entry.path(), receiver.inbox().join(as_seen_from_elsewhere)).unwrap();
        }

        let mut reassembled = None;
        while let Some(frame) = receiver.recv_frame() {
            if let Some(msg) = accept(frame, 0) {
                reassembled = Some(msg);
            }
        }
        assert_eq!(reassembled, Some(payload), "payload must survive the carrier");
    }

    #[test]
    fn a_receive_only_transport_refuses_to_transmit() {
        let root = tmp_root("rxonly");
        let sat = SpoolTransport::new("satellite", root, false, 200);
        assert!(!sat.can_send());
        let frame = split(b"anything", 200, 1).remove(0);
        assert!(sat.send_frame(&frame).is_err(), "receive-only must not transmit");
    }

    #[test]
    fn a_malformed_frame_is_consumed_rather_than_retried_forever() {
        let root = tmp_root("malformed");
        let t = SpoolTransport::new("spool", root, true, 200);
        std::fs::write(t.inbox().join("bad.frame"), b"not json at all").unwrap();
        assert!(t.recv_frame().is_none());
        assert!(t.recv_frame().is_none(), "the bad frame must not still be there");
        assert_eq!(std::fs::read_dir(t.inbox()).unwrap().count(), 0);
    }
}

#[cfg(test)]
mod carrier_tests {
    use super::*;

    #[test]
    fn a_node_reads_frames_from_others_and_skips_its_own() {
        let dir = std::env::temp_dir().join(format!("ego-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let me = SpoolTransport {
            name: "spool", inbox: dir.clone(), outbox: dir.clone(),
            send_enabled: true, max_payload: 200,
        };
        let frame = Frame { v: 1, kind: 1, msg_id: 0xABCD, seq: 1, total: 1, crc: 0, payload: b"mine".to_vec() };
        me.send_frame(&frame).unwrap();
        assert!(
            me.recv_frame().is_none(),
            "a node must not read back its own frame from the shared folder, or every payment              would be delivered to the sender",
        );

        let theirs = dir.join("beefcafe-0000abcd-00001.frame");
        let other = Frame { v: 1, kind: 1, msg_id: 0xBEEF, seq: 1, total: 1, crc: 0, payload: b"yours".to_vec() };
        std::fs::write(&theirs, serde_json::to_vec(&other).unwrap()).unwrap();

        let got = me.recv_frame().expect("a frame from another node must be picked up");
        assert_eq!(got.payload, b"yours".to_vec());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unset_or_blank_override_keeps_the_default_spool() {
        std::env::remove_var("EGO_SIDEBAND_INBOX");
        assert!(spool_dir_override("EGO_SIDEBAND_INBOX").is_none());
        std::env::set_var("EGO_SIDEBAND_INBOX", "   ");
        assert!(
            spool_dir_override("EGO_SIDEBAND_INBOX").is_none(),
            "a blank value must not redirect the spool to the working directory",
        );
        std::env::remove_var("EGO_SIDEBAND_INBOX");
    }
}
