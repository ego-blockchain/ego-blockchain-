use crate::sideband::{Frame, SidebandTransport};
use std::path::PathBuf;

/// A transport that moves frames through a directory rather than a socket.
///
/// Frames written to `inbox/` are read and deleted; frames to transmit are
/// written to `outbox/`. Nothing here knows what carries them, which is the
/// point: a twenty-line script can bridge a LoRa module, a KISS TNC, an SDR or
/// a satellite receiver without any Rust, and a USB stick physically carried
/// between two machines is a valid transport with no code at all.
///
/// It is also the transport used to test the pipeline end to end without radio
/// hardware present.
pub struct SpoolTransport {
    name: &'static str,
    inbox: PathBuf,
    outbox: PathBuf,
    send_enabled: bool,
    max_payload: usize,
}

impl SpoolTransport {
    pub fn new(name: &'static str, root: PathBuf, send_enabled: bool, max_payload: usize) -> Self {
        let inbox = root.join("inbox");
        let outbox = root.join("outbox");
        let _ = std::fs::create_dir_all(&inbox);
        let _ = std::fs::create_dir_all(&outbox);
        Self { name, inbox, outbox, send_enabled, max_payload }
    }

    /// Default spool under the node's data directory, so an operator can find it
    /// without configuration.
    pub fn default_spool() -> Self {
        let root = crate::ledger::base_data_dir().join("sideband");
        Self::new("spool", root, true, 200)
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
        let name = format!("{:08x}-{:05}.frame", frame.msg_id, frame.seq);
        // Write beside the target then rename, so a bridge script never reads a
        // half-written frame.
        let tmp = self.outbox.join(format!("{name}.tmp"));
        std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.outbox.join(&name)).map_err(|e| e.to_string())
    }

    fn recv_frame(&self) -> Option<Frame> {
        let entries = std::fs::read_dir(&self.inbox).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("frame") {
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
            std::fs::copy(entry.path(), receiver.inbox().join(name)).unwrap();
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
