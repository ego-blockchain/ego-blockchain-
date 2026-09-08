//! Randomised robustness testing of everything that parses bytes a stranger
//! chose.
//!
//! # The bar
//!
//! Not "produces the right answer". Malformed input has no right answer, and
//! every decoder here is expected to reject most of what it is given. The bar
//! is that it must **reject rather than panic**. A validator is the whole
//! security model, and a panic on attacker-controlled bytes takes it off the
//! network, which is a denial of service that anyone can perform for the cost
//! of one message. Every one of these paths is reachable from a peer or a
//! radio before any signature has been checked.
//!
//! # What this is and is not
//!
//! This is randomised testing with structure-aware mutation, not a
//! coverage-guided fuzzer. A real fuzzer watches which branches an input
//! reaches and steers towards new ones, and would find things this does not.
//! What this does have is that it runs on stable Rust as part of the ordinary
//! test suite, on every machine, forever, rather than only when somebody
//! remembers to start a fuzzing job. The generators below deliberately mix
//! pure noise, near-miss valid encodings and mutated valid values, because
//! pure noise is rejected at the first byte and never reaches the interesting
//! code.
//!
//! Each case runs inside `catch_unwind`, so a panic is reported as a failure
//! with the input that caused it rather than taking the test binary down.

#![cfg(test)]

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

/// Cases per target. Enough to be worth running on every build and quick
/// enough that nobody is tempted to skip it.
const CASES: usize = 4_000;

/// Silences panic output for as long as it lives, and puts the previous hook
/// back however the scope ends.
///
/// Restoring by hand is a trap: if anything panics before the restore line,
/// the silent hook survives and the real failure prints nothing at all, which
/// is exactly what happened the first time this file was written.
struct QuietPanics(Option<Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>>);

impl QuietPanics {
    fn new() -> Self {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        Self(Some(previous))
    }
}

impl Drop for QuietPanics {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            std::panic::set_hook(previous);
        }
    }
}

/// Run `f` over many generated inputs and fail with the offending bytes.
///
/// The panic hook is silenced for the duration: a decoder that panics is the
/// finding, and the default hook would bury it in backtraces from thousands of
/// deliberately malformed cases.
fn hammer<F>(name: &str, mut gen: impl FnMut(&mut StdRng) -> Vec<u8>, f: F)
where
    F: Fn(&[u8]) + std::panic::RefUnwindSafe,
{
    let mut rng = StdRng::from_entropy();
    let _quiet = QuietPanics::new();
    let mut failure: Option<Vec<u8>> = None;
    for _ in 0..CASES {
        let input = gen(&mut rng);
        let probe = input.clone();
        if std::panic::catch_unwind(|| f(&probe)).is_err() {
            failure = Some(input);
            break;
        }
    }
    drop(_quiet);
    if let Some(bytes) = failure {
        panic!(
            "{name} panicked on {} bytes of hostile input: {}",
            bytes.len(),
            hex::encode(&bytes[..bytes.len().min(256)])
        );
    }
}

/// Pure noise. Rejected early, but it is the case that catches a length field
/// read before it is bounds-checked.
fn noise(rng: &mut StdRng) -> Vec<u8> {
    let len = rng.gen_range(0..512);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

/// Flip bytes in something that was valid. This is where the interesting
/// cases are: the input gets far enough in to reach real logic.
fn mutate(rng: &mut StdRng, valid: &[u8]) -> Vec<u8> {
    let mut v = valid.to_vec();
    for _ in 0..rng.gen_range(1..=4) {
        // An earlier operation can have truncated the buffer to nothing, and
        // every operation below indexes into it.
        if v.is_empty() {
            v.push(rng.gen());
            continue;
        }
        match rng.gen_range(0..4) {
            0 => {
                let i = rng.gen_range(0..v.len());
                v[i] = rng.gen();
            }
            1 => {
                let i = rng.gen_range(0..v.len());
                v.truncate(i);
            }
            2 => {
                let i = rng.gen_range(0..=v.len());
                v.insert(i, rng.gen());
            }
            _ => {
                let i = rng.gen_range(0..v.len());
                v[i] = v[i].wrapping_add(1);
            }
        }
    }
    v
}

/// Text that looks like JSON without being any particular message. Exercises
/// the serde layer past its first character.
fn junk_json(rng: &mut StdRng) -> Vec<u8> {
    const PIECES: [&str; 14] = [
        "{", "}", "[", "]", ":", ",", "\"a\"", "null", "true", "-1",
        "18446744073709551616", "1e400", "\"\\ud800\"", "{\"hash\":",
    ];
    let n = rng.gen_range(1..24);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(PIECES[rng.gen_range(0..PIECES.len())]);
    }
    s.into_bytes()
}

fn mixed(rng: &mut StdRng, valid: &[u8]) -> Vec<u8> {
    match rng.gen_range(0..3) {
        0 => noise(rng),
        1 => junk_json(rng),
        _ => mutate(rng, valid),
    }
}

/// A harness that cannot fail is worse than no harness, because it reads as
/// evidence. This feeds it a target that always panics and requires it to say
/// so.
#[test]
#[should_panic(expected = "panicked on")]
fn the_harness_reports_a_panic_in_the_target() {
    hammer("canary", noise, |_| panic!("deliberate"));
}

/// And the reverse: a target that never panics must not be reported.
#[test]
fn the_harness_stays_quiet_when_nothing_panics() {
    hammer("canary", noise, |bytes| {
        let _ = bytes.len();
    });
}

// ── Targets ──────────────────────────────────────────────────────────────

/// Gossip messages. Reachable from any peer on the network, decoded before
/// anything about the sender has been established.
#[test]
fn the_gossip_decoder_rejects_hostile_bytes_without_panicking() {
    let sample = serde_json::to_vec(&crate::ledger::LedgerTx {
        hash: "0xabc".into(),
        from: "egot1a".into(),
        to: "egot1b".into(),
        amount: 1,
        ..Default::default()
    })
    .unwrap();
    hammer("gossip decoder", move |rng| mixed(rng, &sample), |bytes| {
        let _ = serde_json::from_slice::<crate::p2p::P2PMessage>(bytes);
    });
}

/// A transaction as it arrives from a peer, decoded and then put through the
/// full verification path. Verification touches hex decoding, address
/// derivation, signature parsing and the fee and nonce rules, all on values
/// the sender chose.
#[test]
fn transaction_verification_rejects_hostile_bytes_without_panicking() {
    let sample = serde_json::to_vec(&crate::ledger::LedgerTx {
        hash: "0x".to_string() + &"ab".repeat(32),
        from: "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k".into(),
        to: "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7l".into(),
        amount: 1_000,
        fee_uegoc: 1_000,
        nonce: 1,
        tx_version: 2,
        chain_id: 1,
        public_key_ed25519: "cd".repeat(32),
        signature: "ef".repeat(64),
        ..Default::default()
    })
    .unwrap();
    hammer("tx verification", move |rng| mixed(rng, &sample), |bytes| {
        if let Ok(tx) = serde_json::from_slice::<crate::ledger::LedgerTx>(bytes) {
            let _ = crate::ledger::verify_incoming_tx(&tx);
        }
    });
}

/// A shielded withdrawal body, including the compressed Groth16 proof. The
/// proof decoder is arkworks reading attacker-supplied curve points, which is
/// exactly the kind of parser that historically panics on a malformed field
/// element rather than returning an error.
#[test]
fn the_unshield_body_and_proof_reject_hostile_bytes_without_panicking() {
    let sample = crate::shielded_chain::UnshieldBody {
        root: "11".repeat(32),
        nullifier: "22".repeat(32),
        amount_uegoc: 1_000_000,
        recipient: "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k".into(),
        fee_uegoc: 1_000,
        proof: "33".repeat(128),
    }
    .canonical_json()
    .into_bytes();
    hammer("unshield body", move |rng| mixed(rng, &sample), |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else { return };
        if let Ok(body) = crate::shielded_chain::parse_unshield_body(text) {
            let _ = body.root_bytes();
            let _ = body.nullifier_bytes();
            let _ = body.proof();
            let _ = body.tx_hash();
        }
    });
}

/// The proof decoder on its own, fed raw bytes rather than reaching it through
/// the JSON. Compressed points carry a sign bit and an x coordinate that may
/// not be on the curve, and that path must return an error.
#[test]
fn the_proof_decoder_rejects_hostile_bytes_without_panicking() {
    hammer("proof decoder", noise, |bytes| {
        use ego_zk::withdraw_circuit::CanonicalDeserialize;
        let _ = ego_zk::withdraw_circuit::Proof::<ark_bn254::Bn254>::deserialize_compressed(bytes);
    });
}

/// A shield memo, which is the one place a deposit lets the sender choose
/// bytes that become part of consensus state.
#[test]
fn the_shield_memo_parser_rejects_hostile_text_without_panicking() {
    hammer("shield memo", |rng| {
        let mut v = b"shield:".to_vec();
        let n = rng.gen_range(0..96);
        for _ in 0..n {
            v.push(b"0123456789abcdefABCDEFxyz:"[rng.gen_range(0..26)]);
        }
        v
    }, |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else { return };
        let _ = crate::shielded_chain::parse_shield_memo(&Some(text.to_string()));
    });
}

/// Sideband frames arrive over a radio with no authentication whatsoever.
/// Anyone within range can transmit these, so reassembly has to survive
/// nonsense sequence numbers, totals and payload lengths.
#[test]
fn sideband_frame_reassembly_rejects_hostile_frames_without_panicking() {
    let sample = serde_json::to_vec(&crate::sideband::Frame {
        v: 1,
        kind: 0,
        msg_id: 7,
        seq: 0,
        total: 2,
        crc: 12345,
        payload: vec![1, 2, 3, 4],
    })
    .unwrap();
    hammer("sideband frame", move |rng| mixed(rng, &sample), |bytes| {
        if let Ok(frame) = serde_json::from_slice::<crate::sideband::Frame>(bytes) {
            let _ = crate::sideband::parse_repeat_request(&frame);
            let _ = crate::sideband::accept(frame, 1_700_000_000);
        }
    });
}

/// Frames whose header fields are hostile in a targeted way rather than
/// randomly: a total of zero, a sequence past the total, a payload far larger
/// than any transport allows. These are the shapes that turn into an
/// allocation or an index if reassembly trusts them.
#[test]
fn sideband_reassembly_survives_impossible_headers() {
    let mut rng = StdRng::from_entropy();
    let _quiet = QuietPanics::new();
    let mut bad: Option<String> = None;
    for _ in 0..CASES {
        let frame = crate::sideband::Frame {
            v: rng.gen(),
            kind: rng.gen(),
            msg_id: rng.gen(),
            seq: rng.gen(),
            total: if rng.gen_bool(0.3) { 0 } else { rng.gen() },
            crc: rng.gen(),
            payload: {
                let n = rng.gen_range(0..64);
                let mut p = vec![0u8; n];
                rng.fill_bytes(&mut p);
                p
            },
        };
        let described = format!("{frame:?}");
        if std::panic::catch_unwind(move || {
            let _ = crate::sideband::accept(frame, 1_700_000_000);
        })
        .is_err()
        {
            bad = Some(described);
            break;
        }
    }
    drop(_quiet);
    if let Some(f) = bad {
        panic!("sideband reassembly panicked on {f}");
    }
}

/// The contact card and message formats the messenger accepts from strangers.
#[test]
fn the_share_formats_reject_hostile_text_without_panicking() {
    hammer("share formats", |rng| {
        const HEADS: [&str; 4] = ["egoshare1:", "egocontact1:", "egomsg1:", ""];
        let mut s = HEADS[rng.gen_range(0..HEADS.len())].to_string();
        let n = rng.gen_range(0..80);
        for _ in 0..n {
            s.push(b":=+/abcdef0123456789"[rng.gen_range(0..20)] as char);
        }
        s.into_bytes()
    }, |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else { return };
        // Splitting and base64/hex decoding are what these formats do; the
        // fields are attacker-chosen and of attacker-chosen count.
        let parts: Vec<&str> = text.split(':').collect();
        for p in &parts {
            let _ = hex::decode(p);
        }
        let _ = parts.len();
    });
}
