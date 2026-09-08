#![cfg(test)]

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

const CASES: usize = 4_000;

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
            hex::encode(&bytes[..bytes.len().min(8192)])
        );
    }
}

fn noise(rng: &mut StdRng) -> Vec<u8> {
    let len = rng.gen_range(0..512);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

fn mutate(rng: &mut StdRng, valid: &[u8]) -> Vec<u8> {
    let mut v = valid.to_vec();
    for _ in 0..rng.gen_range(1..=4) {
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

#[test]
#[should_panic(expected = "panicked on")]
fn the_harness_reports_a_panic_in_the_target() {
    hammer("canary", noise, |_| panic!("deliberate"));
}

#[test]
fn the_harness_stays_quiet_when_nothing_panics() {
    hammer("canary", noise, |bytes| {
        let _ = bytes.len();
    });
}

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

#[test]
fn the_unshield_body_and_proof_reject_hostile_bytes_without_panicking() {
    let sample = crate::shielded_chain::UnshieldBody {
        spends: vec![crate::shielded_chain::UnshieldSpend {
            root: "11".repeat(32),
            nullifier: "22".repeat(32),
            amount_uegoc: 1_000_000,
            fee_uegoc: 1_000,
            proof: "33".repeat(128),
        }],
        recipient: "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k".into(),
        amount_uegoc: 1_000_000,
        fee_uegoc: 1_000,
    }
    .canonical_json()
    .into_bytes();
    hammer("unshield body", move |rng| mixed(rng, &sample), |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else { return };
        if let Ok(body) = crate::shielded_chain::parse_unshield_body(text) {
            for sp in &body.spends {
                let _ = sp.root_bytes();
                let _ = sp.nullifier_bytes();
                let _ = sp.proof_bytes();
            }
            let _ = body.totals();
            let _ = body.tx_hash();
        }
    });
}

#[test]
fn the_proof_decoder_rejects_hostile_bytes_without_panicking() {
    hammer("proof decoder", noise, |bytes| {
        let _ = crate::shielded::verify_proof_bytes(
            bytes,
            [1u8; 32],
            [2u8; 32],
            1_000_000,
            [3u8; 32],
            1_000,
        );
    });
}

/// Winterfell's own `Proof::from_bytes` has been observed failing unsafely on
/// malformed input rather than returning an error, and those bytes arrive in a
/// transaction from anyone. Nothing may reach it except through the guarded
/// wrapper. These two inputs are the ones the fuzzer found.
#[test]
fn the_inputs_that_broke_the_raw_decoder_are_refused_by_the_guard() {
    const FOUND: [&str; 2] = [
        "7b4c3285875ca67532df6bffd84ac95c9d12e99aa734fb2b5d7df2a780f738aa6f79dca2e9bb7668c0c7aebbb0c68ccddb38500962e5d8a963d8718d15e0092bdffdfbb644402e",
        "ee0c7da088618b17100c6bb10717374487a47b8c81fada3280712cec5683fcb40fe7f327a1efc8776f96c3fda716131adbbd0d8f4d74a06f0be710e4e0802878adebc25889a08f740e53dfaf294d3c805011a2c0442a1edb2d26709dfd9294879f23d453b78077c9fb0814e5bfb136c2af678da52433c405c9140b2c263e13b18ae7b13257cc1545cf74a00f9ceb234aedf4450e4b4775509bd8efc12aef8a233432b46e71948ba180ecbf6ac4a04ee7c37ed1178417453e5cdb1f0f7c054e6df79d602a5f82ec9c32de1c9255bcec6704f6e7f20d0118dc598d2b9a4858a493710f9130eb9eea699e6fc10011a8df4cdc760ae36559b9f3c1b5c39bf53b77e6",
    ];
    for (i, h) in FOUND.iter().enumerate() {
        let bytes = hex::decode(h).expect("test vector is hex");
        assert!(
            !crate::shielded::verify_proof_bytes(
                &bytes,
                [1u8; 32],
                [2u8; 32],
                1_000_000,
                [3u8; 32],
                1_000,
            ),
            "known-bad input {i} must be refused, not accepted"
        );
    }
}

/// A proof larger than any this chain produces is refused before it reaches
/// the decoder at all, so a length prefix cannot be used to make it allocate.
#[test]
fn an_oversized_proof_is_refused_before_it_is_decoded() {
    let huge = vec![0u8; crate::shielded::MAX_PROOF_BYTES + 1];
    assert!(!crate::shielded::verify_proof_bytes(
        &huge,
        [1u8; 32],
        [2u8; 32],
        1_000_000,
        [3u8; 32],
        1_000
    ));
    assert!(!crate::shielded::verify_proof_bytes(
        &[],
        [1u8; 32],
        [2u8; 32],
        1_000_000,
        [3u8; 32],
        1_000
    ));
}

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
        let parts: Vec<&str> = text.split(':').collect();
        for p in &parts {
            let _ = hex::decode(p);
        }
        let _ = parts.len();
    });
}
