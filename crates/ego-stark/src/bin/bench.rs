use ego_stark::air::POOL_TREE_DEPTH;
use ego_stark::merkle::MerkleTree;
use ego_stark::note::Note;
use ego_stark::prove::{default_options, prove_withdrawal, verify_withdrawal};
use rand::rngs::OsRng;
use std::time::Instant;
use winterfell::{FieldExtension, ProofOptions};

fn bench(label: &str, options: ProofOptions) {
    let mut rng = OsRng;
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
    let mut notes = Vec::new();
    for _ in 0..8 {
        let n = Note::random(1_000_000, &mut rng);
        tree.insert(n.leaf().unwrap()).unwrap();
        notes.push(n);
    }
    let path = tree.path(5).unwrap();

    let t0 = Instant::now();
    let w = prove_withdrawal(&notes[5], &path, &[0xAB; 32], 1_000, options.clone()).unwrap();
    let prove_ms = t0.elapsed().as_millis();
    let size = w.size_bytes();

    let t1 = Instant::now();
    let ok = verify_withdrawal(w.proof, w.public, &options).is_ok();
    let verify_us = t1.elapsed().as_micros();

    println!("{label:<22} verified={ok}  proof={size:>7} bytes  prove={prove_ms:>5} ms  verify={verify_us:>6} us");
}

fn main() {
    println!("full withdrawal proof, depth {POOL_TREE_DEPTH}, Rescue over Goldilocks\n");
    bench("balanced (default)", default_options());
    bench("conservative", ProofOptions::new(54, 8, 8, FieldExtension::Quadratic, 8, 255));
    bench("fewer queries", ProofOptions::new(20, 8, 8, FieldExtension::Quadratic, 8, 255));
}
