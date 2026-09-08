use ego_stark::air::POOL_TREE_DEPTH;
use ego_stark::merkle::MerkleTree;
use ego_stark::note::Note;
use ego_stark::prove::{prove_membership, verify_against_root, default_options};
use rand::rngs::OsRng;
use std::time::Instant;
use winterfell::{FieldExtension, ProofOptions};

fn bench(label: &str, options: ProofOptions) {
    let mut rng = OsRng;
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
    let mut leaves = Vec::new();
    for _ in 0..8 {
        let l = Note::random(1_000_000, &mut rng).leaf().unwrap();
        tree.insert(l).unwrap();
        leaves.push(l);
    }
    let path = tree.path(5).unwrap();

    let t0 = Instant::now();
    let proof = prove_membership(leaves[5], &path, options.clone()).unwrap();
    let prove_ms = t0.elapsed().as_millis();
    let size = proof.size_bytes();
    let root = proof.root;

    let t1 = Instant::now();
    let ok = verify_against_root(proof.proof, root, &options).is_ok();
    let verify_us = t1.elapsed().as_micros();

    println!("{label:<22} verified={ok}  proof={size:>7} bytes  prove={prove_ms:>5} ms  verify={verify_us:>6} us");
}

fn main() {
    println!("depth {POOL_TREE_DEPTH} Merkle membership, Rescue Prime over Goldilocks\n");
    bench("balanced (default)", default_options());
    bench("conservative", ProofOptions::new(54, 8, 8, FieldExtension::Quadratic, 8, 255));
    bench("fewer queries", ProofOptions::new(20, 8, 8, FieldExtension::Quadratic, 8, 255));
}
