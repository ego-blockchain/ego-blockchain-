use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s256, Digest};
use ego_zk::merkle::POOL_TREE_DEPTH;
use ego_zk::withdraw_circuit::setup;
use rand::rngs::OsRng;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "crates/ego-zk/params".into()));
    fs::create_dir_all(&out).expect("create params dir");

    let started = Instant::now();
    let (pk, vk) = setup(POOL_TREE_DEPTH, &mut OsRng).expect("setup");
    eprintln!("setup at depth {POOL_TREE_DEPTH} took {:.1?}", started.elapsed());

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).expect("serialise proving key");
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).expect("serialise verifying key");

    fs::write(out.join("withdraw_pk.bin"), &pk_bytes).expect("write proving key");
    fs::write(out.join("withdraw_vk.bin"), &vk_bytes).expect("write verifying key");

    println!("proving key    {} bytes", pk_bytes.len());
    println!("verifying key  {} bytes", vk_bytes.len());
    println!("vk digest      {}", hex::encode(Blake2s256::digest(&vk_bytes)));
}
