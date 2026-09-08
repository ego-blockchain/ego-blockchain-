//! Runs the withdrawal circuit's trusted setup once and writes the keys that
//! `withdraw_params` embeds.
//!
//!     cargo run -p ego-zk --release --no-default-features --bin gen_withdraw_params -- crates/ego-zk/params
//!
//! `--no-default-features` matters: the library's default build embeds the
//! params, which do not exist yet the first time this runs.
//!
//! The randomness comes from the operating system and the toxic waste is
//! never written anywhere; it dies with this process. That is a single-party
//! setup, acceptable for a testnet and not for mainnet, which needs a
//! multi-party ceremony. Regenerating changes the verifying key, which is a
//! consensus parameter: every validator must ship the same one.

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
