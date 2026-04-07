
pub use ark_bn254::Fr;
use ark_bn254::Bn254;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{CryptoRng, RngCore, SeedableRng, rngs::StdRng};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};


pub const GROTH16_PROOF_BYTES: usize = 128;

/// Magic header that marks a ZK PoRep `proof_data` blob.
pub const ZK_MAGIC: &[u8; 4] = b"ZKPR";


pub fn keys_dir() -> PathBuf {
    if let Ok(d) = std::env::var("EGO_POREP_KEYS_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    #[cfg(not(target_os = "windows"))]
    let base = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    base.join(".ego").join("porep_keys")
}


pub fn pk_path(dir: &Path, depth: usize) -> PathBuf {
    dir.join(format!("porep_pk_depth{depth}.bin"))
}


pub fn vk_path(dir: &Path, depth: usize) -> PathBuf {
    dir.join(format!("porep_vk_depth{depth}.bin"))
}


pub fn mimc_constant(d: usize) -> Fr {
    let digest = blake3::hash(format!("ego/mimc/porep/v1/{d}").as_bytes());
    Fr::from_le_bytes_mod_order(digest.as_bytes())
}


pub fn mimc7_compress(left: Fr, right: Fr, constant: Fr) -> Fr {
    let x  = left + right + constant;
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x2 * x + right
}


pub fn hash_leaf(data: &[u8]) -> Fr {
    let digest = blake3::hash(data);
    Fr::from_le_bytes_mod_order(digest.as_bytes())
}


pub fn merkle_root(leaf: Fr, leaf_index: u64, siblings: &[Fr]) -> Fr {
    let mut node = leaf;
    for (d, &sib) in siblings.iter().enumerate() {
        let c   = mimc_constant(d);
        let bit = (leaf_index >> d) & 1;
        let (left, right) = if bit == 0 { (node, sib) } else { (sib, node) };
        node = mimc7_compress(left, right, c);
    }
    node
}


pub fn bytes_to_fr(b: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

/// BN254 scalar → 32-byte LE array.
pub fn fr_to_bytes(f: Fr) -> [u8; 32] {
    let limbs = f.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..limbs.len().min(32)].copy_from_slice(&limbs[..limbs.len().min(32)]);
    out
}


#[derive(Clone)]
pub struct MerklePoRepCircuit {
    pub tree_depth: usize,
    pub root:       Option<Fr>,
    pub leaf_hash:  Option<Fr>,
    pub leaf_index: Option<u64>,
    pub siblings:   Vec<Option<Fr>>,
}

impl MerklePoRepCircuit {
    /// Blank circuit (all `None`) — used for setup.
    pub fn blank(tree_depth: usize) -> Self {
        Self {
            tree_depth,
            root:      None,
            leaf_hash: None,
            leaf_index: None,
            siblings:  vec![None; tree_depth],
        }
    }

    /// Filled circuit — used for proving.
    pub fn with_witness(
        tree_depth: usize,
        root:       Fr,
        leaf_hash:  Fr,
        leaf_index: u64,
        siblings:   Vec<Fr>,
    ) -> Self {
        assert_eq!(siblings.len(), tree_depth);
        Self {
            tree_depth,
            root:       Some(root),
            leaf_hash:  Some(leaf_hash),
            leaf_index: Some(leaf_index),
            siblings:   siblings.into_iter().map(Some).collect(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for MerklePoRepCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let depth = self.tree_depth;

        // ── public inputs ──────────────────────────────────────────────────────
        let root_var  = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let leaf_var  = FpVar::new_input(cs.clone(), || {
            self.leaf_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let index_var = FpVar::new_input(cs.clone(), || {
            self.leaf_index.map(Fr::from).ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sibling_vars: Vec<FpVar<Fr>> = (0..depth)
            .map(|i| {
                FpVar::new_witness(cs.clone(), || {
                    self.siblings[i].ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;


        let index_bits = index_var.to_bits_le()?;

        let mut current = leaf_var;

        for d in 0..depth {
            let sibling = &sibling_vars[d];
            let bit     = &index_bits[d];
            let c_const = FpVar::constant(mimc_constant(d));

            let left  = bit.select(sibling, &current)?;
            let right = bit.select(&current, sibling)?;


            let mut x = &left + &right;
            x += &c_const;

            let x2 = x.square()?;
            let x4 = x2.square()?;
            let mut x6 = x4;
            x6 *= &x2;
            x6 *= &x;
            x6 += &right;   // non-commutative term

            current = x6;
        }

        // Root constraint: recomputed root must equal the public commitment.
        current.enforce_equal(&root_var)?;
        Ok(())
    }
}

// ── Key material ──────────────────────────────────────────────────────────────

pub struct PoRepKeys {
    pub proving_key:   ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,  // stored for serialisation
    pub pvk:           PreparedVerifyingKey<Bn254>,
    pub tree_depth:    usize,
}

// ── Key generation (internal) ─────────────────────────────────────────────────

fn generate_keys_with_rng<R: RngCore + CryptoRng>(
    tree_depth: usize,
    rng: &mut R,
) -> PoRepKeys {
    let circuit = MerklePoRepCircuit::blank(tree_depth);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
        .expect("Groth16 circuit_specific_setup failed");
    let pvk = prepare_verifying_key(&vk);
    PoRepKeys { proving_key: pk, verifying_key: vk, pvk, tree_depth }
}


pub fn load_keys_from_disk(tree_depth: usize) -> Option<PoRepKeys> {
    let dir = keys_dir();
    let pk_file = pk_path(&dir, tree_depth);
    let vk_file = vk_path(&dir, tree_depth);

    if !pk_file.exists() || !vk_file.exists() {
        return None;
    }

    let pk_bytes = std::fs::read(&pk_file).ok()?;
    let vk_bytes = std::fs::read(&vk_file).ok()?;

    let pk = ProvingKey::<Bn254>::deserialize_compressed(&*pk_bytes)
        .map_err(|e| tracing::warn!("PoRep pk deserialize failed: {e}"))
        .ok()?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&*vk_bytes)
        .map_err(|e| tracing::warn!("PoRep vk deserialize failed: {e}"))
        .ok()?;
    let pvk = prepare_verifying_key(&vk);

    tracing::info!(
        "📂 Loaded PoRep keys for depth={} from {}",
        tree_depth,
        dir.display()
    );
    Some(PoRepKeys { proving_key: pk, verifying_key: vk, pvk, tree_depth })
}

pub fn save_keys_to_disk(keys: &PoRepKeys) -> std::io::Result<()> {
    let dir = keys_dir();
    std::fs::create_dir_all(&dir)?;

    let mut pk_bytes = Vec::new();
    keys.proving_key
        .serialize_compressed(&mut pk_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    std::fs::write(pk_path(&dir, keys.tree_depth), &pk_bytes)?;

    let mut vk_bytes = Vec::new();
    keys.verifying_key
        .serialize_compressed(&mut vk_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    std::fs::write(vk_path(&dir, keys.tree_depth), &vk_bytes)?;

    // Print a VK fingerprint so operators can verify which keys are loaded.
    let fp: String = blake3::hash(&vk_bytes).as_bytes()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    tracing::info!(
        "💾 PoRep keys saved (depth={})  VK fingerprint: {}",
        keys.tree_depth, fp
    );
    Ok(())
}


pub fn generate_and_save_keys(tree_depth: usize) -> PoRepKeys {
    tracing::info!("⚙️  Generating PoRep Groth16 keys for depth={} …", tree_depth);
    tracing::warn!(
        "Single-party setup: toxic waste (α,β,γ,δ) is held in RAM during generation \
         and dropped immediately after.  For mainnet run an MPC ceremony."
    );

    let mut rng = StdRng::from_entropy();
    let keys = generate_keys_with_rng(tree_depth, &mut rng);
    // rng (and therefore the secrets used in setup) is dropped here.

    tracing::info!("✅ PoRep Groth16 keys generated for depth={}", tree_depth);

    if let Err(e) = save_keys_to_disk(&keys) {
        tracing::warn!("Failed to persist PoRep keys to disk: {e}  \
                        (keys are in-memory only this session)");
    }
    keys
}


pub fn import_ceremony_keys(
    tree_depth: usize,
    pk_file: &Path,
    vk_file: &Path,
) -> Result<Arc<PoRepKeys>, String> {
    let pk_bytes = std::fs::read(pk_file)
        .map_err(|e| format!("cannot read pk_file {}: {e}", pk_file.display()))?;
    let vk_bytes = std::fs::read(vk_file)
        .map_err(|e| format!("cannot read vk_file {}: {e}", vk_file.display()))?;

    let pk = ProvingKey::<Bn254>::deserialize_compressed(&*pk_bytes)
        .map_err(|e| format!("pk deserialize failed: {e}"))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&*vk_bytes)
        .map_err(|e| format!("vk deserialize failed: {e}"))?;
    let pvk = prepare_verifying_key(&vk);

    let fp: String = blake3::hash(&vk_bytes).as_bytes()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    tracing::info!(
        "🔑 Imported ceremony keys for depth={depth}  VK fingerprint: {fp}",
        depth = tree_depth,
    );

    let keys = Arc::new(PoRepKeys { proving_key: pk, verifying_key: vk, pvk, tree_depth });

    // Prime the in-memory cache.
    static CACHE: OnceLock<Mutex<HashMap<usize, Arc<PoRepKeys>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
        .lock().unwrap()
        .insert(tree_depth, Arc::clone(&keys));

    Ok(keys)
}


#[cfg(not(test))]
pub fn get_keys(tree_depth: usize) -> Arc<PoRepKeys> {
    static CACHE: OnceLock<Mutex<HashMap<usize, Arc<PoRepKeys>>>> = OnceLock::new();
    let mutex = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = mutex.lock().unwrap();
    guard
        .entry(tree_depth)
        .or_insert_with(|| {
            let keys = load_keys_from_disk(tree_depth)
                .unwrap_or_else(|| generate_and_save_keys(tree_depth));
            Arc::new(keys)
        })
        .clone()
}

/// Test build: use a deterministic seed (no disk I/O, reproducible).
#[cfg(test)]
pub fn get_keys(tree_depth: usize) -> Arc<PoRepKeys> {
    static CACHE: OnceLock<Mutex<HashMap<usize, Arc<PoRepKeys>>>> = OnceLock::new();
    let mutex = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = mutex.lock().unwrap();
    guard
        .entry(tree_depth)
        .or_insert_with(|| {
            // Seed is depth-specific so different depths get different keys.
            let seed = 0x4547_4f5f_5445_5354_u64 ^ (tree_depth as u64 * 0x9e37_79b9);
            let mut rng = StdRng::seed_from_u64(seed);
            Arc::new(generate_keys_with_rng(tree_depth, &mut rng))
        })
        .clone()
}


pub fn prove(
    keys:       &PoRepKeys,
    root:       Fr,
    leaf_hash:  Fr,
    leaf_index: u64,
    siblings:   Vec<Fr>,
) -> Result<Vec<u8>, String> {
    if siblings.len() != keys.tree_depth {
        return Err(format!(
            "siblings.len()={} != tree_depth={}",
            siblings.len(), keys.tree_depth,
        ));
    }
    let mut rng = StdRng::from_entropy();
    let circuit = MerklePoRepCircuit::with_witness(
        keys.tree_depth, root, leaf_hash, leaf_index, siblings,
    );
    let proof = Groth16::<Bn254>::prove(&keys.proving_key, circuit, &mut rng)
        .map_err(|e| format!("Groth16::prove: {e}"))?;

    let mut bytes = Vec::with_capacity(GROTH16_PROOF_BYTES);
    proof.serialize_compressed(&mut bytes)
        .map_err(|e| format!("proof serialise: {e}"))?;
    Ok(bytes)
}


pub fn verify(
    pvk:         &PreparedVerifyingKey<Bn254>,
    root:        Fr,
    leaf_hash:   Fr,
    leaf_index:  u64,
    proof_bytes: &[u8],
) -> Result<bool, String> {
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| format!("proof deserialise: {e}"))?;
    let public_inputs = [root, leaf_hash, Fr::from(leaf_index)];
    Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
        .map_err(|e| format!("Groth16 verify: {e}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const D: usize = 4;

    // ── native helpers ────────────────────────────────────────────────────────

    #[test]
    fn mimc_compress_is_deterministic() {
        let c = mimc_constant(0);
        assert_eq!(
            mimc7_compress(Fr::from(1u64), Fr::from(2u64), c),
            mimc7_compress(Fr::from(1u64), Fr::from(2u64), c),
        );
    }

    #[test]
    fn merkle_root_changes_with_leaf_data() {
        let sib: Vec<Fr> = (0..D).map(|i| Fr::from(i as u64 + 100)).collect();
        assert_ne!(
            merkle_root(hash_leaf(b"block A"), 0, &sib),
            merkle_root(hash_leaf(b"block B"), 0, &sib),
        );
    }

    #[test]
    fn merkle_root_changes_with_leaf_index() {
        let leaf = hash_leaf(b"same data");
        let sib: Vec<Fr> = vec![Fr::from(42u64); D];
        assert_ne!(
            merkle_root(leaf, 0, &sib),
            merkle_root(leaf, (1u64 << D) - 1, &sib),
        );
    }

    #[test]
    fn bytes_fr_roundtrip() {
        let f = Fr::from(0xdead_beef_cafe_babe_u64);
        assert_eq!(f, bytes_to_fr(&fr_to_bytes(f)));
    }


    fn make_witness(data: &[u8], idx: u64) -> (Fr, Fr, Vec<Fr>) {
        let leaf = hash_leaf(data);
        let sib: Vec<Fr> = (0..D)
            .map(|d| hash_leaf(format!("sib-{d}").as_bytes()))
            .collect();
        let root = merkle_root(leaf, idx, &sib);
        (leaf, root, sib)
    }

    #[test]
    fn prove_and_verify_succeeds() {
        let (leaf, root, sib) = make_witness(b"sector chunk #7", 5);
        let keys = get_keys(D);
        let pf = prove(&keys, root, leaf, 5, sib).expect("prove");
        assert_eq!(pf.len(), GROTH16_PROOF_BYTES);
        assert!(verify(&keys.pvk, root, leaf, 5, &pf).expect("verify"));
    }

    #[test]
    fn wrong_root_does_not_verify() {
        let (leaf, root, sib) = make_witness(b"data", 3);
        let keys = get_keys(D);
        let pf = prove(&keys, root, leaf, 3, sib).unwrap();
        assert!(!verify(&keys.pvk, root + Fr::from(1u64), leaf, 3, &pf).unwrap());
    }

    #[test]
    fn wrong_leaf_hash_does_not_verify() {
        let (leaf, root, sib) = make_witness(b"real", 0);
        let fake = hash_leaf(b"fake");
        let keys = get_keys(D);
        let pf = prove(&keys, root, leaf, 0, sib).unwrap();
        assert!(!verify(&keys.pvk, root, fake, 0, &pf).unwrap());
    }

    #[test]
    fn wrong_index_does_not_verify() {
        let (leaf, root, sib) = make_witness(b"indexed", 2);
        let keys = get_keys(D);
        let pf = prove(&keys, root, leaf, 2, sib).unwrap();
        assert!(!verify(&keys.pvk, root, leaf, 3, &pf).unwrap());
    }

    #[test]
    fn truncated_proof_returns_err() {
        let (leaf, root, sib) = make_witness(b"data", 1);
        let keys = get_keys(D);
        let mut pf = prove(&keys, root, leaf, 1, sib).unwrap();
        pf.truncate(64);
        assert!(verify(&keys.pvk, root, leaf, 1, &pf).is_err());
    }

    // ── wire-format roundtrip ─────────────────────────────────────────────────

    #[test]
    fn zk_proof_blob_roundtrip() {
        let challenges: &[(u64, &[u8])] = &[
            (0,  b"challenge 0 data"),
            (13, b"challenge 1 data"),
        ];
        let keys = get_keys(D);

        let mut blob = Vec::new();
        blob.extend_from_slice(ZK_MAGIC);
        blob.extend_from_slice(&(D as u32).to_le_bytes());
        blob.extend_from_slice(&(challenges.len() as u32).to_le_bytes());

        let mut roots = Vec::new();
        let mut leaf_hashes = Vec::new();
        for &(idx, data) in challenges {
            let leaf = hash_leaf(data);
            let sib: Vec<Fr> = (0..D)
                .map(|d| hash_leaf(format!("blobsib-{d}").as_bytes()))
                .collect();
            let root = merkle_root(leaf, idx, &sib);
            let pf = prove(&keys, root, leaf, idx, sib).unwrap();
            blob.extend_from_slice(&idx.to_le_bytes());
            blob.extend_from_slice(&fr_to_bytes(leaf));
            blob.extend_from_slice(&pf);
            roots.push(root);
            leaf_hashes.push(leaf);
        }

        // Structural checks.
        assert!(blob.starts_with(ZK_MAGIC));
        const PER: usize = 8 + 32 + GROTH16_PROOF_BYTES;
        assert_eq!(blob.len(), 12 + challenges.len() * PER);

        // Verify each challenge independently.
        for (i, &(idx, _)) in challenges.iter().enumerate() {
            let base = 12 + i * PER;
            let pf = &blob[base + 40..base + PER];
            assert!(
                verify(&keys.pvk, roots[i], leaf_hashes[i], idx, pf).unwrap(),
                "challenge {i} must verify"
            );
        }
    }
}
