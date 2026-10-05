use ego_stark::merkle::{MerkleTree, POOL_TREE_DEPTH};
use ego_stark::note::{leaf_for, Note, MAX_NOTE_VALUE};
use ego_stark::prove::{default_options, prove_withdrawal};
use ego_stark::{digest_from_bytes, digest_to_bytes, Digest, DIGEST_BYTES};
use serde::Deserialize;
use serde_json::{json, Value};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::HashSet;

pub const MAX_SPENDS: usize = 16;

thread_local! {
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static TREE: RefCell<Option<MerkleTree>> = const { RefCell::new(None) };
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn ego_random(ptr: *mut u8, len: usize) -> u32;
}

#[cfg(target_arch = "wasm32")]
fn host_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    if unsafe { ego_random(buf.as_mut_ptr(), buf.len()) } == 0 {
        Ok(())
    } else {
        Err(getrandom::Error::UNSUPPORTED)
    }
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(host_random);

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Notes { notes: Vec<NoteInput> },
    Append { leaves: Vec<String> },
    Tree,
    Reset,
    Prove { leaf_count: usize, recipient_digest: String, spends: Vec<SpendInput> },
}

#[derive(Deserialize)]
struct NoteInput {
    owner_secret: String,
    rho: String,
    #[serde(default)]
    values: Vec<u64>,
}

#[derive(Deserialize)]
struct SpendInput {
    owner_secret: String,
    rho: String,
    value_uegoc: u64,
    leaf_index: usize,
    fee_uegoc: u64,
}

fn bytes32(field: &str, value: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| format!("{field} is not 32 hex bytes"))
}

fn digest(field: &str, value: &str) -> Result<Digest, String> {
    digest_from_bytes(&bytes32(field, value)?)
        .ok_or_else(|| format!("{field} is not a canonical field digest"))
}

fn to_hex(d: &Digest) -> String {
    hex::encode(digest_to_bytes(d))
}

fn note_of(owner_secret: &str, rho: &str, value_uegoc: u64) -> Result<Note, String> {
    Ok(Note {
        value_uegoc,
        owner_secret: bytes32("owner_secret", owner_secret)?,
        rho: bytes32("rho", rho)?,
    })
}

fn with_tree<T>(f: impl FnOnce(&mut MerkleTree) -> Result<T, String>) -> Result<T, String> {
    TREE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let tree = slot.get_or_insert_with(|| MerkleTree::new(POOL_TREE_DEPTH));
        f(tree)
    })
}

fn tree_summary(tree: &MerkleTree) -> Value {
    json!({ "root": to_hex(&tree.root()), "leaf_count": tree.len() })
}

fn append(leaves: &[Digest]) -> Result<Value, String> {
    with_tree(|tree| {
        tree.extend(leaves)?;
        Ok(tree_summary(tree))
    })
}

fn append_raw(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() % DIGEST_BYTES != 0 {
        return Err(format!("{} bytes is not a whole number of leaves", bytes.len()));
    }
    let leaves = bytes
        .chunks_exact(DIGEST_BYTES)
        .enumerate()
        .map(|(i, chunk)| {
            let mut b = [0u8; DIGEST_BYTES];
            b.copy_from_slice(chunk);
            digest_from_bytes(&b).ok_or_else(|| format!("leaf {i} of the batch is not a canonical field digest"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    append(&leaves)
}

fn notes(inputs: Vec<NoteInput>) -> Result<Value, String> {
    let mut out = Vec::with_capacity(inputs.len());
    for n in inputs {
        let note = note_of(&n.owner_secret, &n.rho, 0)?;
        let commitment = note.commitment().map_err(|e| format!("{e:?}"))?;
        let leaves = n
            .values
            .iter()
            .map(|v| {
                leaf_for(&commitment, *v)
                    .map(|l| to_hex(&l))
                    .map_err(|e| format!("{e:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        out.push(json!({
            "commitment": to_hex(&commitment),
            "nullifier": to_hex(&note.nullifier()),
            "leaves": leaves,
        }));
    }
    Ok(Value::Array(out))
}

fn prove(leaf_count: usize, recipient_digest: String, spends: Vec<SpendInput>) -> Result<Value, String> {
    if spends.is_empty() {
        return Err("select at least one note to spend".into());
    }
    if spends.len() > MAX_SPENDS {
        return Err(format!("a withdrawal can spend at most {MAX_SPENDS} notes at once"));
    }
    let recipient = bytes32("recipient_digest", &recipient_digest)?;
    let mut seen = HashSet::new();
    if !spends.iter().all(|sp| seen.insert(sp.leaf_index)) {
        return Err("the same note is listed twice".into());
    }
    with_tree(|tree| {
        if tree.len() != leaf_count {
            return Err(format!(
                "the prover holds {} leaves but the withdrawal was planned against {leaf_count}",
                tree.len()
            ));
        }
        let mut out = Vec::with_capacity(spends.len());
        for sp in &spends {
            if sp.value_uegoc == 0 || sp.value_uegoc > MAX_NOTE_VALUE {
                return Err(format!("{} uEGOC is not a note value", sp.value_uegoc));
            }
            if sp.fee_uegoc >= sp.value_uegoc {
                return Err(format!(
                    "fee {} uEGOC would consume the whole {} uEGOC note",
                    sp.fee_uegoc, sp.value_uegoc
                ));
            }
            let note = note_of(&sp.owner_secret, &sp.rho, sp.value_uegoc)?;
            let leaf = note.leaf().map_err(|e| format!("{e:?}"))?;
            if tree.leaves().get(sp.leaf_index) != Some(&leaf) {
                return Err(format!(
                    "leaf {} does not hold this note; it was not deposited at its own value",
                    sp.leaf_index
                ));
            }
            let path = tree.path(sp.leaf_index)?;
            let w = prove_withdrawal(&note, &path, &recipient, sp.fee_uegoc, default_options())?;
            out.push(json!({
                "root": to_hex(&w.public.root),
                "nullifier": to_hex(&w.public.nullifier),
                "amount_uegoc": w.public.amount,
                "fee_uegoc": sp.fee_uegoc,
                "proof": hex::encode(w.proof.to_bytes()),
            }));
        }
        Ok(json!({
            "root": to_hex(&tree.root()),
            "leaf_count": tree.len(),
            "spends": out,
        }))
    })
}

pub fn dispatch(input: &[u8]) -> Result<Value, String> {
    let request: Request =
        serde_json::from_slice(input).map_err(|e| format!("bad request: {e}"))?;
    match request {
        Request::Notes { notes: n } => notes(n),
        Request::Append { leaves } => {
            let parsed = leaves
                .iter()
                .map(|l| digest("leaf", l))
                .collect::<Result<Vec<_>, _>>()?;
            append(&parsed)
        }
        Request::Tree => with_tree(|tree| Ok(tree_summary(tree))),
        Request::Reset => {
            TREE.with(|cell| *cell.borrow_mut() = Some(MerkleTree::new(POOL_TREE_DEPTH)));
            with_tree(|tree| Ok(tree_summary(tree)))
        }
        Request::Prove { leaf_count, recipient_digest, spends } => prove(leaf_count, recipient_digest, spends),
    }
}

fn layout(len: usize) -> Option<Layout> {
    Layout::from_size_align(len.max(1), 1).ok()
}

fn finish(result: Result<Value, String>) -> u32 {
    let (status, value) = match result {
        Ok(v) => (1, v),
        Err(e) => (0, json!({ "error": e })),
    };
    let bytes = serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"error\":\"unencodable result\"}".to_vec());
    OUTPUT.with(|o| *o.borrow_mut() = bytes);
    status
}

unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

#[no_mangle]
pub extern "C" fn ego_alloc(len: usize) -> *mut u8 {
    match layout(len) {
        Some(l) => unsafe { alloc(l) },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ego_free(ptr: *mut u8, len: usize) {
    if let (false, Some(l)) = (ptr.is_null(), layout(len)) {
        dealloc(ptr, l);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ego_call(ptr: *const u8, len: usize) -> u32 {
    finish(dispatch(input(ptr, len)))
}

#[no_mangle]
pub unsafe extern "C" fn ego_tree_append(ptr: *const u8, len: usize) -> u32 {
    finish(append_raw(input(ptr, len)))
}

#[no_mangle]
pub extern "C" fn ego_output_ptr() -> *const u8 {
    OUTPUT.with(|o| o.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn ego_output_len() -> usize {
    OUTPUT.with(|o| o.borrow().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_stark::air::PublicInputs;
    use ego_stark::note::withdrawal_binding;
    use ego_stark::prove::verify_withdrawal;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use winterfell::Proof;

    const ONE_EGOC: u64 = 1_000_000;

    fn call(v: Value) -> Result<Value, String> {
        dispatch(v.to_string().as_bytes())
    }

    fn reset() {
        call(json!({ "op": "reset" })).unwrap();
    }

    fn secrets(rng: &mut StdRng) -> (String, String) {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        (hex::encode(a), hex::encode(b))
    }

    fn leaf_hex(secret: &str, rho: &str, value: u64) -> String {
        let out = call(json!({
            "op": "notes",
            "notes": [{ "owner_secret": secret, "rho": rho, "values": [value] }],
        }))
        .unwrap();
        out[0]["leaves"][0].as_str().unwrap().to_string()
    }

    fn random_leaves(rng: &mut StdRng, n: usize) -> Vec<String> {
        (0..n)
            .map(|_| {
                let (s, r) = secrets(rng);
                leaf_hex(&s, &r, ONE_EGOC)
            })
            .collect()
    }

    #[test]
    fn notes_match_the_native_crate() {
        let mut rng = StdRng::seed_from_u64(7);
        let (s, r) = secrets(&mut rng);
        let note = note_of(&s, &r, 10 * ONE_EGOC).unwrap();
        let out = call(json!({
            "op": "notes",
            "notes": [{ "owner_secret": s, "rho": r, "values": [ONE_EGOC, 10 * ONE_EGOC] }],
        }))
        .unwrap();
        assert_eq!(out[0]["commitment"], to_hex(&note.commitment().unwrap()));
        assert_eq!(out[0]["nullifier"], to_hex(&note.nullifier()));
        assert_eq!(out[0]["leaves"][1], to_hex(&note.leaf().unwrap()));
        assert_ne!(out[0]["leaves"][0], out[0]["leaves"][1]);
    }

    #[test]
    fn appends_in_hex_and_raw_build_the_tree_the_chain_builds() {
        let mut rng = StdRng::seed_from_u64(8);
        let leaves = random_leaves(&mut rng, 5);
        let mut native = MerkleTree::new(POOL_TREE_DEPTH);
        for l in &leaves {
            native.insert(digest("leaf", l).unwrap()).unwrap();
        }

        reset();
        assert_eq!(call(json!({ "op": "tree" })).unwrap()["root"], to_hex(&MerkleTree::new(POOL_TREE_DEPTH).root()));
        call(json!({ "op": "append", "leaves": leaves[..2] })).unwrap();
        let raw: Vec<u8> = leaves[2..].iter().flat_map(|l| hex::decode(l).unwrap()).collect();
        let out = append_raw(&raw).unwrap();
        assert_eq!(out["root"], to_hex(&native.root()));
        assert_eq!(out["leaf_count"], 5);
        assert_eq!(call(json!({ "op": "tree" })).unwrap(), out);
    }

    #[test]
    fn a_bad_batch_is_refused_whole() {
        reset();
        let mut rng = StdRng::seed_from_u64(9);
        let good = random_leaves(&mut rng, 1);
        assert!(call(json!({ "op": "append", "leaves": [good[0].clone(), "ff".repeat(32)] }))
            .unwrap_err()
            .contains("canonical"));
        assert!(append_raw(&[0u8; 33]).unwrap_err().contains("whole number"));
        assert_eq!(call(json!({ "op": "tree" })).unwrap()["leaf_count"], 0);
    }

    #[test]
    fn a_proof_from_the_wrapper_verifies_and_binds_recipient_and_fee() {
        let mut rng = StdRng::seed_from_u64(10);
        let (s, r) = secrets(&mut rng);
        let value = 10 * ONE_EGOC;
        let mut leaves = random_leaves(&mut rng, 3);
        leaves.push(leaf_hex(&s, &r, value));
        reset();
        call(json!({ "op": "append", "leaves": leaves })).unwrap();
        let recipient = [42u8; 32];
        let fee = 1_000;
        let spend = json!({ "owner_secret": s, "rho": r, "value_uegoc": value, "leaf_index": 3, "fee_uegoc": fee });
        let stale = call(json!({ "op": "prove", "leaf_count": 3, "recipient_digest": hex::encode(recipient), "spends": [spend] }));
        assert!(stale.unwrap_err().contains("planned against 3"));
        let out = call(json!({ "op": "prove", "leaf_count": 4, "recipient_digest": hex::encode(recipient), "spends": [spend] })).unwrap();
        let sp = &out["spends"][0];
        assert_eq!(sp["amount_uegoc"], value);
        assert_eq!(sp["root"], out["root"]);
        let note = note_of(&s, &r, value).unwrap();
        assert_eq!(sp["nullifier"], to_hex(&note.nullifier()));

        let proof_bytes = hex::decode(sp["proof"].as_str().unwrap()).unwrap();
        let public = |recipient: &[u8; 32], fee: u64| PublicInputs {
            root: digest("root", sp["root"].as_str().unwrap()).unwrap(),
            nullifier: digest("nullifier", sp["nullifier"].as_str().unwrap()).unwrap(),
            amount: value,
            binding: withdrawal_binding(recipient, fee).unwrap(),
        };
        let proof = || Proof::from_bytes(&proof_bytes).unwrap();
        assert!(verify_withdrawal(proof(), public(&recipient, fee), &default_options()).is_ok());
        assert!(verify_withdrawal(proof(), public(&[43u8; 32], fee), &default_options()).is_err());
        assert!(verify_withdrawal(proof(), public(&recipient, fee + 1), &default_options()).is_err());
    }

    #[test]
    fn the_prover_refuses_what_the_chain_would_refuse() {
        let mut rng = StdRng::seed_from_u64(11);
        let (s, r) = secrets(&mut rng);
        reset();
        call(json!({ "op": "append", "leaves": [leaf_hex(&s, &r, ONE_EGOC)] })).unwrap();
        let spend = |index: usize, value: u64, fee: u64| {
            call(json!({
                "op": "prove",
                "leaf_count": 1,
                "recipient_digest": hex::encode([1u8; 32]),
                "spends": [{ "owner_secret": s, "rho": r, "value_uegoc": value, "leaf_index": index, "fee_uegoc": fee }],
            }))
        };
        assert!(spend(0, ONE_EGOC, ONE_EGOC).unwrap_err().contains("consume"));
        assert!(spend(0, 10 * ONE_EGOC, 1).unwrap_err().contains("does not hold"));
        assert!(spend(1, ONE_EGOC, 1).unwrap_err().contains("does not hold"));
        assert!(call(json!({ "op": "prove", "leaf_count": 1, "recipient_digest": "zz", "spends": [] }))
            .unwrap_err()
            .contains("at least one"));
        assert!(dispatch(b"not json").unwrap_err().contains("bad request"));
    }

    #[test]
    fn the_c_interface_round_trips() {
        unsafe {
            let req = json!({ "op": "reset" }).to_string();
            let p = ego_alloc(req.len());
            std::ptr::copy_nonoverlapping(req.as_ptr(), p, req.len());
            assert_eq!(ego_call(p, req.len()), 1);
            ego_free(p, req.len());
            let out = std::slice::from_raw_parts(ego_output_ptr(), ego_output_len());
            let v: Value = serde_json::from_slice(out).unwrap();
            assert_eq!(v["leaf_count"], 0);
            assert_eq!(ego_call(b"{}".as_ptr(), 2), 0);
            assert_eq!(ego_tree_append(std::ptr::null(), 0), 1);
            assert_eq!(ego_tree_append([7u8; 5].as_ptr(), 5), 0);
        }
    }
}

#[cfg(test)]
mod wasm_output {
    use super::*;
    use ego_stark::air::PublicInputs;
    use ego_stark::note::withdrawal_binding;
    use ego_stark::prove::verify_withdrawal;
    use winterfell::Proof;

    #[test]
    #[ignore]
    fn proofs_made_by_the_wasm_build_verify_natively() {
        let path = std::env::var("EGO_WASM_PROOF").expect("EGO_WASM_PROOF");
        let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let recipient = bytes32("recipient", v["recipient"].as_str().unwrap()).unwrap();
        for (i, n) in v["notes"].as_array().unwrap().iter().enumerate() {
            let note = note_of(n["owner_secret"].as_str().unwrap(), n["rho"].as_str().unwrap(), 1_000_000).unwrap();
            assert_eq!(v["made"][i]["commitment"], to_hex(&note.commitment().unwrap()));
            assert_eq!(v["made"][i]["leaves"][0], to_hex(&note.leaf().unwrap()));
        }
        let spends = v["proved"]["spends"].as_array().unwrap();
        assert!(!spends.is_empty());
        for sp in spends {
            let public = PublicInputs {
                root: digest("root", sp["root"].as_str().unwrap()).unwrap(),
                nullifier: digest("nullifier", sp["nullifier"].as_str().unwrap()).unwrap(),
                amount: sp["amount_uegoc"].as_u64().unwrap(),
                binding: withdrawal_binding(&recipient, sp["fee_uegoc"].as_u64().unwrap()).unwrap(),
            };
            let proof = Proof::from_bytes(&hex::decode(sp["proof"].as_str().unwrap()).unwrap()).unwrap();
            verify_withdrawal(proof, public, &default_options()).expect("a wasm proof verifies natively");
        }
    }
}
