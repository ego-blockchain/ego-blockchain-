use crate::merkle::MerklePath;
use crate::{Digest, Elem, DOMAIN_COMMITMENT, DOMAIN_LEAF, DOMAIN_NULLIFIER, SECRET_ELEMS};
use winterfell::crypto::hashers::Rp64_256;
use winterfell::math::{FieldElement, StarkField, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const STATE_WIDTH: usize = Rp64_256::STATE_WIDTH;
pub const NUM_ROUNDS: usize = Rp64_256::NUM_ROUNDS;
pub const CYCLE: usize = 8;

pub const DIR_COL: usize = STATE_WIDTH;
pub const SECRET_COL: usize = DIR_COL + 1;
pub const RHO_COL: usize = SECRET_COL + SECRET_ELEMS;
pub const TRACE_WIDTH: usize = RHO_COL + SECRET_ELEMS;
pub const CARRIED: usize = 2 * SECRET_ELEMS;

pub const CAPACITY: std::ops::Range<usize> = 0..4;
pub const DIGEST: std::ops::Range<usize> = 4..8;
pub const RATE: std::ops::Range<usize> = 4..12;

pub const BLOCK_COMMITMENT: usize = 0;
pub const BLOCK_LEAF: usize = 1;
pub const BLOCK_FIRST_PATH: usize = 2;
pub const POOL_TREE_DEPTH: usize = 29;
pub const BLOCK_NULLIFIER: usize = BLOCK_FIRST_PATH + POOL_TREE_DEPTH;
pub const NUM_BLOCKS: usize = BLOCK_NULLIFIER + 1;
pub const TRACE_LEN: usize = CYCLE * NUM_BLOCKS;

pub const ROOT_ROW: usize = CYCLE * BLOCK_NULLIFIER - 1;
pub const NULLIFIER_ROW: usize = TRACE_LEN - 1;

pub const COMMITMENT_INPUTS: u64 = (1 + 2 * SECRET_ELEMS) as u64;
pub const LEAF_INPUTS: u64 = 6;
pub const NULLIFIER_INPUTS: u64 = (1 + 2 * SECRET_ELEMS) as u64;
pub const MERGE_INPUTS: u64 = 8;

fn sbox<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}

fn apply_matrix<E: FieldElement<BaseField = Elem>>(
    m: &[[Elem; STATE_WIDTH]; STATE_WIDTH],
    v: &[E; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let mut out = [E::ZERO; STATE_WIDTH];
    for (i, o) in out.iter_mut().enumerate() {
        let mut acc = E::ZERO;
        for (j, x) in v.iter().enumerate() {
            acc += E::from(m[i][j]) * *x;
        }
        *o = acc;
    }
    out
}

fn seeded_row(capacity: u64, inputs: &[Elem]) -> [Elem; STATE_WIDTH] {
    assert!(inputs.len() <= RATE.len());
    let mut row = [Elem::ZERO; STATE_WIDTH];
    row[CAPACITY.start] = Elem::new(capacity);
    row[RATE.start..RATE.start + inputs.len()].copy_from_slice(inputs);
    row
}

fn commitment_row(secret: &[Elem], rho: &[Elem]) -> [Elem; STATE_WIDTH] {
    let mut inputs = Vec::with_capacity(COMMITMENT_INPUTS as usize);
    inputs.push(Elem::new(DOMAIN_COMMITMENT));
    inputs.extend_from_slice(secret);
    inputs.extend_from_slice(rho);
    seeded_row(COMMITMENT_INPUTS, &inputs)
}

fn leaf_row(commitment: &Digest, amount: Elem) -> [Elem; STATE_WIDTH] {
    let mut inputs = Vec::with_capacity(LEAF_INPUTS as usize);
    inputs.push(Elem::new(DOMAIN_LEAF));
    inputs.extend_from_slice(commitment.as_elements());
    inputs.push(amount);
    seeded_row(LEAF_INPUTS, &inputs)
}

fn nullifier_row(secret: &[Elem], rho: &[Elem]) -> [Elem; STATE_WIDTH] {
    let mut inputs = Vec::with_capacity(NULLIFIER_INPUTS as usize);
    inputs.push(Elem::new(DOMAIN_NULLIFIER));
    inputs.extend_from_slice(secret);
    inputs.extend_from_slice(rho);
    seeded_row(NULLIFIER_INPUTS, &inputs)
}

fn path_row(digest: &Digest, sibling: &Digest, digest_on_right: bool) -> [Elem; STATE_WIDTH] {
    let mut row = [Elem::ZERO; STATE_WIDTH];
    row[CAPACITY.start] = Elem::new(MERGE_INPUTS);
    let (first, second) = if digest_on_right {
        (sibling.as_elements(), digest.as_elements())
    } else {
        (digest.as_elements(), sibling.as_elements())
    };
    row[RATE.start..RATE.start + 4].copy_from_slice(first);
    row[RATE.start + 4..RATE.start + 8].copy_from_slice(second);
    row
}

fn digest_at(state: &[Elem]) -> Digest {
    Digest::new(state[DIGEST].try_into().expect("digest"))
}

pub struct Witness {
    pub secret: [Elem; SECRET_ELEMS],
    pub rho: [Elem; SECRET_ELEMS],
    pub amount: Elem,
    pub path: MerklePath,
}

pub fn build_trace(w: &Witness) -> TraceTable<Elem> {
    assert_eq!(w.path.depth(), POOL_TREE_DEPTH, "path depth must match the pool tree");
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LEN);

    let secret = w.secret;
    let rho = w.rho;
    let amount = w.amount;
    let siblings = w.path.siblings.clone();
    let is_right = w.path.is_right.clone();
    let first = commitment_row(&secret, &rho);

    trace.fill(
        |state| {
            state[..STATE_WIDTH].copy_from_slice(&first);
            state[DIR_COL] = Elem::ZERO;
            state[SECRET_COL..SECRET_COL + SECRET_ELEMS].copy_from_slice(&secret);
            state[RHO_COL..RHO_COL + SECRET_ELEMS].copy_from_slice(&rho);
        },
        |step, state| {
            let phase = step % CYCLE;
            if phase < NUM_ROUNDS {
                let mut hash_state: [Elem; STATE_WIDTH] =
                    state[..STATE_WIDTH].try_into().expect("state width");
                Rp64_256::apply_round(&mut hash_state, phase);
                state[..STATE_WIDTH].copy_from_slice(&hash_state);
                return;
            }
            let finished = step / CYCLE;
            let next_block = finished + 1;
            let out = digest_at(&state[..STATE_WIDTH]);

            let (row, dir) = if next_block == BLOCK_LEAF {
                (leaf_row(&out, amount), false)
            } else if next_block == BLOCK_NULLIFIER {
                (nullifier_row(&secret, &rho), false)
            } else {
                let level = next_block - BLOCK_FIRST_PATH;
                (path_row(&out, &siblings[level], is_right[level]), is_right[level])
            };
            state[..STATE_WIDTH].copy_from_slice(&row);
            state[DIR_COL] = if dir { Elem::ONE } else { Elem::ZERO };
        },
    );
    trace
}

pub fn root_of(trace: &TraceTable<Elem>) -> Digest {
    use winterfell::Trace;
    let mut e = [Elem::ZERO; 4];
    for (k, v) in e.iter_mut().enumerate() {
        *v = trace.get(DIGEST.start + k, ROOT_ROW);
    }
    Digest::new(e)
}

pub fn nullifier_of(trace: &TraceTable<Elem>) -> Digest {
    use winterfell::Trace;
    let mut e = [Elem::ZERO; 4];
    for (k, v) in e.iter_mut().enumerate() {
        *v = trace.get(DIGEST.start + k, NULLIFIER_ROW);
    }
    Digest::new(e)
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicInputs {
    pub root: Digest,
    pub nullifier: Digest,
    pub amount: u64,
    pub binding: Digest,
}

impl ToElements<Elem> for PublicInputs {
    fn to_elements(&self) -> Vec<Elem> {
        let mut v = Vec::with_capacity(13);
        v.extend_from_slice(self.root.as_elements());
        v.extend_from_slice(self.nullifier.as_elements());
        v.push(Elem::new(self.amount));
        v.extend_from_slice(self.binding.as_elements());
        v
    }
}

pub struct WithdrawAir {
    context: AirContext<Elem>,
    public: PublicInputs,
}

const SEL_ROUND: usize = 0;
const SEL_LEAF: usize = 1;
const SEL_PATH: usize = 2;
const SEL_NULL: usize = 3;
const SEL_FIRST: usize = 4;
const ARK1_BASE: usize = 5;
const ARK2_BASE: usize = ARK1_BASE + STATE_WIDTH;

impl Air for WithdrawAir {
    type BaseField = Elem;
    type PublicInputs = PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, public: PublicInputs, options: ProofOptions) -> Self {
        let mut degrees =
            vec![TransitionConstraintDegree::with_cycles(7, vec![CYCLE]); STATE_WIDTH];
        for _ in 0..CARRIED {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        for _ in 0..CARRIED {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![TRACE_LEN]));
        }
        Self {
            context: AirContext::new(trace_info, degrees, 13, options),
            public,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut cols = Vec::with_capacity(5 + 2 * STATE_WIDTH);

        let mut round = vec![Elem::ONE; CYCLE];
        round[CYCLE - 1] = Elem::ZERO;
        cols.push(round);

        let absorb_row_of = |block: usize| CYCLE * block - 1;
        let mut leaf = vec![Elem::ZERO; TRACE_LEN];
        leaf[absorb_row_of(BLOCK_LEAF)] = Elem::ONE;
        cols.push(leaf);

        let mut path = vec![Elem::ZERO; TRACE_LEN];
        for level in 0..POOL_TREE_DEPTH {
            path[absorb_row_of(BLOCK_FIRST_PATH + level)] = Elem::ONE;
        }
        cols.push(path);

        let mut null = vec![Elem::ZERO; TRACE_LEN];
        null[absorb_row_of(BLOCK_NULLIFIER)] = Elem::ONE;
        cols.push(null);

        let mut first = vec![Elem::ZERO; TRACE_LEN];
        first[0] = Elem::ONE;
        cols.push(first);

        for lane in 0..STATE_WIDTH {
            let mut c = vec![Elem::ZERO; CYCLE];
            for (r, slot) in c.iter_mut().enumerate().take(NUM_ROUNDS) {
                *slot = Rp64_256::ARK1[r][lane];
            }
            cols.push(c);
        }
        for lane in 0..STATE_WIDTH {
            let mut c = vec![Elem::ZERO; CYCLE];
            for (r, slot) in c.iter_mut().enumerate().take(NUM_ROUNDS) {
                *slot = Rp64_256::ARK2[r][lane];
            }
            cols.push(c);
        }
        cols
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        p: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();

        let is_round = p[SEL_ROUND];
        let sel_leaf = p[SEL_LEAF];
        let sel_path = p[SEL_PATH];
        let sel_null = p[SEL_NULL];
        let sel_first = p[SEL_FIRST];
        let ark1 = &p[ARK1_BASE..ARK1_BASE + STATE_WIDTH];
        let ark2 = &p[ARK2_BASE..ARK2_BASE + STATE_WIDTH];

        let mut cur_state = [E::ZERO; STATE_WIDTH];
        let mut next_state = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            cur_state[i] = cur[i];
            next_state[i] = next[i];
        }

        let mut forward = [E::ZERO; STATE_WIDTH];
        for (i, f) in forward.iter_mut().enumerate() {
            *f = sbox(cur_state[i]);
        }
        let forward = apply_matrix(&Rp64_256::MDS, &forward);

        let mut peeled = [E::ZERO; STATE_WIDTH];
        for (i, q) in peeled.iter_mut().enumerate() {
            *q = next_state[i] - ark2[i];
        }
        let peeled = apply_matrix(&Rp64_256::INV_MDS, &peeled);

        let dir = next[DIR_COL];
        let amount = E::from(Elem::new(self.public.amount));
        let dom_leaf = E::from(Elem::new(DOMAIN_LEAF));
        let dom_null = E::from(Elem::new(DOMAIN_NULLIFIER));

        for i in 0..STATE_WIDTH {
            let round_part = forward[i] + ark1[i] - sbox(peeled[i]);

            let leaf_part = if i == CAPACITY.start {
                next_state[i] - E::from(Elem::new(LEAF_INPUTS))
            } else if CAPACITY.contains(&i) {
                next_state[i]
            } else if i == RATE.start {
                next_state[i] - dom_leaf
            } else if (RATE.start + 1..RATE.start + 5).contains(&i) {
                next_state[i] - cur_state[i - 1]
            } else if i == RATE.start + 5 {
                next_state[i] - amount
            } else {
                next_state[i]
            };

            let path_part = if i == CAPACITY.start {
                next_state[i] - E::from(Elem::new(MERGE_INPUTS))
            } else if CAPACITY.contains(&i) {
                next_state[i]
            } else if DIGEST.contains(&i) {
                let carried = cur_state[i];
                (E::ONE - dir) * (next_state[i] - carried) + dir * (next_state[i + 4] - carried)
            } else if i == DIGEST.end {
                dir * dir - dir
            } else {
                E::ZERO
            };

            let null_part = if i == CAPACITY.start {
                next_state[i] - E::from(Elem::new(NULLIFIER_INPUTS))
            } else if CAPACITY.contains(&i) {
                next_state[i]
            } else if i == RATE.start {
                next_state[i] - dom_null
            } else if (RATE.start + 1..RATE.start + 1 + SECRET_ELEMS).contains(&i) {
                next_state[i] - next[SECRET_COL + (i - RATE.start - 1)]
            } else if (RATE.start + 1 + SECRET_ELEMS..RATE.start + 1 + 2 * SECRET_ELEMS)
                .contains(&i)
            {
                next_state[i] - next[RHO_COL + (i - RATE.start - 1 - SECRET_ELEMS)]
            } else {
                next_state[i]
            };

            result[i] = is_round * round_part
                + sel_leaf * leaf_part
                + sel_path * path_part
                + sel_null * null_part;
        }

        for k in 0..CARRIED {
            result[STATE_WIDTH + k] = next[SECRET_COL + k] - cur[SECRET_COL + k];
        }
        for k in 0..CARRIED {
            result[STATE_WIDTH + CARRIED + k] =
                sel_first * (cur[SECRET_COL + k] - cur[RATE.start + 1 + k]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut out = Vec::with_capacity(10);
        out.push(Assertion::single(CAPACITY.start, 0, Elem::new(COMMITMENT_INPUTS)));
        for i in CAPACITY.start + 1..CAPACITY.end {
            out.push(Assertion::single(i, 0, Elem::ZERO));
        }
        out.push(Assertion::single(RATE.start, 0, Elem::new(DOMAIN_COMMITMENT)));
        for (k, e) in self.public.root.as_elements().iter().enumerate() {
            out.push(Assertion::single(DIGEST.start + k, ROOT_ROW, *e));
        }
        for (k, e) in self.public.nullifier.as_elements().iter().enumerate() {
            out.push(Assertion::single(DIGEST.start + k, NULLIFIER_ROW, *e));
        }
        out
    }
}

pub fn amount_fits(amount: u64) -> bool {
    amount < Elem::MODULUS
}
