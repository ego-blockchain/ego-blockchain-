use crate::merkle::MerklePath;
use crate::{Digest, Elem};
use winterfell::crypto::hashers::Rp64_256;
use winterfell::math::{FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

pub const STATE_WIDTH: usize = Rp64_256::STATE_WIDTH;
pub const NUM_ROUNDS: usize = Rp64_256::NUM_ROUNDS;
pub const CYCLE: usize = 8;
pub const DIR_COL: usize = STATE_WIDTH;
pub const TRACE_WIDTH: usize = STATE_WIDTH + 1;

pub const CAPACITY: std::ops::Range<usize> = 0..4;
pub const DIGEST: std::ops::Range<usize> = 4..8;
pub const SIBLING: std::ops::Range<usize> = 8..12;
pub const RATE_WIDTH: u64 = 8;

pub const POOL_TREE_DEPTH: usize = 32;
pub const TRACE_LEN: usize = CYCLE * POOL_TREE_DEPTH;

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

pub fn capacity_seed() -> [Elem; 4] {
    [Elem::new(RATE_WIDTH), Elem::ZERO, Elem::ZERO, Elem::ZERO]
}

fn absorb_row(digest: &Digest, sibling: &Digest, digest_on_right: bool) -> [Elem; STATE_WIDTH] {
    let mut row = [Elem::ZERO; STATE_WIDTH];
    row[CAPACITY].copy_from_slice(&capacity_seed());
    let (first, second) = if digest_on_right {
        (sibling.as_elements(), digest.as_elements())
    } else {
        (digest.as_elements(), sibling.as_elements())
    };
    row[DIGEST].copy_from_slice(first);
    row[SIBLING].copy_from_slice(second);
    row
}

pub fn build_trace(leaf: Digest, path: &MerklePath) -> winterfell::TraceTable<Elem> {
    assert_eq!(path.depth(), POOL_TREE_DEPTH, "path depth must match the pool tree");
    let mut trace = winterfell::TraceTable::new(TRACE_WIDTH, TRACE_LEN);

    let siblings = path.siblings.clone();
    let is_right = path.is_right.clone();
    let first = absorb_row(&leaf, &siblings[0], is_right[0]);

    trace.fill(
        |state| {
            state[..STATE_WIDTH].copy_from_slice(&first);
            state[DIR_COL] = if is_right[0] { Elem::ONE } else { Elem::ZERO };
        },
        |step, state| {
            let phase = step % CYCLE;
            if phase < NUM_ROUNDS {
                let mut hash_state: [Elem; STATE_WIDTH] =
                    state[..STATE_WIDTH].try_into().expect("state width");
                Rp64_256::apply_round(&mut hash_state, phase);
                state[..STATE_WIDTH].copy_from_slice(&hash_state);
            } else {
                let level = step / CYCLE + 1;
                let digest = Digest::new(state[DIGEST].try_into().expect("digest"));
                let row = absorb_row(&digest, &siblings[level], is_right[level]);
                state[..STATE_WIDTH].copy_from_slice(&row);
                state[DIR_COL] = if is_right[level] { Elem::ONE } else { Elem::ZERO };
            }
        },
    );
    trace
}

pub fn root_of(trace: &winterfell::TraceTable<Elem>) -> Digest {
    use winterfell::Trace;
    let mut elems = [Elem::ZERO; 4];
    for (k, e) in elems.iter_mut().enumerate() {
        *e = trace.get(DIGEST.start + k, TRACE_LEN - 1);
    }
    Digest::new(elems)
}

#[derive(Clone)]
pub struct PublicInputs {
    pub root: Digest,
}

impl ToElements<Elem> for PublicInputs {
    fn to_elements(&self) -> Vec<Elem> {
        self.root.as_elements().to_vec()
    }
}

pub struct MerklePathAir {
    context: AirContext<Elem>,
    root: Digest,
}

impl Air for MerklePathAir {
    type BaseField = Elem;
    type PublicInputs = PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees =
            vec![TransitionConstraintDegree::with_cycles(7, vec![CYCLE]); STATE_WIDTH];
        Self {
            context: AirContext::new(trace_info, degrees, 8, options),
            root: pub_inputs.root,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut cols = Vec::with_capacity(1 + 2 * STATE_WIDTH);

        let mut flag = vec![Elem::ONE; CYCLE];
        flag[CYCLE - 1] = Elem::ZERO;
        cols.push(flag);

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
        periodic: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();

        let is_round = periodic[0];
        let is_absorb = E::ONE - is_round;
        let ark1 = &periodic[1..1 + STATE_WIDTH];
        let ark2 = &periodic[1 + STATE_WIDTH..1 + 2 * STATE_WIDTH];

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
        for (i, p) in peeled.iter_mut().enumerate() {
            *p = next_state[i] - ark2[i];
        }
        let peeled = apply_matrix(&Rp64_256::INV_MDS, &peeled);

        let next_dir = next[DIR_COL];
        let seed = capacity_seed();

        for i in 0..STATE_WIDTH {
            let round_part = forward[i] + ark1[i] - sbox(peeled[i]);

            let absorb_part = if CAPACITY.contains(&i) {
                next_state[i] - E::from(seed[i])
            } else if DIGEST.contains(&i) {
                let carried = cur_state[i];
                (E::ONE - next_dir) * (next_state[i] - carried)
                    + next_dir * (next_state[i + 4] - carried)
            } else if i == SIBLING.start {
                next_dir * next_dir - next_dir
            } else {
                E::ZERO
            };

            result[i] = is_round * round_part + is_absorb * absorb_part;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let seed = capacity_seed();
        let last = TRACE_LEN - 1;
        let mut out = Vec::with_capacity(8);
        for (i, s) in seed.iter().enumerate() {
            out.push(Assertion::single(CAPACITY.start + i, 0, *s));
        }
        for (k, e) in self.root.as_elements().iter().enumerate() {
            out.push(Assertion::single(DIGEST.start + k, last, *e));
        }
        out
    }
}
