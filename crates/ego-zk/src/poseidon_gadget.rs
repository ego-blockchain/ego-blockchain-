use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;

pub const SHIELDED_COMMITMENT_DOMAIN: u64 = 1;
pub const SHIELDED_NULLIFIER_DOMAIN: u64 = 2;
pub const SHIELDED_BINDING_DOMAIN: u64 = 4;
pub const SHIELDED_LEAF_DOMAIN: u64 = 5;

pub struct PoseidonGadgetParams {
    ark: Vec<Fr>,
    mds: Vec<Vec<Fr>>,
    full_rounds: usize,
    partial_rounds: usize,
    width: usize,
}

impl PoseidonGadgetParams {
    pub fn circom(nr_inputs: usize) -> Result<Self, String> {
        let width = nr_inputs + 1;
        let p = get_poseidon_parameters::<Fr>(width as u8).map_err(|e| e.to_string())?;
        if p.alpha != 5 {
            return Err(format!("expected alpha = 5 for bn254_x5, got {}", p.alpha));
        }
        if p.width != width {
            return Err(format!("parameter width {} does not match requested {}", p.width, width));
        }
        Ok(Self {
            ark: p.ark,
            mds: p.mds,
            full_rounds: p.full_rounds,
            partial_rounds: p.partial_rounds,
            width: p.width,
        })
    }

    pub fn width(&self) -> usize {
        self.width
    }
}

fn sbox(x: &FpVar<Fr>) -> FpVar<Fr> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    &x4 * x
}

pub fn poseidon_hash_gadget(
    params: &PoseidonGadgetParams,
    domain_tag: Fr,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    if inputs.len() + 1 != params.width {
        return Err(SynthesisError::Unsatisfiable);
    }
    let width = params.width;

    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::Constant(domain_tag));
    state.extend_from_slice(inputs);

    let all_rounds = params.full_rounds + params.partial_rounds;
    let half = params.full_rounds / 2;

    let add_round_constants = |state: &mut Vec<FpVar<Fr>>, round: usize| {
        for (i, s) in state.iter_mut().enumerate() {
            *s = &*s + params.ark[round * width + i];
        }
    };

    let mix = |state: &mut Vec<FpVar<Fr>>| {
        let mut next = Vec::with_capacity(width);
        for row in params.mds.iter().take(width) {
            let mut acc = FpVar::Constant(Fr::zero());
            for (j, s) in state.iter().enumerate() {
                acc = &acc + &(s * row[j]);
            }
            next.push(acc);
        }
        *state = next;
    };

    for round in 0..half {
        add_round_constants(&mut state, round);
        for s in state.iter_mut() {
            *s = sbox(s);
        }
        mix(&mut state);
    }

    for round in half..half + params.partial_rounds {
        add_round_constants(&mut state, round);
        state[0] = sbox(&state[0]);
        mix(&mut state);
    }

    for round in half + params.partial_rounds..all_rounds {
        add_round_constants(&mut state, round);
        for s in state.iter_mut() {
            *s = sbox(s);
        }
        mix(&mut state);
    }

    Ok(state[0].clone())
}

pub fn commitment_gadget(
    value: &FpVar<Fr>,
    secret: &FpVar<Fr>,
    rho: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let params = PoseidonGadgetParams::circom(3).map_err(|_| SynthesisError::Unsatisfiable)?;
    poseidon_hash_gadget(
        &params,
        Fr::from(SHIELDED_COMMITMENT_DOMAIN),
        &[value.clone(), secret.clone(), rho.clone()],
    )
}

pub fn leaf_gadget(
    commitment: &FpVar<Fr>,
    amount: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let params = PoseidonGadgetParams::circom(2).map_err(|_| SynthesisError::Unsatisfiable)?;
    poseidon_hash_gadget(
        &params,
        Fr::from(SHIELDED_LEAF_DOMAIN),
        &[commitment.clone(), amount.clone()],
    )
}

pub fn nullifier_gadget(secret: &FpVar<Fr>, rho: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let params = PoseidonGadgetParams::circom(2).map_err(|_| SynthesisError::Unsatisfiable)?;
    poseidon_hash_gadget(
        &params,
        Fr::from(SHIELDED_NULLIFIER_DOMAIN),
        &[secret.clone(), rho.clone()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::{test_rng, UniformRand};
    use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher};

    fn native(domain: Fr, inputs: &[Fr]) -> Fr {
        let mut p = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), domain).unwrap();
        p.hash(inputs).unwrap()
    }

    fn in_circuit(domain: Fr, inputs: &[Fr]) -> (Fr, bool, usize, ConstraintSystemRef<Fr>) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = PoseidonGadgetParams::circom(inputs.len()).unwrap();
        let vars: Vec<FpVar<Fr>> = inputs
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect();
        let out = poseidon_hash_gadget(&params, domain, &vars).unwrap();
        let value = out.value().unwrap();
        let ok = cs.is_satisfied().unwrap();
        let n = cs.num_constraints();
        (value, ok, n, cs)
    }

    #[test]
    fn the_oracle_reproduces_its_own_documented_vector() {
        let mut p = Poseidon::<Fr>::new_circom(2).unwrap();
        let h = p.hash_bytes_be(&[&[1u8; 32], &[2u8; 32]]).unwrap();
        let documented: [u8; 32] = [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144,
        ];
        assert_eq!(h, documented, "light-poseidon disagrees with its own published vector");
    }

    #[test]
    fn gadget_equals_native_for_two_inputs() {
        let mut rng = test_rng();
        for _ in 0..32 {
            let inputs = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
            let domain = Fr::from(SHIELDED_NULLIFIER_DOMAIN);
            let (got, ok, _, _) = in_circuit(domain, &inputs);
            assert!(ok, "constraint system must be satisfied by an honest witness");
            assert_eq!(got, native(domain, &inputs), "in-circuit hash differs from native");
        }
    }

    #[test]
    fn gadget_equals_native_for_three_inputs() {
        let mut rng = test_rng();
        for _ in 0..32 {
            let inputs = [Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)];
            let domain = Fr::from(SHIELDED_COMMITMENT_DOMAIN);
            let (got, ok, _, _) = in_circuit(domain, &inputs);
            assert!(ok);
            assert_eq!(got, native(domain, &inputs));
        }
    }

    #[test]
    fn the_domain_tag_separates_and_matches_native() {
        let mut rng = test_rng();
        let inputs = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let d1 = Fr::from(SHIELDED_COMMITMENT_DOMAIN);
        let d2 = Fr::from(SHIELDED_NULLIFIER_DOMAIN);
        let (g1, _, _, _) = in_circuit(d1, &inputs);
        let (g2, _, _, _) = in_circuit(d2, &inputs);
        assert_ne!(g1, g2, "different domains must give different hashes");
        assert_eq!(g1, native(d1, &inputs));
        assert_eq!(g2, native(d2, &inputs));
    }

    #[test]
    fn gadget_equals_native_on_all_zero_inputs() {
        let inputs = [Fr::zero(), Fr::zero()];
        let domain = Fr::from(SHIELDED_NULLIFIER_DOMAIN);
        let (got, ok, _, _) = in_circuit(domain, &inputs);
        assert!(ok);
        assert_eq!(got, native(domain, &inputs));
    }

    #[test]
    fn constraint_count_is_exactly_what_the_construction_implies() {
        let mut rng = test_rng();
        for nr_inputs in [2usize, 3] {
            let inputs: Vec<Fr> = (0..nr_inputs).map(|_| Fr::rand(&mut rng)).collect();
            let params = PoseidonGadgetParams::circom(nr_inputs).unwrap();
            let (_, ok, n, _) = in_circuit(Fr::from(1u64), &inputs);
            assert!(ok);
            let width = params.width;
            let sboxes = params.full_rounds * width + params.partial_rounds;
            let expected = sboxes * 3 - 3;
            assert_eq!(
                n, expected,
                "width {width}: got {n} constraints, construction implies {expected}"
            );
        }
    }

    #[test]
    fn a_mismatched_input_count_is_refused() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = PoseidonGadgetParams::circom(2).unwrap();
        let one = FpVar::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap();
        assert!(poseidon_hash_gadget(&params, Fr::from(1u64), &[one]).is_err());
    }

    #[test]
    fn commitment_and_nullifier_gadgets_match_native() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (v, s, r) = (Fr::from(1_000u64), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let vv = FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
        let sv = FpVar::new_witness(cs.clone(), || Ok(s)).unwrap();
        let rv = FpVar::new_witness(cs.clone(), || Ok(r)).unwrap();

        let c = commitment_gadget(&vv, &sv, &rv).unwrap().value().unwrap();
        let n = nullifier_gadget(&sv, &rv).unwrap().value().unwrap();
        assert!(cs.is_satisfied().unwrap());

        assert_eq!(c, native(Fr::from(SHIELDED_COMMITMENT_DOMAIN), &[v, s, r]));
        assert_eq!(n, native(Fr::from(SHIELDED_NULLIFIER_DOMAIN), &[s, r]));
        assert_ne!(c, n);
    }
}
