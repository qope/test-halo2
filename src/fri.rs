// use std::borrow::Borrow;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        range::RangeConfig,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::Fr,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    },
};
use plonky2::fri::FriParams;
use poseidon_circuit::poseidon::{primitives::P128Pow5T3, Pow5Chip, Pow5Config};
use serde::{Deserialize, Serialize};

use crate::{
    field::{
        from_base_field, zero_assigned, AssignedGoldilocksExtension, AssignedGoldilocksField,
        GoldilocksExtension, GoldilocksExtensionChip, GoldilocksField,
    },
    reducing::{AssignedReducingFactor, ReducingFactor},
};

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const L: usize = 2;
pub const K: usize = 18;

#[derive(Clone)]
pub struct FriCircuitConfig {
    poseidon: Pow5Config<Fr, WIDTH, RATE>,
    a: Column<Advice>,
    gate: FlexGateConfig<Fr>,
}

#[derive(Default)]
pub struct FriCircuit;

impl Circuit<Fr> for FriCircuit {
    type Config = FriCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        let poseidon = Pow5Chip::configure::<P128Pow5T3<Fr>>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        let a = meta.advice_column();
        meta.enable_equality(a);

        let gate = FlexGateConfig::configure(meta, GateStrategy::Vertical, &[1], 1, 0, K);

        Self::Config { poseidon, a, gate }
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon);

        todo!()
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct FriPolynomialInfo {
    /// Index into `FriInstanceInfo`'s `oracles` list.
    pub oracle_index: usize,
    /// Index of the polynomial within the oracle.
    pub polynomial_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriBatchInfo {
    pub point: GoldilocksExtension,
    pub polynomials: Vec<FriPolynomialInfo>,
}

#[derive(Clone, Debug)]
pub struct AssignedFriBatchInfo {
    pub point: AssignedGoldilocksExtension,
    pub polynomials: Vec<FriPolynomialInfo>,
}

impl AssignedFriBatchInfo {
    pub fn assign(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: &FriBatchInfo,
    ) -> Result<Self, Error> {
        let point = AssignedGoldilocksExtension::assign(
            layouter.namespace(|| "assign value.point"),
            advice_column,
            value.point,
        )?;
        let polynomials = value.polynomials.clone();

        Ok(Self { point, polynomials })
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct FriOracleInfo {
    pub num_polys: usize,
    pub blinding: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriInstanceInfo {
    /// The oracles involved, not counting oracles created during the commit phase.
    pub oracles: Vec<FriOracleInfo>,
    /// Batches of openings, where each batch is associated with a particular point.
    pub batches: Vec<FriBatchInfo>,
}

#[derive(Clone, Debug)]
pub struct AssignedFriInstanceInfo {
    /// The oracles involved, not counting oracles created during the commit phase.
    pub oracles: Vec<FriOracleInfo>,
    /// Batches of openings, where each batch is associated with a particular point.
    pub batches: Vec<AssignedFriBatchInfo>,
}

impl AssignedFriInstanceInfo {
    pub fn assign(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: &FriInstanceInfo,
    ) -> Result<Self, Error> {
        let oracles = value.oracles.clone();

        let batches = value
            .batches
            .iter()
            .map(|batch| {
                AssignedFriBatchInfo::assign(
                    layouter.namespace(|| "assign batch"),
                    advice_column,
                    batch,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        Ok(Self { oracles, batches })
    }
}

/// opened at that point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrecomputedReducedOpenings {
    pub reduced_openings_at_point: Vec<GoldilocksExtension>,
}

#[derive(Clone, Debug)]
pub struct AssignedPrecomputedReducedOpenings {
    pub reduced_openings_at_point: Vec<AssignedGoldilocksExtension>,
}

impl AssignedPrecomputedReducedOpenings {
    pub fn assign(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: &PrecomputedReducedOpenings,
    ) -> Result<Self, Error> {
        let result = Self {
            reduced_openings_at_point: value
                .reduced_openings_at_point
                .iter()
                .map(|x| {
                    AssignedGoldilocksExtension::assign(
                        layouter.namespace(|| "assign x"),
                        advice_column,
                        *x,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?,
        };

        Ok(result)
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct HashOut {
    pub elements: [GoldilocksField; 4],
}

#[derive(Clone, Debug)]
pub struct AssignedHashOut {
    pub elements: [AssignedGoldilocksField; 4],
}

impl AssignedHashOut {
    pub fn assign(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: HashOut,
    ) -> Result<Self, Error> {
        let result = AssignedHashOut {
            elements: value
                .elements
                .to_vec()
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    AssignedGoldilocksField::assign(
                        layouter.namespace(|| format!("assign hash out element[{i}]")),
                        advice_column,
                        *v,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        };

        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<HashOut>,
}

#[derive(Clone, Debug)]
pub struct AssignedMerkleProof {
    pub siblings: Vec<AssignedHashOut>,
}

impl AssignedMerkleProof {
    pub fn assign(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: &MerkleProof,
    ) -> Result<Self, Error> {
        let result = Self {
            siblings: value
                .siblings
                .iter()
                .map(|sibling| {
                    AssignedHashOut::assign(
                        layouter.namespace(|| "assign sibling"),
                        advice_column,
                        *sibling,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?,
        };

        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriInitialTreeProof {
    pub evals_proofs: Vec<(Vec<GoldilocksField>, MerkleProof)>,
}

const SALT_SIZE: usize = 4;

pub fn salt_size(salted: bool) -> usize {
    if salted {
        SALT_SIZE
    } else {
        0
    }
}

impl FriInitialTreeProof {
    pub(crate) fn unsalted_eval(
        &self,
        oracle_index: usize,
        poly_index: usize,
        salted: bool,
    ) -> GoldilocksField {
        self.unsalted_evals(oracle_index, salted)[poly_index]
    }

    fn unsalted_evals(&self, oracle_index: usize, salted: bool) -> &[GoldilocksField] {
        let evals = &self.evals_proofs[oracle_index].0;
        &evals[..evals.len() - salt_size(salted)]
    }
}

#[derive(Clone, Debug)]
pub struct AssignedFriInitialTreeProof {
    pub evals_proofs: Vec<(Vec<AssignedGoldilocksField>, AssignedMerkleProof)>,
}

impl AssignedFriInitialTreeProof {
    pub fn assign(
        layouter: &mut impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: &FriInitialTreeProof,
    ) -> Result<Self, Error> {
        let result = Self {
            evals_proofs: value
                .evals_proofs
                .iter()
                .map(|(evals, proof)| {
                    Ok((
                        evals
                            .iter()
                            .map(|eval| {
                                AssignedGoldilocksField::assign(
                                    layouter.namespace(|| "assign eval"),
                                    advice_column,
                                    *eval,
                                )
                            })
                            .collect::<Result<Vec<_>, Error>>()?,
                        AssignedMerkleProof::assign(
                            layouter.namespace(|| "assign proof"),
                            advice_column,
                            proof,
                        )?,
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?,
        };

        Ok(result)
    }
}

impl AssignedFriInitialTreeProof {
    pub(crate) fn unsalted_eval(
        &self,
        oracle_index: usize,
        poly_index: usize,
        salted: bool,
    ) -> AssignedGoldilocksField {
        self.unsalted_evals(oracle_index, salted)[poly_index].clone()
    }

    fn unsalted_evals(&self, oracle_index: usize, salted: bool) -> &[AssignedGoldilocksField] {
        let evals = &self.evals_proofs[oracle_index].0;
        &evals[..evals.len() - salt_size(salted)]
    }
}

pub fn fri_combine_initial(
    instance: &FriInstanceInfo,
    proof: &FriInitialTreeProof,
    alpha: GoldilocksExtension,
    subgroup_x: GoldilocksField,
    precomputed_reduced_evals: &PrecomputedReducedOpenings,
    params: &FriParams,
) -> GoldilocksExtension {
    let subgroup_x = GoldilocksExtension::from(subgroup_x);
    let mut alpha = ReducingFactor::new(alpha);
    let mut sum = GoldilocksExtension::zero();

    for (batch, reduced_openings) in instance
        .batches
        .iter()
        .zip(&precomputed_reduced_evals.reduced_openings_at_point)
    {
        let FriBatchInfo { point, polynomials } = batch;
        let evals = polynomials
            .iter()
            .map(|p| {
                let poly_blinding = instance.oracles[p.oracle_index].blinding;
                let salted = params.hiding && poly_blinding;
                proof.unsalted_eval(p.oracle_index, p.polynomial_index, salted)
            })
            .map(GoldilocksExtension::from);
        let reduced_evals = alpha.reduce(evals);
        let numerator = reduced_evals - *reduced_openings;
        let denominator = subgroup_x - *point;
        sum = alpha.shift(sum);
        sum += numerator / denominator;
    }

    sum
}

pub fn fri_combine_initial_assigned(
    mut layouter: impl Layouter<Fr>,
    range: &RangeConfig<Fr>,
    advice_column: Column<Advice>,
    instance: &AssignedFriInstanceInfo,
    proof: &AssignedFriInitialTreeProof,
    alpha: AssignedGoldilocksExtension,
    subgroup_x: AssignedGoldilocksField,
    precomputed_reduced_evals: &AssignedPrecomputedReducedOpenings,
    params: &FriParams,
) -> Result<AssignedGoldilocksExtension, Error> {
    let zero = zero_assigned(layouter.namespace(|| "assign zero"), advice_column)?;
    let subgroup_x = AssignedGoldilocksExtension([subgroup_x.0, zero]);
    let ge_chip = GoldilocksExtensionChip::construct(range.clone());
    let mut alpha = AssignedReducingFactor::new(ge_chip.clone(), alpha);
    let mut sum = AssignedGoldilocksExtension::zero(
        layouter.namespace(|| "assign zero extension"),
        advice_column,
    )
    .unwrap();

    for (batch, reduced_openings) in instance
        .batches
        .iter()
        .zip(&precomputed_reduced_evals.reduced_openings_at_point)
    {
        let AssignedFriBatchInfo { point, polynomials } = batch;
        let evals = polynomials
            .iter()
            .map(|p| {
                let poly_blinding = instance.oracles[p.oracle_index].blinding;
                let salted = params.hiding && poly_blinding;
                proof.unsalted_eval(p.oracle_index, p.polynomial_index, salted)
            })
            .map(|value| {
                from_base_field(
                    layouter.namespace(|| "from base field"),
                    advice_column,
                    value.0,
                ).unwrap()
            })
            .collect::<Vec<_>>();
        let reduced_evals = alpha.reduce(layouter.namespace(|| "reduce"), advice_column, &evals)?;
        let tmp = ge_chip.neg(layouter.namespace(|| "neg1"), reduced_openings.clone())?;
        let numerator = ge_chip.add(layouter.namespace(|| "add1"), reduced_evals, tmp)?;
        let tmp = ge_chip.neg(layouter.namespace(|| "neg2"), point.clone())?;
        let denominator = ge_chip.add(layouter.namespace(|| "add2"), subgroup_x.clone(), tmp)?;
        sum = alpha.shift(
            layouter.namespace(|| "shift alpha by sum"),
            advice_column,
            sum,
        )?;
        let tmp = ge_chip.div(layouter.namespace(|| "div"), numerator, denominator)?;
        sum = ge_chip.add(layouter.namespace(|| "add"), sum, tmp)?;
    }

    Ok(sum)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use halo2_base::{gates::range::RangeStrategy, halo2_proofs};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Advice, Circuit, Column, Error},
    };
    use plonky2::plonk::circuit_data::CircuitConfig;

    use crate::utils::{evm_verify, gen_evm_verifier, gen_pk, gen_proof, gen_srs};

    use super::*;

    const K: usize = 18;

    #[test]
    fn test_fri_combine_initial() {
        let mut file = std::fs::File::open("fri-initial-proof.json").unwrap();
        let mut raw_contents = String::new();
        file.read_to_string(&mut raw_contents).unwrap();
        let proof: FriInitialTreeProof = serde_json::from_str(&raw_contents).unwrap();

        let mut file = std::fs::File::open("fri-precomputed.json").unwrap();
        let mut raw_contents = String::new();
        file.read_to_string(&mut raw_contents).unwrap();
        let precomputed_reduced_evals: PrecomputedReducedOpenings =
            serde_json::from_str(&raw_contents).unwrap();

        let mut file = std::fs::File::open("fri-instance.json").unwrap();
        let mut raw_contents = String::new();
        file.read_to_string(&mut raw_contents).unwrap();
        let instance: FriInstanceInfo = serde_json::from_str(&raw_contents).unwrap();

        let alpha = GoldilocksExtension([
            serde_json::from_str("10996128681446358693").unwrap(),
            serde_json::from_str("6817592260154284178").unwrap(),
        ]);
        let subgroup_x: GoldilocksField = serde_json::from_str("123358979586301028").unwrap();
        let sum = GoldilocksExtension([
            serde_json::from_str("17703852102747170808").unwrap(),
            serde_json::from_str("9208250178161818572").unwrap(),
        ]);

        let config = CircuitConfig::standard_recursion_config();
        let fri_config = config.fri_config;
        let degree_bits = 12;
        let params = fri_config.fri_params(degree_bits, false);
        let actual_sum = fri_combine_initial(
            &instance,
            &proof,
            alpha,
            subgroup_x,
            &precomputed_reduced_evals,
            &params,
        );

        assert_eq!(actual_sum, sum);
    }

    #[derive(Clone)]
    pub struct MyConfig {
        a: Column<Advice>,
        range: RangeConfig<Fr>,
        poseidon: Pow5Config<Fr, WIDTH, RATE>,
    }

    #[derive(Clone, Default)]
    pub struct MyCircuit;

    impl Circuit<Fr> for MyCircuit {
        type Config = MyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(
            meta: &mut halo2_base::halo2_proofs::plonk::ConstraintSystem<Fr>,
        ) -> Self::Config {
            let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let partial_sbox = meta.advice_column();

            let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
            let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

            meta.enable_constant(rc_b[0]);

            let poseidon = Pow5Chip::configure::<P128Pow5T3<Fr>>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            );

            let a = meta.advice_column();
            meta.enable_equality(a);

            let range =
                RangeConfig::configure(meta, RangeStrategy::Vertical, &[1], &[0], 1, 15, 0, K);

            Self::Config { a, range, poseidon }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let range = &config.range;
            let advice_column = config.a;

            let mut file = std::fs::File::open("fri-initial-proof.json").unwrap();
            let mut raw_contents = String::new();
            file.read_to_string(&mut raw_contents).unwrap();
            let proof: FriInitialTreeProof = serde_json::from_str(&raw_contents).unwrap();
            let proof_assigned =
                AssignedFriInitialTreeProof::assign(&mut layouter, advice_column, &proof)?;

            let mut file = std::fs::File::open("fri-precomputed.json").unwrap();
            let mut raw_contents = String::new();
            file.read_to_string(&mut raw_contents).unwrap();
            let precomputed_reduced_evals: PrecomputedReducedOpenings =
                serde_json::from_str(&raw_contents).unwrap();
            let precomputed_reduced_evals_assigned = AssignedPrecomputedReducedOpenings::assign(
                layouter.namespace(|| "assign precomputed reduced evals"),
                advice_column,
                &precomputed_reduced_evals,
            )?;

            let mut file = std::fs::File::open("fri-instance.json").unwrap();
            let mut raw_contents = String::new();
            file.read_to_string(&mut raw_contents).unwrap();
            let instance: FriInstanceInfo = serde_json::from_str(&raw_contents).unwrap();
            let instance_assigned = AssignedFriInstanceInfo::assign(
                layouter.namespace(|| "assign instance"),
                advice_column,
                &instance,
            )?;

            let alpha = GoldilocksExtension([
                serde_json::from_str("10996128681446358693").unwrap(),
                serde_json::from_str("6817592260154284178").unwrap(),
            ]);
            let alpha_assigned = AssignedGoldilocksExtension::assign(
                layouter.namespace(|| "assign alpha"),
                advice_column,
                alpha,
            )?;
            let subgroup_x: GoldilocksField = serde_json::from_str("123358979586301028").unwrap();
            let subgroup_x_assigned = AssignedGoldilocksField::assign(
                layouter.namespace(|| "subgroup_x"),
                advice_column,
                subgroup_x,
            )?;
            let sum = GoldilocksExtension([
                serde_json::from_str("17703852102747170808").unwrap(),
                serde_json::from_str("9208250178161818572").unwrap(),
            ]);

            let config = CircuitConfig::standard_recursion_config();
            let fri_config = config.fri_config;
            let degree_bits = 12;
            let params = fri_config.fri_params(degree_bits, false);
            let output_assigned = fri_combine_initial_assigned(
                layouter,
                range,
                advice_column,
                &instance_assigned,
                &proof_assigned,
                alpha_assigned,
                subgroup_x_assigned,
                &precomputed_reduced_evals_assigned,
                &params,
            )
            .unwrap();
            output_assigned[0]
                .value()
                .assert_if_known(|&&x| x == *sum[0]);
            output_assigned[1]
                .value()
                .assert_if_known(|&&x| x == *sum[1]);

            Ok(())
        }
    }

    #[test]
    fn test_fri_combine_initial_circuit() {
        let params = gen_srs(K as u32);

        let circuit = MyCircuit;
        MockProver::run(K as u32, &circuit, vec![])
            .unwrap()
            .assert_satisfied();
        let pk = gen_pk(&params, &circuit);
        let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![0]);
        let circuit_instances: Vec<Vec<Fr>> = vec![]; // circuit.instances()
        let proof = gen_proof(K, &params, &pk, circuit, circuit_instances.clone());
        evm_verify(deployment_code, circuit_instances, proof);
    }
}
