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
use poseidon_circuit::poseidon::{primitives::P128Pow5T3, Pow5Chip, Pow5Config};

use crate::{
    field::{
        add_extension, div_extension, from_base_field, neg_extension, zero_assigned,
        AssignedGoldilocksExtension, AssignedGoldilocksField, GoldilocksExtension,
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
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let gate = config.gate;
        let a = config.a;

        todo!()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FriPolynomialInfo {
    /// Index into `FriInstanceInfo`'s `oracles` list.
    pub oracle_index: usize,
    /// Index of the polynomial within the oracle.
    pub polynomial_index: usize,
}

#[derive(Clone, Debug)]
pub struct FriBatchInfo {
    pub point: GoldilocksExtension,
    pub polynomials: Vec<FriPolynomialInfo>,
}

#[derive(Clone, Debug)]
pub struct AssignedFriBatchInfo {
    pub point: AssignedGoldilocksExtension,
    pub polynomials: Vec<FriPolynomialInfo>,
}

#[derive(Copy, Clone, Debug)]
pub struct FriOracleInfo {
    pub num_polys: usize,
    pub blinding: bool,
}

#[derive(Clone, Debug)]
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

/// opened at that point.
#[derive(Clone, Debug)]
pub struct PrecomputedReducedOpenings {
    pub reduced_openings_at_point: Vec<GoldilocksExtension>,
}

#[derive(Clone, Debug)]
pub struct AssignedPrecomputedReducedOpenings {
    pub reduced_openings_at_point: Vec<AssignedGoldilocksExtension>,
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub siblings: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct AssignedMerkleProof {
    pub siblings: Vec<AssignedGoldilocksField>,
}

#[derive(Clone, Debug)]
pub struct FriInitialTreeProof {
    pub evals_proofs: Vec<(Vec<Fr>, MerkleProof)>,
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
    pub(crate) fn unsalted_eval(&self, oracle_index: usize, poly_index: usize, salted: bool) -> Fr {
        self.unsalted_evals(oracle_index, salted)[poly_index]
    }

    fn unsalted_evals(&self, oracle_index: usize, salted: bool) -> &[Fr] {
        let evals = &self.evals_proofs[oracle_index].0;
        &evals[..evals.len() - salt_size(salted)]
    }
}

#[derive(Clone, Debug)]
pub struct AssignedFriInitialTreeProof {
    pub evals_proofs: Vec<(Vec<AssignedGoldilocksField>, AssignedMerkleProof)>,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FriReductionStrategy {
    /// Specifies the exact sequence of arities (expressed in bits) to use.
    Fixed(Vec<usize>),

    /// `ConstantArityBits(arity_bits, final_poly_bits)` applies reductions of arity `2^arity_bits`
    /// until the polynomial degree is less than or equal to `2^final_poly_bits` or until any further
    /// `arity_bits`-reduction makes the last FRI tree have height less than `cap_height`.
    /// This tends to work well in the recursive setting, as it avoids needing multiple configurations
    /// of gates used in FRI verification, such as `InterpolationGate`.
    ConstantArityBits(usize, usize),

    /// `MinSize(opt_max_arity_bits)` searches for an optimal sequence of reduction arities, with an
    /// optional max `arity_bits`. If this proof will have recursive proofs on top of it, a max
    /// `arity_bits` of 3 is recommended.
    MinSize(Option<usize>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FriConfig {
    /// `rate = 2^{-rate_bits}`.
    pub rate_bits: usize,

    /// Height of Merkle tree caps.
    pub cap_height: usize,

    pub proof_of_work_bits: u32,

    pub reduction_strategy: FriReductionStrategy,

    /// Number of query rounds to perform.
    pub num_query_rounds: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FriParams {
    /// User-specified FRI configuration.
    pub config: FriConfig,

    /// Whether to use a hiding variant of Merkle trees (where random salts are added to leaves).
    pub hiding: bool,

    /// The degree of the purported codeword, measured in bits.
    pub degree_bits: usize,

    /// The arity of each FRI reduction step, expressed as the log2 of the actual arity.
    /// For example, `[3, 2, 1]` would describe a FRI reduction tree with 8-to-1 reduction, then
    /// a 4-to-1 reduction, then a 2-to-1 reduction. After these reductions, the reduced polynomial
    /// is sent directly.
    pub reduction_arity_bits: Vec<usize>,
}

pub fn fri_combine_initial(
    instance: &FriInstanceInfo,
    proof: &FriInitialTreeProof,
    alpha: GoldilocksExtension,
    subgroup_x: Fr,
    precomputed_reduced_evals: &PrecomputedReducedOpenings,
    params: &FriParams,
) {
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
}

pub fn fri_combine_initial_assigned(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    advice_column: Column<Advice>,
    instance: &AssignedFriInstanceInfo,
    proof: &AssignedFriInitialTreeProof,
    alpha: AssignedGoldilocksExtension,
    subgroup_x: AssignedGoldilocksField,
    precomputed_reduced_evals: &AssignedPrecomputedReducedOpenings,
    params: &FriParams,
) -> Result<(), Error> {
    // layouter
    //     .assign_region(
    //         || "bit decompose",
    //         |region| {
    // let mut ctx = Context::new(
    //     region,
    //     ContextParams {
    //         max_rows: 1 << K,
    //         num_context_ids: 1,
    //         fixed_columns: gate.constants.clone(),
    //     },
    // );

    let zero = zero_assigned(layouter.namespace(|| "assign zero"), advice_column)?;
    let subgroup_x = AssignedGoldilocksExtension([subgroup_x.0, zero]);
    let mut alpha = AssignedReducingFactor::new(alpha);
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
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let reduced_evals = alpha.reduce(
            layouter.namespace(|| "reduce"),
            gate,
            range,
            advice_column,
            &evals,
        );
        let tmp = neg_extension(
            layouter.namespace(|| "neg1"),
            gate,
            range,
            reduced_openings.clone(),
        )
        .unwrap();
        let numerator = add_extension(
            layouter.namespace(|| "add1"),
            gate,
            range,
            reduced_evals,
            tmp,
        )
        .unwrap();
        let tmp = neg_extension(layouter.namespace(|| "neg2"), gate, range, point.clone()).unwrap();
        let denominator = add_extension(
            layouter.namespace(|| "add2"),
            gate,
            range,
            subgroup_x.clone(),
            tmp,
        )
        .unwrap();
        sum = alpha.shift(
            layouter.namespace(|| "shift alpha by sum"),
            gate,
            range,
            advice_column,
            sum,
        );
        let tmp = div_extension(
            layouter.namespace(|| "div"),
            gate,
            range,
            numerator,
            denominator,
        )
        .unwrap();
        sum = add_extension(layouter.namespace(|| "add"), gate, range, sum, tmp).unwrap();
    }

    //         Ok(())
    //     },
    // )
    // .unwrap();

    Ok(())
}
