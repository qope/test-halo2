use std::{
    borrow::Borrow,
    cell::RefCell,
    ops::{Add, Mul, Neg, Sub},
};

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    halo2_proofs::{
        arithmetic::Field,
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        halo2curves::bn256::{Fr, G1Affine, G2Affine},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    },
    Context, ContextParams, QuantumCell,
};
use poseidon_circuit::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use rand::Rng;

use crate::{
    field::FrExtension,
    merkle_tree::{calc_merkle_root, usize_to_vec, MerkleTree},
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
pub struct ReducingFactor {
    base: FrExtension,
    count: u64,
}

impl ReducingFactor {
    pub fn new(base: FrExtension) -> Self {
        Self { base, count: 0 }
    }

    pub fn reduce(
        &mut self,
        iter: impl DoubleEndedIterator<Item = impl Borrow<FrExtension>>,
    ) -> FrExtension {
        iter.rev()
            .fold(FrExtension::zero(), |acc, x| self.mul(acc) + *x.borrow())
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
    pub point: FrExtension,
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

/// opened at that point.
#[derive(Clone, Debug)]
pub struct PrecomputedReducedOpenings {
    pub reduced_openings_at_point: Vec<FrExtension>,
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    siblings: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct FriInitialTreeProof {
    pub evals_proofs: Vec<(Vec<Fr>, MerkleProof)>,
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
    mut layouter: impl Layouter<Fr>,
    gate: FlexGateConfig<Fr>,
    // siblings: Vec<AssignedCell<Fr, Fr>>,
    // leaf_hash: AssignedCell<Fr, Fr>,
    // index: AssignedCell<Fr, Fr>,
    instance: &FriInstanceInfo,
    proof: &FriInitialTreeProof,
    alpha: FrExtension,
    subgroup_x: Fr,
    precomputed_reduced_evals: &PrecomputedReducedOpenings,
    params: &FriParams,
) {
    layouter.assign_region(
        || "bit decompose",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let subgroup_x = FrExtension::from(subgroup_x);
            let mut alpha = ReducingFactor::new(alpha);
            let mut sum = FrExtension::zero();

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
                    .map(FrExtension::from);
                let reduced_evals = alpha.reduce(evals);
                let numerator = reduced_evals - *reduced_openings;
                let denominator = subgroup_x - *point;
                sum = alpha.shift(sum);
                sum += numerator / denominator;
            }

            Ok(())
        },
    )?;
}
