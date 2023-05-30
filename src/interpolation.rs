use std::borrow::Borrow;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        range::RangeConfig,
    },
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
        halo2curves::{bn256::Fr, FieldExt},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    },
};
use plonky2::{
    field::{
        extension::{quadratic::QuadraticExtension, Extendable},
        goldilocks_field::GoldilocksField as GoldilocksFieldOriginal,
        interpolation::barycentric_weights,
        types::{Field, PrimeField},
    },
    fri::FriParams,
    hash::hash_types::RichField,
    util::{bits_u64, reverse_index_bits_in_place},
};
use poseidon_circuit::poseidon::{primitives::P128Pow5T3, Pow5Chip, Pow5Config};
use serde::{Deserialize, Serialize};

use crate::{
    field::{
        from_base_field, zero_assigned, AssignedGoldilocksExtension, AssignedGoldilocksField,
        GoldilocksExtension, GoldilocksExtensionChip, GoldilocksField, GoldilocksFieldChip,
    },
    reducing::{AssignedReducingFactor, ReducingFactor},
};

pub const MAX_QUOTIENT_DEGREE_FACTOR: usize = 8;

/// Computes P'(x^arity) from {P(x*g^i)}_(i=0..arity), where g is a `arity`-th root of unity
/// and P' is the FRI reduced polynomial.
pub fn compute_evaluation(
    mut layouter: impl Layouter<Fr>,
    range: &RangeConfig<Fr>,
    advice_column: Column<Advice>,
    x: AssignedGoldilocksField,
    x_index_within_coset_bits: &[AssignedCell<Fr, Fr>], // bool
    arity_bits: usize,
    evals: &[AssignedGoldilocksExtension],
    beta: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    let gf_chip = GoldilocksFieldChip::construct(range.clone());
    let ge_chip = GoldilocksExtensionChip::construct(range.clone());

    let arity = 1 << arity_bits;
    debug_assert_eq!(evals.len(), arity);

    let g = GoldilocksFieldOriginal::primitive_root_of_unity(arity_bits);
    let g_inv = g.exp_u64((arity as u64) - 1);

    // The evaluation vector needs to be reordered first.
    let mut evals = evals.to_vec();
    reverse_index_bits_in_place(&mut evals);
    // Want `g^(arity - rev_x_index_within_coset)` as in the out-of-circuit version. Compute it
    // as `(g^-1)^rev_x_index_within_coset`.
    let start = exp_from_bits_const_base_assigned(
        layouter.namespace(|| "exp"),
        advice_column,
        &gf_chip,
        g_inv,
        x_index_within_coset_bits.iter().rev(),
    ).unwrap();
    let coset_start = gf_chip.mul(layouter.namespace(|| "mul"), start, x).unwrap();

    // The answer is gotten by interpolating {(x*g^i, P(x*g^i))} and evaluating at beta.
    // let interpolation_gate = <CosetInterpolationGate<F, D>>::with_max_degree(
    //     arity_bits,
    //     self.config.max_quotient_degree_factor,
    // );

    let coset_interpolation_chip =
        CosetInterpolationChip::with_max_degree(ge_chip, arity_bits, MAX_QUOTIENT_DEGREE_FACTOR);
    coset_interpolation_chip.interpolate_coset(
        layouter.namespace(|| "interpolate coset assigned"),
        advice_column,
        coset_start,
        &evals,
        beta,
    )
}

pub fn exp_from_bits_const_base_assigned(
    mut layouter: impl Layouter<Fr>,
    advice_column: Column<Advice>,
    ge_chip: &GoldilocksFieldChip<Fr>,
    base: GoldilocksFieldOriginal,
    exponent_bits: impl IntoIterator<Item = impl Borrow<AssignedCell<Fr, Fr>>>, // &[bool]
) -> Result<AssignedGoldilocksField, Error> {
    let exponent_bits: Vec<_> = exponent_bits
        .into_iter()
        .map(|b| b.borrow().clone())
        .collect();

    let mut product = AssignedGoldilocksField::constant(
        layouter.namespace(|| "assign one"),
        advice_column,
        Fr::one().into(),
    ).unwrap();
    for (i, bit) in exponent_bits.iter().enumerate() {
        let pow = 1 << i;
        // If the bit is on, we multiply product by base^pow.
        // We can arithmetize this as:
        //     product *= 1 + bit (base^pow - 1)
        //     product = (base^pow - 1) product bit + product
        product = ge_chip.arithmetic(
            layouter.namespace(|| "arithmetic"),
            advice_column,
            (base.exp_u64(pow as u64) - GoldilocksFieldOriginal::ONE).into(),
            GoldilocksFieldOriginal::ONE.into(),
            product.clone(),
            bit.clone().into(),
            product,
        ).unwrap();
    }

    Ok(product)
}

#[derive(Clone, Debug)]
pub struct CosetInterpolationChip {
    pub ge_chip: GoldilocksExtensionChip<Fr>,
    pub subgroup_bits: usize,
    pub degree: usize,
    pub barycentric_weights: Vec<GoldilocksField>,
}

impl CosetInterpolationChip {
    pub fn new(ge_chip: GoldilocksExtensionChip<Fr>, subgroup_bits: usize) -> Self {
        Self::with_max_degree(ge_chip, subgroup_bits, 1 << subgroup_bits)
    }

    pub(crate) fn with_max_degree(
        ge_chip: GoldilocksExtensionChip<Fr>,
        subgroup_bits: usize,
        max_degree: usize,
    ) -> Self {
        assert!(max_degree > 1, "need at least quadratic constraints");

        let n_points = 1 << subgroup_bits;

        // Number of intermediate values required to compute interpolation with degree bound
        let n_intermediates = (n_points - 2) / (max_degree - 1);

        // Find minimum degree such that (n_points - 2) / (degree - 1) < n_intermediates + 1
        // Minimizing the degree this way allows the gate to be in a larger selector group
        let degree = (n_points - 2) / (n_intermediates + 1) + 2;

        let barycentric_weights = barycentric_weights(
            &GoldilocksFieldOriginal::two_adic_subgroup(subgroup_bits)
                .into_iter()
                .map(|x| (x, GoldilocksFieldOriginal::ZERO))
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .map(|v| v.into())
        .collect::<Vec<GoldilocksField>>();

        Self {
            ge_chip,
            subgroup_bits,
            degree,
            barycentric_weights,
        }
    }

    pub fn construct(
        ge_chip: GoldilocksExtensionChip<Fr>,
        subgroup_bits: usize,
        degree: usize,
        barycentric_weights: Vec<GoldilocksField>,
    ) -> Self {
        Self {
            ge_chip,
            subgroup_bits,
            degree,
            barycentric_weights,
        }
    }

    fn degree(&self) -> usize {
        self.degree
    }

    fn num_points(&self) -> usize {
        1 << self.subgroup_bits
    }

    fn num_intermediates(&self) -> usize {
        (self.num_points() - 2) / (self.degree() - 1)
    }

    fn interpolate_coset(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        shift: AssignedGoldilocksField,
        values: &[AssignedGoldilocksExtension],
        evaluation_point: AssignedGoldilocksExtension,
        // shifted_evaluation_point: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let gf_chip = GoldilocksFieldChip::construct(self.ge_chip.range.clone());

        let degree = self.degree();
        let num_points = self.num_points();
        let subgroup_bits = self.subgroup_bits;
        let barycentric_weights = &self.barycentric_weights;
        // evaluation_point == shifted_evaluation_point * shift
        let inv_shift = gf_chip.inv(layouter.namespace(|| ""), advice_column, shift).unwrap();
        let shifted_evaluation_point = self.ge_chip.scalar_mul(
            layouter.namespace(|| "scalar mul"),
            advice_column,
            inv_shift.0,
            evaluation_point,
        ).unwrap();

        let domain = GoldilocksFieldOriginal::two_adic_subgroup(subgroup_bits);
        let weights = barycentric_weights;

        let initial_eval = AssignedGoldilocksExtension::constant(
            layouter.namespace(|| "assign zero"),
            advice_column,
            GoldilocksExtension::zero(),
        ).unwrap();
        let initial_partial_prod = AssignedGoldilocksExtension::constant(
            layouter.namespace(|| "assign one"),
            advice_column,
            GoldilocksExtension::one(),
        ).unwrap();
        let (mut computed_eval, mut computed_prod) = partial_interpolate(
            layouter.namespace(|| "partial interpolate"),
            &self.ge_chip,
            advice_column,
            &domain[..degree],
            &values[..degree],
            &weights[..degree],
            shifted_evaluation_point.clone(),
            initial_eval,
            initial_partial_prod,
        ).unwrap();

        for i in 0..self.num_intermediates() {
            let start_index = 1 + (degree - 1) * (i + 1);
            let end_index = (start_index + degree - 1).min(num_points);
            (computed_eval, computed_prod) = partial_interpolate(
                layouter.namespace(|| "partial interpolate"),
                &self.ge_chip,
                advice_column,
                &domain[start_index..end_index],
                &values[start_index..end_index],
                &weights[start_index..end_index],
                shifted_evaluation_point.clone(),
                computed_eval,
                computed_prod,
            ).unwrap();
        }

        Ok(computed_eval)
    }
}

/// Perform a partial interpolation of the polynomial defined by its values on an arbitrary domain.
///
/// The Barycentric algorithm to interpolate a polynomial at a given point `x` is a linear pass
/// over the sequence of domain points, values, and Barycentric weights which maintains two
/// accumulated values, a partial evaluation and a partial product. This partially updates the
/// accumulated values, so that starting with an initial evaluation of 0 and a partial evaluation
/// of 1 and running over the whole domain is a full interpolation.
fn partial_interpolate(
    mut layouter: impl Layouter<Fr>,
    ge_chip: &GoldilocksExtensionChip<Fr>,
    advice_column: Column<Advice>,
    domain: &[GoldilocksFieldOriginal],
    values: &[AssignedGoldilocksExtension],
    barycentric_weights: &[GoldilocksField],
    x: AssignedGoldilocksExtension,
    initial_eval: AssignedGoldilocksExtension,
    initial_partial_prod: AssignedGoldilocksExtension,
) -> Result<(AssignedGoldilocksExtension, AssignedGoldilocksExtension), Error> {
    let n = domain.len();
    assert_ne!(n, 0);
    assert_eq!(n, values.len());
    assert_eq!(n, barycentric_weights.len());

    let weighted_values = values
        .iter()
        .zip(barycentric_weights.iter())
        .map(|(value, &weight)| {
            ge_chip.constant_scalar_mul(layouter.namespace(|| "scalar mul"), weight, value.clone())
        })
        .collect::<Result<Vec<_>, _>>().unwrap();

    weighted_values.iter().zip(domain.iter()).fold(
        Ok((initial_eval, initial_partial_prod)),
        |acc, (val, &x_i)| {
            let (eval, terms_partial_prod) = acc?;
            let x_i_assigned = AssignedGoldilocksField::assign(
                layouter.namespace(|| "assign x_i"),
                advice_column,
                x_i.into(),
            )?;
            let x_i_assigned = from_base_field(
                layouter.namespace(|| "from base field"),
                advice_column,
                (*x_i_assigned).clone(),
            )?;
            let term = ge_chip.sub(layouter.namespace(|| "add"), x.clone(), x_i_assigned)?;
            let tmp1 = ge_chip.mul(layouter.namespace(|| "mul"), eval, term.clone())?;
            let tmp2 = ge_chip.mul(
                layouter.namespace(|| "mul"),
                val.clone(),
                terms_partial_prod.clone(),
            )?;
            let next_eval = ge_chip.add(layouter.namespace(|| "mul"), tmp1, tmp2)?;
            let next_terms_partial_prod =
                ge_chip.mul(layouter.namespace(|| "mul"), terms_partial_prod, term)?;

            Ok((next_eval, next_terms_partial_prod))
        },
    )
}

// fn interpolate_coset_assigned(
//     mut layouter: impl Layouter<Fr>,
//     range: &RangeConfig<Fr>,
//     advice_column: Column<Advice>,
//     // vars: EvaluationTargets<D>,
//     shift: AssignedGoldilocksField,
//     values: &[AssignedGoldilocksExtension],
//     evaluation_point: AssignedGoldilocksExtension,
// ) -> Vec<AssignedGoldilocksExtension> {
//     let degree = self.degree();
//     let num_points = self.num_points();
//     let mut constraints = vec![];

//     let shifted_evaluation_point =
//         vars.get_local_ext_algebra(self.wires_shifted_evaluation_point());

//     let neg_one = -Fr::one();
//     let neg_shift =
//         constant_scalar_mul_extension(layouter.namespace(|| "scalar mul"), range, neg_one, shift);
//     let tmp = constant_scalar_mul_extension(
//         layouter.namespace(|| "scalar mul"),
//         range,
//         neg_shift,
//         shifted_evaluation_point,
//     );
//     let tmp = add_extension(layouter.namespace(|| "add"), range, tmp, evaluation_point);
//     tmp.connect(
//         layouter,
//         AssignedGoldilocksExtension::constant(layouter, advice_column, GoldilocksExtension::zero()),
//     );
//     // constraints.extend(
//     //     scalar_mul_add_ext_algebra(neg_shift, shifted_evaluation_point, evaluation_point)
//     //         .to_ext_target_array(),
//     // );

//     let domain = F::two_adic_subgroup(self.subgroup_bits);
//     let weights = &self.barycentric_weights;

//     let initial_eval = builder.zero_ext_algebra();
//     let initial_prod = builder.constant_ext_algebra(GoldilocksExtension::one().into());
//     let (mut computed_eval, mut computed_prod) = partial_interpolate_ext_algebra_target(
//         builder,
//         &domain[..degree],
//         &values[..degree],
//         &weights[..degree],
//         shifted_evaluation_point,
//         initial_eval,
//         initial_prod,
//     );

//     for i in 0..self.num_intermediates() {
//         let intermediate_eval = vars.get_local_ext_algebra(self.wires_intermediate_eval(i));
//         let intermediate_prod = vars.get_local_ext_algebra(self.wires_intermediate_prod(i));
//         constraints.extend(
//             builder
//                 .sub_ext_algebra(intermediate_eval, computed_eval)
//                 .to_ext_target_array(),
//         );
//         constraints.extend(
//             builder
//                 .sub_ext_algebra(intermediate_prod, computed_prod)
//                 .to_ext_target_array(),
//         );

//         let start_index = 1 + (degree - 1) * (i + 1);
//         let end_index = (start_index + degree - 1).min(num_points);
//         (computed_eval, computed_prod) = partial_interpolate_ext_algebra_target(
//             builder,
//             &domain[start_index..end_index],
//             &values[start_index..end_index],
//             &weights[start_index..end_index],
//             shifted_evaluation_point,
//             intermediate_eval,
//             intermediate_prod,
//         );
//     }

//     // let evaluation_value = vars.get_local_ext_algebra(self.wires_evaluation_value());
//     // constraints.extend(
//     //     builder
//     //         .sub_ext_algebra(evaluation_value, computed_eval)
//     //         .to_ext_target_array(),
//     // );

//     computed_eval
// }

// pub fn interpolate_coset_assigned(
//     gate: CosetInterpolationGate<F, D>, // TODO
//     coset_shift: AssignedGoldilocksField,
//     values: &[AssignedGoldilocksExtension],
//     evaluation_point: AssignedGoldilocksExtension,
// ) -> AssignedGoldilocksExtension {
//     let row = self.num_gates();
//     self.connect(
//         coset_shift,
//         AssignedGoldilocksField::wire(row, gate.wire_shift()),
//     );
//     for (i, &v) in values.iter().enumerate() {
//         self.connect_extension(v, ExtensionTarget::from_range(row, gate.wires_value(i)));
//     }
//     self.connect_extension(
//         evaluation_point,
//         ExtensionTarget::from_range(row, gate.wires_evaluation_point()),
//     );

//     let eval = ExtensionTarget::from_range(row, gate.wires_evaluation_value());
//     self.add_gate(gate, vec![]);

//     eval
// }

/// Interpolate the polynomial defined by an arbitrary set of (point, value) pairs at the given
/// point `x`.
pub fn interpolate<F: Field>(points: &[(F, F)], x: F, barycentric_weights: &[F]) -> F {
    // If x is in the list of points, the Lagrange formula would divide by zero.
    for &(x_i, y_i) in points {
        if x_i == x {
            return y_i;
        }
    }

    let l_x: F = points.iter().map(|&(x_i, _y_i)| x - x_i).product();

    let sum = (0..points.len())
        .map(|i| {
            let x_i = points[i].0;
            let y_i = points[i].1;
            let w_i = barycentric_weights[i];
            w_i / (x - x_i) * y_i
        })
        .sum();

    l_x * sum
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
    use plonky2::{fri::verifier::ComputeEvaluationData, plonk::circuit_data::CircuitConfig};

    use crate::utils::{evm_verify, gen_evm_verifier, gen_pk, gen_proof, gen_srs};

    use super::*;

    const K: usize = 18;

    fn to_bits_le(mut value: usize) -> Vec<bool> {
        let mut result = vec![];
        while value != 0 {
            result.push(value & 1 == 1);
            value >>= 1;
        }

        result
    }

    #[test]
    fn test_to_bits_le() {
        assert_eq!(to_bits_le(6), [false, true, true]);
    }

    #[derive(Clone)]
    pub struct MyConfig {
        a: Column<Advice>,
        range: RangeConfig<Fr>,
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
            let a = meta.advice_column();
            meta.enable_equality(a);

            let range =
                RangeConfig::configure(meta, RangeStrategy::Vertical, &[1], &[0], 1, 15, 0, K);

            Self::Config { a, range }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let range = &config.range;
            let advice_column = config.a;

            let mut file = std::fs::File::open("fri_compute_evaluation_0.json").unwrap();
            let mut raw_contents = String::new();
            file.read_to_string(&mut raw_contents).unwrap();
            let evaluation_data: ComputeEvaluationData<GoldilocksFieldOriginal, 2> =
                serde_json::from_str(&raw_contents).unwrap();
            let x_assigned = AssignedGoldilocksField::assign(
                layouter.namespace(|| "assign x"),
                advice_column,
                evaluation_data.x.into(),
            ).unwrap();
            let x_index_within_coset_bits = to_bits_le(evaluation_data.x_index_within_coset);
            let x_index_within_coset_assigned = x_index_within_coset_bits
                .into_iter()
                .map(|bit| {
                    Ok(AssignedGoldilocksField::assign(
                        layouter.namespace(|| "assign x_index_within_coset"),
                        advice_column,
                        GoldilocksFieldOriginal::from_canonical_u64(bit as u64).into(),
                    )?.0)
                })
                .collect::<Result<Vec<_>, Error>>().unwrap();
            let evals_assigned = evaluation_data
                .evals
                .into_iter()
                .map(|eval| {
                    AssignedGoldilocksExtension::assign(
                        layouter.namespace(|| "assign evals"),
                        advice_column,
                        eval.0.map(GoldilocksField::from).into(),
                    )
                })
                .collect::<Result<Vec<_>, _>>().unwrap();
            let beta_assigned = AssignedGoldilocksExtension::assign(
                layouter.namespace(|| "assign beta"),
                advice_column,
                evaluation_data.beta.0.map(GoldilocksField::from).into(),
            ).unwrap();
            let next_eval: GoldilocksExtension = evaluation_data.next_eval.0.map(GoldilocksField::from).into();

            let output_assigned = compute_evaluation(
                layouter.namespace(|| "compute evaluation"),
                range,
                advice_column,
                x_assigned,
                &x_index_within_coset_assigned,
                evaluation_data.arity_bits,
                &evals_assigned,
                beta_assigned,
            )
            .unwrap();

            // assertion error:
            // 0x000000000000000000000000000000000000000000000000f045f89ce839fa5d
            // 0x0000000000000000000000000000000000000000000000008019383a50d011ef
            output_assigned[0]
                .value()
                .assert_if_known(|&&x| dbg!(x) == dbg!(*next_eval[0]));
            output_assigned[1]
                .value()
                .assert_if_known(|&&x| dbg!(x) == dbg!(*next_eval[1]));

            Ok(())
        }
    }

    #[test]
    fn test_fri_compute_evaluation_circuit() {
        let circuit = MyCircuit;
        MockProver::run(K as u32, &circuit, vec![])
            .unwrap()
            .assert_satisfied();
        // let params = gen_srs(K as u32);
        // let pk = gen_pk(&params, &circuit);
        // let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![0]);
        // let circuit_instances: Vec<Vec<Fr>> = vec![]; // circuit.instances()
        // let proof = gen_proof(K, &params, &pk, circuit, circuit_instances.clone());
        // evm_verify(deployment_code, circuit_instances, proof);
    }
}
