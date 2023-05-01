use std::{
    cell::RefCell,
    ops::{Deref, Div},
};

use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        halo2curves::bn256::Fr,
        plonk::{Advice, Column, Error},
    },
    AssignedValue, Context, ContextParams, QuantumCell,
};
use num_bigint::BigUint;

use crate::utils::assign_val;

const GOLDILOCKS_FIELD_ORDER: u64 = 18446744069414584321;

#[derive(Copy, Clone, Debug)]
pub struct GoldilocksField(pub Fr);

#[derive(Copy, Clone, Debug)]
pub struct GoldilocksExtension(pub [Fr; 2]);

#[derive(Clone, Debug)]
pub struct AssignedGoldilocksExtension(pub [AssignedCell<Fr, Fr>; 2]);

impl Deref for AssignedGoldilocksExtension {
    type Target = [AssignedCell<Fr, Fr>; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Fr> for GoldilocksExtension {
    fn from(value: Fr) -> Self {
        Self([value, Fr::zero()])
    }
}

impl GoldilocksExtension {
    pub fn zero() -> Self {
        Self([Fr::zero(); 2])
    }
}

// impl AssignedGoldilocksExtension {
//     pub fn zero(&mut ctx: , a, ) -> Self {
//         let zero = Fr::zero();
//         let tmp_index =
//                 gate.load_witness(&mut ctx, zero.value().and_then(|v| Value::known(*v)));
//         // assign_val(ctx.namespace(|| "left"), a, zero).unwrap();

//         Self([AssignedCell<Fr, Fr>::zero(); 2])
//     }
// }

pub fn zero(
    mut layouter: impl Layouter<Fr>,
    advice_column: Column<Advice>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let zero_cell = assign_val(
        layouter.namespace(|| "index assign"),
        advice_column,
        Fr::from(0),
    )?;

    Ok(zero_cell)
}

pub fn from_base_field(
    mut layouter: impl Layouter<Fr>,
    advice_column: Column<Advice>,
    value: AssignedCell<Fr, Fr>,
) -> Result<AssignedGoldilocksExtension, Error> {
    let zero = zero(layouter.namespace(|| "assign zero"), advice_column)?;

    Ok(AssignedGoldilocksExtension([value, zero]))
}

const K: usize = 18;

/// Constrain `output = a + b`.
pub fn add_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    a: AssignedGoldilocksExtension,
    b: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    let a_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let b_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let output0_assigned = RefCell::new(None);
    let output1_assigned = RefCell::new(None);

    layouter.assign_region(
        || "assign a and b",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let a0 = gate.load_witness(&mut ctx, a[0].value().and_then(|v| Value::known(*v)));
            let a1 = gate.load_witness(&mut ctx, a[1].value().and_then(|v| Value::known(*v)));
            *a_assigned.borrow_mut() = Some([a0, a1]);

            let b0 = gate.load_witness(&mut ctx, b[0].value().and_then(|v| Value::known(*v)));
            let b1 = gate.load_witness(&mut ctx, b[1].value().and_then(|v| Value::known(*v)));
            *b_assigned.borrow_mut() = Some([b0, b1]);

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "copy a and b",
        |mut region| {
            region.constrain_equal(
                a_assigned.clone().into_inner().unwrap()[0].cell(),
                a[0].cell(),
            )?;
            region.constrain_equal(
                a_assigned.clone().into_inner().unwrap()[1].cell(),
                a[1].cell(),
            )?;
            region.constrain_equal(
                b_assigned.clone().into_inner().unwrap()[0].cell(),
                b[0].cell(),
            )?;
            region.constrain_equal(
                b_assigned.clone().into_inner().unwrap()[1].cell(),
                b[1].cell(),
            )?;

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "assign zero extension",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let a = a_assigned.borrow().clone().unwrap().clone();
            let b = b_assigned.borrow().clone().unwrap().clone();
            let a0 = QuantumCell::Existing(&a[0]);
            let a1 = QuantumCell::Existing(&a[1]);
            let b0 = QuantumCell::Existing(&b[0]);
            let b1 = QuantumCell::Existing(&b[1]);

            // output0 = a0 + b0
            let output0 = gate.add(&mut ctx, a0, b0);
            let output0 = AssignedCell::new(output0.value, output0.cell);
            *output0_assigned.borrow_mut() = Some(output0);

            // output1 = a1 + b1
            let output1 = gate.add(&mut ctx, a1, b1);
            let output1 = AssignedCell::new(output1.value, output1.cell);
            *output1_assigned.borrow_mut() = Some(output1);

            Ok(())
        },
    )?;

    let output0 = mod_by_goldilocks_order(
        layouter.namespace(|| "output0 mod order"),
        gate,
        range,
        output0_assigned.into_inner().unwrap(),
    )
    .unwrap();

    let output1 = mod_by_goldilocks_order(
        layouter.namespace(|| "output1 mod order"),
        gate,
        range,
        output1_assigned.into_inner().unwrap(),
    )
    .unwrap();

    Ok(AssignedGoldilocksExtension([output0, output1]))
}

/// Constrain `output = a * b`.
pub fn mul_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    a: AssignedGoldilocksExtension,
    b: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    let a_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let b_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let output0_assigned = RefCell::new(None);
    let output1_assigned = RefCell::new(None);

    layouter.assign_region(
        || "assign a and b",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let a0 = gate.load_witness(&mut ctx, a[0].value().and_then(|v| Value::known(*v)));
            let a1 = gate.load_witness(&mut ctx, a[1].value().and_then(|v| Value::known(*v)));
            *a_assigned.borrow_mut() = Some([a0, a1]);

            let b0 = gate.load_witness(&mut ctx, b[0].value().and_then(|v| Value::known(*v)));
            let b1 = gate.load_witness(&mut ctx, b[1].value().and_then(|v| Value::known(*v)));
            *b_assigned.borrow_mut() = Some([b0, b1]);

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "copy a and b",
        |mut region| {
            region.constrain_equal(
                a_assigned.clone().into_inner().unwrap()[0].cell(),
                a[0].cell(),
            )?;
            region.constrain_equal(
                a_assigned.clone().into_inner().unwrap()[1].cell(),
                a[1].cell(),
            )?;
            region.constrain_equal(
                b_assigned.clone().into_inner().unwrap()[0].cell(),
                b[0].cell(),
            )?;
            region.constrain_equal(
                b_assigned.clone().into_inner().unwrap()[1].cell(),
                b[1].cell(),
            )?;

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "assign zero extension",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let a = a_assigned.borrow().clone().unwrap().clone();
            let b = b_assigned.borrow().clone().unwrap().clone();
            let a0 = QuantumCell::Existing(&a[0]);
            let a1 = QuantumCell::Existing(&a[1]);
            let b0 = QuantumCell::Existing(&b[0]);
            let b1 = QuantumCell::Existing(&b[1]);

            // output0 = a0 * b0 + W * a1 * b1
            let w = Fr::from(7);
            let w_assigned = gate.load_witness(&mut ctx, Value::known(w));
            let tmp0 = gate.mul(&mut ctx, a0.clone(), b0.clone());
            let tmp1 = gate.mul(&mut ctx, a1.clone(), b1.clone());
            let tmp2 = gate.mul(
                &mut ctx,
                QuantumCell::Existing(&tmp1),
                QuantumCell::Existing(&w_assigned),
            );
            let output0 = gate.add(
                &mut ctx,
                QuantumCell::Existing(&tmp0),
                QuantumCell::Existing(&tmp2),
            );
            let output0 = AssignedCell::new(output0.value, output0.cell);
            *output0_assigned.borrow_mut() = Some(output0);

            // output1 = a0 * b1 + a1 * b0
            let tmp0 = gate.mul(&mut ctx, a0, b1);
            let tmp1 = gate.mul(&mut ctx, a1, b0);
            let output1 = gate.add(
                &mut ctx,
                QuantumCell::Existing(&tmp0),
                QuantumCell::Existing(&tmp1),
            );
            let output1 = AssignedCell::new(output1.value, output1.cell);
            *output1_assigned.borrow_mut() = Some(output1);

            Ok(())
        },
    )?;

    let output0 = mod_by_goldilocks_order(
        layouter.namespace(|| "output0 mod order"),
        gate,
        range,
        output0_assigned.into_inner().unwrap(),
    )
    .unwrap();

    let output1 = mod_by_goldilocks_order(
        layouter.namespace(|| "output0 mod order"),
        gate,
        range,
        output1_assigned.into_inner().unwrap(),
    )
    .unwrap();

    // let output0_cell = AssignedCell::new(output_assigned[0].value, output_assigned[0].cell);
    // let output1_cell = AssignedCell::new(output_assigned[1].value, output_assigned[1].cell);

    Ok(AssignedGoldilocksExtension([output0, output1]))
}

/// Constrain `output = a * scalar`.
pub fn constant_scalar_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    scalar: Fr,
    value: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    let value_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let output0_assigned = RefCell::new(None);
    let output1_assigned = RefCell::new(None);

    layouter.assign_region(
        || "assign value",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let value0 =
                gate.load_witness(&mut ctx, value[0].value().and_then(|v| Value::known(*v)));
            let value1 =
                gate.load_witness(&mut ctx, value[1].value().and_then(|v| Value::known(*v)));
            *value_assigned.borrow_mut() = Some([value0, value1]);

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "copy value",
        |mut region| {
            region.constrain_equal(
                value_assigned.clone().into_inner().unwrap()[0].cell(),
                value[0].cell(),
            )?;
            region.constrain_equal(
                value_assigned.clone().into_inner().unwrap()[1].cell(),
                value[1].cell(),
            )?;

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "assign zero extension",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let scalar_assigned = gate.load_witness(&mut ctx, Value::known(scalar));
            let a = value_assigned.borrow().clone().unwrap().clone();

            // output0 = a0 * scalar
            let output0 = gate.mul(
                &mut ctx,
                QuantumCell::Existing(&a[0]),
                QuantumCell::Existing(&scalar_assigned),
            );
            let output0 = AssignedCell::new(output0.value, output0.cell);
            *output0_assigned.borrow_mut() = Some(output0);

            // output0 = a1 * scalar
            let output1 = gate.mul(
                &mut ctx,
                QuantumCell::Existing(&a[1]),
                QuantumCell::Existing(&scalar_assigned),
            );
            let output1 = AssignedCell::new(output1.value, output1.cell);
            *output1_assigned.borrow_mut() = Some(output1);

            Ok(())
        },
    )?;

    let output0 = mod_by_goldilocks_order(
        layouter.namespace(|| "output0 mod order"),
        gate,
        range,
        output0_assigned.into_inner().unwrap(),
    )
    .unwrap();

    let output1 = mod_by_goldilocks_order(
        layouter.namespace(|| "output1 mod order"),
        gate,
        range,
        output1_assigned.into_inner().unwrap(),
    )
    .unwrap();

    Ok(AssignedGoldilocksExtension([output0, output1]))
}

pub fn scalar_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    advice_column: Column<Advice>,
    scalar: AssignedCell<Fr, Fr>,
    value: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    let zero = zero(layouter.namespace(|| "assign zero"), advice_column).unwrap();
    let b = AssignedGoldilocksExtension([scalar, zero]);

    mul_extension(layouter, gate, range, value, b)
}

/// Constrain `output = constant0 * multiplicand0 * multiplicand1 + constant1 * addend`.
#[allow(clippy::too_many_arguments)]
pub fn arithmetic_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    constant0: Fr,
    constant1: Fr,
    multiplicand0: AssignedGoldilocksExtension,
    multiplicand1: AssignedGoldilocksExtension,
    addend: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    let tmp0 = mul_extension(
        layouter.namespace(|| "multiplication"),
        gate,
        range,
        multiplicand0,
        multiplicand1,
    )?;
    let tmp0 = constant_scalar_extension(
        layouter.namespace(|| "first term"),
        gate,
        range,
        constant0,
        tmp0,
    )?;
    let tmp1 = constant_scalar_extension(
        layouter.namespace(|| "second term"),
        gate,
        range,
        constant1,
        addend,
    )?;

    add_extension(layouter, gate, range, tmp0, tmp1)
}

/// Constrain `output = a % GOLDILOCKS_FIELD_ORDER`.
pub fn mod_by_goldilocks_order(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    a: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let a_assigned = RefCell::new(None);
    let output_assigned = RefCell::new(None);

    layouter.assign_region(
        || "copy modulo",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let a = gate.load_witness(&mut ctx, a.value().and_then(|v| Value::known(*v)));
            *a_assigned.borrow_mut() = Some(a);

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "copy a",
        |mut region| {
            region.constrain_equal(a_assigned.clone().into_inner().unwrap().cell(), a.cell())?;

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "copy modulo",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            // output = a % order
            let order = Fr::from(GOLDILOCKS_FIELD_ORDER); // the order of Goldilocks field
            let order_assigned = gate.load_witness(&mut ctx, Value::known(order));

            // q = a - a % order
            let q = a.value().and_then(|a| {
                let a_bi = BigUint::from_bytes_le(&a.to_bytes());
                let order_bi = BigUint::from_bytes_le(&order.to_bytes());
                let q_bi = a_bi.div(order_bi);
                let mut q_bi_bytes = q_bi.to_bytes_le();
                q_bi_bytes.resize(32, 0);
                let q = Fr::from_bytes(&q_bi_bytes.try_into().unwrap()).unwrap();

                Value::known(q)
            });
            let q_assigned = gate.load_witness(&mut ctx, q);

            // a = output + q * order
            let tmp = gate.mul(
                &mut ctx,
                QuantumCell::Existing(&q_assigned),
                QuantumCell::Existing(&order_assigned),
            );
            let output = gate.sub(
                &mut ctx,
                QuantumCell::Existing(&a_assigned.clone().into_inner().unwrap()),
                QuantumCell::Existing(&tmp),
            );

            // Divide the constraint `0 <= output < order` into two parts.

            // (1) 0 <= output < 2^64
            range.range_check(&mut ctx, &output, 64);

            // (2) 0 <= order - 1 - output < 2^64
            let one_assigned = gate.load_witness(&mut ctx, Value::known(Fr::one()));
            let order_minus_one_assigned = gate.sub(
                &mut ctx,
                QuantumCell::Existing(&order_assigned),
                QuantumCell::Existing(&one_assigned),
            );
            let tmp = gate.sub(
                &mut ctx,
                QuantumCell::Existing(&order_minus_one_assigned),
                QuantumCell::Existing(&output),
            );
            range.range_check(&mut ctx, &tmp, 64);

            *output_assigned.borrow_mut() = Some(output);

            Ok(())
        },
    )?;

    let output_assigned = output_assigned.into_inner().unwrap();
    let output_cell = AssignedCell::new(output_assigned.value, output_assigned.cell);

    Ok(output_cell)
}

#[cfg(test)]
mod tests {
    use halo2_base::{
        gates::range::RangeStrategy,
        halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit},
    };

    use super::*;

    #[derive(Clone)]
    pub struct MyConfig {
        a: Column<Advice>,
        range: RangeConfig<Fr>,
    }

    #[derive(Default)]
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

            // let gate = FlexGateConfig::configure(meta, GateStrategy::Vertical, &[1], 1, 0, K);
            let range =
                RangeConfig::configure(meta, RangeStrategy::Vertical, &[5], &[6], 1, 15, 0, K);

            Self::Config { a, range }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let range = &config.range;
            let gate = range.gate();
            let a = config.a;

            let value00 = Fr::from(1);
            let value01 = Fr::from(2);
            let value10 = Fr::from(3);
            let value11 = Fr::from(4);
            let output0 = Fr::from(181);
            let output1 = Fr::from(38);

            let value00_assigned =
                assign_val(layouter.namespace(|| "value00"), a, value00).unwrap();
            let value01_assigned =
                assign_val(layouter.namespace(|| "value01"), a, value01).unwrap();
            let value10_assigned =
                assign_val(layouter.namespace(|| "value10"), a, value10).unwrap();
            let value11_assigned =
                assign_val(layouter.namespace(|| "value11"), a, value11).unwrap();
            let value0 = AssignedGoldilocksExtension([value00_assigned, value01_assigned]);
            let value1 = AssignedGoldilocksExtension([value10_assigned, value11_assigned]);

            // [181, 38] = 3 * [1, 2] * [3, 4] + 4 * [1, 2] = 3 * [59, 10] + [4, 8] = [177, 30] + [4, 8]
            let output_assigned = arithmetic_extension(
                layouter,
                gate,
                range,
                value10,
                value11,
                value0.clone(),
                value1,
                value0,
            )
            .unwrap();
            dbg!(&output_assigned);
            output_assigned[0]
                .value()
                .assert_if_known(|&&x| x == output0);
            output_assigned[1]
                .value()
                .assert_if_known(|&&x| x == output1);

            Ok(())
        }
    }

    #[test]
    fn test_add_circuit() {
        let circuit = MyCircuit;
        MockProver::run(K as u32, &circuit, vec![])
            .unwrap()
            .assert_satisfied();
    }
}

// impl<'a> Neg for &'a GoldilocksExtension {
//     type Output = GoldilocksExtension;

//     #[inline]
//     fn neg(self) -> GoldilocksExtension {
//         self.neg()
//     }
// }

// impl Neg for GoldilocksExtension {
//     type Output = GoldilocksExtension;

//     #[inline]
//     fn neg(self) -> GoldilocksExtension {
//         -&self
//     }
// }

// impl<'a, 'b> Sub<&'b GoldilocksExtension> for &'a GoldilocksExtension {
//     type Output = GoldilocksExtension;

//     #[inline]
//     fn sub(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
//         self.sub(rhs)
//     }
// }

// impl<'a, 'b> Add<&'b GoldilocksExtension> for &'a GoldilocksExtension {
//     type Output = GoldilocksExtension;

//     #[inline]
//     fn add(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
//         self.add(rhs)
//     }
// }

// impl<'a, 'b> Mul<&'b GoldilocksExtension> for GoldilocksExtension {
//     type Output = GoldilocksExtension;

//     #[inline]
//     fn mul(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
//         self.mul(rhs)
//     }
// }

// impl<'a, 'b> Mul<&'b GoldilocksExtension> for &'a GoldilocksExtension {
//     type Output = GoldilocksExtension;

//     #[inline]
//     fn mul(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
//         self.mul(rhs)
//     }
// }
