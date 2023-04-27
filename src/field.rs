use std::{
    cell::RefCell,
    ops::{Add, Deref, Div, Mul, Neg, Sub},
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

use crate::merkle_tree_circuit::assign_val;

#[derive(Copy, Clone, Debug)]
pub struct FrExtension(pub [Fr; 2]);

#[derive(Clone, Debug)]
pub struct AssignedFrExtension(pub [AssignedCell<Fr, Fr>; 2]);

impl Deref for AssignedFrExtension {
    type Target = [AssignedCell<Fr, Fr>; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Fr> for FrExtension {
    fn from(value: Fr) -> Self {
        Self([value, Fr::zero()])
    }
}

impl FrExtension {
    pub fn zero() -> Self {
        Self([Fr::zero(); 2])
    }
}

// impl AssignedFrExtension {
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
    gate: FlexGateConfig<Fr>,
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
    gate: FlexGateConfig<Fr>,
    advice_column: Column<Advice>,
    value: AssignedCell<Fr, Fr>,
) -> Result<AssignedFrExtension, Error> {
    let zero = zero(layouter.namespace(|| "assign zero"), gate, advice_column)?;

    Ok(AssignedFrExtension([value, zero]))
}

const K: usize = 18;

pub fn add_extension(
    mut layouter: impl Layouter<Fr>,
    gate: FlexGateConfig<Fr>,
    range: RangeConfig<Fr>,
    advice_column: Column<Advice>,
    a: AssignedFrExtension,
    b: AssignedFrExtension,
) -> Result<AssignedFrExtension, Error> {
    let a_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let b_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let output_assigned = RefCell::new(None);

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

            let a0 = QuantumCell::Existing(&a_assigned.clone().into_inner().unwrap()[0]);
            let a1 = QuantumCell::Existing(&a_assigned.clone().into_inner().unwrap()[1]);
            let b0 = QuantumCell::Existing(&b_assigned.clone().into_inner().unwrap()[0]);
            let b1 = QuantumCell::Existing(&b_assigned.clone().into_inner().unwrap()[1]);

            let output0 = gate.add(&mut ctx, a0, b0);
            let output0 = AssignedCell::new(output0.value, output0.cell);
            let output0 = mod_by_goldilocks_order(
                layouter.namespace(|| "output0 mod order"),
                gate,
                range,
                advice_column,
                output0,
            )
            .unwrap();

            let output1 = gate.add(&mut ctx, a1, b1);
            let output1 = AssignedCell::new(output1.value, output1.cell);
            let output1 = mod_by_goldilocks_order(
                layouter.namespace(|| "output1 mod order"),
                gate,
                range,
                advice_column,
                output1,
            )
            .unwrap();

            // fn mul(self, rhs: Self) -> Self {
            //     let Self([a0, a1]) = self;
            //     let Self([b0, b1]) = rhs;
            //     let c = ext2_mul([a0.0, a1.0], [b0.0, b1.0]);
            //     Self(c)
            // }

            *output_assigned.borrow_mut() = Some([output0, output1]);

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

    let output_assigned = output_assigned.clone().into_inner().unwrap();

    Ok(AssignedFrExtension(output_assigned))
}

pub fn mul_extension(
    mut layouter: impl Layouter<Fr>,
    gate: FlexGateConfig<Fr>,
    range: RangeConfig<Fr>,
    advice_column: Column<Advice>,
    a: AssignedFrExtension,
    b: AssignedFrExtension,
) -> Result<AssignedFrExtension, Error> {
    let a_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let b_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let output_assigned = RefCell::new(None);

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

            let a0 = QuantumCell::Existing(&a_assigned.clone().into_inner().unwrap()[0]);
            let a1 = QuantumCell::Existing(&a_assigned.clone().into_inner().unwrap()[1]);
            let b0 = QuantumCell::Existing(&b_assigned.clone().into_inner().unwrap()[0]);
            let b1 = QuantumCell::Existing(&b_assigned.clone().into_inner().unwrap()[1]);

            // Computes a0 * b0 + W * a1 * b1;
            let w = Fr::from(7);
            let w_assigned = gate.load_witness(&mut ctx, Value::known(w));
            let tmp0 = gate.mul(&mut ctx, a0, b0);
            let tmp1 = gate.mul(&mut ctx, a1, b1);
            let tmp2 = gate.mul(
                &mut ctx,
                QuantumCell::Existing(&tmp1),
                QuantumCell::Existing(&w_assigned),
            );
            let output0 = gate.add(
                &mut ctx,
                QuantumCell::Existing(&tmp0),
                QuantumCell::Existing(&tmp1),
            );

            // Computes a0 * b1 + a1 * b0;
            let tmp0 = gate.mul(&mut ctx, a0, b1);
            let tmp1 = gate.mul(&mut ctx, a1, b0);
            let output1 = gate.add(
                &mut ctx,
                QuantumCell::Existing(&tmp0),
                QuantumCell::Existing(&tmp1),
            );

            *output_assigned.borrow_mut() = Some([output0, output1]);

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

    let output_assigned = output_assigned.clone().into_inner().unwrap();
    let output0_cell = AssignedCell::new(output_assigned[0].value, output_assigned[0].cell);
    let output1_cell = AssignedCell::new(output_assigned[1].value, output_assigned[1].cell);

    Ok(AssignedFrExtension([output0_cell, output1_cell]))
}

pub fn scalar_extension(
    mut layouter: impl Layouter<Fr>,
    gate: FlexGateConfig<Fr>,
    range: RangeConfig<Fr>,
    advice_column: Column<Advice>,
    scalar: Fr,
    value: AssignedFrExtension,
) -> Result<AssignedFrExtension, Error> {
    let value_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    let output_assigned = RefCell::new(None);

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
            let a0 = value_assigned.clone().into_inner().unwrap()[0];
            let a1 = value_assigned.clone().into_inner().unwrap()[1];

            let output0 = gate.mul(
                &mut ctx,
                QuantumCell::Existing(&a0),
                QuantumCell::Existing(&scalar_assigned),
            );
            let output0 = AssignedCell::new(output0.value, output0.cell);
            let output0 = mod_by_goldilocks_order(
                layouter.namespace(|| "output0 mod order"),
                gate,
                range,
                advice_column,
                output0,
            )
            .unwrap();

            let output1 = gate.mul(
                &mut ctx,
                QuantumCell::Existing(&a1),
                QuantumCell::Existing(&scalar_assigned),
            );
            let output1 = AssignedCell::new(output1.value, output1.cell);
            let output1 = mod_by_goldilocks_order(
                layouter.namespace(|| "output1 mod order"),
                gate,
                range,
                advice_column,
                output1,
            )
            .unwrap();

            *output_assigned.borrow_mut() = Some([output0, output1]);

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "copy a and b",
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

    let output_assigned = output_assigned.clone().into_inner().unwrap();

    Ok(AssignedFrExtension(output_assigned))
}

/// constant0 * multiplicand0 * multiplicand1 + constant1 * addend
pub fn arithmetic_extension(
    mut layouter: impl Layouter<Fr>,
    gate: FlexGateConfig<Fr>,
    range: RangeConfig<Fr>,
    advice_column: Column<Advice>,
    constant0: Fr,
    constant1: Fr,
    multiplicand0: AssignedFrExtension,
    multiplicand1: AssignedFrExtension,
    addend: AssignedFrExtension,
) -> Result<AssignedFrExtension, Error> {
    let tmp0 = mul_extension(
        layouter,
        gate,
        range,
        advice_column,
        multiplicand0,
        multiplicand1,
    )?;
    let tmp0 = scalar_extension(layouter, gate, range, advice_column, constant0, tmp0)?;
    let tmp1 = scalar_extension(layouter, gate, range, advice_column, constant1, addend)?;

    add_extension(layouter, gate, range, advice_column, tmp0, tmp1)
}

pub fn mod_by_goldilocks_order(
    mut layouter: impl Layouter<Fr>,
    gate: FlexGateConfig<Fr>,
    range: RangeConfig<Fr>,
    advice_column: Column<Advice>,
    a: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let a_assigned = RefCell::new(None);
    let output_assigned = RefCell::new(None);

    layouter.assign_region(
        || "copy modulo",
        |mut region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            // output = a % order
            let order = Fr::from(18446744069414584321); // the order of Goldilocks field
            let order_assigned = gate.load_witness(&mut ctx, Value::known(order));

            // q = a - a % order
            let q = a.value().and_then(|a| {
                let a_bi = BigUint::from_bytes_le(&a.to_bytes());
                let order_bi = BigUint::from_bytes_le(&order.to_bytes());
                let q_bi = a_bi.div(order_bi);
                let q = Fr::from_bytes(&q_bi.to_bytes_le().try_into().unwrap()).unwrap();

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

            // Divide a constraint into two parts to check `0 <= output < order`

            // 0 <= output < 2^64 and
            range.range_check(&mut ctx, &output, 64);

            // 0 <= order - 1 - output < 2^64
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

    layouter.assign_region(
        || "copy a",
        |mut region| {
            region.constrain_equal(a_assigned.clone().into_inner().unwrap().cell(), a.cell())?;

            Ok(())
        },
    )?;

    let output_assigned = output_assigned.into_inner().unwrap();
    let output_cell = AssignedCell::new(output_assigned.value, output_assigned.cell);

    Ok(output_cell)
}

impl<'a> Neg for &'a FrExtension {
    type Output = FrExtension;

    #[inline]
    fn neg(self) -> FrExtension {
        self.neg()
    }
}

impl Neg for FrExtension {
    type Output = FrExtension;

    #[inline]
    fn neg(self) -> FrExtension {
        -&self
    }
}

impl<'a, 'b> Sub<&'b FrExtension> for &'a FrExtension {
    type Output = FrExtension;

    #[inline]
    fn sub(self, rhs: &'b FrExtension) -> FrExtension {
        self.sub(rhs)
    }
}

impl<'a, 'b> Add<&'b FrExtension> for &'a FrExtension {
    type Output = FrExtension;

    #[inline]
    fn add(self, rhs: &'b FrExtension) -> FrExtension {
        self.add(rhs)
    }
}

impl<'a, 'b> Mul<&'b FrExtension> for FrExtension {
    type Output = FrExtension;

    #[inline]
    fn mul(self, rhs: &'b FrExtension) -> FrExtension {
        self.mul(rhs)
    }
}

impl<'a, 'b> Mul<&'b FrExtension> for &'a FrExtension {
    type Output = FrExtension;

    #[inline]
    fn mul(self, rhs: &'b FrExtension) -> FrExtension {
        self.mul(rhs)
    }
}
