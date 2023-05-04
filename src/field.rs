use std::{
    cell::RefCell,
    ops::{Add, AddAssign, Deref, Div, Mul, Sub},
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
use num_traits::{Inv, Zero};
use plonky2::{
    field::{
        extension::quadratic::QuadraticExtension,
        goldilocks_field::GoldilocksField as GoldilocksFieldOriginal,
        types::{Field, PrimeField},
    },
    util::bits_u64,
};

use crate::utils::{assign_val, convert_big_uint_to_fr, convert_fr_to_big_uint};

const GOLDILOCKS_FIELD_ORDER: u64 = 18446744069414584321;

#[derive(Copy, Clone, Debug)]
pub struct GoldilocksField(pub(crate) Fr);

impl<'a> PartialEq<GoldilocksField> for &'a GoldilocksField {
    fn eq(&self, other: &GoldilocksField) -> bool {
        let diff = self.0 - other.0;
        let diff_bi = convert_fr_to_big_uint(diff) % BigUint::from(GOLDILOCKS_FIELD_ORDER);

        diff_bi.is_zero()
    }
}

impl PartialEq<GoldilocksField> for GoldilocksField {
    fn eq(&self, other: &GoldilocksField) -> bool {
        (&self).eq(other)
    }
}

impl<'a, 'b> Mul<&'b GoldilocksField> for &'a GoldilocksField {
    type Output = GoldilocksField;

    #[inline]
    fn mul(self, rhs: &'b GoldilocksField) -> GoldilocksField {
        let output0 = convert_fr_to_big_uint(self.0) * convert_fr_to_big_uint(rhs.0);
        let output0_bi = output0 % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output_fr = convert_big_uint_to_fr(output0_bi);

        GoldilocksField(output_fr)
    }
}

impl<'b> Mul<&'b GoldilocksField> for GoldilocksField {
    type Output = GoldilocksField;

    #[inline]
    fn mul(self, rhs: &'b GoldilocksField) -> GoldilocksField {
        (&self).mul(rhs)
    }
}

impl Mul<GoldilocksField> for GoldilocksField {
    type Output = GoldilocksField;

    #[inline]
    fn mul(self, rhs: GoldilocksField) -> GoldilocksField {
        self.mul(&rhs)
    }
}

impl Inv for GoldilocksField {
    type Output = GoldilocksField;

    fn inv(self) -> Self::Output {
        // if self.0 == Fr::zero() {
        //     return GoldilocksField::from(Fr::from(0));
        // }

        let value_bi = convert_fr_to_big_uint(self.0);
        let value = GoldilocksFieldOriginal::from_noncanonical_biguint(value_bi);
        let value_inv = value.inverse();
        let value_inv_bi = value_inv.to_canonical_biguint();
        let value_inv_fr = convert_big_uint_to_fr(value_inv_bi);

        GoldilocksField::from(value_inv_fr)
    }
}

#[test]
fn test_inv() {
    let one = GoldilocksField::from(Fr::one());
    let a = GoldilocksField::from(Fr::from(0x7fffffff80000001));
    let inv_a = a.inv();
    dbg!(inv_a);
    assert_eq!(a * inv_a, one);
}

impl From<Fr> for GoldilocksField {
    fn from(value: Fr) -> Self {
        let value_bi = convert_fr_to_big_uint(value) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let value_fr = convert_big_uint_to_fr(value_bi);

        Self(value_fr)
    }
}

#[derive(Clone, Debug)]
pub struct AssignedGoldilocksField(pub(crate) AssignedCell<Fr, Fr>);

#[derive(Copy, Clone, Debug)]
pub struct GoldilocksExtension(pub(crate) [Fr; 2]);

impl Deref for GoldilocksExtension {
    type Target = [Fr; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[Fr; 2]> for GoldilocksExtension {
    fn from(value: [Fr; 2]) -> Self {
        let value0_bi = convert_fr_to_big_uint(value[0]) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let value0_fr = convert_big_uint_to_fr(value0_bi);
        let value1_bi = convert_fr_to_big_uint(value[1]) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let value1_fr = convert_big_uint_to_fr(value1_bi);

        Self([value0_fr, value1_fr])
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

impl<'a, 'b> Sub<&'b GoldilocksExtension> for &'a GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn sub(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
        // output0 = a0 + b0
        let output0 = Fr::from(GOLDILOCKS_FIELD_ORDER) + self[0] - rhs[0];
        let output0_bi = convert_fr_to_big_uint(output0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output0_fr = convert_big_uint_to_fr(output0_bi);
        // output1 = a1 + b1
        let output1 = Fr::from(GOLDILOCKS_FIELD_ORDER) + self[1] - rhs[1];
        let output1_bi = convert_fr_to_big_uint(output1) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output1_fr = convert_big_uint_to_fr(output1_bi);

        GoldilocksExtension([output0_fr, output1_fr])
    }
}

impl<'b> Sub<&'b GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn sub(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
        (&self).sub(rhs)
    }
}

impl Sub<GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn sub(self, rhs: GoldilocksExtension) -> GoldilocksExtension {
        self.sub(&rhs)
    }
}

impl<'a, 'b> Add<&'b GoldilocksExtension> for &'a GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn add(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
        // output0 = a0 + b0
        let output0 = self[0] + rhs[0];
        let output0_bi = convert_fr_to_big_uint(output0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output0_fr = convert_big_uint_to_fr(output0_bi);
        // output1 = a1 + b1
        let output1 = self[1] + rhs[1];
        let output1_bi = convert_fr_to_big_uint(output1) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output1_fr = convert_big_uint_to_fr(output1_bi);

        GoldilocksExtension([output0_fr, output1_fr])
    }
}

impl<'b> Add<&'b GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn add(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
        (&self).add(rhs)
    }
}

impl Add<GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn add(self, rhs: GoldilocksExtension) -> GoldilocksExtension {
        self.add(&rhs)
    }
}

impl<'b> AddAssign<&'b GoldilocksExtension> for GoldilocksExtension {
    fn add_assign(&mut self, rhs: &'b GoldilocksExtension) {
        let _ = std::mem::replace(self, self.add(rhs));
    }
}

impl AddAssign<GoldilocksExtension> for GoldilocksExtension {
    fn add_assign(&mut self, rhs: GoldilocksExtension) {
        self.add_assign(&rhs);
    }
}

impl<'a, 'b> Mul<&'b GoldilocksExtension> for &'a GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn mul(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
        // output0 = a0 * b0 + W * a1 * b1
        let w = Fr::from(7);
        let output0 = self[0] * rhs[0] + w * self[1] * rhs[1];
        let output0_bi = convert_fr_to_big_uint(output0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output0_fr = convert_big_uint_to_fr(output0_bi);
        // output1 = a0 * b1 + a1 * b0
        let output1 = self[0] * rhs[1] + self[1] * rhs[0];
        let output1_bi = convert_fr_to_big_uint(output1) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output1_fr = convert_big_uint_to_fr(output1_bi);

        GoldilocksExtension([output0_fr, output1_fr])
    }
}

impl<'b> Mul<&'b GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn mul(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
        (&self).mul(rhs)
    }
}

impl Mul<GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn mul(self, rhs: GoldilocksExtension) -> GoldilocksExtension {
        self.mul(&rhs)
    }
}

impl<'a, 'b> Div<&'b GoldilocksExtension> for &'a GoldilocksExtension {
    type Output = GoldilocksExtension;

    fn div(self, rhs: &'b GoldilocksExtension) -> Self::Output {
        let lhs0_bi = convert_fr_to_big_uint(self[0]);
        let lhs0 = GoldilocksFieldOriginal::from_noncanonical_biguint(lhs0_bi);
        let lhs1_bi = convert_fr_to_big_uint(self[1]);
        let lhs1 = GoldilocksFieldOriginal::from_noncanonical_biguint(lhs1_bi);
        let lhs = QuadraticExtension::<GoldilocksFieldOriginal>([lhs0, lhs1]);

        let rhs0_bi = convert_fr_to_big_uint(rhs[0]);
        let rhs0 = GoldilocksFieldOriginal::from_noncanonical_biguint(rhs0_bi);
        let rhs1_bi = convert_fr_to_big_uint(rhs[1]);
        let rhs1 = GoldilocksFieldOriginal::from_noncanonical_biguint(rhs1_bi);
        let rhs = QuadraticExtension::<GoldilocksFieldOriginal>([rhs0, rhs1]);

        let result = lhs.div(rhs);

        let result0 = result.0[0];
        let result1 = result.0[1];
        let result0_bi = result0.to_canonical_biguint();
        let result1_bi = result1.to_canonical_biguint();
        let result0_fr = convert_big_uint_to_fr(result0_bi);
        let result1_fr = convert_big_uint_to_fr(result1_bi);

        GoldilocksExtension([result0_fr, result1_fr])
    }
}

impl<'b> Div<&'b GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn div(self, rhs: &'b GoldilocksExtension) -> GoldilocksExtension {
        (&self).div(rhs)
    }
}

impl Div<GoldilocksExtension> for GoldilocksExtension {
    type Output = GoldilocksExtension;

    #[inline]
    fn div(self, rhs: GoldilocksExtension) -> GoldilocksExtension {
        self.div(&rhs)
    }
}

impl Inv for GoldilocksExtension {
    type Output = GoldilocksExtension;

    fn inv(self) -> Self::Output {
        let value_fr = self.0;
        let value0_bi = convert_fr_to_big_uint(value_fr[0]);
        let value0 = GoldilocksFieldOriginal::from_noncanonical_biguint(value0_bi);
        let value1_bi = convert_fr_to_big_uint(value_fr[1]);
        let value1 = GoldilocksFieldOriginal::from_noncanonical_biguint(value1_bi);
        let value = QuadraticExtension::<GoldilocksFieldOriginal>([value0, value1]);
        let value_inv = value.inverse();
        let value_inv0 = value_inv.0[0];
        let value_inv1 = value_inv.0[1];
        let value_inv0_bi = value_inv0.to_canonical_biguint();
        let value_inv1_bi = value_inv1.to_canonical_biguint();
        let value_inv0_fr = convert_big_uint_to_fr(value_inv0_bi);
        let value_inv1_fr = convert_big_uint_to_fr(value_inv1_bi);

        GoldilocksExtension([value_inv0_fr, value_inv1_fr])
    }
}

impl GoldilocksExtension {
    pub fn exp_u64(&self, power: u64) -> Self {
        let value_fr = self.0;
        let value0_bi = convert_fr_to_big_uint(value_fr[0]);
        let value0 = GoldilocksFieldOriginal::from_noncanonical_biguint(value0_bi);
        let value1_bi = convert_fr_to_big_uint(value_fr[1]);
        let value1 = GoldilocksFieldOriginal::from_noncanonical_biguint(value1_bi);
        let value = QuadraticExtension::<GoldilocksFieldOriginal>([value0, value1]);

        let result = value.exp_u64(power);

        let result0 = result.0[0];
        let result1 = result.0[1];
        let result0_bi = result0.to_canonical_biguint();
        let result1_bi = result1.to_canonical_biguint();
        let result0_fr = convert_big_uint_to_fr(result0_bi);
        let result1_fr = convert_big_uint_to_fr(result1_bi);

        GoldilocksExtension([result0_fr, result1_fr])
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

pub fn zero_assigned(
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

#[derive(Clone, Debug)]
pub struct AssignedGoldilocksExtension(pub [AssignedCell<Fr, Fr>; 2]);

impl Deref for AssignedGoldilocksExtension {
    type Target = [AssignedCell<Fr, Fr>; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AssignedGoldilocksExtension {
    pub fn zero(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
    ) -> Result<Self, Error> {
        let zero_cell = zero_assigned(layouter.namespace(|| "assign zero"), advice_column)?;

        Ok(Self([zero_cell.clone(), zero_cell]))
    }

    pub fn constant(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        val: GoldilocksExtension,
    ) -> Result<Self, Error> {
        let constant0_cell = assign_val(
            layouter.namespace(|| "assign constant"),
            advice_column,
            val[0],
        )?;
        let constant1_cell = assign_val(
            layouter.namespace(|| "assign constant"),
            advice_column,
            val[1],
        )?;

        Ok(Self([constant0_cell, constant1_cell]))
    }
}

pub fn from_base_field(
    mut layouter: impl Layouter<Fr>,
    advice_column: Column<Advice>,
    value: AssignedCell<Fr, Fr>,
) -> Result<AssignedGoldilocksExtension, Error> {
    let zero = zero_assigned(layouter.namespace(|| "assign zero"), advice_column)?;

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

/// Constrain `output = -a`.
pub fn neg_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    a: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    let a0 =
        mod_by_goldilocks_order(layouter.namespace(|| "a0 mod order"), gate, range, a[0].clone()).unwrap();

    let a1 =
        mod_by_goldilocks_order(layouter.namespace(|| "a1 mod order"), gate, range, a[1].clone()).unwrap();

    let a_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
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

            let a0 = gate.load_witness(&mut ctx, a0.value().and_then(|v| Value::known(*v)));
            let a1 = gate.load_witness(&mut ctx, a1.value().and_then(|v| Value::known(*v)));
            *a_assigned.borrow_mut() = Some([a0, a1]);

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
            let a0 = QuantumCell::Existing(&a[0]);
            let a1 = QuantumCell::Existing(&a[1]);
            let order = Fr::from(GOLDILOCKS_FIELD_ORDER); // the order of Goldilocks field
            let order_assigned = gate.load_witness(&mut ctx, Value::known(order));

            // output0 = order - a0
            let output0 = gate.sub(&mut ctx, QuantumCell::Existing(&order_assigned), a0);
            let output0 = AssignedCell::new(output0.value, output0.cell);
            *output0_assigned.borrow_mut() = Some(output0);

            // output1 = order - a1
            let output1 = gate.sub(&mut ctx, QuantumCell::Existing(&order_assigned), a1);
            let output1 = AssignedCell::new(output1.value, output1.cell);
            *output1_assigned.borrow_mut() = Some(output1);

            Ok(())
        },
    )?;

    Ok(AssignedGoldilocksExtension([
        output0_assigned.into_inner().unwrap(),
        output1_assigned.into_inner().unwrap(),
    ]))
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

/// Constrain `output = a / b`.
pub fn div_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    a: AssignedGoldilocksExtension,
    b: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    // let a_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    // let b_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
    // let output0_assigned = RefCell::new(None);
    // let output1_assigned = RefCell::new(None);
    // let mut expected_a = RefCell::new(None);
    let output = RefCell::new(None);

    layouter.assign_region(
        || "divide a into b",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let a_raw = {
                let a_raws = RefCell::new(vec![]);
                a.0.iter().for_each(|a_i| {
                    a_i.value().map(|a_i_raw| {
                        a_raws.borrow_mut().push(*a_i_raw);
                    });
                });

                GoldilocksExtension(a_raws.into_inner().try_into().unwrap())
            };
            let b_raw = {
                let b_raws = RefCell::new(vec![]);
                b.0.iter().for_each(|b_i| {
                    b_i.value().map(|b_i_raw| {
                        b_raws.borrow_mut().push(*b_i_raw);
                    });
                });

                GoldilocksExtension(b_raws.into_inner().try_into().unwrap())
            };

            let output_raw = a_raw / b_raw;
            let output0 = gate.load_witness(&mut ctx, Value::known(output_raw[0]));
            let output1 = gate.load_witness(&mut ctx, Value::known(output_raw[1]));
            let output0_assigned = AssignedCell::new(output0.value, output0.cell);
            let output1_assigned = AssignedCell::new(output1.value, output1.cell);
            let output_assigned = AssignedGoldilocksExtension([output0_assigned, output1_assigned]);
            *output.borrow_mut() = Some(output_assigned);

            Ok(())
        },
    )?;

    let output_assigned = output.into_inner().unwrap();
    let expected_a_assigned = mul_extension(
        layouter.namespace(|| "mul"),
        gate,
        range,
        output_assigned.clone(),
        b,
    )?;

    layouter.assign_region(
        || "constrain equal",
        |mut region| {
            region.constrain_equal(expected_a_assigned[0].cell(), a[0].cell())?;
            region.constrain_equal(expected_a_assigned[1].cell(), a[1].cell())?;

            Ok(())
        },
    )?;

    Ok(output_assigned)
}

/// Constrain `output = a * b`.
pub fn square_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    a: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    mul_extension(layouter.namespace(|| "mul"), gate, range, a.clone(), a)
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
    let zero = zero_assigned(layouter.namespace(|| "assign zero"), advice_column).unwrap();
    let b = AssignedGoldilocksExtension([scalar, zero]);

    mul_extension(layouter, gate, range, value, b)
}

/// Constrain `output = constant0 * multiplicand0 * multiplicand1 + constant1 * addend`.
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

pub fn exp_u64_extension(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    range: &RangeConfig<Fr>,
    advice_column: Column<Advice>,
    base: AssignedGoldilocksExtension,
    power: u64,
) -> Result<AssignedGoldilocksExtension, Error> {
    let mut current = base;
    let mut product = AssignedGoldilocksExtension::constant(
        layouter.namespace(|| "assign one"),
        advice_column,
        GoldilocksExtension([Fr::one(), Fr::zero()]),
    )?;

    for j in 0..bits_u64(power) {
        if j != 0 {
            current = square_extension(layouter.namespace(|| "square"), gate, range, current.clone())?;
        }
        if (power >> j & 1) != 0 {
            product = mul_extension(layouter.namespace(|| "mul"), gate, range, product, current.clone())?;
        }
    }

    Ok(product)
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
