use std::{
    cell::RefCell,
    ops::{Add, AddAssign, Deref, Div, Mul, Sub},
};

use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        halo2curves::{bn256::Fr, FieldExt},
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
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::utils::{assign_val, convert_big_uint_to_fr, convert_fr_to_big_uint};

const GOLDILOCKS_FIELD_ORDER: u64 = 18446744069414584321;

#[derive(Copy, Clone, Debug)]
pub struct GoldilocksField(pub(crate) Fr);

impl Deref for GoldilocksField {
    type Target = Fr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for GoldilocksField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = u64::from_le_bytes(self.0.to_bytes()[..8].try_into().unwrap());

        SerilizableGoldilocksField(value).serialize(serializer)
    }
}

#[derive(Serialize, Deserialize)]
#[repr(transparent)]
pub struct SerilizableGoldilocksField(pub u64);

impl<'de> Deserialize<'de> for GoldilocksField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SerilizableGoldilocksField::deserialize(deserializer)?;

        Ok(GoldilocksField(Fr::from(value.0)))
    }
}

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
        let output = convert_fr_to_big_uint(self.0) * convert_fr_to_big_uint(rhs.0);
        let output_bi = output % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output_fr = convert_big_uint_to_fr(output_bi);

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

impl<'a, 'b> Div<&'b GoldilocksField> for &'a GoldilocksField {
    type Output = GoldilocksField;

    #[inline]
    fn div(self, rhs: &'b GoldilocksField) -> GoldilocksField {
        let inv_rhs = rhs.inv();
        let output = convert_fr_to_big_uint(self.0) * convert_fr_to_big_uint(inv_rhs.0);
        let output_bi = output % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output_fr = convert_big_uint_to_fr(output_bi);

        GoldilocksField(output_fr)
    }
}

impl<'b> Div<&'b GoldilocksField> for GoldilocksField {
    type Output = GoldilocksField;

    #[inline]
    fn div(self, rhs: &'b GoldilocksField) -> GoldilocksField {
        (&self).div(rhs)
    }
}

impl Div<GoldilocksField> for GoldilocksField {
    type Output = GoldilocksField;

    #[inline]
    fn div(self, rhs: GoldilocksField) -> GoldilocksField {
        self.div(&rhs)
    }
}

impl From<Fr> for GoldilocksField {
    fn from(value: Fr) -> Self {
        let value_bi = convert_fr_to_big_uint(value) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let value_fr = convert_big_uint_to_fr(value_bi);

        Self(value_fr)
    }
}

impl From<GoldilocksFieldOriginal> for GoldilocksField {
    fn from(value: GoldilocksFieldOriginal) -> Self {
        let value_bi = value.to_canonical_biguint();
        let value_fr = convert_big_uint_to_fr(value_bi);

        Self(value_fr)
    }
}

#[derive(Clone, Debug)]
pub struct AssignedGoldilocksField(pub(crate) AssignedCell<Fr, Fr>);

impl Deref for AssignedGoldilocksField {
    type Target = AssignedCell<Fr, Fr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<AssignedCell<Fr, Fr>> for AssignedGoldilocksField {
    fn from(value: AssignedCell<Fr, Fr>) -> Self {
        Self(value)
    }
}

impl AssignedGoldilocksField {
    pub fn assign(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: GoldilocksField,
    ) -> Result<Self, Error> {
        let result = assign_val(layouter.namespace(|| "assign value"), advice_column, *value)
            .unwrap()
            .into();

        Ok(result)
    }
}

impl AssignedGoldilocksField {
    pub fn zero(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
    ) -> Result<Self, Error> {
        let zero = GoldilocksField::from(Fr::zero());

        Self::constant(layouter, advice_column, zero)
    }

    pub fn one(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
    ) -> Result<Self, Error> {
        let one = GoldilocksField::from(Fr::one());

        Self::constant(layouter, advice_column, one)
    }

    pub fn constant(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        val: GoldilocksField,
    ) -> Result<Self, Error> {
        let constant_cell = assign_val(
            layouter.namespace(|| "assign constant"),
            advice_column,
            val.0,
        )?;

        Ok(Self(constant_cell))
    }

    /// Constrain `a == b`.
    pub fn connect(&self, mut layouter: impl Layouter<Fr>, other: Self) -> Result<(), Error> {
        layouter.assign_region(
            || "constrain_equal self and other",
            |mut region| {
                region.constrain_equal(self.cell(), other.cell())?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct GoldilocksFieldChip<F: FieldExt> {
    pub range: RangeConfig<F>,
}

impl GoldilocksFieldChip<Fr> {
    pub fn construct(range_config: RangeConfig<Fr>) -> Self {
        Self {
            range: range_config,
        }
    }

    pub fn add(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        a: AssignedGoldilocksField,
        b: AssignedGoldilocksField,
    ) -> Result<AssignedGoldilocksField, Error> {
        let gate = self.range.gate();
        let a_assigned: RefCell<Option<AssignedValue<Fr>>> = RefCell::new(None);
        let b_assigned: RefCell<Option<AssignedValue<Fr>>> = RefCell::new(None);
        let output0_assigned = RefCell::new(None);

        layouter.assign_region(
            || "assign a and b",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                let a = gate.load_witness(&mut ctx, a.value().and_then(|v| Value::known(*v)));
                *a_assigned.borrow_mut() = Some(a);

                let b = gate.load_witness(&mut ctx, b.value().and_then(|v| Value::known(*v)));
                *b_assigned.borrow_mut() = Some(b);

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "copy a and b",
            |mut region| {
                region
                    .constrain_equal(a_assigned.clone().into_inner().unwrap().cell(), a.cell())?;
                region
                    .constrain_equal(b_assigned.clone().into_inner().unwrap().cell(), b.cell())?;

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "assign zero extension",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                let a = a_assigned.borrow().clone().unwrap().clone();
                let b = b_assigned.borrow().clone().unwrap().clone();
                let a0 = QuantumCell::Existing(&a);
                let b0 = QuantumCell::Existing(&b);

                // output0 = a0 + b0
                let output0 = gate.add(&mut ctx, a0, b0);
                let output0 = AssignedCell::new(output0.value, output0.cell);
                *output0_assigned.borrow_mut() = Some(output0);

                Ok(())
            },
        )?;

        let output0 = mod_by_goldilocks_order(
            layouter.namespace(|| "output0 mod order"),
            &self.range,
            output0_assigned.into_inner().unwrap(),
        )
        .unwrap();

        Ok(AssignedGoldilocksField(output0))
    }

    /// Constrain `output = a * b`.
    pub fn mul(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksField,
        b: AssignedGoldilocksField,
    ) -> Result<AssignedGoldilocksField, Error> {
        let gate = self.range.gate();
        let a_assigned: RefCell<Option<AssignedValue<Fr>>> = RefCell::new(None);
        let b_assigned: RefCell<Option<AssignedValue<Fr>>> = RefCell::new(None);
        let output0_assigned = RefCell::new(None);

        layouter.assign_region(
            || "assign a and b",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                let a0 = gate.load_witness(&mut ctx, a.value().and_then(|v| Value::known(*v)));
                *a_assigned.borrow_mut() = Some(a0);

                let b0 = gate.load_witness(&mut ctx, b.value().and_then(|v| Value::known(*v)));
                *b_assigned.borrow_mut() = Some(b0);

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "copy a and b",
            |mut region| {
                region
                    .constrain_equal(a_assigned.clone().into_inner().unwrap().cell(), a.cell())?;
                region
                    .constrain_equal(b_assigned.clone().into_inner().unwrap().cell(), b.cell())?;

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "assign zero extension",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                let a = a_assigned.borrow().clone().unwrap().clone();
                let b = b_assigned.borrow().clone().unwrap().clone();
                let a0 = QuantumCell::Existing(&a);
                let b0 = QuantumCell::Existing(&b);

                // output0 = a0 * b0 + W * a1 * b1
                let w = Fr::from(7);
                let w_assigned = gate.load_witness(&mut ctx, Value::known(w));
                let output0 = gate.mul(&mut ctx, a0.clone(), b0.clone());
                let output0 = AssignedCell::new(output0.value, output0.cell);
                *output0_assigned.borrow_mut() = Some(output0);

                Ok(())
            },
        )?;

        let output0 = mod_by_goldilocks_order(
            layouter.namespace(|| "output0 mod order"),
            &self.range,
            output0_assigned.into_inner().unwrap(),
        )
        .unwrap();

        Ok(AssignedGoldilocksField(output0))
    }

    /// Constrain `output = a / b`.
    fn div(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksField,
        b: AssignedGoldilocksField,
    ) -> Result<AssignedGoldilocksField, Error> {
        let gate = self.range.gate();
        let output = RefCell::new(None);

        layouter.assign_region(
            || "divide a into b",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                let output_raw = a.value().zip(b.value()).map(|(&a_raw, &b_raw)| {
                    let a_raw: GoldilocksField = a_raw.into();
                    let b_raw: GoldilocksField = b_raw.into();
                    let output_raw = a_raw / b_raw;

                    *output_raw
                });

                let output0 = gate.load_witness(&mut ctx, output_raw);
                let output_assigned =
                    AssignedGoldilocksField(AssignedCell::new(output0.value, output0.cell));
                *output.borrow_mut() = Some(output_assigned);

                Ok(())
            },
        )?;

        let output_assigned = output.into_inner().unwrap();
        let expected_a_assigned =
            self.mul(layouter.namespace(|| "mul"), output_assigned.clone(), b)?;

        layouter.assign_region(
            || "constrain equal",
            |mut region| {
                region.constrain_equal(expected_a_assigned.cell(), a.cell())?;

                Ok(())
            },
        )?;

        Ok(output_assigned)
    }

    /// Constrain `output = 1 / value`.
    pub fn inv(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        value: AssignedGoldilocksField,
    ) -> Result<AssignedGoldilocksField, Error> {
        let one = AssignedGoldilocksField::one(layouter.namespace(|| "assign one"), advice_column)?;

        self.div(layouter.namespace(|| "div"), one, value)
    }

    /// Constrain `output = a * scalar`.
    pub fn constant_scalar_mul(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        scalar: GoldilocksField,
        value: AssignedGoldilocksField,
    ) -> Result<AssignedGoldilocksField, Error> {
        let scalar_assigned = AssignedGoldilocksField::constant(layouter.namespace(|| "assign scalar"), advice_column, scalar)?;
        
        self.mul(layouter, scalar_assigned, value)
    }

    pub fn arithmetic(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        const_0: GoldilocksField,
        const_1: GoldilocksField,
        multiplicand_0: AssignedGoldilocksField,
        multiplicand_1: AssignedGoldilocksField,
        addend: AssignedGoldilocksField,
    ) -> Result<AssignedGoldilocksField, Error> {
        let tmp = self.mul(layouter.namespace(|| "mul"), multiplicand_0, multiplicand_1)?;
        let left = self.constant_scalar_mul(layouter.namespace(|| "left scalar mul"), advice_column, const_0, tmp)?;
        let right = self.constant_scalar_mul(layouter.namespace(|| "right scalar mul"), advice_column, const_1, addend)?;

        self.add(layouter.namespace(|| "add"), advice_column, left, right)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GoldilocksExtension(pub(crate) [GoldilocksField; 2]);

impl Deref for GoldilocksExtension {
    type Target = [GoldilocksField; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[GoldilocksField; 2]> for GoldilocksExtension {
    fn from(value: [GoldilocksField; 2]) -> Self {
        let value0_bi = convert_fr_to_big_uint(value[0].0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let value0_fr = convert_big_uint_to_fr(value0_bi);
        let value1_bi = convert_fr_to_big_uint(value[1].0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let value1_fr = convert_big_uint_to_fr(value1_bi);

        Self([value0_fr.into(), value1_fr.into()])
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
        let output0 = Fr::from(GOLDILOCKS_FIELD_ORDER) + self[0].0 - rhs[0].0;
        let output0_bi = convert_fr_to_big_uint(output0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output0_fr = convert_big_uint_to_fr(output0_bi);
        // output1 = a1 + b1
        let output1 = Fr::from(GOLDILOCKS_FIELD_ORDER) + self[1].0 - rhs[1].0;
        let output1_bi = convert_fr_to_big_uint(output1) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output1_fr = convert_big_uint_to_fr(output1_bi);

        GoldilocksExtension([output0_fr.into(), output1_fr.into()])
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
        let output0 = self[0].0 + rhs[0].0;
        let output0_bi = convert_fr_to_big_uint(output0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output0_fr = convert_big_uint_to_fr(output0_bi);
        // output1 = a1 + b1
        let output1 = self[1].0 + rhs[1].0;
        let output1_bi = convert_fr_to_big_uint(output1) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output1_fr = convert_big_uint_to_fr(output1_bi);

        GoldilocksExtension([output0_fr.into(), output1_fr.into()])
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
        let output0 = self[0].0 * rhs[0].0 + w * self[1].0 * rhs[1].0;
        let output0_bi = convert_fr_to_big_uint(output0) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output0_fr = convert_big_uint_to_fr(output0_bi);
        // output1 = a0 * b1 + a1 * b0
        let output1 = self[0].0 * rhs[1].0 + self[1].0 * rhs[0].0;
        let output1_bi = convert_fr_to_big_uint(output1) % BigUint::from(GOLDILOCKS_FIELD_ORDER);
        let output1_fr = convert_big_uint_to_fr(output1_bi);

        GoldilocksExtension([output0_fr.into(), output1_fr.into()])
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
        let lhs0_bi = convert_fr_to_big_uint(self[0].0);
        let lhs0 = GoldilocksFieldOriginal::from_noncanonical_biguint(lhs0_bi);
        let lhs1_bi = convert_fr_to_big_uint(self[1].0);
        let lhs1 = GoldilocksFieldOriginal::from_noncanonical_biguint(lhs1_bi);
        let lhs = QuadraticExtension::<GoldilocksFieldOriginal>([lhs0, lhs1]);

        let rhs0_bi = convert_fr_to_big_uint(rhs[0].0);
        let rhs0 = GoldilocksFieldOriginal::from_noncanonical_biguint(rhs0_bi);
        let rhs1_bi = convert_fr_to_big_uint(rhs[1].0);
        let rhs1 = GoldilocksFieldOriginal::from_noncanonical_biguint(rhs1_bi);
        let rhs = QuadraticExtension::<GoldilocksFieldOriginal>([rhs0, rhs1]);

        let result = lhs.div(rhs);

        let result0 = result.0[0];
        let result1 = result.0[1];
        let result0_bi = result0.to_canonical_biguint();
        let result1_bi = result1.to_canonical_biguint();
        let result0_fr = convert_big_uint_to_fr(result0_bi);
        let result1_fr = convert_big_uint_to_fr(result1_bi);

        GoldilocksExtension([result0_fr.into(), result1_fr.into()])
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
        let value0_bi = convert_fr_to_big_uint(value_fr[0].0);
        let value0 = GoldilocksFieldOriginal::from_noncanonical_biguint(value0_bi);
        let value1_bi = convert_fr_to_big_uint(value_fr[1].0);
        let value1 = GoldilocksFieldOriginal::from_noncanonical_biguint(value1_bi);
        let value = QuadraticExtension::<GoldilocksFieldOriginal>([value0, value1]);
        let value_inv = value.inverse();
        let value_inv0 = value_inv.0[0];
        let value_inv1 = value_inv.0[1];
        let value_inv0_bi = value_inv0.to_canonical_biguint();
        let value_inv1_bi = value_inv1.to_canonical_biguint();
        let value_inv0_fr = convert_big_uint_to_fr(value_inv0_bi);
        let value_inv1_fr = convert_big_uint_to_fr(value_inv1_bi);

        GoldilocksExtension([value_inv0_fr.into(), value_inv1_fr.into()])
    }
}

impl GoldilocksExtension {
    pub fn exp_u64(&self, power: u64) -> Self {
        let value_fr = self.0;
        let value0_bi = convert_fr_to_big_uint(value_fr[0].0);
        let value0 = GoldilocksFieldOriginal::from_noncanonical_biguint(value0_bi);
        let value1_bi = convert_fr_to_big_uint(value_fr[1].0);
        let value1 = GoldilocksFieldOriginal::from_noncanonical_biguint(value1_bi);
        let value = QuadraticExtension::<GoldilocksFieldOriginal>([value0, value1]);

        let result = value.exp_u64(power);

        let result0 = result.0[0];
        let result1 = result.0[1];
        let result0_bi = result0.to_canonical_biguint();
        let result1_bi = result1.to_canonical_biguint();
        let result0_fr = convert_big_uint_to_fr(result0_bi);
        let result1_fr = convert_big_uint_to_fr(result1_bi);

        GoldilocksExtension([result0_fr.into(), result1_fr.into()])
    }
}

impl From<GoldilocksField> for GoldilocksExtension {
    fn from(value: GoldilocksField) -> Self {
        Self([value, Fr::zero().into()])
    }
}

impl GoldilocksExtension {
    pub fn zero() -> Self {
        Self([Fr::zero().into(); 2])
    }

    pub fn one() -> Self {
        Self([Fr::one().into(), Fr::zero().into()])
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

impl From<[AssignedCell<Fr, Fr>; 2]> for AssignedGoldilocksExtension {
    fn from(value: [AssignedCell<Fr, Fr>; 2]) -> Self {
        Self(value)
    }
}

impl AssignedGoldilocksExtension {
    pub fn assign(
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        x: GoldilocksExtension,
    ) -> Result<Self, Error> {
        let result = Self([
            assign_val(
                layouter.namespace(|| "reduced_openings_at_point[0]"),
                advice_column,
                *x[0],
            )?,
            assign_val(
                layouter.namespace(|| "reduced_openings_at_point[1]"),
                advice_column,
                *x[1],
            )?,
        ]);

        Ok(result)
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
            val[0].0,
        )?;
        let constant1_cell = assign_val(
            layouter.namespace(|| "assign constant"),
            advice_column,
            val[1].0,
        )?;

        Ok(Self([constant0_cell, constant1_cell]))
    }

    /// Constrain `a == b`.
    pub fn connect(&self, mut layouter: impl Layouter<Fr>, other: Self) -> Result<(), Error> {
        layouter.assign_region(
            || "constrain_equal self and other",
            |mut region| {
                region.constrain_equal(self[0].cell(), other[0].cell())?;
                region.constrain_equal(self[1].cell(), other[1].cell())?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct GoldilocksExtensionChip<F: FieldExt> {
    pub range: RangeConfig<F>,
}

impl GoldilocksExtensionChip<Fr> {
    pub fn construct(range_config: RangeConfig<Fr>) -> Self {
        Self {
            range: range_config,
        }
    }

    // pub fn from_base_field(
    //     &mut self,
    //     mut layouter: impl Layouter<Fr>,
    //     advice_column: Column<Advice>,
    //     value: AssignedCell<Fr, Fr>,
    // ) -> Result<AssignedGoldilocksExtension, Error> {
    //     let zero = zero_assigned(layouter.namespace(|| "assign zero"), advice_column)?;

    //     Ok(AssignedGoldilocksExtension([value, zero]))
    // }

    /// Constrain `output = a + b`.
    pub fn add(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksExtension,
        b: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let gate = self.range.gate();
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
                        max_rows: gate.max_rows,
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
                        max_rows: gate.max_rows,
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
            &self.range,
            output0_assigned.into_inner().unwrap(),
        )
        .unwrap();

        let output1 = mod_by_goldilocks_order(
            layouter.namespace(|| "output1 mod order"),
            &self.range,
            output1_assigned.into_inner().unwrap(),
        )
        .unwrap();

        Ok(AssignedGoldilocksExtension([output0, output1]))
    }

    /// Constrain `output = -a`.
    pub fn neg(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let gate = self.range.gate();
        let a0 = mod_by_goldilocks_order(
            layouter.namespace(|| "a0 mod order"),
            &self.range,
            a[0].clone(),
        )
        .unwrap();

        let a1 = mod_by_goldilocks_order(
            layouter.namespace(|| "a1 mod order"),
            &self.range,
            a[1].clone(),
        )
        .unwrap();

        let a_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
        let output0_assigned = RefCell::new(None);
        let output1_assigned = RefCell::new(None);

        layouter.assign_region(
            || "assign a and b",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
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
                        max_rows: gate.max_rows,
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

    pub fn sub(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksExtension,
        b: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let minus_b = self.neg(layouter.namespace(|| "minus b"), b)?;

        self.add(layouter.namespace(|| "add"), a, minus_b)
    }

    /// Constrain `output = a * b`.
    pub fn mul(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksExtension,
        b: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let gate = self.range.gate();
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
                        max_rows: gate.max_rows,
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
                        max_rows: gate.max_rows,
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
            &self.range,
            output0_assigned.into_inner().unwrap(),
        )
        .unwrap();

        let output1 = mod_by_goldilocks_order(
            layouter.namespace(|| "output0 mod order"),
            &self.range,
            output1_assigned.into_inner().unwrap(),
        )
        .unwrap();

        // let output0_cell = AssignedCell::new(output_assigned[0].value, output_assigned[0].cell);
        // let output1_cell = AssignedCell::new(output_assigned[1].value, output_assigned[1].cell);

        Ok(AssignedGoldilocksExtension([output0, output1]))
    }

    /// Constrain `output = a / b`.
    pub fn div(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksExtension,
        b: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let gate = self.range.gate();
        let output = RefCell::new(None);

        layouter.assign_region(
            || "divide a into b",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                let output_raw = a[0]
                    .value()
                    .zip(a[1].value())
                    .zip(b[0].value())
                    .zip(b[1].value())
                    .map(|(((&a_0_raw, &a_1_raw), &b_0_raw), &b_1_raw)| {
                        let a_raw = GoldilocksExtension([a_0_raw.into(), a_1_raw.into()]);
                        let b_raw = GoldilocksExtension([b_0_raw.into(), b_1_raw.into()]);

                        let output_raw = a_raw / b_raw;

                        (*output_raw[0], *output_raw[1])
                    });
                let output_raw = output_raw.unzip();

                let output0 = gate.load_witness(&mut ctx, output_raw.0);
                let output1 = gate.load_witness(&mut ctx, output_raw.1);
                let output0_assigned = AssignedCell::new(output0.value, output0.cell);
                let output1_assigned = AssignedCell::new(output1.value, output1.cell);
                let output_assigned =
                    AssignedGoldilocksExtension([output0_assigned, output1_assigned]);
                *output.borrow_mut() = Some(output_assigned);

                Ok(())
            },
        )?;

        let output_assigned = output.into_inner().unwrap();
        let expected_a_assigned =
            self.mul(layouter.namespace(|| "mul"), output_assigned.clone(), b)?;

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
    pub fn square(
        &self,
        mut layouter: impl Layouter<Fr>,
        a: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        self.mul(layouter.namespace(|| "mul"), a.clone(), a)
    }

    /// Constrain `output = a * scalar`.
    pub fn constant_scalar_mul(
        &self,
        mut layouter: impl Layouter<Fr>,
        scalar: Fr,
        value: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let gate = self.range.gate();
        let value_assigned: RefCell<Option<[AssignedValue<Fr>; 2]>> = RefCell::new(None);
        let output0_assigned = RefCell::new(None);
        let output1_assigned = RefCell::new(None);

        layouter.assign_region(
            || "assign value",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
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
                        max_rows: gate.max_rows,
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
            &self.range,
            output0_assigned.into_inner().unwrap(),
        )
        .unwrap();

        let output1 = mod_by_goldilocks_order(
            layouter.namespace(|| "output1 mod order"),
            &self.range,
            output1_assigned.into_inner().unwrap(),
        )
        .unwrap();

        Ok(AssignedGoldilocksExtension([output0, output1]))
    }

    pub fn scalar_mul(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        scalar: AssignedCell<Fr, Fr>,
        value: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let zero = zero_assigned(layouter.namespace(|| "assign zero"), advice_column).unwrap();
        let b = AssignedGoldilocksExtension([scalar, zero]);

        self.mul(layouter.namespace(|| "mul"), value, b)
    }

    /// Constrain `output = constant0 * multiplicand0 * multiplicand1 + constant1 * addend`.
    pub fn arithmetic(
        &self,
        mut layouter: impl Layouter<Fr>,
        constant0: Fr,
        constant1: Fr,
        multiplicand0: AssignedGoldilocksExtension,
        multiplicand1: AssignedGoldilocksExtension,
        addend: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let tmp0 = self.mul(
            layouter.namespace(|| "multiplication"),
            multiplicand0,
            multiplicand1,
        )?;
        let tmp0 =
            self.constant_scalar_mul(layouter.namespace(|| "first term"), constant0, tmp0)?;
        let tmp1 =
            self.constant_scalar_mul(layouter.namespace(|| "second term"), constant1, addend)?;

        self.add(layouter.namespace(|| "add"), tmp0, tmp1)
    }

    pub fn exp_u64(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        base: AssignedGoldilocksExtension,
        power: u64,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let mut current = base;
        let mut product = AssignedGoldilocksExtension::constant(
            layouter.namespace(|| "assign one"),
            advice_column,
            GoldilocksExtension([Fr::one().into(), Fr::zero().into()]),
        )?;

        for j in 0..bits_u64(power) {
            if j != 0 {
                current = self.square(layouter.namespace(|| "square"), current.clone())?;
            }
            if (power >> j & 1) != 0 {
                product = self.mul(layouter.namespace(|| "mul"), product, current.clone())?;
            }
        }

        Ok(product)
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

/// Constrain `output = a % GOLDILOCKS_FIELD_ORDER`.
pub fn mod_by_goldilocks_order(
    mut layouter: impl Layouter<Fr>,
    range: &RangeConfig<Fr>,
    a: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let gate = range.gate();
    let a_assigned = RefCell::new(None);
    let output_assigned = RefCell::new(None);

    layouter.assign_region(
        || "copy modulo",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: gate.max_rows,
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
                    max_rows: gate.max_rows,
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

pub fn simple_constraints(
    mut layouter: impl Layouter<Fr>,
    gate: &FlexGateConfig<Fr>,
    // advice_column: Column<Advice>,
    a: AssignedGoldilocksExtension,
) -> Result<AssignedGoldilocksExtension, Error> {
    // let gate = range.gate();
    let output = RefCell::new(None);

    layouter.assign_region(
        || "divide a into b",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: gate.max_rows,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );

            let output_raw = a.0[0]
                .value()
                .zip(a.0[1].value())
                .map(|(&a_0_raw, &a_1_raw)| (a_0_raw, a_1_raw));
            let output_raw = output_raw.unzip();

            let output0 = gate.load_witness(&mut ctx, output_raw.0);
            let output1 = gate.load_witness(&mut ctx, output_raw.1);
            let output0_assigned = AssignedCell::new(output0.value, output0.cell);
            let output1_assigned = AssignedCell::new(output1.value, output1.cell);
            let output_assigned = AssignedGoldilocksExtension([output0_assigned, output1_assigned]);
            *output.borrow_mut() = Some(output_assigned);

            Ok(())
        },
    )?;

    Ok(output.into_inner().unwrap())
}

#[cfg(test)]
mod tests {
    use halo2_base::{
        gates::range::RangeStrategy,
        halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit},
    };

    use crate::utils::{evm_verify, gen_evm_verifier, gen_pk, gen_proof, gen_srs};

    use super::*;

    const K: usize = 12;

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

            let range =
                RangeConfig::configure(meta, RangeStrategy::Vertical, &[1], &[0], 1, 15, 0, K); // 10k bytes
                                                                                                // RangeConfig::configure(meta, RangeStrategy::Vertical, &[2], &[1], 1, 15, 0, K); // 15k bytes
                                                                                                // RangeConfig::configure(meta, RangeStrategy::Vertical, &[1], &[6], 1, 15, 0, K); // invalid circuit
                                                                                                // RangeConfig::configure(meta, RangeStrategy::Vertical, &[5], &[6], 1, 15, 0, K); // exceed code size

            Self::Config { a, range }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let a = config.a;

            let value00 = Fr::from(1);
            let value01 = Fr::from(2);
            let value10 = Fr::from(3);
            let value11 = Fr::from(4);
            let output0 = Fr::from(181);
            let output1 = Fr::from(38);

            let value0 = AssignedGoldilocksExtension::assign(
                layouter.namespace(|| "assign value0"),
                a,
                [value00.into(), value01.into()].into(),
            )?;
            let value1 = AssignedGoldilocksExtension::assign(
                layouter.namespace(|| "assign value1"),
                a,
                [value10.into(), value11.into()].into(),
            )?;

            let mut ge_chip = GoldilocksExtensionChip::construct(config.range);

            // [181, 38] = 3 * [1, 2] * [3, 4] + 4 * [1, 2] = 3 * [59, 10] + [4, 8] = [177, 30] + [4, 8]
            let output_assigned = ge_chip.arithmetic(
                layouter.namespace(|| "arithmetic"),
                value10,
                value11,
                value0.clone(),
                value1,
                value0,
            )?;
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

    #[test]
    fn test_simple_circuit() {
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

    // #[derive(Clone)]
    // pub struct SimpleConfig {
    //     a: Column<Advice>,
    //     range: RangeConfig<Fr>,
    // }

    // #[derive(Default)]
    // pub struct SimpleCircuit;

    // impl Circuit<Fr> for SimpleCircuit {
    //     type Config = SimpleConfig;
    //     type FloorPlanner = SimpleFloorPlanner;

    //     fn without_witnesses(&self) -> Self {
    //         Self::default()
    //     }

    //     fn configure(
    //         meta: &mut halo2_base::halo2_proofs::plonk::ConstraintSystem<Fr>,
    //     ) -> Self::Config {
    //         let a = meta.advice_column();
    //         meta.enable_equality(a);

    //         let range =
    //             RangeConfig::configure(meta, RangeStrategy::Vertical, &[5], &[6], 1, 15, 0, K);

    //         Self::Config { a, range }
    //     }

    //     fn synthesize(
    //         &self,
    //         config: Self::Config,
    //         mut layouter: impl Layouter<Fr>,
    //     ) -> Result<(), Error> {
    //         let a = config.a;
    //         let gate = config.range.gate();

    //         let value00 = Fr::from(1);
    //         let value01 = Fr::from(2);

    //         let value0 = AssignedGoldilocksExtension::assign(
    //             layouter.namespace(|| "assign value0"),
    //             a,
    //             [value00.into(), value01.into()].into(),
    //         )?;

    //         simple_constraints(layouter, gate, value0)?;

    //         Ok(())
    //     }
    // }
}
