use std::borrow::Borrow;

use halo2_base::{
    halo2_proofs::{
        circuit::Layouter,
        halo2curves::bn256::Fr,
        plonk::{Advice, Column, Error},
    },
};

use crate::field::{
    zero_assigned, AssignedGoldilocksExtension, GoldilocksExtension, GoldilocksExtensionChip,
};

#[derive(Copy, Clone, Debug)]
pub struct ReducingFactor {
    base: GoldilocksExtension,
    count: u64,
}

impl ReducingFactor {
    pub fn new(base: GoldilocksExtension) -> Self {
        Self { base, count: 0 }
    }

    fn mul(&mut self, x: GoldilocksExtension) -> GoldilocksExtension {
        self.count += 1;
        self.base * x
    }

    pub fn reduce(
        &mut self,
        iter: impl DoubleEndedIterator<Item = impl Borrow<GoldilocksExtension>>,
    ) -> GoldilocksExtension {
        iter.rev().fold(GoldilocksExtension::zero(), |acc, x| {
            self.mul(acc) + *x.borrow()
        })
    }

    pub fn shift(&mut self, x: GoldilocksExtension) -> GoldilocksExtension {
        let tmp = self.base.exp_u64(self.count) * x;
        self.count = 0;
        tmp
    }
}

#[derive(Clone, Debug)]
pub struct AssignedReducingFactor {
    pub ge_chip: GoldilocksExtensionChip<Fr>,
    base: AssignedGoldilocksExtension,
    count: u64,
}

impl AssignedReducingFactor {
    pub fn new(ge_chip: GoldilocksExtensionChip<Fr>, base: AssignedGoldilocksExtension) -> Self {
        Self {
            ge_chip,
            base,
            count: 0,
        }
    }

    /// Reduces a vector of `ExtensionTarget`s using `ReducingExtensionGate`s.
    pub fn reduce(
        &mut self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        terms: &[AssignedGoldilocksExtension], // Could probably work with a `DoubleEndedIterator` too.
    ) -> Result<AssignedGoldilocksExtension, Error> {
        self.reduce_arithmetic(
            layouter.namespace(|| "reduce arithmetic"),
            advice_column,
            terms,
        )
    }

    pub fn shift(
        &mut self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        x: AssignedGoldilocksExtension,
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let exp = self.ge_chip
            .exp_u64(
                layouter.namespace(|| "exp"),
                advice_column,
                self.base.clone(),
                self.count,
            )?;

        self.count = 0;

        self.ge_chip
            .mul(layouter.namespace(|| "multiply exp by x"), exp, x)
    }

    /// Reduces a vector of `ExtensionTarget`s using `ArithmeticGate`s.
    fn reduce_arithmetic(
        &mut self,
        mut layouter: impl Layouter<Fr>,
        advice_column: Column<Advice>,
        terms: &[AssignedGoldilocksExtension],
    ) -> Result<AssignedGoldilocksExtension, Error> {
        let zero = zero_assigned(layouter.namespace(|| "zero"), advice_column)?;
        self.count += terms.len() as u64;
        terms.iter().rev().fold(
            Ok(AssignedGoldilocksExtension([zero.clone(), zero])),
            |acc, et| {
                // builder.mul_add_extension(self.base, acc, et)
                let tmp = self.ge_chip
                    .mul(layouter.namespace(|| "mul"), self.base.clone(), acc?)?;

                self.ge_chip
                    .add(layouter.namespace(|| "add"), tmp, et.clone())
            },
        )
    }
}
