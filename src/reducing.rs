use std::borrow::Borrow;

use halo2_base::{
    gates::range::RangeConfig,
    halo2_proofs::{
        circuit::Layouter,
        halo2curves::bn256::Fr,
        plonk::{Advice, Column},
    },
};

use crate::field::{
    add_extension, exp_u64_extension, mul_extension, zero_assigned, AssignedGoldilocksExtension,
    GoldilocksExtension,
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
    base: AssignedGoldilocksExtension,
    count: u64,
}

impl AssignedReducingFactor {
    pub fn new(base: AssignedGoldilocksExtension) -> Self {
        Self { base, count: 0 }
    }

    /// Reduces a vector of `ExtensionTarget`s using `ReducingExtensionGate`s.
    pub fn reduce(
        &mut self,
        mut layouter: impl Layouter<Fr>,
        range: &RangeConfig<Fr>,
        advice_column: Column<Advice>,
        terms: &[AssignedGoldilocksExtension], // Could probably work with a `DoubleEndedIterator` too.
    ) -> AssignedGoldilocksExtension {
        self.reduce_arithmetic(
            layouter.namespace(|| "reduce arithmetic"),
            range,
            advice_column,
            terms,
        )
    }

    pub fn shift(
        &mut self,
        mut layouter: impl Layouter<Fr>,
        range: &RangeConfig<Fr>,
        advice_column: Column<Advice>,
        x: AssignedGoldilocksExtension,
    ) -> AssignedGoldilocksExtension {
        let exp = exp_u64_extension(
            layouter.namespace(|| "exp"),
            range,
            advice_column,
            self.base.clone(),
            self.count,
        )
        .unwrap();

        self.count = 0;
        mul_extension(layouter.namespace(|| "multiply exp by x"), range, exp, x).unwrap()
    }

    /// Reduces a vector of `ExtensionTarget`s using `ArithmeticGate`s.
    fn reduce_arithmetic(
        &mut self,
        mut layouter: impl Layouter<Fr>,
        range: &RangeConfig<Fr>,
        advice_column: Column<Advice>,
        terms: &[AssignedGoldilocksExtension],
    ) -> AssignedGoldilocksExtension {
        let zero = zero_assigned(layouter.namespace(|| "zero"), advice_column).unwrap();
        self.count += terms.len() as u64;
        terms.iter().rev().fold(
            AssignedGoldilocksExtension([zero.clone(), zero]),
            |acc, et| {
                // builder.mul_add_extension(self.base, acc, et)
                let tmp =
                    mul_extension(layouter.namespace(|| "mul"), range, self.base.clone(), acc)
                        .unwrap();
                add_extension(layouter.namespace(|| "add"), range, tmp, et.clone()).unwrap()
            },
        )
    }
}
