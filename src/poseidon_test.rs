use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use poseidon_circuit::poseidon::{
    primitives::{ConstantLength, Spec},
    Hash, Pow5Chip, Pow5Config,
};

struct HashCircuit<S: Spec<Fr, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
{
    message: Option<[Fr; L]>,
    output: Option<Fr>,
    _spec: PhantomData<S>,
}

impl<S: Spec<Fr, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fr>
    for HashCircuit<S, WIDTH, RATE, L>
{
    type Config = Pow5Config<Fr, WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: None,
            output: None,
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Pow5Config<Fr, WIDTH, RATE> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        Pow5Chip::configure::<S>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        )
    }

    fn synthesize(
        &self,
        config: Pow5Config<Fr, WIDTH, RATE>,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.state[i],
                        0,
                        || {
                            if let Some(v) = value {
                                Value::known(v)
                            } else {
                                Value::unknown()
                            }
                        },
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected_var = region.assign_advice(
                    || "load output",
                    config.state[0],
                    0,
                    || {
                        if let Some(v) = self.output {
                            Value::known(v)
                        } else {
                            Value::unknown()
                        }
                    },
                )?;
                region.constrain_equal(output.cell(), expected_var.cell())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use poseidon_circuit::poseidon::primitives::{ConstantLength, P128Pow5T3};

    use halo2_base::halo2_proofs::{arithmetic::Field, dev::MockProver, halo2curves::bn256::Fr};

    use crate::poseidon_test::HashCircuit;

    #[test]
    fn test_poseidon_hash() {
        use poseidon_circuit::poseidon::primitives::Hash as NativeHash;
        type OrchardNullifier = P128Pow5T3<Fr>;
        use rand::rngs::OsRng;

        let rng = OsRng;

        let message = [Fr::random(rng), Fr::random(rng)];
        let output =
            NativeHash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

        let k = 6;
        let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
            message: Some(message),
            output: Some(output),
            _spec: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }
}
