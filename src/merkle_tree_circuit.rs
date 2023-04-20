use std::{cell::RefCell, marker::PhantomData};

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
        halo2curves::bn256::Fr,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    },
    AssignedValue, Context, ContextParams,
};
use poseidon_circuit::poseidon::{
    primitives::{ConstantLength, P128Pow5T3, Spec},
    Hash, Pow5Chip, Pow5Config,
};

use crate::merkle_tree::usize_to_vec;

const WIDTH: usize = 3;
const RATE: usize = 2;
const L: usize = 2;
const K: usize = 17;

#[derive(Clone)]
struct MyConfig {
    poseidon: Pow5Config<Fr, WIDTH, RATE>,
    a: Column<Advice>,
}

struct MyCircuit;

impl Circuit<Fr> for MyCircuit {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self
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

        Self::Config { poseidon, a }
    }

    fn synthesize(&self, config: MyConfig, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let a = config.a;

        let input_val0 = assign_val(layouter.namespace(|| "assign 0"), a, Fr::one())?;
        let input_val1 = assign_val(layouter.namespace(|| "assign 1"), a, Fr::zero())?;

        let hashed = hash_circuit(
            layouter.namespace(|| "hash"),
            chip,
            [input_val0, input_val1],
        )?;

        dbg!(hashed);

        Ok(())
    }
}

fn hash_circuit(
    mut layouter: impl Layouter<Fr>,
    chip: Pow5Chip<Fr, WIDTH, RATE>,
    input: [AssignedCell<Fr, Fr>; L],
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let hasher = Hash::<_, _, P128Pow5T3<Fr>, ConstantLength<L>, WIDTH, RATE>::init(
        chip,
        layouter.namespace(|| "init"),
    )?;
    let output = hasher.hash(layouter.namespace(|| "output"), input)?;
    Ok(output)
}

fn select(ctx: &mut Context<Fr>, gate: FlexGateConfig<Fr>) {
    let a = gate.load_constant(ctx, Fr::one());
    let a_cell = a.cell;

    // let a_assigend: AssignedCell<Fr, Fr> = a_cell.into();
}

fn assign_val(
    mut layouter: impl Layouter<Fr>,
    column: Column<Advice>,
    val: Fr,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let a_outside = RefCell::new(None);
    layouter.assign_region(
        || "a",
        |mut region| {
            let a = region.assign_advice(|| "assign", column, 0, || Value::known(val))?;
            *a_outside.borrow_mut() = Some(a);
            Ok(())
        },
    )?;
    let a_value = a_outside.into_inner().unwrap();
    Ok(a_value)
}

fn calc_merkle_root(
    mut layouter: impl Layouter<Fr>,
    chip: Pow5Chip<Fr, WIDTH, RATE>,
    siblings: Vec<AssignedCell<Fr, Fr>>,
    leaf: [AssignedCell<Fr, Fr>; 2],
    index: usize,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let mut path = usize_to_vec(index, siblings.len());
    path.reverse();

    let mut h = hash_circuit(layouter.namespace(|| "hash"), chip.clone(), leaf)?;
    for (i, s) in siblings.iter().enumerate() {
        if path[i] {
            h = hash_circuit(layouter.namespace(|| "right"), chip.clone(), [s.clone(), h])?;
        } else {
            h = hash_circuit(layouter.namespace(|| "left"), chip.clone(), [h, s.clone()])?;
        }
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::dev::MockProver;

    use super::*;

    #[test]
    fn test_merkle_tree_circuit() {
        let circuit = MyCircuit;
        MockProver::run(K as u32, &circuit, vec![])
            .unwrap()
            .assert_satisfied();
    }
}
