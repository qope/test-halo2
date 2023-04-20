use std::cell::RefCell;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        halo2curves::bn256::Fr,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    },
    Context, ContextParams,
};
use poseidon_circuit::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};

const WIDTH: usize = 3;
const RATE: usize = 2;
const L: usize = 2;
const K: usize = 17;

#[derive(Clone)]
struct MyConfig {
    poseidon: Pow5Config<Fr, WIDTH, RATE>,
    a: Column<Advice>,
    gate: FlexGateConfig<Fr>,
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

        let gate = FlexGateConfig::configure(meta, GateStrategy::Vertical, &[1], 1, 0, K);

        Self::Config { poseidon, a, gate }
    }

    fn synthesize(&self, config: MyConfig, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let a = config.a;
        let gate = config.gate;

        let input_val0 = assign_val(layouter.namespace(|| "assign 0"), a, Fr::one())?;
        let input_val1 = assign_val(layouter.namespace(|| "assign 1"), a, Fr::zero())?;
        let index = assign_val(layouter.namespace(|| "lr bit"), a, Fr::from(2))?;

        let hashed = calc_merkle_root(
            layouter.namespace(|| "hash"),
            chip,
            gate,
            vec![input_val0.clone(), input_val1.clone()],
            [input_val0, input_val1],
            index,
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

fn calc_merkle_root_level(
    mut layouter: impl Layouter<Fr>,
    chip: Pow5Chip<Fr, WIDTH, RATE>,
    gate: FlexGateConfig<Fr>,
    sibling: AssignedCell<Fr, Fr>,
    child: AssignedCell<Fr, Fr>,
    lr_bit: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let fixed_columns = gate.constants.clone();

    let left = RefCell::new(None);
    let right = RefCell::new(None);
    let new_child = RefCell::new(None);
    let new_sibling = RefCell::new(None);
    let new_lr_bit = RefCell::new(None);
    layouter.assign_region(
        || "a",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: fixed_columns.clone(),
                },
            );

            let tmp_child =
                gate.load_witness(&mut ctx, child.value().and_then(|v| Value::known(*v)));
            *new_child.borrow_mut() = Some(tmp_child.clone());
            let tmp_sibling =
                gate.load_witness(&mut ctx, sibling.value().and_then(|v| Value::known(*v)));
            *new_sibling.borrow_mut() = Some(tmp_sibling.clone());
            let tmp_lr_bit =
                gate.load_witness(&mut ctx, lr_bit.value().and_then(|v| Value::known(*v)));
            *new_lr_bit.borrow_mut() = Some(tmp_lr_bit.clone());

            // XXX: AssignedCell -> AssignedValue
            let child = halo2_base::QuantumCell::Existing(&tmp_child);
            let sibling = halo2_base::QuantumCell::Existing(&tmp_sibling);
            let lr_bit = halo2_base::QuantumCell::Existing(&tmp_lr_bit);
            *left.borrow_mut() =
                Some(gate.select(&mut ctx, child.clone(), sibling.clone(), lr_bit.clone()));
            *right.borrow_mut() = Some(gate.select(&mut ctx, sibling, child, lr_bit));

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "a",
        |mut region| {
            region.constrain_equal(new_child.clone().into_inner().unwrap().cell(), child.cell())?;
            region.constrain_equal(
                new_sibling.clone().into_inner().unwrap().cell(),
                sibling.cell(),
            )?;
            region.constrain_equal(
                new_lr_bit.clone().into_inner().unwrap().cell(),
                lr_bit.cell(),
            )?;

            Ok(())
        },
    )?;

    let left_assigned_value = left.into_inner().unwrap();
    let right_assigned_value = right.into_inner().unwrap();
    let left = AssignedCell::new(left_assigned_value.value, left_assigned_value.cell());
    let right = AssignedCell::new(right_assigned_value.value, right_assigned_value.cell());
    let parent = hash_circuit(layouter.namespace(|| "right"), chip, [left, right])?;

    Ok(parent)
}

fn calc_merkle_root(
    mut layouter: impl Layouter<Fr>,
    chip: Pow5Chip<Fr, WIDTH, RATE>,
    gate: FlexGateConfig<Fr>,
    siblings: Vec<AssignedCell<Fr, Fr>>,
    leaf: [AssignedCell<Fr, Fr>; 2],
    index: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let fixed_columns = gate.constants.clone();

    let mut new_path = vec![];
    let new_index = RefCell::new(None);

    layouter.assign_region(
        || "a",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: fixed_columns.clone(),
                },
            );

            let tmp_index =
                gate.load_witness(&mut ctx, index.value().and_then(|v| Value::known(*v)));
            *new_index.borrow_mut() = Some(tmp_index.clone());

            let path = gate.num_to_bits(&mut ctx, &tmp_index, siblings.len());
            for bit in path.into_iter().rev() {
                new_path.push(bit);
            }

            Ok(())
        },
    )?;

    layouter.assign_region(
        || "copy index",
        |mut region| {
            region.constrain_equal(new_index.clone().into_inner().unwrap().cell(), index.cell())?;

            Ok(())
        },
    )?;

    let mut h = hash_circuit(layouter.namespace(|| "hash"), chip.clone(), leaf)?;
    for (i, s) in siblings.iter().enumerate() {
        let lr_bit = AssignedCell::new(new_path[i].value, new_path[i].cell());
        h = calc_merkle_root_level(
            layouter.namespace(|| format!("level {i}")),
            chip.clone(),
            gate.clone(),
            s.clone(),
            h,
            lr_bit,
        )?;
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
