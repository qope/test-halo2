use std::cell::RefCell;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    halo2_proofs::{
        arithmetic::Field,
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        halo2curves::bn256::{Fr, G1Affine, G2Affine},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    },
    Context, ContextParams, QuantumCell,
};
use poseidon_circuit::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use rand::Rng;

use crate::merkle_tree::{calc_merkle_root, usize_to_vec, MerkleTree};

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const L: usize = 2;
pub const K: usize = 18;

#[derive(Clone)]
pub struct MyConfig {
    poseidon: Pow5Config<Fr, WIDTH, RATE>,
    a: Column<Advice>,
    gate: FlexGateConfig<Fr>,
}

#[derive(Default)]
pub struct MyCircuit;

impl Circuit<Fr> for MyCircuit {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
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
        let gate = config.gate;
        let a = config.a;

        let mut rng = rand::thread_rng();

        for _ in 0..150 {
            let height = 32;
            let mut tree = MerkleTree::new(height);

            let index = rng.gen_range(0..1 << height);
            let path = usize_to_vec(index, height);
            let leaf = [Fr::random(&mut rng), Fr::random(&mut rng)];
            tree.update(&path, leaf.clone());
            let proof = tree.prove(&path);
            let root_raw = calc_merkle_root(index, leaf, proof.clone());

            let leaf_assigned = [
                assign_val(layouter.namespace(|| "left"), a, leaf[0]).unwrap(),
                assign_val(layouter.namespace(|| "right"), a, leaf[1]).unwrap(),
            ];

            let proof_assigned = proof
                .iter()
                .map(|x| assign_val(layouter.namespace(|| "space"), a, *x).unwrap())
                .collect::<Vec<_>>();

            let index_assigend = assign_val(
                layouter.namespace(|| "index assign"),
                a,
                Fr::from(index as u64),
            )?;

            let root = calc_merkle_root_circuit(
                layouter.namespace(|| "hash"),
                chip.clone(),
                gate.clone(),
                proof_assigned,
                leaf_assigned,
                index_assigend,
            )?;

            root.value().assert_if_known(|&&x| x == root_raw);
        }

        Ok(())
    }
}

pub fn hash_circuit(
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

pub fn assign_val(
    mut layouter: impl Layouter<Fr>,
    column: Column<Advice>,
    val: Fr,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let a_outside = RefCell::new(None);
    layouter.assign_region(
        || "assign val",
        |mut region| {
            let a = region.assign_advice(|| "assign", column, 0, || Value::known(val))?;
            *a_outside.borrow_mut() = Some(a);
            Ok(())
        },
    )?;
    let a_value = a_outside.into_inner().unwrap();
    Ok(a_value)
}

pub fn merkle_level(
    mut layouter: impl Layouter<Fr>,
    chip: Pow5Chip<Fr, WIDTH, RATE>,
    gate: FlexGateConfig<Fr>,
    sibling: AssignedCell<Fr, Fr>,
    child: AssignedCell<Fr, Fr>,
    lr_bit: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let left = RefCell::new(None);
    let right = RefCell::new(None);
    let new_child = RefCell::new(None);
    let new_sibling = RefCell::new(None);
    let new_lr_bit = RefCell::new(None);

    layouter.assign_region(
        || "bit decompose",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
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
            let child = QuantumCell::Existing(&tmp_child);
            let sibling = QuantumCell::Existing(&tmp_sibling);
            let lr_bit = QuantumCell::Existing(&tmp_lr_bit);
            *left.borrow_mut() =
                Some(gate.select(&mut ctx, sibling.clone(), child.clone(), lr_bit.clone()));
            *right.borrow_mut() = Some(gate.select(&mut ctx, child, sibling, lr_bit));

            Ok(())
        },
    )?;

    // copy constraint
    layouter.assign_region(
        || "merkle_level copy constraint",
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
    let parent = hash_circuit(layouter.namespace(|| "normal hash"), chip, [left, right])?;

    Ok(parent)
}

pub fn calc_merkle_root_circuit(
    mut layouter: impl Layouter<Fr>,
    chip: Pow5Chip<Fr, WIDTH, RATE>,
    gate: FlexGateConfig<Fr>,
    siblings: Vec<AssignedCell<Fr, Fr>>,
    leaf: [AssignedCell<Fr, Fr>; 2],
    index: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let mut new_path = vec![];
    let new_index = RefCell::new(None);

    layouter.assign_region(
        || "merkle root calc",
        |region| {
            let mut ctx = Context::new(
                region,
                ContextParams {
                    max_rows: 1 << K,
                    num_context_ids: 1,
                    fixed_columns: gate.constants.clone(),
                },
            );
            let tmp_index =
                gate.load_witness(&mut ctx, index.value().and_then(|v| Value::known(*v)));
            *new_index.borrow_mut() = Some(tmp_index.clone());
            let path = gate.num_to_bits(&mut ctx, &tmp_index, siblings.len());
            for bit in path.into_iter() {
                new_path.push(bit);
            }
            Ok(())
        },
    )?;

    // copy constraint of index
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
        h = merkle_level(
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
