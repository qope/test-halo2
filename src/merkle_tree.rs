use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use poseidon_circuit::poseidon::primitives::{ConstantLength, Hash as NativeHash, P128Pow5T3};
use std::collections::HashMap;

fn native_hash(input: [Fr; 2]) -> Fr {
    NativeHash::<_, P128Pow5T3<Fr>, ConstantLength<2>, 3, 2>::init().hash(input)
}

#[derive(Debug)]
pub struct MerkleTree {
    height: usize,
    nodes: HashMap<Vec<bool>, Node>,
    zero_hashes: Vec<Fr>,
}

#[derive(Debug)]
pub enum Node {
    InnerNode { left: Fr, right: Fr },
    Leaf { value: [Fr; 2] },
}

impl Node {
    fn hash(&self) -> Fr {
        match self {
            Node::InnerNode { left, right } => native_hash([*left, *right]),
            Node::Leaf { value } => native_hash(*value),
        }
    }
}

impl MerkleTree {
    pub fn new(height: usize) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let node = Node::Leaf {
            value: [Fr::zero(); 2],
        };
        let mut h = node.hash();
        zero_hashes.push(h);
        for _ in 0..height {
            let node = Node::InnerNode { left: h, right: h };
            h = node.hash();
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let nodes: HashMap<Vec<bool>, Node> = HashMap::new();

        Self {
            height,
            nodes,
            zero_hashes,
        }
    }

    pub fn get_leaf(&self, path: &Vec<bool>) -> [Fr; 2] {
        assert_eq!(path.len(), self.height);
        match self.nodes.get(path) {
            Some(Node::Leaf { value }) => value.clone(),
            _ => [Fr::zero(); 2],
        }
    }

    pub fn get_node_hash(&self, path: &Vec<bool>) -> Fr {
        assert!(path.len() <= self.height);
        match self.nodes.get(path) {
            Some(node) => node.hash(),
            None => self.zero_hashes[path.len()],
        }
    }

    pub fn get_root(&self) -> Fr {
        self.get_node_hash(&vec![])
    }

    pub fn get_sibling_hash(&self, path: &Vec<bool>) -> Fr {
        assert!(path.len() > 0);
        // TODO maybe more elegant code exists
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];
        self.get_node_hash(&path)
    }

    pub fn update(&mut self, path: &Vec<bool>, value: [Fr; 2]) {
        assert_eq!(path.len(), self.height);
        let mut path = path.clone();

        self.nodes.insert(path.clone(), Node::Leaf { value });

        loop {
            let hash = self.get_node_hash(&path);
            let parent_path = path[0..path.len() - 1].to_vec();
            self.nodes.insert(
                parent_path,
                if path[path.len() - 1] {
                    Node::InnerNode {
                        left: self.get_sibling_hash(&path),
                        right: hash,
                    }
                } else {
                    Node::InnerNode {
                        left: hash,
                        right: self.get_sibling_hash(&path),
                    }
                },
            );
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }
    }

    pub fn prove(&self, path: &Vec<bool>) -> Vec<Fr> {
        assert_eq!(path.len(), self.height);
        let mut path = path.clone();
        let mut siblings = vec![];
        loop {
            siblings.push(self.get_sibling_hash(&path));
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }
        siblings
    }
}

pub fn usize_to_vec(x: usize, length: usize) -> Vec<bool> {
    let mut x = x;
    let mut v = vec![];
    for _ in 0..length {
        v.push((x & 1) == 1);
        x >>= 1;
    }
    v.reverse();
    v
}

pub fn calc_merkle_root(index: usize, leaf: [Fr; 2], siblings: Vec<Fr>) -> Fr {
    let mut position = usize_to_vec(index, siblings.len());
    position.reverse();
    let mut h = native_hash(leaf);
    for (i, s) in siblings.iter().enumerate() {
        if position[i] {
            h = native_hash([*s, h]);
        } else {
            h = native_hash([h, *s]);
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::arithmetic::Field;
    use rand::Rng;

    #[test]
    fn test_calc_merkle_root() {
        let input0 = Fr::one();
        let input1 = Fr::zero();
        let proof = vec![input0, input1];
        let leaf = [input0, input1];
        let index = 2;
        let new_root = calc_merkle_root(index, leaf, proof);
        let mut new_root_bytes = new_root.to_bytes();
        new_root_bytes.reverse();
        assert_eq!(
            hex::encode(new_root_bytes),
            "23caa5cc15e79f42039db5057260ad32e0b21318ef641ef7713666c7d47c4d30"
        );
    }

    #[test]
    fn test_merkle_tree() {
        let mut rng = rand::thread_rng();
        let height = 32;
        let mut tree = MerkleTree::new(height);

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let path = usize_to_vec(index, height);
            let new_leaf = [Fr::random(&mut rng), Fr::random(&mut rng)];
            tree.update(&path, new_leaf.clone());
            let proof = tree.prove(&path);
            assert_eq!(tree.get_leaf(&path), new_leaf.clone());
            let new_root = calc_merkle_root(index, new_leaf, proof);
            let expected_root = tree.get_root();
            assert!(new_root == expected_root);
        }
    }
}
