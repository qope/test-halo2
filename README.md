# Halo2 Verifier for Plonky2

## How to test

### Compile Verifier

```sh
cargo test -r test_fri_combine_initial_circuit -- --nocapture
```

```sh
solc --bin --yul verifier.yul
```
