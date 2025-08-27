# NTRU-based Circuit Bootstrapping
This is an implementation of 'NTRU-based Circuit Bootstrapping' based on [TFHE-rs](https://github.com/zama-ai/tfhe-rs) library.
The added NTRU implementation source codes are given in [tfhe/src/ntru](./tfhe/src/ntru/).
Test and benchmarks are given in [tfhe/tests/ntru](./tfhe/tests/ntru/) and [tfhe/benches/ntru](./tfhe/benches/ntru/).

## Contents
We implement:
- tests for
  - NTRU-based bootstrapping: [ntru_cmux_bootstrap](tfhe/tests/ntru/ntru_cmux_bootstrap_mod_power_of_two.rs)
  - NTRU-based RevHomtrace: [ntru_rev_trace](tfhe/tests/ntru/ntru_rev_trace_mod_power_of_two.rs)
  - NTRU-based circuit-bootstrapping: [ntru_cmux_circuit_bootstrap](tfhe/tests/ntru/ntru_cmux_circuit_bootstrap_mod_power_of_two.rs)
- benchmarks for
  - NTRU-based bootstrapping: [ntru_cmux_bootstrap](tfhe/benches/ntru/ntru_cmux_bootstrap.rs)
  - NTRU-based RevHomTrace: [ntru_rev_trace](tfhe/benches/ntru/ntru_rev_trace.rs)
  - NTRU-based circuit bootstrapping: [ntru_cmux_circuit_bootstrap](tfhe/benches/ntru/ntru_cmux_circuit_bootstrap.rs)

## How to Use
First, move to [tfhe](tfhe) directory. Then, run the following command.
- test: `cargo test --release --test 'test_name'`
- bench: `cargo bench --bench 'benchmark_name'`
    - To use AVX512: `cargo +nightly bench --bench 'benchamrk_name' --features=nightly-avx512`