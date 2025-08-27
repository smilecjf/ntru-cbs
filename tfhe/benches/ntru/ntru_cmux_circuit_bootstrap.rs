use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::entities::*;
use tfhe::ntru::algorithms::*;

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_ntru_cmux_bootstrap,
);
criterion_main!(benches);

fn criterion_benchmark_ntru_cmux_bootstrap(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTRU CMux Bootstrap");

    type Scalar = u64;
    type SmallScalar = u32;

    let small_log_modulus = 12;
    let small_ciphertext_modulus = CiphertextModulus::<SmallScalar>::try_new_power_of_2(small_log_modulus).unwrap();

    let param_list = [
        (NTRU_CMUX_STD128B2, DecompositionBaseLog(3), DecompositionLevelCount(4), LutCountLog(2)),
        (NTRU_CMUX_STD128B3, DecompositionBaseLog(3), DecompositionLevelCount(4), LutCountLog(2)),
    ];

    for (param, decomp_base_log, decomp_level_count, log_lut_count) in param_list.iter() {
        let name = param.name();
        let polynomial_size = param.polynomial_size();
        let lwe_dimension = param.input_lwe_dimension();
        let log_modulus = param.log_output_modulus().0;

        let decomp_base_log = *decomp_base_log;
        let decomp_level_count = *decomp_level_count;
        let log_lut_count = *log_lut_count;

        let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_modulus).unwrap();

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let ntru_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(param.torus_ntru_std_dev()), 0.0);
        let rlwe_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(param.torus_rlwe_std_dev()), 0.0);
        let lwe_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(param.torus_lwe_std_dev()), 0.0);

        let ntru_secret_key = allocate_and_generate_new_gaussian_ntru_secret_key(
            polynomial_size,
            ciphertext_modulus,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        let rlwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            GlweDimension(1),
            polynomial_size,
            &mut secret_generator,
        );

        let lwe_secret_key: LweSecretKeyOwned<SmallScalar> = allocate_and_generate_new_binary_lwe_secret_key(
            lwe_dimension,
            &mut secret_generator,
        );

        let ntru_cmux_cbs_key = allocate_and_generate_new_ntru_cmux_circuit_bootstrap_key(
            &lwe_secret_key,
            &ntru_secret_key,
            &rlwe_secret_key,
            param.br_decomp_base_log(),
            param.br_decomp_level_count(),
            param.br_decomp_base_log(),
            param.br_decomp_level_count(),
            param.tr_decomp_base_log(),
            param.tr_decomp_level_count(),
            param.ksk_decomp_base_log(),
            param.ksk_decomp_level_count(),
            param.ss_decomp_base_log(),
            param.ss_decomp_level_count(),
            ntru_noise_distribution,
            rlwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut fourier_ntru_cmux_cbs_key = FourierNtruCMuxCircuitBootstrapKey::new(
            polynomial_size,
            param.input_lwe_dimension(),
            param.br_decomp_base_log(),
            param.br_decomp_level_count(),
            FftType::Vanilla,
            param.br_decomp_base_log(),
            param.br_decomp_level_count(),
            FftType::Vanilla,
            param.tr_decomp_base_log(),
            param.tr_decomp_level_count(),
            FftType::Vanilla,
            param.ksk_decomp_base_log(),
            param.ksk_decomp_level_count(),
            FftType::Vanilla,
            param.ss_decomp_base_log(),
            param.ss_decomp_level_count(),
            FftType::Vanilla,
        );
        convert_standard_ntru_cmux_circuit_bootstrap_key_to_fourier(&ntru_cmux_cbs_key, &mut fourier_ntru_cmux_cbs_key);

        let mut lwe_in = LweCiphertext::new(
            SmallScalar::ZERO,
            param.input_lwe_dimension().to_lwe_size(),
            small_ciphertext_modulus,
        );
        encrypt_lwe_ciphertext(
            &lwe_secret_key,
            &mut lwe_in,
            Plaintext(0),
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut out = GgswCiphertext::new(
            Scalar::ZERO,
            GlweSize(2),
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        );

        group.bench_function(
            BenchmarkId::new(
                "NTRU CMux Circuit Bootstrap",
                format!("{name}"),
            ),
            |b| b.iter(|| {
                ntru_cmux_circuit_bootstrap_lwe_ciphertext(
                    black_box(&lwe_in),
                    black_box(&mut out),
                    black_box(&fourier_ntru_cmux_cbs_key),
                    black_box(log_lut_count),
                );
            }),
        );
    }
}
