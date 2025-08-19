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
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    let polynomial_size = PolynomialSize(2048);
    let lwe_dimension = LweDimension(571);

    let param_list = [
        ("STD128B2'", DecompositionBaseLog(12), DecompositionLevelCount(2), DecompositionBaseLog(10), DecompositionLevelCount(3)),
        ("STD128B2", DecompositionBaseLog(13), DecompositionLevelCount(2), DecompositionBaseLog(10), DecompositionLevelCount(2)),
        ("STD128B3", DecompositionBaseLog(10), DecompositionLevelCount(3), DecompositionBaseLog(10), DecompositionLevelCount(2)),
    ];

    for param in param_list.iter() {
        let name = param.0;
        let br_decomp_base_log = param.1;
        let br_decomp_level_count = param.2;
        let swk_decomp_base_log = param.3;
        let swk_decomp_level_count= param.4;

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let ntru_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(5.38420863449573516845703125e-12), 0.0);
        let lwe_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(0.00077880859375), 0.0);

        let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

        let lwe_secret_key: LweSecretKeyOwned<Scalar> = allocate_and_generate_new_binary_lwe_secret_key(
            lwe_dimension,
            &mut secret_generator,
        );


        let ntru_cmux_bsk = allocate_and_generate_new_ntru_cmux_bootstrap_key(
            &lwe_secret_key,
            &ntru_secret_key,
            br_decomp_base_log,
            br_decomp_level_count,
            swk_decomp_base_log,
            swk_decomp_level_count,
            ntru_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut fourier_ntru_cmux_bsk = FourierNtruCMuxBootstrapKey::new(
            polynomial_size,
            br_decomp_base_log,
            br_decomp_level_count,
            swk_decomp_base_log,
            swk_decomp_level_count,
            ntru_cmux_bsk.input_lwe_dimension(),
            FftType::Vanilla,
        );

        convert_standard_ntru_cmux_bootstrap_key_to_fourier(&ntru_cmux_bsk, &mut fourier_ntru_cmux_bsk);

        let mut acc = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);
        let plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut acc,
            &plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        let mut lwe_in = LweCiphertext::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        encrypt_lwe_ciphertext(
            &lwe_secret_key,
            &mut lwe_in,
            Plaintext(Scalar::ZERO),
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut lwe_out = LweCiphertext::new(
            Scalar::ZERO,
            ntru_cmux_bsk.output_lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        group.bench_function(
            BenchmarkId::new(
                "NTRU CMux Bootstrap",
                format!("{name}"),
            ),
            |b| b.iter(|| {
                ntru_cmux_bootstrap_lwe_ciphertext(
                    black_box(&lwe_in),
                    black_box(&mut lwe_out),
                    black_box(&acc),
                    black_box(&fourier_ntru_cmux_bsk),
                );
            }),
        );
    }
}
