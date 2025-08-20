use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::entities::*;
use tfhe::ntru::algorithms::*;

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_ntru_rev_trace,
);
criterion_main!(benches);

fn criterion_benchmark_ntru_rev_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTRU RevHomTrace");

    type Scalar = u64;
    let polynomial_size = PolynomialSize(2048);

    let param_list = [
        ("STD128B2'", DecompositionBaseLog(8), DecompositionLevelCount(4), 39),
        ("STD128B2", DecompositionBaseLog(9), DecompositionLevelCount(4), 45),
        ("STD128B3", DecompositionBaseLog(9), DecompositionLevelCount(4), 45),
    ];

    for param in param_list.iter() {
        let name = param.0;
        let tr_decomp_base_log = param.1;
        let tr_decomp_level_count = param.2;
        let power = param.3;

        let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(power).unwrap();

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let ntru_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(5.38420863449573516845703125e-12), 0.0);

        let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

        let ntru_trace_key = allocate_and_generate_new_ntru_trace_key(
            &ntru_secret_key,
            tr_decomp_base_log,
            tr_decomp_level_count,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        let mut fourier_ntru_trace_key = FourierNtruTraceKey::new(
            polynomial_size,
            tr_decomp_base_log,
            tr_decomp_level_count,
            FftType::Vanilla,
        );
        convert_standard_ntru_trace_key_to_fourier(
            &ntru_trace_key,
            &mut fourier_ntru_trace_key,
        );

        let mut ntru_ciphertext = NtruCiphertext::new(
            Scalar::ZERO,
            polynomial_size,
            ciphertext_modulus,
        );
        let plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut ntru_ciphertext,
            &plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        let mut ntru_trace_ciphertext = NtruCiphertext::new(
            Scalar::ZERO,
            polynomial_size,
            ciphertext_modulus,
        );

        group.bench_function(
            BenchmarkId::new(
                "NTRU RevHomTrace",
                format!("{name}"),
            ),
            |b| b.iter(|| {
                rev_trace_ntru_ciphertext(
                    black_box(&fourier_ntru_trace_key),
                    black_box(&ntru_ciphertext),
                    black_box(&mut ntru_trace_ciphertext),
                );
            }),
        );
    }
}
