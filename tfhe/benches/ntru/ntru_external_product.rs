use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::entities::*;
use tfhe::ntru::algorithms::*;

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_ntru_external_product,
);
criterion_main!(benches);

fn criterion_benchmark_ntru_external_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTRU external product");

    type Scalar = u64;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    let polynomial_size = PolynomialSize(2048);

    let param_list = [
        (DecompositionBaseLog(12), DecompositionLevelCount(2)),
        (DecompositionBaseLog(10), DecompositionLevelCount(3)),
        (DecompositionBaseLog(8), DecompositionLevelCount(4)),
    ];

    for param in param_list.iter() {
        let decomp_base_log = param.0;
        let decomp_level_count = param.1;

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let ntru_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);

        let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

        // NTRU input parameter
        let log_message_modulus = 4;
        let message_modulus = Scalar::ONE << log_message_modulus;
        let delta = Scalar::ONE << (Scalar::BITS - log_message_modulus);

        let mut input_plaintext_list = PlaintextList::new(
            Scalar::ZERO,
            PlaintextCount(polynomial_size.0),
        );

        let mut ntru_ciphertext = NtruCiphertext::new(
            Scalar::ZERO,
            polynomial_size,
            ciphertext_modulus,
        );

        let mut ngsw_ciphertext = NgswCiphertext::new(
            Scalar::ZERO,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        );

        let mut fourier_ngsw_ciphertext = FourierNgswCiphertext::new(
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            FftType::Vanilla,
        );

        let a = rand::thread_rng().gen_range(0..=Scalar::ONE);
        encrypt_constant_ngsw_ciphertext(
            &ntru_secret_key,
            &mut ngsw_ciphertext,
            Cleartext(a),
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        for i in 0..polynomial_size.0 {
            let rand_num = rand::thread_rng().gen_range(0..message_modulus);
            input_plaintext_list.as_mut()[i] = rand_num * delta;
        }

        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut ntru_ciphertext,
            &input_plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        convert_standard_ngsw_ciphertext_to_fourier(&ngsw_ciphertext, &mut fourier_ngsw_ciphertext);

        let mut output = NtruCiphertext::new(
            Scalar::ZERO,
            polynomial_size,
            ciphertext_modulus,
        );

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        let mut computation_buffers = ComputationBuffers::new();
        computation_buffers.resize(
            add_ntru_external_product_assign_scratch::<Scalar>(
                polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = computation_buffers.stack();

        group.bench_function(
            BenchmarkId::new(
                "NTRU external product",
                format!("decomp level count {}", decomp_level_count.0),
            ),
            |b| b.iter(|| {
                add_ntru_external_product_assign(
                    black_box(&mut output.as_mut_view()),
                    black_box(fourier_ngsw_ciphertext.as_view()),
                    black_box(ntru_ciphertext.as_view()),
                    black_box(fft),
                    black_box(stack),
                );
            }),
        );
    }
}
