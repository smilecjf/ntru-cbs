use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::Instant;

type Scalar = u64;

mod utils;
use utils::*;

pub fn test_external_product(
    polynomial_size: PolynomialSize,
    log_modulus: usize,
    ntru_std_dev: f64,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
) {
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_modulus).unwrap();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(ntru_std_dev / 2.0.powi(log_modulus as i32)), 0.0);

    let ntru_secret_key = allocate_and_generate_new_gaussian_ntru_secret_key(polynomial_size, ciphertext_modulus, ntru_noise_distribution, &mut encryption_generator);

    // NTRU input parameter
    let log_message_modulus = 4;
    let message_modulus = Scalar::ONE << log_message_modulus;
    let delta = Scalar::ONE << (log_modulus - log_message_modulus);

    let mut input_message_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );
    let mut input_plaintext_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );
    let mut correct_val_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );
    let mut decrypted_plaintext_list = PlaintextList::new(
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
        fft_type,
    );

    let num_test = 10;
    for idx in 1..=num_test {
        let a = rand::thread_rng().gen_range(0..Scalar::ONE << 2);
        encrypt_constant_ngsw_ciphertext(
            &ntru_secret_key,
            &mut ngsw_ciphertext,
            Cleartext(a),
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        for i in 0..polynomial_size.0 {
            let rand_num = rand::thread_rng().gen_range(0..message_modulus);
            input_message_list.as_mut()[i] = rand_num;
            input_plaintext_list.as_mut()[i] = rand_num * delta;
            correct_val_list.as_mut()[i] = (rand_num * a) % message_modulus;
        }

        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut ntru_ciphertext,
            &input_plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
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

        convert_standard_ngsw_ciphertext_to_fourier(&ngsw_ciphertext, &mut fourier_ngsw_ciphertext);

        let mut output = NtruCiphertext::new(
            Scalar::ZERO,
            polynomial_size,
            ciphertext_modulus,
        );

        let now = Instant::now();
        add_ntru_external_product_assign(
            &mut output.as_mut_view(),
            fourier_ngsw_ciphertext.as_view(),
            ntru_ciphertext.as_view(),
            fft,
            stack,
        );
        let time = now.elapsed();

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &output,
            &mut decrypted_plaintext_list,
        );

        let max_err = get_max_error(
            &decrypted_plaintext_list,
            &correct_val_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );

        println!(
            "[Test {idx}] NGSW input: {a}, time: {} µs, max error: {:.3} bits",
            time.as_micros(),
            (max_err as f64).log2(),
        );
    }
}

pub fn main() {
    let polynomial_size = PolynomialSize(2048);

    let param_list = [
        (polynomial_size, 39, 2.96, DecompositionBaseLog(12), DecompositionLevelCount(2), FftType::Vanilla),
        (polynomial_size, 39, 2.96, DecompositionBaseLog(12), DecompositionLevelCount(2), FftType::Split(20)),
    ];
    for param in param_list {
        let polynomial_size = param.0;
        let log_modulus = param.1;
        let ntru_std_dev = param.2;
        let decomp_base_log = param.3;
        let decomp_level_count = param.4;
        let fft_type = param.5;

        println!(
            "N: {}, Q: 2^{}, std_dev: {} (= {} in torus), B: 2^{}, l: {}, FftType: {:?}",
            polynomial_size.0,
            log_modulus,
            ntru_std_dev,
            ntru_std_dev / 2.0.powi(log_modulus as i32),
            decomp_base_log.0,
            decomp_level_count.0,
            fft_type,
        );
        test_external_product(polynomial_size, log_modulus, ntru_std_dev, decomp_base_log, decomp_level_count, fft_type);
        println!();
    }
}
