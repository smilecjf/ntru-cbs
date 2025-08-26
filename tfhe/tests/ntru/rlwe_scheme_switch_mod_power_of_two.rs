use rand::Rng;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_mul;
use tfhe::core_crypto::prelude::slice_algorithms::*;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::Instant;

type Scalar = u64;

mod utils;
use utils::*;

pub fn test_rlwe_scheme_switch(
    polynomial_size: PolynomialSize,
    log_modulus: usize,
    rlwe_std_dev: f64,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
) {
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_modulus).unwrap();
    let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let rlwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(rlwe_std_dev / 2.0.powi(log_modulus as i32)), 0.0);
    let rlwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(GlweDimension(1), polynomial_size, &mut secret_generator);

    let rlwe_sk_poly = rlwe_secret_key.as_polynomial_list();
    let rlwe_sk_poly = rlwe_sk_poly.get(0);

    let rlwe_ss_key = allocate_and_generate_new_rlwe_scheme_switch_key(
        &rlwe_secret_key,
        decomp_base_log,
        decomp_level_count,
        rlwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_rlwe_ss_key = FourierRlweSchemeSwitchKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        fft_type,
    );
    convert_standard_rlwe_scheme_switch_key_to_fourier(
        &rlwe_ss_key,
        &mut fourier_rlwe_ss_key,
    );

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
    let mut scaled_input_plaintext_list = PlaintextList::new(
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

    let mut input_rlwe_ciphertext = GlweCiphertext::new(
        Scalar::ZERO,
        GlweSize(2),
        polynomial_size,
        ciphertext_modulus,
    );
    let mut output_rlwe_ciphertext = GlweCiphertext::new(
        Scalar::ZERO,
        GlweSize(2),
        polynomial_size,
        ciphertext_modulus,
    );

    let num_test = 10;
    for idx in 1..=num_test {
        for i in 0..polynomial_size.0 {
            let rand_msg = rand::thread_rng().gen_range(0..message_modulus);
            input_message_list.as_mut()[i] = rand_msg;
            input_plaintext_list.as_mut()[i] = rand_msg * delta;
        }
        input_message_list.as_mut()[0] = 1;
        input_plaintext_list.as_mut()[0] = delta;

        scaled_input_plaintext_list.as_mut().clone_from_slice(input_plaintext_list.as_ref());
        slice_wrapping_scalar_mul_assign(
            &mut scaled_input_plaintext_list.as_mut(),
            torus_scaling,
        );
        polynomial_wrapping_mul(
            &mut correct_val_list.as_mut_polynomial(),
            &scaled_input_plaintext_list.as_polynomial(),
            &rlwe_sk_poly,
        );
        slice_wrapping_scalar_div_assign(
            &mut correct_val_list.as_mut(),
            torus_scaling.wrapping_mul(delta),
        );

        encrypt_glwe_ciphertext(
            &rlwe_secret_key,
            &mut input_rlwe_ciphertext,
            &input_plaintext_list,
            rlwe_noise_distribution,
            &mut encryption_generator,
        );

        let now = Instant::now();
        scheme_switch_rlwe_ciphertext(
            &fourier_rlwe_ss_key,
            &input_rlwe_ciphertext,
            &mut output_rlwe_ciphertext,
        );
        let time = now.elapsed();

        decrypt_glwe_ciphertext(
            &rlwe_secret_key,
            &output_rlwe_ciphertext,
            &mut decrypted_plaintext_list,
        );

        let (avg_err, max_err) = get_avg_and_max_error(
            &decrypted_plaintext_list,
            &correct_val_list,
            torus_scaling,
            delta,
        );
        println!(
            "[Test {idx}] time: {} μs, avg_err: {:.3} bits, max_err: {:.3} bits",
            time.as_micros(),
            avg_err.log2(),
            (max_err as f64).log2(),
        );
    }
}

pub fn main() {
    let polynomial_size = PolynomialSize(2048);

    let param_list = [
        (polynomial_size, 39, 2.96, DecompositionBaseLog(12), DecompositionLevelCount(3), FftType::Vanilla),
        (polynomial_size, 39, 2.96, DecompositionBaseLog(12), DecompositionLevelCount(3), FftType::Split(20)),
    ];
    for param in param_list {
        let polynomial_size = param.0;
        let log_modulus = param.1;
        let rlwe_std_dev = param.2;
        let decomp_base_log = param.3;
        let decomp_level_count = param.4;
        let fft_type = param.5;

        println!(
            "N: {}, Q: 2^{}, rlwe_std_dev: {} (= {} in torus), B: 2^{}, l: {}, FftType: {:?}",
            polynomial_size.0,
            log_modulus,
            rlwe_std_dev,
            rlwe_std_dev / 2.0.powi(log_modulus as i32),
            decomp_base_log.0,
            decomp_level_count.0,
            fft_type,
        );
        test_rlwe_scheme_switch(
            polynomial_size,
            log_modulus,
            rlwe_std_dev,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        );
        println!();
    }
}
