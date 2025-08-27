use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::Instant;

type Scalar = u64;

mod utils;
use utils::*;

pub fn test_ntru_rev_trace(param: NtruCMuxParameters, fft_type: FftType) {
    let log_modulus = param.log_output_modulus().0;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_modulus).unwrap();
    let polynomial_size = param.polynomial_size();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(param.torus_ntru_std_dev()), 0.0);

    let ntru_secret_key = allocate_and_generate_new_gaussian_ntru_secret_key(
        polynomial_size,
        ciphertext_modulus,
        ntru_noise_distribution,
        &mut encryption_generator,
    );

    // NTRU automorphism parameters
    let decomp_base_log = param.tr_decomp_base_log();
    let decomp_level_count = param.tr_decomp_level_count();

    let ntru_trace_key = allocate_and_generate_new_ntru_trace_key(
        &ntru_secret_key,
        decomp_base_log,
        decomp_level_count,
        ntru_noise_distribution,
        &mut encryption_generator,
    );

    let mut fourier_ntru_trace_key = FourierNtruTraceKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        fft_type,
    );
    convert_standard_ntru_trace_key_to_fourier(
        &ntru_trace_key,
        &mut fourier_ntru_trace_key,
    );

    // NTRU message parameters
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
    let mut decrypted_plaintext_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );
    let mut correct_message_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );

    let mut ntru_ciphertext = NtruCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );

    let mut ntru_trace_ciphertext = NtruCiphertext::new(
        Scalar::ZERO,
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
        correct_message_list.as_mut()[0] = input_message_list.as_ref()[0];

        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut ntru_ciphertext,
            &input_plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        let now = Instant::now();
        rev_trace_ntru_ciphertext(
            &fourier_ntru_trace_key,
            &ntru_ciphertext,
            &mut ntru_trace_ciphertext,
        );
        let time = now.elapsed();

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &ntru_trace_ciphertext,
            &mut decrypted_plaintext_list,
        );

        let max_err = get_max_error(
            &decrypted_plaintext_list,
            &correct_message_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );

        println!(
            "[Test {idx}] time: {} µs, max error: {:.3} bits",
            time.as_micros(),
            (max_err as f64).log2(),
        );
    }
}

pub fn main() {
    println!("* Test RevHomTrace with tr decomposition parameters\n");

    let param_list = [
        (NTRU_CMUX_STD128B2, FftType::Vanilla),
        (NTRU_CMUX_STD128B3, FftType::Vanilla),
        ];

    for (param, fft_type) in param_list {
        param.print_info();
        println!("FftType: {fft_type:?}");
        test_ntru_rev_trace(param, fft_type);
        println!();
    }
}
