use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

type Scalar = u64;

mod utils;
use utils::*;

pub fn main() {
    let power = 39;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(power).unwrap();
    let polynomial_size = PolynomialSize(2048);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(5.38420863449573516845703125e-12), 0.0);

    let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(
        polynomial_size,
        ciphertext_modulus,
        &mut secret_generator,
    );

    // NTRU automorphism parameters
    let decomp_base_log = DecompositionBaseLog(8);
    let decomp_level_count = DecompositionLevelCount(2);

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
        FftType::Vanilla,
    );
    convert_standard_ntru_trace_key_to_fourier(
        &ntru_trace_key,
        &mut fourier_ntru_trace_key,
    );

    let mut split_fourier_ntru_trace_key = FourierNtruTraceKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        FftType::Split(20),
    );
    convert_standard_ntru_trace_key_to_fourier(
        &ntru_trace_key,
        &mut split_fourier_ntru_trace_key,
    );

    // NTRU message parameters
    let log_message_modulus = 4;
    let message_modulus = Scalar::ONE << log_message_modulus;
    let delta = Scalar::ONE << (power - log_message_modulus);

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

        // Vanilla FFT-based RevHomTrace
        rev_trace_ntru_ciphertext(
            &fourier_ntru_trace_key,
            &ntru_ciphertext,
            &mut ntru_trace_ciphertext,
        );

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

        // Split FFT-based RevHomTrace
        rev_trace_ntru_ciphertext(
            &split_fourier_ntru_trace_key,
            &ntru_ciphertext,
            &mut ntru_trace_ciphertext,
        );

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &ntru_trace_ciphertext,
            &mut decrypted_plaintext_list,
        );

        let split_max_err = get_max_error(
            &decrypted_plaintext_list,
            &correct_message_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );

        println!(
            "[Test {idx}] Vanilla RevHomTrace max error: {:.3} bits, Split RevHomTrace max error: {:.3} bits",
            (max_err as f64).log2(),
            (split_max_err as f64).log2(),
        );
    }
}
