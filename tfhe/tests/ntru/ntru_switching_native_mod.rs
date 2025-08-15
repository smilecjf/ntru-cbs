use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

type Scalar = u64;

mod utils;
use utils::*;

pub fn main() {
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    let polynomial_size = PolynomialSize(2048);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);

    let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

    // NTRU switching parameters
    let decomp_base_log = DecompositionBaseLog(18);
    let decomp_level_count = DecompositionLevelCount(2);

    let ntru_swk = allocate_and_generate_new_ntru_switching_key(
        &ntru_secret_key,
        decomp_base_log,
        decomp_level_count,
        ntru_noise_distribution,
        &mut encryption_generator,
    );

    let mut fourier_ntru_swk = FourierNtruSwitchingKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        FftType::Vanilla,
    );
    convert_standard_ntru_switching_key_to_fourier(
        &ntru_swk,
        &mut fourier_ntru_swk,
    );

    let mut split_fourier_ntru_swk = FourierNtruSwitchingKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        FftType::Split(45),
    );
    convert_standard_ntru_switching_key_to_fourier(
        &ntru_swk,
        &mut split_fourier_ntru_swk,
    );

    // NTRU input parameter
    let log_message_modulus = 4;
    let message_modulus = Scalar::ONE << log_message_modulus;
    let delta = Scalar::ONE << (Scalar::BITS - log_message_modulus);

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

    let mut ntru_ciphertext = NtruCiphertext::new(
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

        // Vanilla FFT-based NTRU switching
        switch_to_ntru_ciphertext(
            &fourier_ntru_swk,
            &input_plaintext_list,
            &mut ntru_ciphertext,
        );

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &ntru_ciphertext,
            &mut decrypted_plaintext_list,
        );

        let max_err = get_max_error(
            &decrypted_plaintext_list,
            &input_message_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );

        // Split FFT-based NTRU switching
        switch_to_ntru_ciphertext(
            &split_fourier_ntru_swk,
            &input_plaintext_list,
            &mut ntru_ciphertext,
        );

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &ntru_ciphertext,
            &mut decrypted_plaintext_list,
        );

        let split_max_err = get_max_error(
            &decrypted_plaintext_list,
            &input_message_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );

        println!(
            "[Test {idx}] Vanilla switching max error: {:.3} bits, Split switching max error: {:.3} bits",
            (max_err as f64).log2(),
            (split_max_err as f64).log2(),
        );
    }
}
