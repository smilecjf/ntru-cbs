use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

type Scalar = u64;

mod utils;
use utils::*;

pub fn main() {
    let power = 62;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(power).unwrap();
    let polynomial_size = PolynomialSize(2048);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let std_dev_scaling = 2.0_f64.powi((Scalar::BITS as usize - power) as i32);
    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533 * std_dev_scaling), 0.0);

    let ntru_secret_key1 = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);
    let ntru_secret_key2 = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

    // NTRU keyswitching parameters
    let decomp_base_log = DecompositionBaseLog(22);
    let decomp_level_count = DecompositionLevelCount(2);

    let ntru_ksk = allocate_and_generate_new_ntru_keyswitch_key(
        &ntru_secret_key1,
        &ntru_secret_key2,
        decomp_base_log,
        decomp_level_count,
        ntru_noise_distribution,
        &mut encryption_generator,
    );

    let mut fourier_ntru_ksk = FourierNtruKeyswitchKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        FftType::Vanilla,
    );
    convert_standard_ntru_keyswitch_key_to_fourier(&ntru_ksk, &mut fourier_ntru_ksk);

    let mut split_fourier_ntru_ksk = FourierNtruKeyswitchKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        FftType::Split(43),
    );
    convert_standard_ntru_keyswitch_key_to_fourier(&ntru_ksk, &mut split_fourier_ntru_ksk);

    // NTRU message parameters
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

    let mut ntru_ciphertext1 = NtruCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );
    let mut ntru_ciphertext2 = NtruCiphertext::new(
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

        encrypt_ntru_ciphertext(
            &ntru_secret_key1,
            &mut ntru_ciphertext1,
            &input_plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        // Vanilla FFT-based NTRU keyswitching
        keyswitch_ntru_ciphertext(
            &fourier_ntru_ksk,
            &ntru_ciphertext1,
            &mut ntru_ciphertext2,
        );

        decrypt_ntru_ciphertext(
            &ntru_secret_key2,
            &ntru_ciphertext2,
            &mut decrypted_plaintext_list,
        );

        let max_err = get_max_error(
            &decrypted_plaintext_list,
            &input_message_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );

        // Split FFT-based NTRU keyswitching
        keyswitch_ntru_ciphertext(
            &split_fourier_ntru_ksk,
            &ntru_ciphertext1,
            &mut ntru_ciphertext2,
        );

        decrypt_ntru_ciphertext(
            &ntru_secret_key2,
            &ntru_ciphertext2,
            &mut decrypted_plaintext_list,
        );

        let split_max_err = get_max_error(
            &decrypted_plaintext_list,
            &input_message_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );

        println!(
            "[Test {idx}] Vanilla KS max error: {:.3} bits, Split KS max error: {:.3}",
            (max_err as f64).log2(),
            (split_max_err as f64).log2(),
        );
    }
}
