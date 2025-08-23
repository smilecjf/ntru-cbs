use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::Instant;

type Scalar = u64;

mod utils;
use utils::*;

pub fn test_ntru_keyswitch(
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

    let ntru_secret_key1 = allocate_and_generate_new_gaussian_ntru_secret_key(polynomial_size, ciphertext_modulus, ntru_noise_distribution, &mut encryption_generator);
    let ntru_secret_key2 = allocate_and_generate_new_gaussian_ntru_secret_key(polynomial_size, ciphertext_modulus, ntru_noise_distribution, &mut encryption_generator);


    // NTRU keyswitching parameters
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
        fft_type,
    );
    convert_standard_ntru_keyswitch_key_to_fourier(&ntru_ksk, &mut fourier_ntru_ksk);

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

        let now = Instant::now();
        keyswitch_ntru_ciphertext(
            &fourier_ntru_ksk,
            &ntru_ciphertext1,
            &mut ntru_ciphertext2,
        );
        let time = now.elapsed();

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

        println!(
            "[Test {idx}] time: {} µs, max error: {:.3} bits",
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
        test_ntru_keyswitch(polynomial_size, log_modulus, ntru_std_dev, decomp_base_log, decomp_level_count, fft_type);
        println!();
    }
}
