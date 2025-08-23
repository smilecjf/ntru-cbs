use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::{Instant, Duration};

type Scalar = u64;
type SmallScalar = u32;

pub fn test_ntru_cmux_boot_lut_many(
    param: NtruCMuxParameters,
    log_lut_count: LutCountLog,
    fft_type: FftType,
) {
    let log_output_modulus = param.log_output_modulus().0;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_output_modulus).unwrap();

    let log_input_modulus = param.log_input_modulus().0;
    let small_ciphertext_modulus = CiphertextModulus::<SmallScalar>::try_new_power_of_2(log_input_modulus).unwrap();

    let polynomial_size = param.polynomial_size();
    let lwe_dimension = param.input_lwe_dimension();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(param.torus_ntru_std_dev()), 0.0);

    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(param.torus_lwe_std_dev()), 0.0);

    let ntru_secret_key = allocate_and_generate_new_gaussian_ntru_secret_key(
        polynomial_size,
        ciphertext_modulus,
        ntru_noise_distribution,
        &mut encryption_generator,
    );
    let large_lwe_secret_key = ntru_secret_key.clone().into_lwe_secret_key();

    let lwe_secret_key: LweSecretKeyOwned<SmallScalar> = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    );

    let decomp_base_log = param.br_decomp_base_log();
    let decomp_level_count = param.br_decomp_level_count();

    let ntru_cmux_bsk = allocate_and_generate_new_ntru_cmux_bootstrap_key(
        &lwe_secret_key,
        &ntru_secret_key,
        decomp_base_log,
        decomp_level_count,
        decomp_base_log,
        decomp_level_count,
        ntru_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_ntru_cmux_bsk = FourierNtruCMuxBootstrapKey::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        decomp_base_log,
        decomp_level_count,
        param.input_lwe_dimension(),
        fft_type,
        fft_type,
    );

    convert_standard_ntru_cmux_bootstrap_key_to_fourier(&ntru_cmux_bsk, &mut fourier_ntru_cmux_bsk);

    let log_message_modulus = 2usize;
    let message_modulus = 1usize << log_message_modulus;
    let delta = Scalar::ONE << (log_output_modulus - 1 - log_message_modulus);
    let small_delta = SmallScalar::ONE << (log_input_modulus - 1 - log_message_modulus);

    let lut_count = 1 << log_lut_count.0;
    let mut lwe_out_list = LweCiphertextList::new(
        Scalar::ZERO,
        ntru_cmux_bsk.output_lwe_dimension().to_lwe_size(),
        LweCiphertextCount(lut_count),
        ciphertext_modulus,
    );

    let mut acc = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    {
        let box_size = polynomial_size.0 / message_modulus;
        for x in 0..message_modulus {
            let index = x * box_size;
            for (i, elem) in acc.as_mut()[index..index + box_size].iter_mut().enumerate() {
                let k = i % lut_count;
                let scale = delta >> k;
                *elem = Scalar::cast_from((x + k) % message_modulus).wrapping_mul(scale);
            }
        }

        let half_box_size = box_size / 2;

        for a_i in acc.as_mut()[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        acc.as_mut().rotate_left(half_box_size);
    }

    let num_test = 10;
    for idx in 1..=num_test {
        let input_message = rand::thread_rng().gen_range(0..message_modulus);

        let mut lwe_in = LweCiphertext::new(SmallScalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size(), small_ciphertext_modulus);
        encrypt_lwe_ciphertext(
            &lwe_secret_key,
            &mut lwe_in,
            Plaintext(input_message as SmallScalar * small_delta),
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut time = Duration::ZERO;
        let now = Instant::now();
        ntru_cmux_bootstrap_lwe_ciphertext_lut_many(
            &lwe_in,
            &mut lwe_out_list,
            &acc,
            log_lut_count,
            &fourier_ntru_cmux_bsk,
        );
        time += now.elapsed();

        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();

        println!("[Test {idx}] input: {input_message}, time: {} ms", (time.as_micros() as f64) / 1000_f64);
        for (i, lwe_out) in lwe_out_list.iter().enumerate() {
            let scale = delta >> i;
            let scaled_decrypted = decrypt_lwe_ciphertext(
                &large_lwe_secret_key,
                &lwe_out
            ).0.wrapping_mul(torus_scaling);

            let decoded = {
                let rounding = (scaled_decrypted & (scale.wrapping_mul(torus_scaling) >> 1)) << 1;
                scaled_decrypted.wrapping_add(rounding) / scale.wrapping_mul(torus_scaling)
            };
            let err = {
                let correct_val = (((input_message + i) % message_modulus) as Scalar)
                    .wrapping_mul(scale)
                    .wrapping_mul(torus_scaling);
                let d0 = scaled_decrypted.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(scaled_decrypted);
                std::cmp::min(d0, d1).wrapping_div(torus_scaling)
            };

            println!(
                "\t[{i}] output: {decoded}, err: {:.3} bits",
                (err as f64).log2(),
            );
        }
    }
}

pub fn main() {
    let log_lut_count = LutCountLog(2);

    let param_list = [
        (NTRU_CMUX_STD128B2_PRIME, log_lut_count, FftType::Vanilla),
        (NTRU_CMUX_STD128B2_PRIME, log_lut_count, FftType::Split(20)),
        (NTRU_CMUX_STD128B2, log_lut_count, FftType::Vanilla),
        (NTRU_CMUX_STD128B2, log_lut_count, FftType::Split(25)),
        (NTRU_CMUX_STD128B3, log_lut_count, FftType::Vanilla),
        (NTRU_CMUX_STD128B3, log_lut_count, FftType::Split(25)),
    ];
    for (param, log_lut_count, fft_type) in param_list {
        param.print_info();
        println!("FftType: {fft_type:?}, LutCountLog: {log_lut_count:?}");
        test_ntru_cmux_boot_lut_many(param, log_lut_count, fft_type);
        println!();
    }
}
