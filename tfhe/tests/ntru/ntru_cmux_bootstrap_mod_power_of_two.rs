use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::{Instant, Duration};

type Scalar = u64;
type SmallScalar = u32;

pub fn main() {
    let power = 39;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(power).unwrap();

    let small_power = 12;
    let small_ciphertext_modulus = CiphertextModulus::<SmallScalar>::try_new_power_of_2(small_power).unwrap();

    let polynomial_size = PolynomialSize(2048);
    let lwe_dimension = LweDimension(571);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(5.38420863449573516845703125e-12), 0.0);

    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00077880859375), 0.0);

    let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(
        polynomial_size,
        ciphertext_modulus,
        &mut secret_generator,
    );
    let large_lwe_secret_key = ntru_secret_key.clone().into_lwe_secret_key();

    let lwe_secret_key: LweSecretKeyOwned<SmallScalar> = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    );

    let br_decomp_base_log = DecompositionBaseLog(12);
    let br_decomp_level_count = DecompositionLevelCount(2);
    let swk_decomp_base_log = DecompositionBaseLog(2);
    let swk_decomp_level_count= DecompositionLevelCount(3);

    let ntru_cmux_bsk = allocate_and_generate_new_ntru_cmux_bootstrap_key(
        &lwe_secret_key,
        &ntru_secret_key,
        br_decomp_base_log,
        br_decomp_level_count,
        swk_decomp_base_log,
        swk_decomp_level_count,
        ntru_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_ntru_cmux_bsk = FourierNtruCMuxBootstrapKey::new(
        polynomial_size,
        br_decomp_base_log,
        br_decomp_level_count,
        swk_decomp_base_log,
        swk_decomp_level_count,
        ntru_cmux_bsk.input_lwe_dimension(),
        FftType::Vanilla,
    );

    convert_standard_ntru_cmux_bootstrap_key_to_fourier(&ntru_cmux_bsk, &mut fourier_ntru_cmux_bsk);

    let log_message_modulus = 4usize;
    let message_modulus = 1usize << log_message_modulus;
    let delta = Scalar::ONE << (power - 1 - log_message_modulus);
    let small_delta = SmallScalar::ONE << (small_power - 1 - log_message_modulus);

    let mut lwe_out = LweCiphertext::new(
        Scalar::ZERO,
        ntru_cmux_bsk.output_lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let mut acc = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    {
        let box_size = polynomial_size.0 / message_modulus;
        for i in 0..message_modulus {
            let index = i * box_size;
            acc.as_mut()[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = Scalar::cast_from(i).wrapping_mul(delta));
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
        ntru_cmux_bootstrap_lwe_ciphertext(
            &lwe_in,
            &mut lwe_out,
            &acc,
            &fourier_ntru_cmux_bsk,
        );
        time += now.elapsed();
    
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();

        let scaled_decrypted = decrypt_lwe_ciphertext(
            &large_lwe_secret_key,
            &lwe_out
        ).0.wrapping_mul(torus_scaling);

        let decoded = {
            let rounding = (scaled_decrypted & (delta.wrapping_mul(torus_scaling) >> 1)) << 1;
            scaled_decrypted.wrapping_add(rounding) / delta.wrapping_mul(torus_scaling)
        };
        let err = {
            let correct_val = (input_message as Scalar)
                .wrapping_mul(delta)
                .wrapping_mul(torus_scaling);
            let d0 = scaled_decrypted.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(scaled_decrypted);
            std::cmp::min(d0, d1).wrapping_div(torus_scaling)
        };
        println!("[Test {idx}] input: {}, output: {}, time: {} ms, err: {:.3} bits",
            input_message,
            decoded,
            (time.as_micros() as f64) / 1000_f64,
            (err as f64).log2(),
        );
    }
}
