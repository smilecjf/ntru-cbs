// use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::{Instant, Duration};

type Scalar = u64;

// mod utils;
// use utils::*;

pub fn main() {
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
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

    let lwe_secret_key: LweSecretKeyOwned<Scalar> = allocate_and_generate_new_binary_lwe_secret_key(
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

    let mut acc = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);
    let plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    encrypt_ntru_ciphertext(
        &ntru_secret_key,
        &mut acc,
        &plaintext_list,
        ntru_noise_distribution,
        &mut encryption_generator,
    );

    let mut lwe_in = LweCiphertext::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);
    encrypt_lwe_ciphertext(
        &lwe_secret_key,
        &mut lwe_in,
        Plaintext(Scalar::ZERO),
        lwe_noise_distribution,
        &mut encryption_generator,
    );

    let mut lwe_out = LweCiphertext::new(
        Scalar::ZERO,
        ntru_cmux_bsk.output_lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let mut time = Duration::ZERO;
    let num_test = 1000;
    let now = Instant::now();
    for _ in 0..num_test {
        ntru_cmux_bootstrap_lwe_ciphertext(
            &lwe_in,
            &mut lwe_out,
            &acc,
            &fourier_ntru_cmux_bsk,
        );
    }
    time += now.elapsed();

    let decrypted = decrypt_lwe_ciphertext(
        &large_lwe_secret_key,
        &lwe_out
    );
    let err = {
        let d0 = decrypted.0;
        let d1 = decrypted.0.wrapping_neg();
        std::cmp::min(d0, d1)
    };
    println!("{} ms, {:.3}",
        (time.as_micros() as f64) / (1000 * num_test) as f64,
        (err as f64).log2(),
    );
}
