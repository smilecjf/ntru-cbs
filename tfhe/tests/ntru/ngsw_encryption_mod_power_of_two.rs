use rand::Rng;
use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

type Scalar = u64;

pub fn main() {
    let power = 48;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(power).unwrap();
    let polynomial_size = PolynomialSize(2048);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let std_dev_scaling = 2.0_f64.powi((Scalar::BITS as usize - power) as i32);
    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533 * std_dev_scaling), 0.0);

    let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

    let decomp_base_log = DecompositionBaseLog(8);
    let decomp_level_count = DecompositionLevelCount(3);

    let mut ngsw_ciphertext = NgswCiphertext::new(Scalar::ZERO, polynomial_size, decomp_base_log, decomp_level_count, ciphertext_modulus);

    let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
    let mut err_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));

    let num_test = 10;
    for i in 0..num_test {
        let a = rand::thread_rng().gen_range(0..Scalar::ONE << decomp_base_log.0);

        encrypt_constant_ngsw_ciphertext(
            &ntru_secret_key,
            &mut ngsw_ciphertext,
            Cleartext(a),
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        let decrypted = decrypt_constant_ngsw_ciphertext(
            &ntru_secret_key,
            &ngsw_ciphertext,
        );

        let mut first_row = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);
        first_row.as_mut().clone_from_slice(ngsw_ciphertext.first().unwrap().as_ref());

        let factor = ngsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            DecompositionLevel(decomp_level_count.0),
            decomp_base_log,
            Cleartext(a),
        ).wrapping_mul(torus_scaling);
        first_row.as_mut()[0] = first_row.as_mut()[0].wrapping_sub(factor);

        decrypt_ntru_ciphertext(&ntru_secret_key, &first_row, &mut err_list);
        let mut max_err = Scalar::ZERO;
        for err in err_list.iter() {
            let err = (*err.0).wrapping_mul(torus_scaling);
            let err= std::cmp::min(err, err.wrapping_neg())
                .wrapping_div(torus_scaling);
            max_err = std::cmp::max(max_err, err);
        }

        println!("[{i}] input: {}, decrypted: {}, err: {:.3} bits", a.into_signed(), decrypted.0.into_signed(), (max_err as f64).log2());

        if a != decrypted.0 {
            println!("Invalid result");
            return;
        }
    }
}
