use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

type Scalar = u64;

pub fn main() {
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(48).unwrap();
    let polynomial_size = PolynomialSize(2048);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);

    let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

    let decomp_base_log = DecompositionBaseLog(8);
    let decomp_level_count = DecompositionLevelCount(3);

    let mut ngsw_ciphertext = NgswCiphertext::new(Scalar::ZERO, polynomial_size, decomp_base_log, decomp_level_count, ciphertext_modulus);

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
        println!("[{i}] input: {}, decrypted: {}", a.into_signed(), decrypted.0.into_signed());

        if a != decrypted.0 {
            println!("Invalid result");
            return;
        }
    }
}
