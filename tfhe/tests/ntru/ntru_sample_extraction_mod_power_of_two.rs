use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

type Scalar = u64;

pub fn main() {
    let power = 39;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(power).unwrap();
    let polynomial_size = PolynomialSize(2048);
    let lwe_size = LweDimension(polynomial_size.0).to_lwe_size();
    let lwe_ciphertext_count = LweCiphertextCount(polynomial_size.0);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(5.38420863449573516845703125e-12), 0.0);

    let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);
    let lwe_secret_key = ntru_secret_key.clone().into_lwe_secret_key();

    let mut ntru_ciphertext = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);

    let mut lwe_ciphertext_list = LweCiphertextList::new(Scalar::ZERO, lwe_size, lwe_ciphertext_count, ciphertext_modulus);

    // NTRU message parameters
    let log_message_modulus = 4;
    let message_modulus = Scalar::ONE << log_message_modulus;
    let delta = Scalar::ONE << (power - log_message_modulus);
    let mut input_message_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    let mut input_plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));

    let mut ntru_decrypted_plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    let mut lwe_decrypted_plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));

    let num_test = 10;
    for idx in 1..=num_test {
        input_message_list.iter_mut().zip(input_plaintext_list.iter_mut())
            .for_each(|(msg, ptxt)| {
            *(msg.0) = rand::thread_rng().gen_range(0..message_modulus);
            *(ptxt.0) = *(msg.0) * delta;
        });

        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut ntru_ciphertext,
            &input_plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &ntru_ciphertext,
            &mut ntru_decrypted_plaintext_list,
        );

        for (i, mut lwe) in lwe_ciphertext_list.iter_mut().enumerate() {
            extract_lwe_sample_from_ntru_ciphertext(
                &ntru_ciphertext,
                &mut lwe,
                MonomialDegree(i),
            );
        }

        decrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &lwe_ciphertext_list,
            &mut lwe_decrypted_plaintext_list,
        );

        let mut pass = true;
        for (ntru_dec, lwe_dec) in ntru_decrypted_plaintext_list
            .iter_mut()
            .zip(lwe_decrypted_plaintext_list.iter_mut())
        {
            if *ntru_dec.0 != *lwe_dec.0 {
                pass = false;
                break;
            }
        }
        println!("[Test {idx}] {pass}");
    }
}
