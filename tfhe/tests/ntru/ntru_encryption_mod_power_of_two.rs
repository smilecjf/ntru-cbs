use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

mod utils;
use utils::*;

type Scalar = u64;

pub fn test_ntru_encryption(param: NtruCMuxParameters) {
    let log_modulus = param.log_output_modulus().0;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_modulus).unwrap();
    let polynomial_size = param.polynomial_size();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let ntru_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(param.torus_ntru_std_dev()), 0.0);

    let mut ntru_ciphertext = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);

    let log_message_modulus = 4;
    let message_modulus = Scalar::ONE << log_message_modulus;
    let delta = Scalar::ONE << (log_modulus - log_message_modulus);
    let mut input_message_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    let mut input_plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));


    let num_test = 10;
    for idx in 1..=num_test {
        let ntru_secret_key = allocate_and_generate_new_gaussian_ntru_secret_key(polynomial_size, ciphertext_modulus, ntru_noise_distribution, &mut encryption_generator);

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

        let mut decrypted_plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
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
        println!("[Test {idx}] Max error: {:.3} bits", (max_err as f64).log2());
    }
}

pub fn main() {
    let param_list = [NTRU_CMUX_STD128B2_PRIME, NTRU_CMUX_STD128B2, NTRU_CMUX_STD128B3];
    for param in param_list {
        param.print_info();
        test_ntru_encryption(param);
        println!();
    }
}
