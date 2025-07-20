use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

mod utils;
use utils::*;

type Scalar = u64;

pub fn main() {
    let power = 16;
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

    let mut ntru_ciphertext = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);

    let log_message_modulus = 4;
    let message_modulus = Scalar::ONE << log_message_modulus;
    let delta = Scalar::ONE << (power - log_message_modulus);
    let mut input_message_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    let mut input_plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));


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

    for i in 0..4 {
        let decrypted = decrypted_plaintext_list.as_ref()[i];
        let rounding = (decrypted & (delta >> 1)) << 1;
        let decoded = (decrypted.wrapping_add(rounding)) / delta;
        let correct_val = input_message_list.as_ref()[i];

        println!("[{i}] he: {decoded}, plain: {correct_val}");
    }

    let max_err = get_max_error(
        &decrypted_plaintext_list,
        &input_message_list,
        ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        delta,
    );
    println!("Max error: {:.3} bits", (max_err as f64).log2());
}
