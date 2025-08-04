use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;

type Scalar = u64;

mod utils;
use utils::*;

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

    // NTRU input parameter
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
    let mut correct_val_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );
    let mut decrypted_plaintext_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );

    let mut ntru_ciphertext = NtruCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );

    // NGSW decomposition parameter
    let decomp_base_log = DecompositionBaseLog(12);
    let decomp_level_count = DecompositionLevelCount(3);

    let mut ngsw_ciphertext = NgswCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    let mut fourier_ngsw_ciphertext = FourierNgswCiphertext::new(
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
    );

    let num_test = 10;
    for idx in 1..=num_test {
        let a = rand::thread_rng().gen_range(0..Scalar::ONE << 2);
        encrypt_constant_ngsw_ciphertext(
            &ntru_secret_key,
            &mut ngsw_ciphertext,
            Cleartext(a),
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        for i in 0..polynomial_size.0 {
            let rand_num = rand::thread_rng().gen_range(0..message_modulus);
            input_message_list.as_mut()[i] = rand_num;
            input_plaintext_list.as_mut()[i] = rand_num * delta;
            correct_val_list.as_mut()[i] = (rand_num * a) % message_modulus;
        }

        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut ntru_ciphertext,
            &input_plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );

        convert_standard_ngsw_ciphertext_to_fourier(&ngsw_ciphertext, &mut fourier_ngsw_ciphertext);

        let mut output = NtruCiphertext::new(
            Scalar::ZERO,
            polynomial_size,
            ciphertext_modulus,
        );

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        let mut computation_buffers = ComputationBuffers::new();
        computation_buffers.resize(
            add_ntru_external_product_assign_scratch::<Scalar>(
                polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = computation_buffers.stack();

        add_ntru_external_product_assign(
            &mut output.as_mut_view(),
            fourier_ngsw_ciphertext.as_view(),
            ntru_ciphertext.as_view(),
            fft,
            stack,
        );

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &output,
            &mut decrypted_plaintext_list,
        );

        let max_err = get_max_error(
            &decrypted_plaintext_list,
            &correct_val_list,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            delta,
        );
        println!("[Test {idx}] Max error: {:.3} bits", (max_err as f64).log2());
    }
}

