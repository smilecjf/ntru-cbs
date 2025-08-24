use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::*;
use tfhe::ntru::entities::*;
use std::time::Instant;

type Scalar = u64;
type SmallScalar = u32;

mod utils;
use utils::*;

const NUM_TEST: usize = 4;

pub fn test_ntru_cmux_cbs(
    param: NtruCMuxParameters,
    log_lut_count: LutCountLog,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    br_fft_type: FftType,
    swk_fft_type: FftType,
    tr_fft_type: FftType,
    ss_fft_type: FftType,
) {
    let log_output_modulus = param.log_output_modulus().0;
    let ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_output_modulus).unwrap();
    let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();

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

    let lwe_secret_key: LweSecretKeyOwned<SmallScalar> = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    );
    let lwe_size = lwe_secret_key.lwe_dimension().to_lwe_size();

    let ntru_cmux_cbs_key = allocate_and_generate_new_ntru_cmux_circuit_bootstrap_key(
        &lwe_secret_key,
        &ntru_secret_key,
        param.br_decomp_base_log(),
        param.br_decomp_level_count(),
        param.br_decomp_base_log(),
        param.br_decomp_level_count(),
        param.tr_decomp_base_log(),
        param.tr_decomp_level_count(),
        param.ss_decomp_base_log(),
        param.ss_decomp_level_count(),
        ntru_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_ntru_cmux_cbs_key = FourierNtruCMuxCircuitBootstrapKey::new(
        polynomial_size,
        param.input_lwe_dimension(),
        param.br_decomp_base_log(),
        param.br_decomp_level_count(),
        br_fft_type,
        param.br_decomp_base_log(),
        param.br_decomp_level_count(),
        swk_fft_type,
        param.tr_decomp_base_log(),
        param.tr_decomp_level_count(),
        tr_fft_type,
        param.ss_decomp_base_log(),
        param.ss_decomp_level_count(),
        ss_fft_type,
    );

    convert_standard_ntru_cmux_circuit_bootstrap_key_to_fourier(&ntru_cmux_cbs_key, &mut fourier_ntru_cmux_cbs_key);

    for idx in 1..=NUM_TEST {
        let msg_bit = rand::thread_rng().gen_range(0..2) as SmallScalar;
        let msg_delta = msg_bit << (log_input_modulus - 1);

        let mut input_lwe = LweCiphertext::new(SmallScalar::ZERO, lwe_size, small_ciphertext_modulus);
        encrypt_lwe_ciphertext(
            &lwe_secret_key,
            &mut input_lwe,
            Plaintext(msg_bit * msg_delta),
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut output_ngsw = NgswCiphertext::new(Scalar::ZERO, polynomial_size, decomp_base_log, decomp_level_count, ciphertext_modulus);

        let now = Instant::now();
        ntru_cmux_circuit_bootstrap_lwe_ciphertext(
            &input_lwe,
            &mut output_ngsw,
            &fourier_ntru_cmux_cbs_key,
            log_lut_count,
        );
        let time = now.elapsed();

        let mut decrypted_plaintext_list = PlaintextList::new(Scalar::ONE, PlaintextCount(polynomial_size.0));

        println!("[Test {idx}] input: {msg_bit}, time: {:.3} ms", (time.as_micros() as f64) / 1000f64);
        for (k, mut output_ntru_ciphertext) in output_ngsw.as_mut_ntru_ciphertext_list().iter_mut().enumerate() {
            // /*
            let factor = if msg_bit == SmallScalar::ONE {
                Scalar::ONE << (Scalar::BITS as usize - (decomp_level_count.0 - k) * decomp_base_log.0)
            } else {
                Scalar::ZERO
            };

            output_ntru_ciphertext.as_mut()[0] = output_ntru_ciphertext.as_ref()[0].wrapping_sub(factor);
            decrypt_ntru_ciphertext(
                &ntru_secret_key,
                &output_ntru_ciphertext,
                &mut decrypted_plaintext_list,
            );

            let (avg_err, max_err) = get_avg_and_max_error(
                &decrypted_plaintext_list,
                &PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0)),
                torus_scaling,
                Scalar::ONE,
            );

            println!("\t[Level {} CBS] avg_err: {:.3} bits | max_err: {:.3} bits", decomp_level_count.0 - k, avg_err.log2(), (max_err as f64).log2());
            // */

            /* RevHomTrace test
            let log_scale = log_output_modulus - (decomp_level_count.0 - k) * decomp_base_log.0;
            let delta = Scalar::ONE << log_scale;

            decrypt_ntru_ciphertext(
                &ntru_secret_key,
                &output_ntru_ciphertext,
                &mut decrypted_plaintext_list,
            );

            let mut correct_val_list = PlaintextList::new(Scalar::ONE, PlaintextCount(polynomial_size.0));
            correct_val_list.as_mut()[0] = if msg_bit == SmallScalar::ZERO {
                (delta / 2).wrapping_neg()
            } else {
                delta / 2
            };

            let (avg_err, max_err) = get_avg_and_max_error(
                &decrypted_plaintext_list,
                &correct_val_list,
                torus_scaling,
                Scalar::ONE,
            );

            println!("\t[Level {} BR + Tr] avg_err: {:.3} bits | max_err:  {:.3} bits", k+1, avg_err.log2(), (max_err as f64).log2());
            // */

            /* BlindRotationManyLUT test
            extract_lwe_sample_from_ntru_ciphertext(
                &output_ntru_ciphertext,
                &mut buffer,
                MonomialDegree(0),
            );

            let decrypted = decrypt_lwe_ciphertext(&large_lwe_secret_key, &buffer);
            let decrypted = decrypted.0.wrapping_mul(torus_scaling);

            let decoded = {
                let rounding = (decrypted & (delta.wrapping_mul(torus_scaling) >> 2)) << 2;
                decrypted.wrapping_add(rounding).wrapping_div(delta).wrapping_div(torus_scaling)
            };

            let correct_val = if msg_bit == SmallScalar::ZERO {
                (delta / 2).wrapping_neg()
            } else {
                delta / 2
            }.wrapping_mul(torus_scaling);

            let err = {
                let d0 = decrypted.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(decrypted);
                std::cmp::min(d0, d1)
            }.wrapping_div(torus_scaling);

            let val = {
                let d0 = decrypted;
                let d1 = decrypted.wrapping_neg();
                std::cmp::min(d0, d1)
            }.wrapping_div(torus_scaling);

            println!("\t[Level {}] decoded: {}, err: {:.3} bits, val: {:.3} bits", k+1, decoded, (err as f64).log2(), (val as f64).log2());
            */
        }
        // */

        // /*
        let mut fourier_ngsw_output = FourierNgswCiphertext::new(polynomial_size, decomp_base_log, decomp_level_count, FftType::Vanilla);
        convert_standard_ngsw_ciphertext_to_fourier(&output_ngsw, &mut fourier_ngsw_output);

        let log_message_modulus = 1;
        let message_modulus = Scalar::ONE << log_message_modulus;
        let delta = Scalar::ONE << (log_output_modulus - log_message_modulus);

        let mut plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        for elt in plaintext_list.as_mut().iter_mut() {
            *elt = rand::thread_rng().gen_range(0..message_modulus).wrapping_mul(delta);
        }

        let mut ntru_ciphertext_in = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);
        encrypt_ntru_ciphertext(
            &ntru_secret_key,
            &mut ntru_ciphertext_in,
            &plaintext_list,
            ntru_noise_distribution,
            &mut encryption_generator,
        );
        let mut ntru_ciphertext_out = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        let mut computation_buffers = ComputationBuffers::new();
        computation_buffers.resize(
            add_ntru_external_product_assign_scratch::<Scalar>(polynomial_size, fft)
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = computation_buffers.stack();

        add_ntru_external_product_assign(&mut ntru_ciphertext_out.as_mut_view(), fourier_ngsw_output.as_view(), ntru_ciphertext_in.as_view(), fft, stack);

        decrypt_ntru_ciphertext(
            &ntru_secret_key,
            &ntru_ciphertext_out,
            &mut decrypted_plaintext_list,
        );

        let zero = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        let (avg_err, max_err) = get_avg_and_max_error(
            &decrypted_plaintext_list,
            if msg_bit == SmallScalar::ZERO {
                &zero
            } else {
                &plaintext_list
            },
            torus_scaling,
            delta,
        );

        println!("[Test {idx}] external product: avg err {:.3} bits | max err {:.3} bits", avg_err.log2(), (max_err as f64).log2());
        // */
    }
}

pub fn main() {
    let param_list = [
        (NTRU_CMUX_STD128B2_PRIME, LutCountLog(2), DecompositionBaseLog(2), DecompositionLevelCount(4), FftType::Vanilla, FftType::Vanilla, FftType::Vanilla, FftType::Vanilla),
        (NTRU_CMUX_STD128B2, LutCountLog(2), DecompositionBaseLog(2), DecompositionLevelCount(4), FftType::Vanilla, FftType::Vanilla, FftType::Vanilla, FftType::Vanilla),
        (NTRU_CMUX_STD128B3, LutCountLog(2), DecompositionBaseLog(2), DecompositionLevelCount(4), FftType::Vanilla, FftType::Vanilla, FftType::Vanilla, FftType::Vanilla),
    ];

    for (param, log_lut_count, decomp_base_log, decomp_level_count, br_fft_type, swk_fft_type, tr_fft_type, ss_fft_type) in param_list {
        param.print_info();
        println!(
            "LutCountLog: {:?}, B 2^{}, l: {}, BR: {:?}, SWK: {:?}, Tr: {:?}, SS: {:?}",
            log_lut_count,
            decomp_base_log.0,
            decomp_level_count.0,
            br_fft_type,
            swk_fft_type,
            tr_fft_type,
            ss_fft_type,
        );
        test_ntru_cmux_cbs(param, log_lut_count, decomp_base_log, decomp_level_count, br_fft_type, swk_fft_type, tr_fft_type, ss_fft_type);
        println!();
    }
}
