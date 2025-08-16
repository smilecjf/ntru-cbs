use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

pub fn generate_ntru_trace_key<
    Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    output_ntru_trace_key: &mut NtruTraceKeyOwned<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) {
    assert!(
        input_ntru_secret_key
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "Only support power-of-two modulus currently.",
    );

    assert_eq!(
        input_ntru_secret_key.ciphertext_modulus(),
        output_ntru_trace_key.ciphertext_modulus(),
    );

    assert_eq!(
        input_ntru_secret_key.polynomial_size(),
        output_ntru_trace_key.polynomial_size(),
    );

    let polynomial_size = input_ntru_secret_key.polynomial_size();
    let decomp_base_log = output_ntru_trace_key.decomposition_base_log();
    let decomp_level_count = output_ntru_trace_key.decomposition_level_count();
    let fft_type = output_ntru_trace_key.fft_type();

    let auto_keys = output_ntru_trace_key.get_mut_automorphism_keys();

    assert!(
        auto_keys.is_empty(),
        "Automorphism keys are not empty.",
    );


    for k in 1..=polynomial_size.0.ilog2() {
        let auto_index = AutomorphismIndex((1 << k) + 1);
        let ntru_auto_key = allocate_and_generate_new_ntru_automorphism_key(
            input_ntru_secret_key,
            auto_index,
            decomp_base_log,
            decomp_level_count,
            noise_distribution,
            generator,
        );

        let mut fourier_ntru_auto_key = FourierNtruAutomorphismKey::new(
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        );
        convert_standard_ntru_automorphism_key_to_fourier(
            &ntru_auto_key,
            &mut fourier_ntru_auto_key,
        );

        (*auto_keys).insert(auto_index.0, fourier_ntru_auto_key);
    }
}

pub fn allocate_and_generate_new_ntru_trace_key<
    Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruTraceKeyOwned<Scalar> {
    let mut new_ntru_trace_key = NtruTraceKeyOwned::new(
        input_ntru_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        fft_type,
        input_ntru_secret_key.ciphertext_modulus(),
    );

    generate_ntru_trace_key(
        input_ntru_secret_key,
        &mut new_ntru_trace_key,
        noise_distribution,
        generator,
    );

    new_ntru_trace_key
}
