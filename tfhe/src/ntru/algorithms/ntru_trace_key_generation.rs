use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

pub fn generate_ntru_trace_key<
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    output_ntru_trace_key: &mut NtruTraceKey<OutputCont>,
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

    for k in 1..=polynomial_size.0.ilog2() {
        let auto_index = AutomorphismIndex((1 << k) + 1);
        let mut ntru_auto_key = output_ntru_trace_key.get_mut_automorphism_key(k as usize - 1);

        generate_ntru_automorphism_key(
            input_ntru_secret_key,
            auto_index,
            &mut ntru_auto_key,
            noise_distribution,
            generator,
        );
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
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruTraceKeyOwned<Scalar> {
    let mut new_ntru_trace_key = NtruTraceKeyOwned::new(
        input_ntru_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
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
