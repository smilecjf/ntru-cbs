//! Module containing primitives pertaining to the generation of NtruCMuxCircuitBootstrapKey

use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{
    Distribution, Uniform,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

pub fn generate_ntru_cmux_circuit_bootstrap_key<
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    ntru_secret_key: &NtruSecretKey<OutputKeyCont>,
    output_rlwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut NtruCMuxCircuitBootstrapKey<OutputCont>,
    ntru_noise_distribution: NoiseDistribution,
    rlwe_noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) {
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.polynomial_size() == output_rlwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output RLWE secret key and LWE bootstrap key. \
        Output RLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_rlwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    assert!(
        ntru_secret_key.polynomial_size() == output_rlwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between NTRU secret key and output RLWE secret key. \
        NTRU secret key PolynomialSize: {:?}, Output RLWE secret key PolynomialSize: {:?}.",
        ntru_secret_key.polynomial_size(),
        output_rlwe_secret_key.polynomial_size(),
    );

    assert!(
        output_rlwe_secret_key.glwe_dimension() == GlweDimension(1),
        "Only support RLWE output",
    );


    generate_ntru_cmux_bootstrap_key(
        input_lwe_secret_key,
        ntru_secret_key,
        &mut output.get_mut_ntru_cmux_bootstrap_key(),
        ntru_noise_distribution,
        generator,
    );

    generate_ntru_trace_key(
        ntru_secret_key,
        &mut output.get_mut_ntru_trace_key(),
        ntru_noise_distribution,
        generator,
    );

    generate_ntru_to_rlwe_keyswitch_key(
        ntru_secret_key,
        output_rlwe_secret_key,
        &mut output.get_mut_ntru_to_rlwe_keyswitch_key(),
        rlwe_noise_distribution,
        generator,
    );

    generate_rlwe_scheme_switch_key(
        output_rlwe_secret_key,
        &mut output.get_mut_rlwe_scheme_switch_key(),
        rlwe_noise_distribution,
        generator,
    );
}

pub fn allocate_and_generate_new_ntru_cmux_circuit_bootstrap_key<
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    ntru_secret_key: &NtruSecretKey<OutputKeyCont>,
    output_rlwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    br_decomp_base_log: DecompositionBaseLog,
    br_decomp_level_count: DecompositionLevelCount,
    swk_decomp_base_log: DecompositionBaseLog,
    swk_decomp_level_count: DecompositionLevelCount,
    tr_decomp_base_log: DecompositionBaseLog,
    tr_decomp_level_count: DecompositionLevelCount,
    ksk_decomp_base_log: DecompositionBaseLog,
    ksk_decomp_level_count: DecompositionLevelCount,
    ss_decomp_base_log: DecompositionBaseLog,
    ss_decomp_level_count: DecompositionLevelCount,
    ntru_noise_distribution: NoiseDistribution,
    rlwe_noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruCMuxCircuitBootstrapKeyOwned<OutputScalar> {
    let mut cbs_key = NtruCMuxCircuitBootstrapKey::new(
        OutputScalar::ZERO,
        ntru_secret_key.polynomial_size(),
        input_lwe_secret_key.lwe_dimension(),
        br_decomp_base_log,
        br_decomp_level_count,
        swk_decomp_base_log,
        swk_decomp_level_count,
        tr_decomp_base_log,
        tr_decomp_level_count,
        ksk_decomp_base_log,
        ksk_decomp_level_count,
        ss_decomp_base_log,
        ss_decomp_level_count,
        ciphertext_modulus,
    );

    generate_ntru_cmux_circuit_bootstrap_key(
        input_lwe_secret_key,
        ntru_secret_key,
        output_rlwe_secret_key,
        &mut cbs_key,
        ntru_noise_distribution,
        rlwe_noise_distribution,
        generator,
    );

    cbs_key
}
