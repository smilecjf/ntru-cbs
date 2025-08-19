//! Module containing primitives pertaining tothe generation of NtruCMuxBootstrapKey

use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{
    Distribution, Uniform,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

pub fn generate_ntru_cmux_bootstrap_key<
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_ntru_secret_key: &NtruSecretKey<OutputKeyCont>,
    output: &mut NtruCMuxBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
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
        output.polynomial_size() == output_ntru_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output NTRU secret key and LWE bootstrap key. \
        Output NTRU secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_ntru_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    for (mut ngsw, &input_key_element) in output
        .get_mut_ngsw_list().iter_mut()
        .zip(input_lwe_secret_key.as_ref()) {
            encrypt_constant_ngsw_ciphertext(
                output_ntru_secret_key,
                &mut ngsw,
                Cleartext(input_key_element.cast_into()),
                noise_distribution,
                generator,
            );
        }
}

pub fn allocate_and_generate_new_ntru_cmux_bootstrap_key<
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_ntru_secret_key: &NtruSecretKey<OutputKeyCont>,
    br_decomp_base_log: DecompositionBaseLog,
    br_decomp_level_count: DecompositionLevelCount,
    swk_decomp_base_log: DecompositionBaseLog,
    swk_decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruCMuxBootstrapKeyOwned<OutputScalar> {
    let mut bsk = NtruCMuxBootstrapKey::new(
        OutputScalar::ZERO,
        output_ntru_secret_key.polynomial_size(),
        br_decomp_base_log,
        br_decomp_level_count,
        swk_decomp_base_log,
        swk_decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        ciphertext_modulus,
    );

    generate_ntru_cmux_bootstrap_key(
        input_lwe_secret_key,
        output_ntru_secret_key,
        &mut bsk,
        noise_distribution,
        generator,
    );

    bsk
}

