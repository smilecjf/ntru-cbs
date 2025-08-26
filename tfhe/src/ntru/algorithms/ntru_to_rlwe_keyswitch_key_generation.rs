use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_div_assign;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTermSlice};
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;

pub fn generate_ntru_to_rlwe_keyswitch_key<
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    input_ntru_sk: &NtruSecretKey<InputKeyCont>,
    output_rlwe_sk: &GlweSecretKey<OutputKeyCont>,
    ntru_to_rlwe_keyswitch_key: &mut NtruToRlweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) {
    assert!(
        output_rlwe_sk.glwe_dimension() == GlweDimension(1),
        "Only support RLWE secret key",
    );

    assert!(
        input_ntru_sk.polynomial_size() == output_rlwe_sk.polynomial_size(),
        "Mismatch between polynomial size of input ntru secret key and output rlwe secret key. \
        Input {:?} and output {:?}.",
        input_ntru_sk.polynomial_size(),
        output_rlwe_sk.polynomial_size(),
    );

    assert!(
        input_ntru_sk.polynomial_size() == ntru_to_rlwe_keyswitch_key.polynomial_size(),
        "Mismatch between polynomial size of the input ntru secret key and keyswitch key. \
        Input {:?} and keyswitch key {:?}.",
        input_ntru_sk.polynomial_size(),
        ntru_to_rlwe_keyswitch_key.polynomial_size(),
    );

    assert!(
        input_ntru_sk.ciphertext_modulus() == ntru_to_rlwe_keyswitch_key.ciphertext_modulus(),
        "Mismatch between ciphertext modulus of the input ntru secret key and keyswitch key. \
        Input {:?} and keyswitch key {:?}.",
        input_ntru_sk.ciphertext_modulus(),
        ntru_to_rlwe_keyswitch_key.ciphertext_modulus(),
    );

    let ciphertext_modulus = ntru_to_rlwe_keyswitch_key.ciphertext_modulus();
    assert!(
        ciphertext_modulus.is_compatible_with_native_modulus(),
        "Only support power-of-two modulus, currently.",
    );

    let decomp_base_log = ntru_to_rlwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = ntru_to_rlwe_keyswitch_key.decomposition_level_count();
    let polynomial_size = ntru_to_rlwe_keyswitch_key.polynomial_size();

    let ntru_sk_poly = input_ntru_sk.get_secret_key_polynomial();
    let mut decomp_polynomials_buffer = PolynomialList::new(
        Scalar::ZERO,
        polynomial_size,
        PolynomialCount(decomp_level_count.0),
    );

    for ((level, mut message_polynomial), mut glwe) in (1..=decomp_level_count.0)
        .rev()
        .map(DecompositionLevel)
        .zip(decomp_polynomials_buffer.as_mut_view().iter_mut())
        .zip(ntru_to_rlwe_keyswitch_key.as_mut_glwe_ciphertext_list().iter_mut())
    {
        DecompositionTermSlice::new(level, decomp_base_log, ntru_sk_poly.as_ref())
            .fill_slice_with_recomposition_summand(message_polynomial.as_mut());

        slice_wrapping_scalar_div_assign(
            message_polynomial.as_mut(),
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );

        let decomp_plaintexts_buffer
            = PlaintextList::from_container(message_polynomial.as_ref());

        encrypt_glwe_ciphertext(
            output_rlwe_sk,
            // &mut ntru_to_rlwe_keyswitch_key.as_mut_glwe_ciphertext_list(),
            &mut glwe,
            &decomp_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

pub fn allocate_and_generate_new_ntru_to_rlwe_keyswitch_key<
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    input_ntru_sk: &NtruSecretKey<InputKeyCont>,
    output_rlwe_sk: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruToRlweKeyswitchKeyOwned<Scalar> {
    let mut new_ntru_to_rlwe_keyswitch_key = NtruToRlweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        output_rlwe_sk.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    generate_ntru_to_rlwe_keyswitch_key(
        input_ntru_sk,
        output_rlwe_sk,
        &mut new_ntru_to_rlwe_keyswitch_key,
        noise_distribution,
        generator,
    );

    new_ntru_to_rlwe_keyswitch_key
}
