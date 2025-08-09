use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_div_assign;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTermSlice};
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

pub fn generate_ntru_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KskCont,
    Gen,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    output_ntru_secret_key: &NtruSecretKey<OutputKeyCont>,
    ntru_keyswitch_key: &mut NtruKeyswitchKey<KskCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        input_ntru_secret_key
            .ciphertext_modulus()
            .is_power_of_two(),
        "Only support power-of-two modulus currently.",
    );

    assert_eq!(
        input_ntru_secret_key.polynomial_size(),
        output_ntru_secret_key.polynomial_size(),
    );

    assert_eq!(
        input_ntru_secret_key.polynomial_size(),
        ntru_keyswitch_key.polynomial_size(),
    );

    assert_eq!(
        input_ntru_secret_key.ciphertext_modulus(),
        output_ntru_secret_key.ciphertext_modulus(),
    );

    assert_eq!(
        input_ntru_secret_key.ciphertext_modulus(),
        ntru_keyswitch_key.ciphertext_modulus(),
    );

    let decomp_base_log = ntru_keyswitch_key.decomposition_base_log();
    let decomp_level_count = ntru_keyswitch_key.decomposition_level_count();
    let polynomial_size = ntru_keyswitch_key.polynomial_size();
    let ciphertext_modulus = ntru_keyswitch_key.ciphertext_modulus();

    let input_sk_poly = input_ntru_secret_key.get_secret_key_polynomial();

    let mut decomp_poly_buffer = Polynomial::new(Scalar::ZERO, polynomial_size);

    // NGSW_f2(f1/f2) = {NTRU_f2(q/B^j * f1)}_{j=1}^{l}
    for (level, mut ksk_ntru_ciphertext) in (1..=decomp_level_count.0)
        .map(DecompositionLevel)
        .zip(ntru_keyswitch_key.as_mut_ntru_ciphertext_list().iter_mut())
    {
        DecompositionTermSlice::new(level, decomp_base_log, input_sk_poly.as_ref())
            .fill_slice_with_recomposition_summand(decomp_poly_buffer.as_mut());

        slice_wrapping_scalar_div_assign(
            decomp_poly_buffer.as_mut(),
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );

        let decomp_plaintext_buffer = PlaintextList::from_container(
            decomp_poly_buffer.as_ref(),
        );

        encrypt_ntru_ciphertext(
            output_ntru_secret_key,
            &mut ksk_ntru_ciphertext,
            &decomp_plaintext_buffer,
            noise_distribution,
            generator,
        );
    }
}

pub fn allocate_and_generate_new_ntru_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    output_ntru_secret_key: &NtruSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruKeyswitchKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ntru_keyswitch_key = NtruKeyswitchKeyOwned::new(
        Scalar::ZERO,
        output_ntru_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        output_ntru_secret_key.ciphertext_modulus(),
    );

    generate_ntru_keyswitch_key(
        input_ntru_secret_key,
        output_ntru_secret_key,
        &mut new_ntru_keyswitch_key,
        noise_distribution,
        generator,
    );

    new_ntru_keyswitch_key
}
