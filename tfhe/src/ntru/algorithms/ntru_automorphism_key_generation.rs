use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

pub fn generate_ntru_automorphism_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    KskCont,
    Gen,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    automorphism_index: AutomorphismIndex,
    ntru_automorphism_key: &mut NtruAutomorphismKey<KskCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
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
        ntru_automorphism_key.polynomial_size(),
    );

    assert_eq!(
        input_ntru_secret_key.ciphertext_modulus(),
        ntru_automorphism_key.ciphertext_modulus(),
    );

    assert!(
        automorphism_index.0 % 2 == 1,
        "Automorphism index should be odd.",
    );

    let polynomial_size = ntru_automorphism_key.polynomial_size();

    assert!(
        automorphism_index.0 > 0 && automorphism_index.0 < 2 * polynomial_size.0,
        "Automorphism index should be a positive number smaller than 2 * polynomial_size.",
    );

    let ciphertext_modulus = ntru_automorphism_key.ciphertext_modulus();

    let mut auto_ntru_secret_key = NtruSecretKey::new_empty_key(Scalar::ZERO, polynomial_size, ciphertext_modulus);

    input_ntru_secret_key.as_polynomial_list().iter()
        .zip(auto_ntru_secret_key.as_mut_polynomial_list().iter_mut())
        .for_each(|(sk_poly, mut auto_sk_poly)| {
            frobenius_map_poly(
                &sk_poly,
                &mut auto_sk_poly,
                automorphism_index,
            );
        });

    generate_ntru_keyswitch_key(
        &auto_ntru_secret_key,
        &input_ntru_secret_key,
        &mut ntru_automorphism_key.as_mut_ntru_keyswitch_key(),
        noise_distribution,
        generator,
    );
}

pub fn allocate_and_generate_new_ntru_automorphism_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    Gen,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    automorphism_index: AutomorphismIndex,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruAutomorphismKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ntru_automorphism_key = NtruAutomorphismKeyOwned::new(
        Scalar::ZERO,
        automorphism_index,
        input_ntru_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_ntru_secret_key.ciphertext_modulus(),
    );

    generate_ntru_automorphism_key(
        input_ntru_secret_key,
        automorphism_index,
        &mut new_ntru_automorphism_key,
        noise_distribution,
        generator,
    );

    new_ntru_automorphism_key
}

pub(crate) fn frobenius_map_poly<Scalar, InputCont, OutputCont>(
    input: &Polynomial<InputCont>,
    output: &mut Polynomial<OutputCont>,
    index: AutomorphismIndex,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    // Assume that valid input, output, and index are given
    let polynomial_size = input.polynomial_size().0;
    let index = index.0;

    output.as_mut()[0] = input.as_ref()[0];

    for i in 1..polynomial_size {
        let j = (i * index) % polynomial_size;
        let sign = if ((i * index) / polynomial_size) % 2 == 0
        { Scalar::ONE } else { Scalar::MAX };
        output.as_mut()[j] = input.as_ref()[i].wrapping_mul(sign);
    }
}