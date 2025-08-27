use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

pub fn generate_ntru_switching_key<
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    SwkCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    ntru_switching_key: &mut NtruSwitchingKey<SwkCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
)
{
    assert!(
        input_ntru_secret_key
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "Only support poewr-of-two modulus currently.",
    );

    assert_eq!(
        input_ntru_secret_key.polynomial_size(),
        ntru_switching_key.polynomial_size(),
    );

    assert_eq!(
        input_ntru_secret_key.ciphertext_modulus(),
        ntru_switching_key.ciphertext_modulus(),
    );

    let polynomial_size = input_ntru_secret_key.polynomial_size();
    let ciphertext_modulus = input_ntru_secret_key.ciphertext_modulus();

    let mut ntru_secret_key_one = NtruSecretKey::new_empty_key(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );

    for mut poly in ntru_secret_key_one.as_mut_polynomial_list().iter_mut() {
        poly.as_mut()[0] = Scalar::ONE;
    }

    generate_ntru_keyswitch_key(
        &ntru_secret_key_one,
        &input_ntru_secret_key,
        &mut ntru_switching_key.as_mut_ntru_keyswitch_key(),
        noise_distribution,
        generator,
    );
}

pub fn allocate_and_generate_new_ntru_switching_key<
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    input_ntru_secret_key: &NtruSecretKey<InputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> NtruSwitchingKeyOwned<Scalar>
{
    let mut new_ntru_switching_key = NtruSwitchingKey::new(
        Scalar::ZERO,
        input_ntru_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_ntru_secret_key.ciphertext_modulus(),
    );

    generate_ntru_switching_key(
        input_ntru_secret_key,
        &mut new_ntru_switching_key,
        noise_distribution,
        generator,
    );

    new_ntru_switching_key
}
