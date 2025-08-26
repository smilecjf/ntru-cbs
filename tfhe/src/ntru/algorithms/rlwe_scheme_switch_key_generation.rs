use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_add_scalar_mul_assign;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;

pub fn generate_rlwe_scheme_switch_key<
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    SSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    rlwe_secret_key: &GlweSecretKey<KeyCont>,
    rlwe_scheme_switch_key: &mut RlweSchemeSwitchKey<SSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) {
    assert!(
        rlwe_secret_key.glwe_dimension() == GlweDimension(1),
        "Only support RLWE secret key",
    );

    assert!(
        rlwe_secret_key.polynomial_size() == rlwe_scheme_switch_key.polynomial_size(),
        "Mismatch between polynomial size of input rlwe secret key and output rlwe scheme switch key. \
        Input {:?} and output {:?}.",
        rlwe_secret_key.polynomial_size(),
        rlwe_scheme_switch_key.polynomial_size(),
    );

    let ciphertext_modulus = rlwe_scheme_switch_key.ciphertext_modulus();
    assert!(
        ciphertext_modulus.is_compatible_with_native_modulus(),
        "Only support power-of-two modulus, currently.",
    );

    let decomp_base_log = rlwe_scheme_switch_key.decomposition_base_log();
    let decomp_level_count = rlwe_scheme_switch_key.decomposition_level_count();
    let polynomial_size = rlwe_scheme_switch_key.polynomial_size();

    let rlwe_sk_poly = rlwe_secret_key.as_polynomial_list();
    let rlwe_sk_poly = rlwe_sk_poly.get(0);

    for (level, mut rlwe_ciphertext) in (1..=decomp_level_count.0)
        .rev()
        .map(DecompositionLevel)
        .zip(rlwe_scheme_switch_key.as_mut_glwe_ciphertext_list().iter_mut())
    {
        rlwe_ciphertext.as_mut().fill(Scalar::ZERO);

        encrypt_glwe_ciphertext(
            &rlwe_secret_key,
            &mut rlwe_ciphertext,
            &PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0)),
            noise_distribution,
            generator,
        );

        let mut rlwe_mask = rlwe_ciphertext.get_mut_mask();
        let mut rlwe_mask = rlwe_mask.as_mut_polynomial_list();
        let mut rlwe_mask = rlwe_mask.get_mut(0);

        let log_scale = Scalar::BITS - decomp_base_log.0 * level.0;
        slice_wrapping_add_scalar_mul_assign(
            rlwe_mask.as_mut(),
            &rlwe_sk_poly.as_ref(),
            Scalar::ONE << log_scale,
        );
    }
}

pub fn allocate_and_generate_new_rlwe_scheme_switch_key<
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    rlwe_secret_key: &GlweSecretKey<KeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> RlweSchemeSwitchKeyOwned<Scalar> {
    let mut new_rlwe_scheme_switch_key = RlweSchemeSwitchKeyOwned::new(
        Scalar::ZERO,
        rlwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    generate_rlwe_scheme_switch_key(
        rlwe_secret_key,
        &mut new_rlwe_scheme_switch_key,
        noise_distribution,
        generator,
    );

    new_rlwe_scheme_switch_key
}

