use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::commons::ciphertext_modulus::{CiphertextModulus, CiphertextModulusKind};
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm, SignedDecomposer};
use crate::core_crypto::commons::math::random::{Distribution, Uniform};

use crate::core_crypto::prelude::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::ntru::algorithms::decrypt_ntru_ciphertext;
use crate::ntru::entities::*;

pub fn ngsw_encryption_multiplicative_factor<Scalar: UnsignedInteger> (
    ciphertext_modulus: CiphertextModulus<Scalar>,
    decomp_level: DecompositionLevel,
    decomp_base_log: DecompositionBaseLog,
    cleartext: Cleartext<Scalar>,
) -> Scalar {
    assert!(
        ciphertext_modulus.is_power_of_two(),
        "Only support power-of-two modulus currently."
    );

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
            let native_decomp_term = DecompositionTerm::new(decomp_level, decomp_base_log, cleartext.0)
                .to_recomposition_summand();
            native_decomp_term
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus())
        },
        CiphertextModulusKind::Other => Scalar::ONE
    }
}

pub fn encrypt_constant_ngsw_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    ntru_secret_key: &NtruSecretKey<KeyCont>,
    output: &mut NgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == ntru_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        ntru_secret_key.polynomial_size(),
    );

    assert!(
        output.ciphertext_modulus() == ntru_secret_key.ciphertext_modulus(),
        "Mismatch between ciphertext moduli of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.ciphertext_modulus(),
        ntru_secret_key.ciphertext_modulus(),
    );

    assert!(
        output.ciphertext_modulus().is_power_of_two(),
        "Only support poewr-of-two modulus currently."
    );

    let polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    let sk_inv_poly = ntru_secret_key.get_secret_key_inverse_polynomial();
    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);

    for (level, mut ntru_ciphertext) in (1..=decomp_level_count.0)
        .rev()
        .map(DecompositionLevel)
        .zip(output.iter_mut())
    {
        let factor = ngsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            level,
            decomp_base_log,
            cleartext,
        );

        generator.unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
            buf.as_mut(),
            noise_distribution,
            ciphertext_modulus,
        );

        polynomial_wrapping_mul(
            &mut ntru_ciphertext.as_mut_polynomial(),
            &buf,
            &sk_inv_poly,
        );

        ntru_ciphertext.as_mut()[0] = ntru_ciphertext.as_mut()[0].wrapping_add(factor);

        if !ciphertext_modulus.is_native_modulus() {
            let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
            slice_wrapping_scalar_mul_assign(
                ntru_ciphertext.as_mut(),
                torus_scaling,
            );
        }

    }
}

pub fn encrypt_monomial_ngsw_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    ntru_secret_key: &NtruSecretKey<KeyCont>,
    output: &mut NgswCiphertext<OutputCont>,
    monomial_degree: MonomialDegree,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    Scalar: std::fmt::Display + CastInto<f64>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == ntru_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        ntru_secret_key.polynomial_size(),
    );

    assert!(
        output.ciphertext_modulus() == ntru_secret_key.ciphertext_modulus(),
        "Mismatch between ciphertext moduli of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.ciphertext_modulus(),
        ntru_secret_key.ciphertext_modulus(),
    );

    assert!(
        output.ciphertext_modulus().is_power_of_two(),
        "Only support poewr-of-two modulus currently."
    );

    let polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    let sign = if monomial_degree.0 % (2 * polynomial_size.0) < polynomial_size.0 { Scalar::ONE } else { Scalar::MAX };
    let monomial_degree = monomial_degree.0 % polynomial_size.0;

    let sk_inv_poly = ntru_secret_key.get_secret_key_inverse_polynomial();
    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);

    for (level, mut ntru_ciphertext) in (1..=decomp_level_count.0)
        .rev()
        .map(DecompositionLevel)
        .zip(output.iter_mut())
    {
        let factor = ngsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            level,
            decomp_base_log,
            Cleartext(Scalar::ONE),
        ).wrapping_mul(sign);

        generator.unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
            buf.as_mut(),
            noise_distribution,
            ciphertext_modulus,
        );

        polynomial_wrapping_mul(
            &mut ntru_ciphertext.as_mut_polynomial(),
            &buf,
            &sk_inv_poly,
        );

        ntru_ciphertext.as_mut()[monomial_degree] = ntru_ciphertext.as_mut()[monomial_degree].wrapping_add(factor);

        if !ciphertext_modulus.is_native_modulus() {
            let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
            slice_wrapping_scalar_mul_assign(
                ntru_ciphertext.as_mut(),
                torus_scaling,
            );
        }

    }
}

pub fn decrypt_constant_ngsw_ciphertext<Scalar, KeyCont, InputCont>(
    ntru_secret_key: &NtruSecretKey<KeyCont>,
    ngsw_ciphertext: &NgswCiphertext<InputCont>,
) -> Cleartext<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        ngsw_ciphertext.polynomial_size() == ntru_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of input ciphertext and input secret key. \
        Got {:?} in ciphertext, and {:?} in secret key.",
        ngsw_ciphertext.polynomial_size(),
        ntru_secret_key.polynomial_size(),
    );

    assert!(
        ngsw_ciphertext.ciphertext_modulus() == ntru_secret_key.ciphertext_modulus(),
        "Mismatch between ciphertext moduli of input ciphertext and input secret key. \
        Got {:?} in ciphertext, and {:?} in secret key.",
        ngsw_ciphertext.ciphertext_modulus(),
        ntru_secret_key.ciphertext_modulus(),
    );

    let polynomial_size = ngsw_ciphertext.polynomial_size();
    let ciphertext_modulus = ngsw_ciphertext.ciphertext_modulus();

    assert!(
        ciphertext_modulus.is_power_of_two(),
        "Only support power-of-two modulus currently.",
    );

    let first_row = ngsw_ciphertext.first().unwrap();
    let decomp_level = ngsw_ciphertext.decomposition_level_count();
    let decomp_base_log = ngsw_ciphertext.decomposition_base_log();

    let mut decrypted_plaintext_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(polynomial_size.0),
    );

    decrypt_ntru_ciphertext(ntru_secret_key, &first_row, &mut decrypted_plaintext_list);

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
            let decomposer = SignedDecomposer::new(decomp_base_log, decomp_level);

            for elt in decrypted_plaintext_list.iter_mut() {
                let rounded = decomposer.closest_representable(
                    (*elt.0)
                        .wrapping_mul(ciphertext_modulus.get_power_of_two_scaling_to_native_torus()),
                );
                *elt.0 = rounded.wrapping_div(Scalar::ONE << (Scalar::BITS - decomp_base_log.0 * decomp_level.0));
            }
        },
        CiphertextModulusKind::Other => {},
    }

    let sk_inv_poly = ntru_secret_key.get_secret_key_inverse_polynomial();

    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);
    polynomial_wrapping_mul(&mut buf, &decrypted_plaintext_list.as_polynomial(), &sk_inv_poly);

    let torus_scale = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
    let m =buf.as_ref()[0].wrapping_mul(torus_scale);

    Cleartext(m.wrapping_div(torus_scale))
}
