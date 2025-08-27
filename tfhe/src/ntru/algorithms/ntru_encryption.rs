//! Module containing ntru encryption

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::{
    slice_wrapping_scalar_mul_assign,
    slice_wrapping_scalar_div_assign,
};
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
// use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

// use crate::ntru::algorithms::*;
use crate::ntru::entities::*;

pub fn encrypt_ntru_ciphertext<Scalar, NoiseDistribution, KeyCont, InputCont, OutputCont, Gen>(
    ntru_secret_key: &NtruSecretKey<KeyCont>,
    output_ntru_ciphertext: &mut NtruCiphertext<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        ntru_secret_key.polynomial_size().0 == output_ntru_ciphertext.polynomial_size().0,
        "Mismatch between PolynomialSize of input secret key and output ciphertext. \
        Got {:?} in secret key, and {:?} in output.",
        ntru_secret_key.polynomial_size().0,
        output_ntru_ciphertext.polynomial_size().0,
    );
    assert!(
        output_ntru_ciphertext.polynomial_size().0 == input_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of output ciphertext and PlaintextCount of input. \
        Got {:?} in output, and {:} in input.",
        output_ntru_ciphertext.polynomial_size().0,
        input_plaintext_list.plaintext_count().0,
    );
    assert!(
        ntru_secret_key.ciphertext_modulus() == output_ntru_ciphertext.ciphertext_modulus(),
        "Mismatch between CiphertextModulus of input secret key and output. \
        Got {:?} in secret key, and {:?} in output.",
        ntru_secret_key.ciphertext_modulus(),
        output_ntru_ciphertext.ciphertext_modulus(),
    );

    let polynomial_size = ntru_secret_key.polynomial_size();
    let ciphertext_modulus = ntru_secret_key.ciphertext_modulus();

    assert!(
        ciphertext_modulus.is_compatible_with_native_modulus(),
        "Only support power-of-two modulus currently."
    );

    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);

    generator.unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
        buf.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );

    polynomial_wrapping_add_assign(
        &mut buf,
        &input_plaintext_list.as_polynomial(),
    );

    let sk_inv_poly = ntru_secret_key.get_secret_key_inverse_polynomial();

    polynomial_wrapping_mul(
        &mut output_ntru_ciphertext.as_mut_polynomial(),
        &buf,
        &sk_inv_poly,
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_scalar_mul_assign(
            output_ntru_ciphertext.as_mut(),
            torus_scaling,
        );
    }
}

pub fn decrypt_ntru_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    ntru_secret_key: &NtruSecretKey<KeyCont>,
    input_ntru_ciphertext: &NtruCiphertext<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    // Scalar: UnsignedTorus,
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        ntru_secret_key.polynomial_size().0 == input_ntru_ciphertext.polynomial_size().0,
        "Mismatch between PolynomialSize of input secret key and input ciphertext. \
        Got {:?} in secret key, and {:?} in input.",
        ntru_secret_key.polynomial_size().0,
        input_ntru_ciphertext.polynomial_size().0,
    );
    assert!(
        input_ntru_ciphertext.polynomial_size().0 == output_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of input ciphertext and PlaintextCount of output. \
        Got {:?} in input, and {:?} in output.",
        input_ntru_ciphertext.polynomial_size().0,
        output_plaintext_list.plaintext_count().0,
    );
    assert!(
        ntru_secret_key.ciphertext_modulus() == input_ntru_ciphertext.ciphertext_modulus(),
        "Mistmatch between CiphertextModulus of input secret key and input ciphertext. \
        Got {:?} in secret key, and {:?} in input.",
        ntru_secret_key.ciphertext_modulus(),
        input_ntru_ciphertext.ciphertext_modulus(),
    );

    let ciphertext_modulus = ntru_secret_key.ciphertext_modulus();

    assert!(
        ciphertext_modulus.is_compatible_with_native_modulus(),
        "Only support power-of-two modulus currently."
    );

    let sk_poly = ntru_secret_key.get_secret_key_polynomial();

    polynomial_wrapping_mul(
        &mut output_plaintext_list.as_mut_polynomial(),
        &input_ntru_ciphertext.as_polynomial(),
        &sk_poly,
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_scalar_div_assign(
            output_plaintext_list.as_mut(),
            torus_scaling,
        );
    }
}
