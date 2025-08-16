use crate::core_crypto::commons::traits::*;
use crate::core_crypto::prelude::slice_algorithms::slice_wrapping_scalar_div_assign;
use crate::ntru::algorithms::*;
use crate::ntru::entities::*;

use tfhe_fft::c64;


pub fn rev_trace_ntru_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    ntru_trace_key: &NtruTraceKey<Scalar, KeyCont>,
    input_ntru_ciphertext: &NtruCiphertext<InputCont>,
    output_ntru_ciphertext: &mut NtruCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        ntru_trace_key.polynomial_size(),
        input_ntru_ciphertext.polynomial_size(),
    );

    assert_eq!(
        ntru_trace_key.polynomial_size(),
        output_ntru_ciphertext.polynomial_size(),
    );

    assert_eq!(
        ntru_trace_key.ciphertext_modulus(),
        input_ntru_ciphertext.ciphertext_modulus(),
    );

    assert_eq!(
        ntru_trace_key.ciphertext_modulus(),
        output_ntru_ciphertext.ciphertext_modulus(),
    );

    assert!(
        ntru_trace_key
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "Only support power-of-two modulus currently.",
    );

    let polynomial_size = ntru_trace_key.polynomial_size();
    let ciphertext_modulus = ntru_trace_key.ciphertext_modulus();

    let ntru_auto_keys = ntru_trace_key.get_automorphism_keys();

    let mut buf = NtruCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );
    output_ntru_ciphertext.as_mut()
        .clone_from_slice(input_ntru_ciphertext.as_ref());

    for k in 1..=polynomial_size.0.ilog2() {
        let auto_index = AutomorphismIndex((1 << k) + 1);
        let fourier_ntru_auto_key = ntru_auto_keys.get(&auto_index.0).unwrap();

        slice_wrapping_scalar_div_assign(output_ntru_ciphertext.as_mut(), Scalar::TWO);

        automorphism_ntru_ciphertext(
            fourier_ntru_auto_key,
            &output_ntru_ciphertext,
            &mut buf,
        );

        ntru_ciphertext_add_assign(
            output_ntru_ciphertext,
            &buf,
        );
    }
}

pub fn rev_trace_ntru_ciphertext_assign<Scalar, KeyCont, InputCont>(
    ntru_trace_key: &NtruTraceKey<Scalar, KeyCont>,
    input_ntru_ciphertext: &mut NtruCiphertext<InputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = c64>,
    InputCont: ContainerMut<Element = Scalar>,
{
    let mut buf = NtruCiphertext::new(
        Scalar::ZERO,
        input_ntru_ciphertext.polynomial_size(),
        input_ntru_ciphertext.ciphertext_modulus(),
    );
    buf.as_mut().clone_from_slice(input_ntru_ciphertext.as_ref());

    rev_trace_ntru_ciphertext(
        ntru_trace_key,
        &buf,
        input_ntru_ciphertext,
    );
}
