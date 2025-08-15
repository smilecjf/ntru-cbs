use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_opposite_assign;
use crate::ntru::entities::*;

pub fn extract_lwe_sample_from_ntru_ciphertext<Scalar, InputCont, OutputCont>(
    input_ntru: &NtruCiphertext<InputCont>,
    output_lwe: &mut LweCiphertext<OutputCont>,
    nth: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let in_lwe_dim = LweDimension(input_ntru.polynomial_size().0);
    let out_lwe_dim = output_lwe.lwe_size().to_lwe_dimension();

    assert_eq!(
        in_lwe_dim, out_lwe_dim,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {in_lwe_dim:?} for input and {out_lwe_dim:?} for output.",
    );

    assert_eq!(
        input_ntru.ciphertext_modulus(),
        output_lwe.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_ntru.ciphertext_modulus(),
        output_lwe.ciphertext_modulus()
    );

    assert!(
        input_ntru
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "Only support power-of-two modulus, currently.",
    );

    let (mut lwe_mask, lwe_body) = output_lwe.get_mut_mask_and_body();

    // LWE body part
    *lwe_body.data = Scalar::ZERO;

    // LWE mask part
    lwe_mask.as_mut().copy_from_slice(input_ntru.as_ref());
    let opposite_count = input_ntru.polynomial_size().0 - nth.0 - 1;

    let lwe_mask = lwe_mask.as_mut();
    lwe_mask.reverse();
    // Unlike GLWE decryption, NTRU decryption multiplies ntru ciphertext polynomial
    // by secret key polynomial, and do not subtract by the result.
    slice_wrapping_opposite_assign(&mut lwe_mask[opposite_count..]);
    lwe_mask.rotate_left(opposite_count);
}