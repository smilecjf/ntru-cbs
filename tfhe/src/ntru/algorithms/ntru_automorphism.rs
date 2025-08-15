use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_ntru_automorphism_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_ntru_auto_key: &NtruAutomorphismKey<InputCont>,
    fourier_ntru_auto_key: &mut FourierNtruAutomorphismKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_ntru_auto_key.polynomial_size(),
        fourier_ntru_auto_key.polynomial_size(),
    );

    assert_eq!(
        standard_ntru_auto_key.decomposition_base_log(),
        fourier_ntru_auto_key.decomposition_base_log(),
    );

    assert_eq!(
        standard_ntru_auto_key.decomposition_level_count(),
        fourier_ntru_auto_key.decomposition_level_count(),
    );

    let fft = Fft::new(fourier_ntru_auto_key.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ntru_automorphism_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_ntru_automorphism_key_to_fourier_mem_optimized(
        standard_ntru_auto_key,
        fourier_ntru_auto_key,
        fft,
        stack,
    );
}

pub fn convert_standard_ntru_automorphism_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
}

pub fn convert_standard_ntru_automorphism_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_ntru_auto_key: &NtruAutomorphismKey<InputCont>,
    fourier_ntru_auto_key: &mut FourierNtruAutomorphismKey<OutputCont>,
    fft: FftView,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    fourier_ntru_auto_key.set_automorphism_index(standard_ntru_auto_key.automorphism_index());
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized(
        &standard_ntru_auto_key.as_ngsw_ciphertext(),
        &mut fourier_ntru_auto_key.as_mut_fourier_ngsw_ciphertext(),
        fft,
        stack,
    );
}

pub fn automorphism_ntru_ciphertext<Scalar, KskCont, InputCont, OutputCont>(
    ntru_automorphism_key: &FourierNtruAutomorphismKey<KskCont>,
    input_ntru_ciphertext: &NtruCiphertext<InputCont>,
    output_ntru_ciphertext: &mut NtruCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KskCont: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_ntru_ciphertext.polynomial_size(),
        output_ntru_ciphertext.polynomial_size(),
    );

    assert_eq!(
        input_ntru_ciphertext.polynomial_size(),
        ntru_automorphism_key.polynomial_size(),
    );

    assert_eq!(
        input_ntru_ciphertext.ciphertext_modulus(),
        output_ntru_ciphertext.ciphertext_modulus(),
    );

    assert!(
        input_ntru_ciphertext
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "Only support power-of-two modulus currently.",
    );

    let polynomial_size = ntru_automorphism_key.polynomial_size();
    let ciphertext_modulus = input_ntru_ciphertext.ciphertext_modulus();

    let mut frobenius_ntru_ciphertext = NtruCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );
    frobenius_map_poly(
        &input_ntru_ciphertext.as_polynomial(),
        &mut frobenius_ntru_ciphertext.as_mut_polynomial(),
        ntru_automorphism_key.automorphism_index(),
    );

    keyswitch_ntru_ciphertext(
        &ntru_automorphism_key.as_fourier_ntru_keyswitch_key(),
        &frobenius_ntru_ciphertext,
        output_ntru_ciphertext,
    );
}
