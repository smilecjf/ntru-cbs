use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::ntru::algorithms::*;
use crate::ntru::entities::*;

use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_ntru_trace_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_ntru_trace_key: &NtruTraceKey<InputCont>,
    fourier_ntru_trace_key: &mut FourierNtruTraceKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_ntru_trace_key.polynomial_size(),
        fourier_ntru_trace_key.polynomial_size(),
    );

    assert_eq!(
        standard_ntru_trace_key.decomposition_base_log(),
        fourier_ntru_trace_key.decomposition_base_log(),
    );

    assert_eq!(
        standard_ntru_trace_key.decomposition_level_count(),
        fourier_ntru_trace_key.decomposition_level_count(),
    );

    let polynomial_size = standard_ntru_trace_key.polynomial_size();
    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ntru_trace_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_ntru_trace_key_to_fourier_mem_optimized(
        standard_ntru_trace_key,
        fourier_ntru_trace_key,
        fft,
        stack,
    );
}

pub fn convert_standard_ntru_trace_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    convert_standard_ntru_automorphism_key_to_fourier_mem_optimized_requirement(fft)
}

pub fn convert_standard_ntru_trace_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_ntru_trace_key: &NtruTraceKey<InputCont>,
    fourier_ntru_trace_key: &mut FourierNtruTraceKey<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let polynomial_size = standard_ntru_trace_key.polynomial_size();

    for k in 1..=polynomial_size.0.ilog2() {
        let ntru_auto_key = standard_ntru_trace_key.get_automorphism_key(k as usize - 1);
        let mut fourier_ntru_auto_key = fourier_ntru_trace_key.get_mut_automorphism_key(k as usize - 1);

        convert_standard_ntru_automorphism_key_to_fourier_mem_optimized(
            &ntru_auto_key,
            &mut fourier_ntru_auto_key,
            fft,
            stack,
        );
    }
}

pub fn rev_trace_ntru_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    ntru_trace_key: &FourierNtruTraceKey<KeyCont>,
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
        input_ntru_ciphertext.ciphertext_modulus(),
        output_ntru_ciphertext.ciphertext_modulus(),
    );

    assert!(
        input_ntru_ciphertext
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "Only support power-of-two modulus currently.",
    );

    let polynomial_size = input_ntru_ciphertext.polynomial_size();
    let ciphertext_modulus = input_ntru_ciphertext.ciphertext_modulus();

    let mut buf = NtruCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );
    output_ntru_ciphertext.as_mut()
        .clone_from_slice(input_ntru_ciphertext.as_ref());

    for k in 1..=polynomial_size.0.ilog2() {
        let fourier_ntru_auto_key = ntru_trace_key.get_automorphism_key(k as usize - 1);

        ntru_ciphertext_round_by_2_assign(output_ntru_ciphertext);

        automorphism_ntru_ciphertext(
            &fourier_ntru_auto_key,
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
    ntru_trace_key: &FourierNtruTraceKey<KeyCont>,
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
