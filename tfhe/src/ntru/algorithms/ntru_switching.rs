use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::PlaintextList;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::core_crypto::prelude::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_ntru_switching_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_ntru_swk: &NtruSwitchingKey<InputCont>,
    fourier_ntru_swk: &mut FourierNtruSwitchingKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_ntru_swk.polynomial_size(),
        fourier_ntru_swk.polynomial_size(),
    );

    assert_eq!(
        standard_ntru_swk.decomposition_base_log(),
        fourier_ntru_swk.decomposition_base_log(),
    );

    assert_eq!(
        standard_ntru_swk.decomposition_level_count(),
        fourier_ntru_swk.decomposition_level_count(),
    );

    let fft = Fft::new(fourier_ntru_swk.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ntru_switching_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_ntru_switching_key_to_fourier_mem_optimized(
        standard_ntru_swk,
        fourier_ntru_swk,
        fft,
        stack,
    );
}

pub fn convert_standard_ntru_switching_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
}

pub fn convert_standard_ntru_switching_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_ntru_swk: &NtruSwitchingKey<InputCont>,
    fourier_ntru_swk: &mut FourierNtruSwitchingKey<OutputCont>,
    fft: FftView,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized(
        &standard_ntru_swk.as_ngsw_ciphertext(),
        &mut fourier_ntru_swk.as_mut_fourier_ngsw_ciphertext(),
        fft,
        stack,
    );
}

pub fn switch_to_ntru_ciphertext<Scalar, SwkCont, InputCont, OutputCont>(
    ntru_switching_key: &FourierNtruSwitchingKey<SwkCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    output_ntru_ciphertext: &mut NtruCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    SwkCont: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        ntru_switching_key.polynomial_size().0,
        input_plaintext_list.plaintext_count().0,
    );

    assert_eq!(
        ntru_switching_key.polynomial_size(),
        output_ntru_ciphertext.polynomial_size(),
    );

    assert!(
        output_ntru_ciphertext
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "Only support power-of-two modulus currently.",
    );

    let polynomial_size = output_ntru_ciphertext.polynomial_size();
    let ciphertext_modulus = output_ntru_ciphertext.ciphertext_modulus();
    let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();

    let mut input_ntru_ciphertext = NtruCiphertext::new(
        Scalar::ZERO,
        polynomial_size,
        ciphertext_modulus,
    );
    input_ntru_ciphertext.as_mut().clone_from_slice(input_plaintext_list.as_ref());
    slice_wrapping_scalar_mul_assign(
        &mut input_ntru_ciphertext.as_mut(),
        torus_scaling,
    );

    keyswitch_ntru_ciphertext(
        &ntru_switching_key.as_fourier_ntru_keyswitch_key(),
        &input_ntru_ciphertext,
        output_ntru_ciphertext,
    );
}
