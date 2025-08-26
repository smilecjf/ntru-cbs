use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_rlwe_scheme_switch_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_rlwe_ss_key: &RlweSchemeSwitchKey<InputCont>,
    fourier_rlwe_ss_key: &mut FourierRlweSchemeSwitchKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_rlwe_ss_key.polynomial_size(),
        fourier_rlwe_ss_key.polynomial_size(),
    );

    assert_eq!(
        standard_rlwe_ss_key.decomposition_base_log(),
        fourier_rlwe_ss_key.decomposition_base_log(),
    );

    assert_eq!(
        standard_rlwe_ss_key.decomposition_level_count(),
        fourier_rlwe_ss_key.decomposition_level_count(),
    );

    let fft = Fft::new(fourier_rlwe_ss_key.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_rlwe_scheme_switch_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_rlwe_scheme_switch_key_to_fourier_mem_optimized(
        standard_rlwe_ss_key,
        fourier_rlwe_ss_key,
        fft,
        stack,
    );
}

pub fn convert_standard_rlwe_scheme_switch_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

pub fn convert_standard_rlwe_scheme_switch_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_rlwe_ss_key: &RlweSchemeSwitchKey<InputCont>,
    fourier_rlwe_ss_key: &mut FourierRlweSchemeSwitchKey<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    convert_standard_ntru_to_rlwe_keyswitch_key_to_fourier_mem_optimized(
        &standard_rlwe_ss_key.as_ntru_to_rlwe_keyswitch_key(),
        &mut fourier_rlwe_ss_key.as_mut_fourier_ntru_to_rlwe_keyswitch_key(),
        fft,
        stack,
    );
}

pub fn scheme_switch_rlwe_ciphertext<Scalar, SSKeyCont, InputCont, OutputCont>(
    rlwe_scheme_switch_key: &FourierRlweSchemeSwitchKey<SSKeyCont>,
    input_rlwe_ciphertext: &GlweCiphertext<InputCont>,
    output_rlwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    SSKeyCont: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let polynomial_size = rlwe_scheme_switch_key.polynomial_size();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        scheme_switch_rlwe_ciphertext_scratch::<Scalar>(
            polynomial_size,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    scheme_switch_rlwe_ciphertext_mem_optimized(
        rlwe_scheme_switch_key,
        input_rlwe_ciphertext,
        output_rlwe_ciphertext,
        fft,
        stack,
    );
}

pub fn scheme_switch_rlwe_ciphertext_scratch<Scalar>(
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    keyswitch_ntru_to_rlwe_scratch::<Scalar>(polynomial_size, fft)
}

pub fn scheme_switch_rlwe_ciphertext_mem_optimized<Scalar, SSKeyCont, InputCont, OutputCont>(
    rlwe_scheme_switch_key: &FourierRlweSchemeSwitchKey<SSKeyCont>,
    input_rlwe_ciphertext: &GlweCiphertext<InputCont>,
    output_rlwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    SSKeyCont: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(input_rlwe_ciphertext.glwe_size() == GlweSize(2));
    assert!(output_rlwe_ciphertext.glwe_size() == GlweSize(2));

    assert_eq!(
        rlwe_scheme_switch_key.polynomial_size(),
        input_rlwe_ciphertext.polynomial_size(),
    );

    assert_eq!(
        rlwe_scheme_switch_key.polynomial_size(),
        output_rlwe_ciphertext.polynomial_size(),
    );

    assert_eq!(
        input_rlwe_ciphertext.ciphertext_modulus(),
        output_rlwe_ciphertext.ciphertext_modulus(),
    );

    assert!(
        input_rlwe_ciphertext
            .ciphertext_modulus()
            .is_power_of_two(),
        "Only support power-of-two modulus currently.",
    );

    let input_rlwe_mask = input_rlwe_ciphertext.get_mask();
    let input_rlwe_mask_poly = input_rlwe_mask.as_polynomial_list();
    let input_rlwe_mask_poly = input_rlwe_mask_poly.get(0);
    let input_rlwe_mask_poly = NtruCiphertext::from_container(
        input_rlwe_mask_poly.as_ref(),
        input_rlwe_ciphertext.polynomial_size(),
        input_rlwe_ciphertext.ciphertext_modulus(),
    );

    output_rlwe_ciphertext.as_mut().fill(Scalar::ZERO);
    keyswitch_ntru_to_rlwe_mem_optimized(
        rlwe_scheme_switch_key.as_fourier_ntru_to_rlwe_keyswitch_key(),
        input_rlwe_mask_poly.as_view(),
        &mut output_rlwe_ciphertext.as_mut_view(),
        fft,
        stack,
    );

    let input_rlwe_body = input_rlwe_ciphertext.get_body();
    let input_rlwe_body_poly = input_rlwe_body.as_polynomial();

    let mut output_rlwe_mask = output_rlwe_ciphertext.get_mut_mask();
    let mut output_rlwe_mask_poly = output_rlwe_mask.as_mut_polynomial_list();
    let mut output_rlwe_mask_poly = output_rlwe_mask_poly.get_mut(0);

    slice_wrapping_sub_assign(output_rlwe_mask_poly.as_mut(), input_rlwe_body_poly.as_ref());
    slice_wrapping_opposite_assign(output_rlwe_ciphertext.as_mut());
}

