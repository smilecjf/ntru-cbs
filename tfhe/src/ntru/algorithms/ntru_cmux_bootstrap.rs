use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::core_crypto::prelude::lwe_ciphertext_modulus_switch;
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_div;
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_and_subtract;
use crate::core_crypto::prelude::ModulusSwitchedLweCiphertext;
use crate::core_crypto::prelude::SignedDecomposer;
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_ntru_cmux_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_ntru_cmux_bsk: &NtruCMuxBootstrapKey<InputCont>,
    fourier_ntru_cmux_bsk: &mut FourierNtruCMuxBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_ntru_cmux_bsk.input_lwe_dimension(),
        fourier_ntru_cmux_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        standard_ntru_cmux_bsk.output_lwe_dimension(),
        fourier_ntru_cmux_bsk.output_lwe_dimension(),
    );

    let polynomial_size = PolynomialSize(standard_ntru_cmux_bsk.output_lwe_dimension().0);
    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ntru_cmux_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_ntru_cmux_bootstrap_key_to_fourier_mem_optimized(
        standard_ntru_cmux_bsk,
        fourier_ntru_cmux_bsk,
        fft,
        stack,
    );
}

pub fn convert_standard_ntru_cmux_bootstrap_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
}

pub fn convert_standard_ntru_cmux_bootstrap_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_ntru_cmux_bsk: &NtruCMuxBootstrapKey<InputCont>,
    fourier_ntru_cmux_bsk: &mut FourierNtruCMuxBootstrapKey<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let ngsw_list = standard_ntru_cmux_bsk.get_ngsw_list();
    let mut fourier_ngsw_list = fourier_ntru_cmux_bsk.get_mut_fourier_ngsw_list();

    ngsw_list.iter()
        .zip(fourier_ngsw_list.iter_mut())
        .for_each(|(ngsw, mut fourier_ngsw)| {
            convert_standard_ngsw_ciphertext_to_fourier_mem_optimized(
                &ngsw,
                &mut fourier_ngsw,
                fft,
                stack,
            )
        });

    let ntru_switching_key = standard_ntru_cmux_bsk.get_ntru_switching_key();
    let mut fourier_ntru_switching_key = fourier_ntru_cmux_bsk.get_mut_fourier_ntru_switching_key();
    convert_standard_ntru_switching_key_to_fourier_mem_optimized(
        &ntru_switching_key,
        &mut fourier_ntru_switching_key,
        fft,
        stack,
    );
}

pub fn ntru_cmux_bootstrap_lwe_ciphertext<
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &PlaintextList<AccCont>,
    fourier_bsk: &FourierNtruCMuxBootstrapKey<KeyCont>,
) {
    assert!(
        input.ciphertext_modulus().is_power_of_two(),
        "This operation requires the input to have a power of two modulus."
    );
    assert_eq!(
        output.lwe_size().to_lwe_dimension().0,
        accumulator.plaintext_count().0,
    );

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        ntru_cmux_bootstrap_scratch::<OutputScalar>(
            PolynomialSize(accumulator.plaintext_count().0),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    ntru_cmux_bootstrap_mem_optimized(
        fourier_bsk,
        input,
        output,
        accumulator,
        fft,
        stack,
    );
}

pub fn ntru_cmux_bootstrap_scratch<Scalar>(
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    ntru_cmux_blind_rotate_assign_scratch::<Scalar>(polynomial_size, fft)?
        .try_and(StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?,
    )
}

pub fn ntru_cmux_blind_rotate_assign_scratch<Scalar>(
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_any_of([
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?,
        StackReq::try_all_of([
            StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?,
            add_ntru_external_product_assign_scratch::<Scalar>(polynomial_size, fft)?,
        ])?,
    ])
}

pub fn ntru_cmux_bootstrap_mem_optimized<InputScalar, OutputScalar, KeyCont, InputCont, OutputCont, AccCont>(
    bsk: &FourierNtruCMuxBootstrapKey<KeyCont>,
    lwe_in: &LweCiphertext<InputCont>,
    lwe_out: &mut LweCiphertext<OutputCont>,
    accumulator: &PlaintextList<AccCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    KeyCont: Container<Element = c64>,
    InputScalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = InputScalar>,
    OutputScalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
{
    let polynomial_size = PolynomialSize(accumulator.plaintext_count().0);
    // let (local_accumulator_data, stack) = stack.collect_aligned(CACHELINE_ALIGN, acc.as_ref().iter().copied());
    let (local_accumulator_data, stack) = stack.make_aligned_raw::<OutputScalar>(polynomial_size.0, CACHELINE_ALIGN);
    let mut local_accumulator = NtruCiphertextMutView::from_container(
        &mut *local_accumulator_data,
        polynomial_size,
        lwe_out.ciphertext_modulus(),
    );
    switch_to_ntru_ciphertext(
        &bsk.get_fourier_ntru_switching_key(),
        &accumulator,
        &mut local_accumulator,
    );

    let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

    let msed = lwe_ciphertext_modulus_switch(lwe_in.as_view(), log_modulus);

    ntru_cmux_blind_rotate_assign(
        bsk.as_view(),
        local_accumulator.as_mut_view(),
        &msed,
        fft,
        stack,
    );

    extract_lwe_sample_from_ntru_ciphertext(
        &local_accumulator,
        lwe_out,
        MonomialDegree(0),
    );
}

pub fn ntru_cmux_blind_rotate_assign<OutputScalar: UnsignedTorus>(
    bsk: FourierNtruCMuxBootstrapKeyView,
    mut lut: NtruCiphertextMutView<'_, OutputScalar>,
    msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) {
    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    assert_eq!(
        msed_lwe.log_modulus(),
        lut_poly_size.to_blind_rotation_input_modulus_log(),
    );

    let msed_lwe_mask = msed_lwe.mask();
    let msed_lwe_body = msed_lwe.body();
    let monomial_degree = MonomialDegree(msed_lwe_body.cast_into());

    let mut lut_poly = lut.as_mut_polynomial();
    let (tmp_poly, _) = stack.make_aligned_raw(lut_poly.as_ref().len(), CACHELINE_ALIGN);
    let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
    tmp_poly.as_mut().copy_from_slice(lut_poly.as_ref());
    polynomial_wrapping_monic_monomial_div(&mut lut_poly, &tmp_poly, monomial_degree);

    let mut ct0 = lut;
    let (ct1, stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
    let mut ct1 = NtruCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

    for (lwe_mask_element, bsk_ngsw) in msed_lwe_mask
        .zip(bsk.get_fourier_ngsw_list().iter()) {
            if lwe_mask_element != 0 {
                let monomial_degree = MonomialDegree(lwe_mask_element);

                let mut ct1_poly = ct1.as_mut_polynomial();
                let ct0_poly = ct0.as_polynomial();
                polynomial_wrapping_monic_monomial_mul_and_subtract(
                    &mut ct1_poly,
                    &ct0_poly, 
                    monomial_degree,
                );

                add_ntru_external_product_assign(
                    &mut ct0.as_mut_view(),
                    bsk_ngsw,
                    ct1.as_view(),
                    fft,
                    stack,
                );
            }
        }
    
    if !ciphertext_modulus.is_native_modulus() {
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}
