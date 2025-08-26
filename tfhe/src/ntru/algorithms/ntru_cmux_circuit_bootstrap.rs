use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_div_assign;
use crate::ntru::entities::*;
use crate::ntru::algorithms::*;

use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_ntru_cmux_circuit_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_ntru_cmux_cbs_key: &NtruCMuxCircuitBootstrapKey<InputCont>,
    fourier_ntru_cmux_cbs_key: &mut FourierNtruCMuxCircuitBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_ntru_cmux_cbs_key.input_lwe_dimension(),
        fourier_ntru_cmux_cbs_key.input_lwe_dimension(),
    );

    assert_eq!(
        standard_ntru_cmux_cbs_key.output_lwe_dimension(),
        fourier_ntru_cmux_cbs_key.output_lwe_dimension(),
    );

    let polynomial_size = standard_ntru_cmux_cbs_key.polynomial_size();
    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ntru_cmux_circuit_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_ntru_cmux_circuit_bootstrap_key_to_fourier_mem_optimized(
        standard_ntru_cmux_cbs_key,
        fourier_ntru_cmux_cbs_key,
        fft,
        stack,
    );
}

pub fn convert_standard_ntru_cmux_circuit_bootstrap_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
}

pub fn convert_standard_ntru_cmux_circuit_bootstrap_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_ntru_cmux_cbs_key: &NtruCMuxCircuitBootstrapKey<InputCont>,
    fourier_ntru_cmux_cbs_key: &mut FourierNtruCMuxCircuitBootstrapKey<OutputCont>,
    fft: FftView,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let ntru_cmux_bsk = standard_ntru_cmux_cbs_key.get_ntru_cmux_bootstrap_key();
    let mut fourier_ntru_cmux_bsk = fourier_ntru_cmux_cbs_key.get_mut_fourier_ntru_cmux_bootstrap_key();
    convert_standard_ntru_cmux_bootstrap_key_to_fourier_mem_optimized(
        &ntru_cmux_bsk,
        &mut fourier_ntru_cmux_bsk,
        fft,
        stack,
    );

    let ntru_trace_key = standard_ntru_cmux_cbs_key.get_ntru_trace_key();
    let mut fourier_ntru_trace_key = fourier_ntru_cmux_cbs_key.get_mut_fourier_ntru_trace_key();
    convert_standard_ntru_trace_key_to_fourier_mem_optimized(
        &ntru_trace_key,
        &mut fourier_ntru_trace_key,
        fft,
        stack,
    );

    let ntru_to_rlwe_ksk = standard_ntru_cmux_cbs_key.get_ntru_to_rlwe_keyswitch_key();
    let mut fourier_ntru_to_rlwe_ksk = fourier_ntru_cmux_cbs_key.get_mut_fourier_ntru_to_rlwe_keyswitch_key();
    convert_standard_ntru_to_rlwe_keyswitch_key_to_fourier_mem_optimized(
        &ntru_to_rlwe_ksk,
        &mut fourier_ntru_to_rlwe_ksk,
        fft,
        stack,
    );

    let rlwe_ss_key = standard_ntru_cmux_cbs_key.get_rlwe_scheme_switch_key();
    let mut fourier_rlwe_ss_key = fourier_ntru_cmux_cbs_key.get_mut_fourier_rlwe_scheme_switch_key();
    convert_standard_rlwe_scheme_switch_key_to_fourier_mem_optimized(
        &rlwe_ss_key,
        &mut fourier_rlwe_ss_key,
        fft,
        stack,
    );
}

pub fn ntru_cmux_circuit_bootstrap_lwe_ciphertext<
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut GgswCiphertext<OutputCont>,
    fourier_ntru_cmux_cbs_key: &FourierNtruCMuxCircuitBootstrapKey<KeyCont>,
    log_lut_count: LutCountLog,
) {
    let polynomial_size = output.polynomial_size();

    let mut buffers = ComputationBuffers::new();
    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    buffers.resize(
        ntru_cmux_circuit_bootstrap_lwe_ciphertext_scratch::<OutputScalar>(
            polynomial_size,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    ntru_cmux_circuit_bootstrap_lwe_ciphertext_mem_optimized(
        input,
        output,
        fourier_ntru_cmux_cbs_key,
        log_lut_count,
        fft,
        stack,
    );
}

pub fn ntru_cmux_circuit_bootstrap_lwe_ciphertext_scratch<Scalar>(
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        StackReq::try_new::<Scalar>(2 * polynomial_size.0)?,
        StackReq::try_new::<Scalar>(polynomial_size.0)?,
        StackReq::try_any_of([
            ntru_cmux_blind_rotate_assign_scratch::<Scalar>(polynomial_size, fft)?,
            // trace
            // scheme_switch
        ])?,
    ])
}

pub fn ntru_cmux_circuit_bootstrap_lwe_ciphertext_mem_optimized<
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut GgswCiphertext<OutputCont>,
    fourier_ntru_cmux_cbs_key: &FourierNtruCMuxCircuitBootstrapKey<KeyCont>,
    log_lut_count: LutCountLog,
    fft: FftView<'_>,
    stack: &mut PodStack,
) {
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        fourier_ntru_cmux_cbs_key.input_lwe_dimension(),
    );

    assert_eq!(
        output.polynomial_size(),
        fourier_ntru_cmux_cbs_key.polynomial_size(),
    );

    let polynomial_size = output.polynomial_size();
    let half_box_size = polynomial_size.0 / 2;
    let ciphertext_modulus = output.ciphertext_modulus();
    let log_ciphertext_modulus = ciphertext_modulus.into_modulus_log().0;

    let lut_count = 1 << log_lut_count.0;
    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();

    let fourier_ntru_cmux_bsk = fourier_ntru_cmux_cbs_key.get_fourier_ntru_cmux_bootstrap_key();
    let fourier_ntru_trace_key = fourier_ntru_cmux_cbs_key.get_fourier_ntru_trace_key();
    let fourier_ntru_to_rlwe_ksk = fourier_ntru_cmux_cbs_key.get_fourier_ntru_to_rlwe_keyswitch_key();
    let fourier_rlwe_ss_key = fourier_ntru_cmux_cbs_key.get_fourier_rlwe_scheme_switch_key();

    // TODO: add it to stack memory
    let mut ntru_buffer = NtruCiphertextList::new(OutputScalar::ZERO, polynomial_size, NtruCiphertextCount(decomp_level_count.0), ciphertext_modulus);

    for (acc_idx, mut ntru_chunk) in ntru_buffer.chunks_mut(lut_count).enumerate()
    {
        let (accumulator_plaintext_list, stack1) = stack.make_raw::<OutputScalar>(polynomial_size.0);
        let (accumulator_ntru_ciphertext, stack2) = stack1.make_raw::<OutputScalar>(polynomial_size.0);

        let mut accumulator = PlaintextList::from_container(accumulator_plaintext_list.as_mut());
        for (i, elt) in accumulator.as_mut().iter_mut().enumerate() {
            let k = i % lut_count;
            let level = if decomp_level_count.0 > acc_idx * lut_count + k {
                decomp_level_count.0 - (acc_idx * lut_count + k)
            } else {
                1
            };
            let log_scale = log_ciphertext_modulus - level * decomp_base_log.0;
            *elt = (OutputScalar::ONE).wrapping_neg() << (log_scale - 1); // - (q / 2 B^k)
        }

        for a_i in accumulator.as_mut()[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
        accumulator.as_mut().rotate_left(half_box_size);

        let mut accumulator_ntru_ciphertext = NtruCiphertext::from_container(accumulator_ntru_ciphertext, polynomial_size, ciphertext_modulus);
        switch_to_ntru_ciphertext(
            &fourier_ntru_cmux_bsk.get_fourier_ntru_switching_key(),
            &accumulator,
            &mut accumulator_ntru_ciphertext,
        );

        let log_br_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

        let msed = lwe_ciphertext_modulus_switch_lut_many(input.as_view(), log_br_modulus, log_lut_count);

        ntru_cmux_blind_rotate_assign(
            fourier_ntru_cmux_bsk.as_view(),
            accumulator_ntru_ciphertext.as_mut_view(),
            &msed,
            fft,
            stack2,
        );

        for (k, mut ntru_ciphertext) in ntru_chunk.iter_mut().enumerate() {
            ntru_ciphertext.as_mut().clone_from_slice(accumulator_ntru_ciphertext.as_ref());
            polynomial_wrapping_monic_monomial_div_assign(
                &mut ntru_ciphertext.as_mut_polynomial(),
                MonomialDegree(k),
            );

            rev_trace_ntru_ciphertext_assign(
                &fourier_ntru_trace_key,
                &mut ntru_ciphertext,
            );
        }
    }

    // TODO: add it to stack memory
    for (i, (ntru, mut rgsw_level_mat)) in ntru_buffer.iter().zip(output.iter_mut()).enumerate() {
        let log_scale = OutputScalar::BITS - decomp_base_log.0 * (decomp_level_count.0 - i);

        let mut rlwe_list = rgsw_level_mat.as_mut_glwe_list();
        let (mut rlwe0, mut rlwe1) = rlwe_list.split_at_mut(1);
        let mut rlwe0 = rlwe0.get_mut(0);
        let mut rlwe1 = rlwe1.get_mut(0);

        keyswitch_ntru_to_rlwe(
            &fourier_ntru_to_rlwe_ksk,
            &ntru,
            &mut rlwe1,
        );

        let mut rlwe1_body = rlwe1.get_mut_body();
        let mut rlwe1_body = rlwe1_body.as_mut_polynomial();
        rlwe1_body.as_mut()[0] = rlwe1_body.as_ref()[0].wrapping_add(OutputScalar::ONE << (log_scale - 1));

        scheme_switch_rlwe_ciphertext(
            &fourier_rlwe_ss_key,
            &rlwe1,
            &mut rlwe0,
        );
    }
}
