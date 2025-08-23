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

    let ntru_ss_key = standard_ntru_cmux_cbs_key.get_ntru_scheme_switch_key();
    let mut fourier_ntru_ss_key = fourier_ntru_cmux_cbs_key.get_mut_fourier_ntru_scheme_switch_key();
    convert_standard_ntru_scheme_switch_key_to_fourier_mem_optimized(
        &ntru_ss_key,
        &mut fourier_ntru_ss_key,
        fft,
        stack,
    );
}


