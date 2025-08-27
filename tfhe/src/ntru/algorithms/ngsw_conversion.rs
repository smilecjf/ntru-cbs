use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::ntru::entities::*;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;


pub fn convert_standard_ngsw_ciphertext_to_fourier<Scalar, InputCont, OutputCont>(
    input_ngsw: &NgswCiphertext<InputCont>,
    output_ngsw: &mut FourierNgswCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert!(
        input_ngsw.ciphertext_modulus().into_modulus_log().0 > output_ngsw.fft_type().split_base_log(),
        "Log of ciphertext modulus should be greater than FFT split base log. \
        Log of ciphertext modulus is {:?}, and split base log is {}.",
        input_ngsw.ciphertext_modulus().into_modulus_log(),
        output_ngsw.fft_type().split_base_log(),
    );

    let fft = Fft::new(output_ngsw.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );

    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized(
        input_ngsw,
        output_ngsw,
        fft,
        buffers.stack(),
    );
}

pub fn convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

pub fn convert_standard_ngsw_ciphertext_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    input_ngsw: &NgswCiphertext<InputCont>,
    output_ngsw: &mut FourierNgswCiphertext<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    output_ngsw
        .as_mut_view()
        .fill_with_forward_fourier(input_ngsw.as_view(), fft, stack);
}
