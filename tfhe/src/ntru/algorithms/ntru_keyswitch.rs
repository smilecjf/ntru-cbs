use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::ntru::algorithms::{add_ntru_external_product_assign, add_ntru_external_product_assign_scratch, convert_standard_ngsw_ciphertext_to_fourier_mem_optimized, convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement};
use crate::ntru::entities::*;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_ntru_keyswitch_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_ntru_ksk: &NtruKeyswitchKey<InputCont>,
    fourier_ntru_ksk: &mut FourierNtruKeyswitchKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_ntru_ksk.polynomial_size(),
        fourier_ntru_ksk.polynomial_size(),
    );

    assert_eq!(
        standard_ntru_ksk.decomposition_base_log(),
        fourier_ntru_ksk.decomposition_base_log(),
    );

    assert_eq!(
        standard_ntru_ksk.decomposition_level_count(),
        fourier_ntru_ksk.decomposition_level_count(),
    );

    let fft = Fft::new(fourier_ntru_ksk.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ntru_keyswitch_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_ntru_keyswitch_key_to_fourier_mem_optimized(
        standard_ntru_ksk,
        fourier_ntru_ksk,
        fft,
        stack,
    );
}

pub fn convert_standard_ntru_keyswitch_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
}

pub fn convert_standard_ntru_keyswitch_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_ntru_ksk: &NtruKeyswitchKey<InputCont>,
    fourier_ntru_ksk: &mut FourierNtruKeyswitchKey<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    convert_standard_ngsw_ciphertext_to_fourier_mem_optimized(
        &standard_ntru_ksk.as_ngsw_ciphertext(),
        &mut fourier_ntru_ksk.as_mut_fourier_ngsw_ciphertext(),
        fft,
        stack,
    );
}

pub fn keyswitch_ntru_ciphertext<Scalar, KskCont, InputCont, OutputCont>(
    ntru_keyswitch_key: &FourierNtruKeyswitchKey<KskCont>,
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
        ntru_keyswitch_key.polynomial_size(),
    );

    assert_eq!(
        input_ntru_ciphertext.ciphertext_modulus(),
        output_ntru_ciphertext.ciphertext_modulus(),
    );

    assert!(
        input_ntru_ciphertext
            .ciphertext_modulus()
            .is_power_of_two(),
        "Only support power-of-two modulus currently.",
    );

    let polynomial_size = ntru_keyswitch_key.polynomial_size();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        add_ntru_external_product_assign_scratch::<Scalar>(
            polynomial_size,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    output_ntru_ciphertext.as_mut().fill(Scalar::ZERO);
    add_ntru_external_product_assign(
        &mut output_ntru_ciphertext.as_mut_view(),
        ntru_keyswitch_key.as_fourier_ngsw_ciphertext(),
        input_ntru_ciphertext.as_view(),
        fft,
        stack,
    );
}
