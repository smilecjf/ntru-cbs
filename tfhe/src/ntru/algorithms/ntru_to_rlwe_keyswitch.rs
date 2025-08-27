use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{collect_next_term, update_with_fmadd};
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use crate::ntru::entities::*;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_ntru_to_rlwe_keyswitch_key_to_fourier<Scalar, InputCont, OutputCont>(
    standard_ntru_to_rlwe_ksk: &NtruToRlweKeyswitchKey<InputCont>,
    fourier_ntru_to_rlwe_ksk: &mut FourierNtruToRlweKeyswitchKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    assert_eq!(
        standard_ntru_to_rlwe_ksk.polynomial_size(),
        fourier_ntru_to_rlwe_ksk.polynomial_size(),
    );

    assert_eq!(
        standard_ntru_to_rlwe_ksk.decomposition_base_log(),
        fourier_ntru_to_rlwe_ksk.decomposition_base_log(),
    );

    assert_eq!(
        standard_ntru_to_rlwe_ksk.decomposition_level_count(),
        fourier_ntru_to_rlwe_ksk.decomposition_level_count(),
    );

    let fft = Fft::new(fourier_ntru_to_rlwe_ksk.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ntru_to_rlwe_keyswitch_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    convert_standard_ntru_to_rlwe_keyswitch_key_to_fourier_mem_optimized(
        standard_ntru_to_rlwe_ksk,
        fourier_ntru_to_rlwe_ksk,
        fft,
        stack,
    );
}

pub fn convert_standard_ntru_to_rlwe_keyswitch_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

pub fn convert_standard_ntru_to_rlwe_keyswitch_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    standard_ntru_to_rlwe_ksk: &NtruToRlweKeyswitchKey<InputCont>,
    fourier_ntru_to_rlwe_ksk: &mut FourierNtruToRlweKeyswitchKey<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    fourier_ntru_to_rlwe_ksk
        .as_mut_view()
        .fill_with_forward_fourier(standard_ntru_to_rlwe_ksk.as_view(), fft, stack);
}

pub fn keyswitch_ntru_to_rlwe_scratch<Scalar>(
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;
    let standard_scratch = StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?;
    let fourier_scratch
        = StackReq::try_new_aligned::<c64>(2 * fourier_polynomial_size, CACHELINE_ALIGN)?;
    let fourier_scratch_single = StackReq::try_new_aligned::<c64>(fourier_polynomial_size, CACHELINE_ALIGN)?;

    let substack3 = fft.forward_scratch()?;
    let substack2 = substack3.try_and(fourier_scratch_single)?;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = StackReq::try_any_of([
        substack1.try_and(standard_scratch)?,
        fft.backward_scratch()?,
    ])?;
    substack0.try_and(fourier_scratch)
}

pub fn keyswitch_ntru_to_rlwe<Scalar, KskCont, InputCont, OutputCont>(
    ntru_to_rlwe_keyswitch_key: &FourierNtruToRlweKeyswitchKey<KskCont>,
    input_ntru_ciphertext: &NtruCiphertext<InputCont>,
    output_rlwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KskCont: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let polynomial_size = ntru_to_rlwe_keyswitch_key.polynomial_size();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        keyswitch_ntru_to_rlwe_scratch::<Scalar>(
            polynomial_size,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    keyswitch_ntru_to_rlwe_mem_optimized(
        ntru_to_rlwe_keyswitch_key.as_view(),
        input_ntru_ciphertext.as_view(),
        &mut output_rlwe_ciphertext.as_mut_view(),
        fft,
        stack,
    );
}

pub fn keyswitch_ntru_to_rlwe_mem_optimized<Scalar>(
    ntru_to_rlwe_keyswitch_key: FourierNtruToRlweKeyswitchKeyView<'_>,
    input_ntru_ciphertext: NtruCiphertextView<'_, Scalar>,
    output_rlwe_ciphertext: &mut GlweCiphertextMutView<'_, Scalar>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
{
    assert_eq!(
        input_ntru_ciphertext.polynomial_size(),
        output_rlwe_ciphertext.polynomial_size(),
    );

    assert_eq!(
        input_ntru_ciphertext.polynomial_size(),
        ntru_to_rlwe_keyswitch_key.polynomial_size(),
    );

    assert_eq!(
        output_rlwe_ciphertext.glwe_size(),
        GlweSize(2),
    );

    assert_eq!(
        input_ntru_ciphertext.ciphertext_modulus(),
        output_rlwe_ciphertext.ciphertext_modulus(),
    );

    assert!(
        input_ntru_ciphertext
            .ciphertext_modulus()
            .is_power_of_two(),
        "Only support power-of-two modulus currently.",
    );

    let fft_type = ntru_to_rlwe_keyswitch_key.fft_type();
    let split_base_log = fft_type.split_base_log();

    output_rlwe_ciphertext.as_mut().fill(Scalar::ZERO);
    ntru_to_rlwe_keyswitch_key.into_splits().rev().enumerate()
        .for_each(|(i, ksk_split)| {
            add_keyswitch_split_external_product_assign(
                ksk_split.as_view(),
                input_ntru_ciphertext.as_view(),
                &mut output_rlwe_ciphertext.as_mut_view(),
                fft,
                stack,
            );
            if i == 0 {
                slice_wrapping_scalar_mul_assign(
                    output_rlwe_ciphertext.as_mut(),
                    Scalar::ONE << split_base_log,
                );
            }
        });
}

fn add_keyswitch_split_external_product_assign<Scalar>(
    ksk_split: FourierNtruToRlweKeyswitchKeySplitView<'_>,
    input: NtruCiphertextView<'_, Scalar>,
    output: &mut GlweCiphertextMutView<'_, Scalar>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
{
    let fourier_poly_size = ksk_split.polynomial_size().to_fourier_polynomial_size().0;

    let decomposer = SignedDecomposer::<Scalar>::new(
        ksk_split.decomposition_base_log(),
        ksk_split.decomposition_level_count(),
    );

    let (output_fft_buffer, substack0)
        = stack.make_aligned_raw::<c64>(2 * fourier_poly_size, CACHELINE_ALIGN);
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer = &mut *output_fft_buffer;
    let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the fourier domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition, substack1) = TensorSignedDecompositionLendingIter::new(
            input.as_ref()
                .iter()
                .map(|s| decomposer.init_decomposer_state(*s)),
            DecompositionBaseLog(decomposer.base_log),
            DecompositionLevelCount(decomposer.level_count),
            substack0,
        );

        ksk_split.into_levels().for_each(|ksk_level| {
            let (ntru_level, ntru_decomp_poly, substack2)
                = collect_next_term(&mut decomposition, substack1, CACHELINE_ALIGN);
            let ntru_decomp_poly = NtruCiphertextView::from_container(
                &*ntru_decomp_poly,
                ksk_split.polynomial_size(),
                output.ciphertext_modulus(),
            );
            assert_eq!(ksk_level.decomposition_level(), ntru_level);

            let (fourier, substack3)
                = substack2.make_aligned_raw::<c64>(fourier_poly_size, CACHELINE_ALIGN);
            let fourier = fft
                .forward_as_integer(
                    FourierPolynomialMutView { data: fourier },
                    ntru_decomp_poly.as_polynomial(),
                    substack3,
                ).data;

            update_with_fmadd(
                output_fft_buffer,
                ksk_level.data(),
                fourier,
                is_output_uninit,
                fourier_poly_size,
            );

            is_output_uninit = false;
        });
    }

    if !is_output_uninit {
        izip!(
            output.as_mut_polynomial_list().iter_mut(),
            output_fft_buffer
                .into_chunks(fourier_poly_size)
                .map(|slice| FourierPolynomialMutView { data: slice }),
        )
        .for_each(|(output, fourier)| {
            fft.add_backward_in_place_as_torus(output, fourier, substack0);
        });
    }

    let ciphertext_modulus = output.ciphertext_modulus();
    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        output.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}
