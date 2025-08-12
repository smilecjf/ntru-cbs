use crate::core_crypto::commons::traits::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{collect_next_term, update_with_fmadd};
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::fft_impl::fft64::math::fft::FftView;
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use crate::ntru::entities::*;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

pub fn add_ntru_external_product_assign_scratch<Scalar>(
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let standard_scratch= StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?;
    let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;
    let fourier_scratch
        = StackReq::try_new_aligned::<c64>(fourier_polynomial_size, CACHELINE_ALIGN)?;
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

pub fn add_ntru_external_product_assign<Scalar>(
    out: &mut NtruCiphertextMutView<'_, Scalar>,
    ngsw: FourierNgswCiphertextView<'_>,
    ntru: NtruCiphertextView<Scalar>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
{
    assert_eq!(ngsw.polynomial_size(), ntru.polynomial_size());
    assert_eq!(ngsw.polynomial_size(), out.polynomial_size());
    assert_eq!(ngsw.polynomial_size(), fft.polynomial_size());
    assert_eq!(out.ciphertext_modulus(), ntru.ciphertext_modulus());

    let polynomial_size = out.polynomial_size();
    let ciphertext_modulus = out.ciphertext_modulus();

    let fft_type = ngsw.fft_type();
    let split_base_log = fft_type.split_base_log();

    let mut external_product_buffer = NtruCiphertext::new(Scalar::ZERO, polynomial_size, ciphertext_modulus);

    ngsw.into_splits().rev().enumerate()
        .for_each(|(i, ngsw_split)| {
            add_ntru_split_external_product_assign(
                &mut external_product_buffer.as_mut_view(),
                ngsw_split.as_view(),
                ntru.as_view(),
                fft,
                stack,
            );
            if i == 0 {
                slice_wrapping_scalar_mul_assign(
                    external_product_buffer.as_mut(),
                    Scalar::ONE << split_base_log,
                );
            }
        });

    slice_wrapping_add_assign(out.as_mut(), external_product_buffer.as_ref());
}

fn add_ntru_split_external_product_assign<Scalar>(
    out: &mut NtruCiphertextMutView<'_, Scalar>,
    ngsw_split: FourierNgswSplitBlockView<'_>,
    ntru: NtruCiphertextView<Scalar>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
{
    let fourier_poly_size = ngsw_split.polynomial_size().to_fourier_polynomial_size().0;

    let decomposer = SignedDecomposer::<Scalar>::new(
        ngsw_split.decomposition_base_log(),
        ngsw_split.decomposition_level_count(),
    );

    let (output_fft_buffer, substack0)
        = stack.make_aligned_raw::<c64>(fourier_poly_size, CACHELINE_ALIGN);
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
            ntru.as_ref()
                .iter()
                .map(|s| decomposer.init_decomposer_state(*s)),
            DecompositionBaseLog(decomposer.base_log),
            DecompositionLevelCount(decomposer.level_count),
            substack0,
        );

        ngsw_split.into_levels().for_each(|ngsw_decomp_poly| {
            let (ntru_level, ntru_decomp_poly, substack2)
                = collect_next_term(&mut decomposition, substack1, CACHELINE_ALIGN);
            let ntru_decomp_poly = NtruCiphertextView::from_container(
                &*ntru_decomp_poly,
                ngsw_split.polynomial_size(),
                out.ciphertext_modulus(),
            );
            assert_eq!(ngsw_decomp_poly.decomposition_level(), ntru_level);

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
                ngsw_decomp_poly.data(),
                fourier,
                is_output_uninit,
                fourier_poly_size,
            );

            is_output_uninit = false;
        });
    }

    if !is_output_uninit {
        fft.add_backward_in_place_as_torus(
            out.as_mut_polynomial(),
            FourierPolynomialMutView {
                data: output_fft_buffer
            },
            substack0,
        );
    }
}
