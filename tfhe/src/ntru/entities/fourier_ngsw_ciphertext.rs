use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::fft_impl::fft64::math::fft::{FftView, FourierPolynomialList};
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use crate::ntru::entities::*;
use dyn_stack::PodStack;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNgswCiphertext<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNgswLevelPoly<C: Container<Element = c64>> {
    data: C,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

pub type FourierNgswCiphertextView<'a> = FourierNgswCiphertext<&'a [c64]>;
pub type FourierNgswCiphertextMutView<'a> = FourierNgswCiphertext<&'a mut [c64]>;
pub type FourierNgswLevelPolyView<'a> = FourierNgswLevelPoly<&'a [c64]>;
pub type FourierNgswLevelPolyMutView<'a> = FourierNgswLevelPoly<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNgswCiphertext<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0
                * decomposition_level_count.0
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierNgswCiphertextView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierNgswCiphertextView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierNgswCiphertextMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNgswCiphertextMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl<C: Container<Element = c64>> FourierNgswLevelPoly<C> {
    pub fn new(
        data: C,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(), polynomial_size.to_fourier_polynomial_size().0
        );
        Self {
            data,
            polynomial_size,
            decomposition_level,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<'a> FourierNgswCiphertextView<'a> {
    pub fn into_levels(self) -> impl DoubleEndedIterator<Item = FourierNgswLevelPolyView<'a>> {
        let decomposition_level_count = self.decomposition_level_count.0;
        self.fourier
            .data
            .split_into(decomposition_level_count)
            .enumerate()
            .map(move |(i, slice)| {
                FourierNgswLevelPolyView::new(
                    slice,
                    self.fourier.polynomial_size,
                    DecompositionLevel(i + 1),
                )
            })
    }
}

impl FourierNgswCiphertextMutView<'_> {
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        standard_ngsw: NgswCiphertextView<'_, Scalar>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) {
        assert_eq!(standard_ngsw.polynomial_size(), self.polynomial_size());
        let fourier_poly_size = standard_ngsw.polynomial_size().to_fourier_polynomial_size().0;

        for (fourier_poly, standard_poly) in izip!(
            self.data().into_chunks(fourier_poly_size),
            standard_ngsw.as_polynomial_list().iter()
        ) {
            fft.forward_as_torus(
                FourierPolynomialMutView { data: fourier_poly },
                standard_poly,
                stack,
            );
        }
    }
}

type FourierNgswCiphertextOwned = FourierNgswCiphertext<ABox<[c64]>>;

impl FourierNgswCiphertextOwned {
    pub fn new (
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * decomposition_level_count.0
        ]
        .into_boxed_slice();

        FourierNgswCiphertext::from_container(
            boxed,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}
