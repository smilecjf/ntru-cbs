use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::fft_impl::fft64::math::fft::{FftView, FourierPolynomialList};
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use crate::ntru::entities::*;
use dyn_stack::PodStack;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum FftType {
    Vanilla,
    Split(usize),
}

impl FftType {
    pub fn num_split(&self) -> usize {
        match self {
            FftType::Vanilla => 1,
            FftType::Split(_) => 2,
        }
    }

    pub fn split_base_log(&self) -> usize {
        match self {
            FftType::Vanilla => 0,
            FftType::Split(b) => *b,
        }
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNgswCiphertext<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomposition_base_log: DecompositionBaseLog,
    fft_type: FftType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNgswSplitBlock<C: Container<Element = c64>> {
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
pub type FourierNgswSplitBlockView<'a> = FourierNgswSplitBlock<&'a [c64]>;
pub type FourierNgswSplitBlockMutView<'a> = FourierNgswSplitBlock<&'a mut [c64]>;
pub type FourierNgswLevelPolyView<'a> = FourierNgswLevelPoly<&'a [c64]>;
pub type FourierNgswLevelPolyMutView<'a> = FourierNgswLevelPoly<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNgswCiphertext<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        fft_type: FftType,
    ) -> Self {
        assert!(
            data.container_len() % (
                polynomial_size.to_fourier_polynomial_size().0
                    * fft_type.num_split()
            ) == 0,
            "The provided container length is not valid. \
            It needs to be divisible by polynomial size * fft_type.num_split(). \
            Got container length: {}, polynomial size {:?}, fft_type: {:?}.",
            data.container_len(),
            polynomial_size,
            fft_type,
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            decomposition_base_log,
            fft_type,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(
            self.fourier.data.container_len() / (
                self.fourier.polynomial_size
                    .to_fourier_polynomial_size().0
                    * self.fft_type.num_split()
            )
        )
    }

    pub fn fft_type(&self) -> FftType {
        self.fft_type
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
            fft_type: self.fft_type,
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
            fft_type: self.fft_type,
        }
    }
}

impl<C: Container<Element = c64>> FourierNgswSplitBlock<C> {
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

    pub fn as_view(&self) -> FourierNgswSplitBlockView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierNgswSplitBlockView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierNgswSplitBlockMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNgswSplitBlockMutView {
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
    pub fn from_container(
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
    pub fn into_splits(self) -> impl DoubleEndedIterator<Item = FourierNgswSplitBlockView<'a>> {
        self.fourier
            .data
            .split_into(self.fft_type.num_split())
            .map(move |slice| {
                FourierNgswSplitBlockView::from_container(
                    slice,
                    self.fourier.polynomial_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count(),
                )
            })
    }
}

impl<'a> FourierNgswSplitBlockView<'a> {
    pub fn into_levels(self) -> impl DoubleEndedIterator<Item = FourierNgswLevelPolyView<'a>> {
        let decomposition_level_count = self.decomposition_level_count.0;
        self.fourier
            .data
            .split_into(decomposition_level_count)
            .enumerate()
            .map(move |(i, slice)| {
                FourierNgswLevelPolyView::from_container(
                    slice,
                    self.fourier.polynomial_size,
                    DecompositionLevel(decomposition_level_count - i),
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
        let polynomial_size = self.polynomial_size();
        let fourier_poly_size = polynomial_size.to_fourier_polynomial_size().0;

        let fft_type = self.fft_type;
        let mut poly_buffer = Polynomial::new(Scalar::ZERO, polynomial_size);

        self.data().split_into(fft_type.num_split())
            .enumerate()
            .for_each(|(split_idx, split_fourier)| {
                for (fourier_poly, standard_poly) in izip!(
                    split_fourier.into_chunks(fourier_poly_size),
                    standard_ngsw.as_polynomial_list().iter(),
                ) {
                    match fft_type {
                        FftType::Vanilla => {
                            fft.forward_as_torus(
                                FourierPolynomialMutView { data: fourier_poly },
                                standard_poly,
                                stack,
                            );
                        },
                        FftType::Split(b) => {
                            let (lsh_bit, rsh_bit) = if split_idx == 0 {
                                (Scalar::BITS - b, Scalar::BITS - b)
                            } else {
                                (0, b)
                            };

                            for (standard_coeff, split_coeff)
                                in standard_poly.iter().zip(poly_buffer.iter_mut())
                            {
                                *split_coeff = ((*standard_coeff) << lsh_bit) >> rsh_bit;
                            }

                            fft.forward_as_torus(
                                FourierPolynomialMutView { data: fourier_poly },
                                poly_buffer.as_view(),
                                stack,
                            );
                        },
                    }
                }
            });
    }
}

type FourierNgswCiphertextOwned = FourierNgswCiphertext<ABox<[c64]>>;

impl FourierNgswCiphertextOwned {
    pub fn new (
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        fft_type: FftType,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * decomposition_level_count.0
                * fft_type.num_split()
        ]
        .into_boxed_slice();

        FourierNgswCiphertext::from_container(
            boxed,
            polynomial_size,
            decomposition_base_log,
            fft_type,
        )
    }
}

#[derive(Clone, Copy)]
pub struct FourierNgswCiphertextCreationMetadata {
    pub polynomial_size: PolynomialSize,
    pub decomposition_base_log: DecompositionBaseLog,
    pub fft_type: FftType,
}

impl<C: Container<Element = c64>> CreateFrom<C> for FourierNgswCiphertext<C> {
    type Metadata = FourierNgswCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let FourierNgswCiphertextCreationMetadata {
            polynomial_size,
            decomposition_base_log,
            fft_type,
        } = meta;
        Self::from_container(
            from,
            polynomial_size,
            decomposition_base_log,
            fft_type,
        )
    }
}
