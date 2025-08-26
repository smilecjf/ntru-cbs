use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{FftView, FourierPolynomialList};
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use crate::ntru::entities::*;

use aligned_vec::{avec, ABox};
use dyn_stack::PodStack;
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruToRlweKeyswitchKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_base_log: DecompositionBaseLog,
    fft_type: FftType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruToRlweKeyswitchKeySplit<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_base_log: DecompositionBaseLog,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruToRlweKeyswitchKeyLevel<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_level: DecompositionLevel,
}

pub type FourierNtruToRlweKeyswitchKeyOwned = FourierNtruToRlweKeyswitchKey<ABox<[c64]>>;
pub type FourierNtruToRlweKeyswitchKeyView<'a> = FourierNtruToRlweKeyswitchKey<&'a [c64]>;
pub type FourierNtruToRlweKeyswitchKeyMutView<'a> = FourierNtruToRlweKeyswitchKey<&'a mut [c64]>;
pub type FourierNtruToRlweKeyswitchKeySplitView<'a> = FourierNtruToRlweKeyswitchKeySplit<&'a [c64]>;
pub type FourierNtruToRlweKeyswitchKeySplitMutView<'a> = FourierNtruToRlweKeyswitchKeySplit<&'a mut [c64]>;
pub type FourierNtruToRlweKeyswitchKeyLevelView<'a> = FourierNtruToRlweKeyswitchKeyLevel<&'a [c64]>;
pub type FourierNtruToRlweKeyswitchKeyLevelMutView<'a> = FourierNtruToRlweKeyswitchKeyLevel<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNtruToRlweKeyswitchKey<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        fft_type: FftType,
    ) -> Self {
        assert!(
            data.container_len() % (
                polynomial_size.to_fourier_polynomial_size().0
                    * fft_type.num_split() * 2
            ) == 0,
            "The provided container length is not valid. \
            It needs to be divisible by 2 * polynomial size * fft_type.num_split(). \
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
            decomp_base_log,
            fft_type,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(
            self.fourier.data.container_len() / (
                self.fourier.polynomial_size
                    .to_fourier_polynomial_size().0
                    * self.fft_type.num_split() * 2
            )
        )
    }

    pub fn fft_type(&self) -> FftType {
        self.fft_type
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierNtruToRlweKeyswitchKeyView<'_>
    where
        C: AsRef<[c64]>
    {
        FourierNtruToRlweKeyswitchKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierNtruToRlweKeyswitchKeyMutView<'_>
    where
        C: AsMut<[c64]>
    {
        FourierNtruToRlweKeyswitchKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }

}

impl<C: Container<Element = c64>> FourierNtruToRlweKeyswitchKeySplit<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self {
        assert!(
            data.container_len() % (
                polynomial_size.to_fourier_polynomial_size().0 * 2
            ) == 0,
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            decomp_base_log,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(
            self.fourier.data.container_len() / (
                self.fourier.polynomial_size
                    .to_fourier_polynomial_size().0 * 2
            )
        )
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierNtruToRlweKeyswitchKeySplitView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierNtruToRlweKeyswitchKeySplitView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierNtruToRlweKeyswitchKeySplitMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNtruToRlweKeyswitchKeySplitMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
        }
    }
}

impl<C: Container<Element = c64>> FourierNtruToRlweKeyswitchKeyLevel<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomp_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0 * 2,
        );
        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            decomp_level,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomp_level
    }

    pub fn data(self) -> C {
        self.fourier.data
    }
}

impl<'a> FourierNtruToRlweKeyswitchKeyView<'a> {
    pub fn into_splits(self) -> impl DoubleEndedIterator<Item = FourierNtruToRlweKeyswitchKeySplitView<'a>> {
        self.fourier
            .data
            .split_into(self.fft_type.num_split())
            .map(move |slice| {
                FourierNtruToRlweKeyswitchKeySplitView::from_container(
                    slice,
                    self.fourier.polynomial_size,
                    self.decomp_base_log,
                )
            })
    }
}

impl<'a> FourierNtruToRlweKeyswitchKeySplitView<'a> {
    pub fn into_levels(self) -> impl DoubleEndedIterator<Item = FourierNtruToRlweKeyswitchKeyLevelView<'a>> {
        let decomp_level_count = self.decomposition_level_count().0;
        self.fourier
            .data
            .split_into(decomp_level_count)
            .enumerate()
            .map(move |(i, slice)| {
                FourierNtruToRlweKeyswitchKeyLevelView::from_container(
                    slice,
                    self.fourier.polynomial_size,
                    DecompositionLevel(decomp_level_count - i),
                )
            })
    }
}

impl FourierNtruToRlweKeyswitchKeyMutView<'_> {
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        standard_ntru_to_rlwe_ksk: NtruToRlweKeyswitchKeyView<'_, Scalar>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) {
        assert_eq!(
            standard_ntru_to_rlwe_ksk.polynomial_size(),
            self.polynomial_size(),
        );
        let polynomial_size = self.polynomial_size();
        let fourier_poly_size = polynomial_size.to_fourier_polynomial_size().0;
        let log_modulus = standard_ntru_to_rlwe_ksk.ciphertext_modulus().into_modulus_log().0;
        let log_torus_scaling = Scalar::BITS - log_modulus;

        let fft_type = self.fft_type;
        let mut poly_buffer = Polynomial::new(Scalar::ZERO, polynomial_size);

        match fft_type {
            FftType::Vanilla => {
                for (fourier_poly, standard_poly) in izip!(
                    self.data().into_chunks(fourier_poly_size),
                    standard_ntru_to_rlwe_ksk.as_polynomial_list().iter(),
                ) {
                    fft.forward_as_torus(
                        FourierPolynomialMutView { data: fourier_poly },
                        standard_poly,
                        stack,
                    );
                }
            },
            FftType::Split(b) => {
                self.data().split_into(fft_type.num_split())
                    .enumerate()
                    .for_each(|(split_idx, split_fourier)| {
                        for (fourier_poly, standard_poly) in izip!(
                            split_fourier.into_chunks(fourier_poly_size),
                            standard_ntru_to_rlwe_ksk.as_polynomial_list().iter(),
                        ) {
                            if split_idx == 0 {
                                let shift_bit = log_modulus - b;
                                for (&standard_coeff, split_coeff)
                                    in standard_poly.iter().zip(poly_buffer.iter_mut())
                                {
                                    *split_coeff = (standard_coeff << shift_bit) >> shift_bit;
                                }

                                fft.forward_as_torus(
                                    FourierPolynomialMutView {
                                        data: fourier_poly,
                                    },
                                    poly_buffer.as_view(),
                                    stack,
                                );
                            } else { // split_idx == 1
                                let rsh_bit = log_torus_scaling + b;
                                let lsh_bit = log_torus_scaling;
                                for (&standard_coeff, split_coeff)
                                    in standard_poly.iter().zip(poly_buffer.iter_mut())
                                {
                                    *split_coeff = (standard_coeff >> rsh_bit) << lsh_bit;
                                }

                                fft.forward_as_torus(
                                    FourierPolynomialMutView {
                                        data: fourier_poly,
                                    },
                                    poly_buffer.as_view(),
                                    stack,
                                );
                            }
                        }
                    });
            }
        }
    }
}

impl FourierNtruToRlweKeyswitchKeyOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        fft_type: FftType,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
                * fft_type.num_split() * 2
        ]
        .into_boxed_slice();

        FourierNtruToRlweKeyswitchKey::from_container(
            boxed,
            polynomial_size,
            decomp_base_log,
            fft_type,
        )
    }
}

