use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{FftView, FourierPolynomialList};
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use crate::core_crypto::commons::utils::izip;
use crate::ntru::entities::*;

use dyn_stack::PodStack;
use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruKeyswitchKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
}

pub type FourierNtruKeyswitchKeyView<'a> = FourierNtruKeyswitchKey<&'a [c64]>;
pub type FourierNtruKeyswitchKeyMutView<'a> = FourierNtruKeyswitchKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNtruKeyswitchKey<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        fft_type: FftType,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
                * fft_type.num_split()
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            decomp_base_log,
            decomp_level_count,
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
        self.decomp_level_count
    }

    pub fn fft_type(&self) -> FftType {
        self.fft_type
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierNtruKeyswitchKeyView<'_>
    where
        C: AsRef<[c64]>
    {
        FourierNtruKeyswitchKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }

    pub fn as_fourier_ngsw_ciphertext(&self) -> FourierNgswCiphertextView<'_> {
        FourierNgswCiphertext::from_container(
            self.fourier.data.as_ref(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.fft_type,
        )
    }

    pub fn as_mut_view(&mut self) -> FourierNtruKeyswitchKeyMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNtruKeyswitchKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }
}

impl FourierNtruKeyswitchKeyMutView<'_> {
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        standard_ntru_ksk: NtruKeyswitchKeyView<'_, Scalar>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) {
        assert_eq!(
            standard_ntru_ksk.polynomial_size(),
            self.polynomial_size(),
        );

        let fourier_polynomial_size = standard_ntru_ksk.polynomial_size().to_fourier_polynomial_size().0;

        for (fourier_poly, standard_poly) in izip!(
            self.data().into_chunks(fourier_polynomial_size),
            standard_ntru_ksk.as_polynomial_list().iter()
        ) {
            fft.forward_as_torus(
                FourierPolynomialMutView { data: fourier_poly },
                standard_poly,
                stack,
            );
        }
    }
}

type FourierNtruKeyswitchKeyOwned = FourierNtruKeyswitchKey<ABox<[c64]>>;

impl FourierNtruKeyswitchKeyOwned {
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
                * fft_type.num_split()
        ]
        .into_boxed_slice();

        FourierNtruKeyswitchKey::from_container(
            boxed,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        )
    }
}
