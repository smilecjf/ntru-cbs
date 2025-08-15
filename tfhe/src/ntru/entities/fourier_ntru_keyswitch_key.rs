use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::ntru::entities::*;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruKeyswitchKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_base_log: DecompositionBaseLog,
    fft_type: FftType,
}

pub type FourierNtruKeyswitchKeyView<'a> = FourierNtruKeyswitchKey<&'a [c64]>;
pub type FourierNtruKeyswitchKeyMutView<'a> = FourierNtruKeyswitchKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNtruKeyswitchKey<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
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
            self.fourier.data.container_len() /  (
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
            fft_type: self.fft_type,
        }
    }

    pub fn as_fourier_ngsw_ciphertext(&self) -> FourierNgswCiphertextView<'_> {
        FourierNgswCiphertext::from_container(
            self.fourier.data.as_ref(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
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
            fft_type: self.fft_type,
        }
    }

    pub fn as_mut_fourier_ngsw_ciphertext(&mut self) -> FourierNgswCiphertextMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNgswCiphertext::from_container(
            self.fourier.data.as_mut(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
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
            fft_type,
        )
    }
}
