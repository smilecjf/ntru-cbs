use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::ntru::entities::*;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierRlweSchemeSwitchKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_base_log: DecompositionBaseLog,
    fft_type: FftType,
}

pub type FourierRlweSchemeSwitchKeyOwned = FourierRlweSchemeSwitchKey<ABox<[c64]>>;
pub type FourierRlweSchemeSwitchKeyView<'a> = FourierRlweSchemeSwitchKey<&'a [c64]>;
pub type FourierRlweSchemeSwitchKeyMutView<'a> = FourierRlweSchemeSwitchKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierRlweSchemeSwitchKey<C> {
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

    pub fn as_view(&self) -> FourierRlweSchemeSwitchKeyView<'_>
    where
        C: AsRef<[c64]>
    {
        FourierRlweSchemeSwitchKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }

    pub fn as_fourier_ntru_to_rlwe_keyswitch_key(&self) -> FourierNtruToRlweKeyswitchKeyView<'_> {
        FourierNtruToRlweKeyswitchKey::from_container(
            self.fourier.data.as_ref(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
    }

    pub fn as_mut_view(&mut self) -> FourierRlweSchemeSwitchKeyMutView<'_>
    where
        C: AsMut<[c64]>
    {
        FourierRlweSchemeSwitchKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }

    pub fn as_mut_fourier_ntru_to_rlwe_keyswitch_key(&mut self) -> FourierNtruToRlweKeyswitchKeyMutView<'_>
    where
        C: AsMut<[c64]>
    {
        FourierNtruToRlweKeyswitchKey::from_container(
            self.fourier.data.as_mut(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
    }
}

impl FourierRlweSchemeSwitchKeyOwned {
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

        FourierRlweSchemeSwitchKey::from_container(
            boxed,
            polynomial_size,
            decomp_base_log,
            fft_type,
        )
    }
}
