use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

use aligned_vec::ABox;
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruCMuxBootstrapKey<C: Container<Element = c64>> {
    fourier_ngsw_list: FourierNgswCiphertextList<C>,
    fourier_ntru_switching_key: FourierNtruSwitchingKey<C>,
}

pub type FourierNtruCMuxBootstrapKeyView<'a> = FourierNtruCMuxBootstrapKey<&'a [c64]>;
pub type FourierNtruCMuxBootstrapKeyMutView<'a> = FourierNtruCMuxBootstrapKey<&'a mut [c64]>;
pub type FourierNtruCMuxBootstrapKeyOwned = FourierNtruCMuxBootstrapKey<ABox<[c64]>>;

impl<C: Container<Element = c64>> FourierNtruCMuxBootstrapKey<C> {
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.fourier_ngsw_list.ciphertext_count().0)
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.fourier_ngsw_list.polynomial_size().0)
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier_ngsw_list.polynomial_size()
    }

    pub fn br_fft_type(&self) -> FftType {
        self.fourier_ngsw_list.fft_type()
    }

    pub fn swk_fft_type(&self) -> FftType {
        self.fourier_ntru_switching_key.fft_type()
    }

    pub fn get_fourier_ngsw_list(&self) -> FourierNgswCiphertextListView<'_> {
        self.fourier_ngsw_list.as_view()
    }

    pub fn get_fourier_ntru_switching_key(&self) -> FourierNtruSwitchingKeyView<'_> {
        self.fourier_ntru_switching_key.as_view()
    }

    pub fn as_view(&self) -> FourierNtruCMuxBootstrapKeyView<'_> {
        FourierNtruCMuxBootstrapKeyView::<'_> {
            fourier_ngsw_list: self.fourier_ngsw_list.as_view(),
            fourier_ntru_switching_key: self.fourier_ntru_switching_key.as_view(),
        }
    }
}

impl<C: ContainerMut<Element = c64>> FourierNtruCMuxBootstrapKey<C> {
    pub fn get_mut_fourier_ngsw_list(&mut self) -> FourierNgswCiphertextListMutView<'_> {
        self.fourier_ngsw_list.as_mut_view()
    }

    pub fn get_mut_fourier_ntru_switching_key(&mut self) -> FourierNtruSwitchingKeyMutView<'_> {
        self.fourier_ntru_switching_key.as_mut_view()
    }

    pub fn as_mut_view(&mut self) -> FourierNtruCMuxBootstrapKeyMutView<'_> {
        FourierNtruCMuxBootstrapKeyMutView::<'_> {
            fourier_ngsw_list: self.fourier_ngsw_list.as_mut_view(),
            fourier_ntru_switching_key: self.fourier_ntru_switching_key.as_mut_view(),
        }
    }
}

impl FourierNtruCMuxBootstrapKeyOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        br_decomp_base_log: DecompositionBaseLog,
        br_decomp_level_count: DecompositionLevelCount,
        swk_decomp_base_log: DecompositionBaseLog,
        swk_decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        br_fft_type: FftType,
        swk_fft_type: FftType,
    ) -> Self {
        Self {
            fourier_ngsw_list: FourierNgswCiphertextList::new(
                polynomial_size,
                br_decomp_base_log,
                br_decomp_level_count,
                FourierNgswCiphertextCount(input_lwe_dimension.0),
                br_fft_type,
            ),
            fourier_ntru_switching_key: FourierNtruSwitchingKey::new(
                polynomial_size,
                swk_decomp_base_log,
                swk_decomp_level_count,
                swk_fft_type,
            ),
        }
    }
}
