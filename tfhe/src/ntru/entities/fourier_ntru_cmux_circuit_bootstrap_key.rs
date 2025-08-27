use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

use aligned_vec::ABox;
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruCMuxCircuitBootstrapKey<C: Container<Element = c64>> {
    fourier_ntru_cmux_bsk: FourierNtruCMuxBootstrapKey<C>,
    fourier_ntru_trace_key: FourierNtruTraceKey<C>,
    fourier_ntru_to_rlwe_ksk: FourierNtruToRlweKeyswitchKey<C>,
    fourier_rlwe_ss_key: FourierRlweSchemeSwitchKey<C>,
}

pub type FourierNtruCMuxCircuitBootstrapKeyView<'a> = FourierNtruCMuxCircuitBootstrapKey<&'a [c64]>;
pub type FourierNtruCMuxCircuitBootstrapKeyMutView<'a> = FourierNtruCMuxCircuitBootstrapKey<&'a mut [c64]>;
pub type FourierNtruCMuxCircuitBootstrapKeyOwned = FourierNtruCMuxCircuitBootstrapKey<ABox<[c64]>>;

impl<C: Container<Element = c64>> FourierNtruCMuxCircuitBootstrapKey<C> {
    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.fourier_ntru_cmux_bsk.input_lwe_dimension()
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.fourier_ntru_cmux_bsk.output_lwe_dimension()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier_ntru_cmux_bsk.polynomial_size()
    }

    pub fn br_fft_type(&self) -> FftType {
        self.fourier_ntru_cmux_bsk.br_fft_type()
    }

    pub fn swk_fft_type(&self) -> FftType {
        self.fourier_ntru_cmux_bsk.swk_fft_type()
    }

    pub fn tr_fft_type(&self) -> FftType {
        self.fourier_ntru_trace_key.fft_type()
    }

    pub fn ksk_fft_type(&self) -> FftType {
        self.fourier_ntru_to_rlwe_ksk.fft_type()
    }

    pub fn ss_fft_type(&self) -> FftType {
        self.fourier_rlwe_ss_key.fft_type()
    }

    pub fn get_fourier_ntru_cmux_bootstrap_key(&self) -> FourierNtruCMuxBootstrapKeyView<'_> {
        self.fourier_ntru_cmux_bsk.as_view()
    }

    pub fn get_fourier_ntru_trace_key(&self) -> FourierNtruTraceKeyView<'_> {
        self.fourier_ntru_trace_key.as_view()
    }

    pub fn get_fourier_ntru_to_rlwe_keyswitch_key(&self) -> FourierNtruToRlweKeyswitchKeyView<'_> {
        self.fourier_ntru_to_rlwe_ksk.as_view()
    }

    pub fn get_fourier_rlwe_scheme_switch_key(&self) -> FourierRlweSchemeSwitchKeyView<'_> {
        self.fourier_rlwe_ss_key.as_view()
    }

    pub fn as_view(&self) -> FourierNtruCMuxCircuitBootstrapKeyView<'_> {
        FourierNtruCMuxCircuitBootstrapKeyView::<'_> {
            fourier_ntru_cmux_bsk: self.fourier_ntru_cmux_bsk.as_view(),
            fourier_ntru_trace_key: self.fourier_ntru_trace_key.as_view(),
            fourier_ntru_to_rlwe_ksk: self.fourier_ntru_to_rlwe_ksk.as_view(),
            fourier_rlwe_ss_key: self.fourier_rlwe_ss_key.as_view(),
        }
    }
}

impl<C: ContainerMut<Element = c64>> FourierNtruCMuxCircuitBootstrapKey<C> {
    pub fn get_mut_fourier_ntru_cmux_bootstrap_key(&mut self) -> FourierNtruCMuxBootstrapKeyMutView<'_> {
        self.fourier_ntru_cmux_bsk.as_mut_view()
    }

    pub fn get_mut_fourier_ntru_trace_key(&mut self) -> FourierNtruTraceKeyMutView<'_> {
        self.fourier_ntru_trace_key.as_mut_view()
    }

    pub fn get_mut_fourier_ntru_to_rlwe_keyswitch_key(&mut self) -> FourierNtruToRlweKeyswitchKeyMutView<'_> {
        self.fourier_ntru_to_rlwe_ksk.as_mut_view()
    }

    pub fn get_mut_fourier_rlwe_scheme_switch_key(&mut self) -> FourierRlweSchemeSwitchKeyMutView<'_> {
        self.fourier_rlwe_ss_key.as_mut_view()
    }

    pub fn as_mut_view(&mut self) -> FourierNtruCMuxCircuitBootstrapKeyMutView<'_> {
        FourierNtruCMuxCircuitBootstrapKeyMutView::<'_> {
            fourier_ntru_cmux_bsk: self.fourier_ntru_cmux_bsk.as_mut_view(),
            fourier_ntru_trace_key: self.fourier_ntru_trace_key.as_mut_view(),
            fourier_ntru_to_rlwe_ksk: self.fourier_ntru_to_rlwe_ksk.as_mut_view(),
            fourier_rlwe_ss_key: self.fourier_rlwe_ss_key.as_mut_view(),
        }
    }
}

impl FourierNtruCMuxCircuitBootstrapKeyOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        input_lwe_dimension: LweDimension,
        br_decomp_base_log: DecompositionBaseLog,
        br_decomp_level_count: DecompositionLevelCount,
        br_fft_type: FftType,
        swk_decomp_base_log: DecompositionBaseLog,
        swk_decomp_level_count: DecompositionLevelCount,
        swk_fft_type: FftType,
        tr_decomp_base_log: DecompositionBaseLog,
        tr_decomp_level_count: DecompositionLevelCount,
        tr_fft_type: FftType,
        ksk_decomp_base_log: DecompositionBaseLog,
        ksk_decomp_level_count: DecompositionLevelCount,
        ksk_fft_type: FftType,
        ss_decomp_base_log: DecompositionBaseLog,
        ss_decomp_level_count: DecompositionLevelCount,
        ss_fft_type: FftType,
    ) -> Self {
        Self {
            fourier_ntru_cmux_bsk: FourierNtruCMuxBootstrapKey::new(
                polynomial_size,
                br_decomp_base_log,
                br_decomp_level_count,
                swk_decomp_base_log,
                swk_decomp_level_count,
                input_lwe_dimension,
                br_fft_type,
                swk_fft_type,
            ),
            fourier_ntru_trace_key: FourierNtruTraceKey::new(
                polynomial_size,
                tr_decomp_base_log,
                tr_decomp_level_count,
                tr_fft_type,
            ),
            fourier_ntru_to_rlwe_ksk: FourierNtruToRlweKeyswitchKey::new(
                polynomial_size,
                ksk_decomp_base_log,
                ksk_decomp_level_count,
                ksk_fft_type,
            ),
            fourier_rlwe_ss_key: FourierRlweSchemeSwitchKey::new(
                polynomial_size,
                ss_decomp_base_log,
                ss_decomp_level_count,
                ss_fft_type,
            ),
        }
    }
}
