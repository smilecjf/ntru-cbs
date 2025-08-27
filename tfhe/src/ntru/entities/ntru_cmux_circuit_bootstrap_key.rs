//! Module containing the definition of the NtruCMuxCircuitBootstrapKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruCMuxCircuitBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    ntru_cmux_bsk: NtruCMuxBootstrapKey<C>,
    ntru_trace_key: NtruTraceKey<C>,
    ntru_to_rlwe_ksk: NtruToRlweKeyswitchKey<C>,
    rlwe_ss_key: RlweSchemeSwitchKey<C>,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

pub type NtruCMuxCircuitBootstrapKeyView<'data, Scalar> = NtruCMuxCircuitBootstrapKey<&'data [Scalar]>;
pub type NtruCMuxCircuitBootstrapKeyMutView<'data, Scalar> = NtruCMuxCircuitBootstrapKey<&'data mut [Scalar]>;
pub type NtruCMuxCircuitBootstrapKeyOwned<Scalar> = NtruCMuxCircuitBootstrapKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruCMuxCircuitBootstrapKey<C> {
    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.ntru_cmux_bsk.input_lwe_dimension()
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.ntru_cmux_bsk.output_lwe_dimension()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.ntru_cmux_bsk.polynomial_size()
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }

    pub fn get_ntru_cmux_bootstrap_key(&self) -> NtruCMuxBootstrapKeyView<'_, Scalar> {
        self.ntru_cmux_bsk.as_view()
    }

    pub fn get_ntru_trace_key(&self) -> NtruTraceKeyView<'_, Scalar> {
        self.ntru_trace_key.as_view()
    }

    pub fn get_ntru_to_rlwe_keyswitch_key(&self) -> NtruToRlweKeyswitchKeyView<'_, Scalar> {
        self.ntru_to_rlwe_ksk.as_view()
    }

    pub fn get_rlwe_scheme_switch_key(&self) -> RlweSchemeSwitchKeyView<'_, Scalar> {
        self.rlwe_ss_key.as_view()
    }

    pub fn as_view(&self) -> NtruCMuxCircuitBootstrapKeyView<'_, Scalar> {
        NtruCMuxCircuitBootstrapKeyView::<'_, Scalar> {
            ntru_cmux_bsk: self.ntru_cmux_bsk.as_view(),
            ntru_trace_key: self.ntru_trace_key.as_view(),
            ntru_to_rlwe_ksk: self.ntru_to_rlwe_ksk.as_view(),
            rlwe_ss_key: self.rlwe_ss_key.as_view(),
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruCMuxCircuitBootstrapKey<C> {
    pub fn get_mut_ntru_cmux_bootstrap_key(&mut self) -> NtruCMuxBootstrapKeyMutView<'_, Scalar> {
        self.ntru_cmux_bsk.as_mut_view()
    }

    pub fn get_mut_ntru_trace_key(&mut self) -> NtruTraceKeyMutView<'_, Scalar> {
        self.ntru_trace_key.as_mut_view()
    }

    pub fn get_mut_ntru_to_rlwe_keyswitch_key(&mut self) -> NtruToRlweKeyswitchKeyMutView<'_, Scalar> {
        self.ntru_to_rlwe_ksk.as_mut_view()
    }

    pub fn get_mut_rlwe_scheme_switch_key(&mut self) -> RlweSchemeSwitchKeyMutView<'_, Scalar> {
        self.rlwe_ss_key.as_mut_view()
    }

    pub fn as_mut_view(&mut self) -> NtruCMuxCircuitBootstrapKeyMutView<'_, Scalar> {
        NtruCMuxCircuitBootstrapKeyMutView::<'_, Scalar> {
            ntru_cmux_bsk: self.ntru_cmux_bsk.as_mut_view(),
            ntru_trace_key: self.ntru_trace_key.as_mut_view(),
            ntru_to_rlwe_ksk: self.ntru_to_rlwe_ksk.as_mut_view(),
            rlwe_ss_key: self.rlwe_ss_key.as_mut_view(),
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger> NtruCMuxCircuitBootstrapKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        input_lwe_dimension: LweDimension,
        br_decomp_base_log: DecompositionBaseLog,
        br_decomp_level_count: DecompositionLevelCount,
        swk_decomp_base_log: DecompositionBaseLog,
        swk_decomp_level_count: DecompositionLevelCount,
        tr_decomp_base_log: DecompositionBaseLog,
        tr_decomp_level_count: DecompositionLevelCount,
        ksk_decomp_base_log: DecompositionBaseLog,
        ksk_decomp_level_count: DecompositionLevelCount,
        ss_decomp_base_log: DecompositionBaseLog,
        ss_decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            ntru_cmux_bsk: NtruCMuxBootstrapKey::new(
                fill_with,
                polynomial_size,
                br_decomp_base_log,
                br_decomp_level_count,
                swk_decomp_base_log,
                swk_decomp_level_count,
                input_lwe_dimension,
                ciphertext_modulus,
            ),
            ntru_trace_key: NtruTraceKey::new(
                polynomial_size,
                tr_decomp_base_log,
                tr_decomp_level_count,
                ciphertext_modulus,
            ),
            ntru_to_rlwe_ksk: NtruToRlweKeyswitchKey::new(
                fill_with,
                polynomial_size,
                ksk_decomp_base_log,
                ksk_decomp_level_count,
                ciphertext_modulus,
            ),
            rlwe_ss_key: RlweSchemeSwitchKey::new(
                fill_with,
                polynomial_size,
                ss_decomp_base_log,
                ss_decomp_level_count,
                ciphertext_modulus,
            ),
            ciphertext_modulus,
        }
    }
}
