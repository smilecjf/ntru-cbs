//! Module containing the definition of the FourierNtruTraceKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

use aligned_vec::ABox;
use tfhe_fft::c64;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FourierNtruTraceKey<C: Container<Element = c64>> {
    fourier_ntru_auto_keys: FourierNtruKeyswitchKeyList<C>,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
}

pub type FourierNtruTraceKeyOwned = FourierNtruTraceKey<ABox<[c64]>>;

impl<C: Container<Element = c64>> FourierNtruTraceKey<C> {
    pub fn get_automorphism_key(&self, index: usize) -> FourierNtruAutomorphismKeyView {
        let automorphism_key_count = self.automorphism_key_count().0;
        assert!(
            index < automorphism_key_count,
            "Input index {} should be smaller than the number of automorphism keys {}",
            index,
            automorphism_key_count,
        );

        let fourier_ntru_auto_key = self.fourier_ntru_auto_keys.get(index);
        let auto_index = AutomorphismIndex((1 << (index + 1)) + 1);
        FourierNtruAutomorphismKey::from_container(
            fourier_ntru_auto_key.data(),
            auto_index,
            self.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
    }

    pub fn automorphism_key_count(&self) -> FourierNtruKeyswitchKeyCount {
        self.fourier_ntru_auto_keys.fourier_ntru_keyswitch_key_count()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
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
}

impl<C: ContainerMut<Element = c64>> FourierNtruTraceKey<C> {
    pub fn get_mut_automorphism_key(&mut self, index: usize) -> FourierNtruAutomorphismKeyMutView {
        let automorphism_key_count = self.automorphism_key_count().0;
        assert!(
            index < automorphism_key_count,
            "Input index {} should be smaller than the number of automorphism keys {}",
            index,
            automorphism_key_count,
        );

        let fourier_ntru_auto_key = self.fourier_ntru_auto_keys.get_mut(index);
        let auto_index = AutomorphismIndex((1 << (index + 1)) + 1);
        FourierNtruAutomorphismKey::from_container(
            fourier_ntru_auto_key.data(),
            auto_index,
            self.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
    }
}

impl FourierNtruTraceKeyOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        fft_type: FftType,
    ) -> Self {
        let fourier_ntru_auto_keys = FourierNtruKeyswitchKeyList::new(
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            FourierNtruKeyswitchKeyCount(polynomial_size.0.ilog2() as usize),
            fft_type,
        );

        Self {
            fourier_ntru_auto_keys,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        }
    }
}
