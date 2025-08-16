//! Module containing the definition of the FourierNtruTraceKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

use aligned_vec::ABox;
use tfhe_fft::c64;
use std::collections::HashMap;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FourierNtruTraceKey<C: Container<Element = c64>> {
    fourier_ntru_auto_keys: HashMap<usize, FourierNtruAutomorphismKey<C>>,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
}

pub type FourierNtruTraceKeyOwned = FourierNtruTraceKey<ABox<[c64]>>;

impl<C: Container<Element = c64>> FourierNtruTraceKey<C> {
    pub fn get_automorphism_keys(&self) -> &HashMap<usize, FourierNtruAutomorphismKey<C>> {
        &self.fourier_ntru_auto_keys
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
    pub fn get_mut_automorphism_keys(&mut self) -> &mut HashMap<usize, FourierNtruAutomorphismKey<C>> {
        &mut self.fourier_ntru_auto_keys
    }
}

impl FourierNtruTraceKeyOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        fft_type: FftType,
    ) -> Self {
        let mut fourier_ntru_auto_keys = HashMap::new();
        for k in 1..=polynomial_size.0.ilog2() {
            let auto_index = AutomorphismIndex((1 << k) + 1);
            let fourier_ntru_auto_key = FourierNtruAutomorphismKey::new(
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                fft_type,
            );
            fourier_ntru_auto_keys.insert(auto_index.0, fourier_ntru_auto_key);
        }

        Self {
            fourier_ntru_auto_keys,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        }
    }
}
