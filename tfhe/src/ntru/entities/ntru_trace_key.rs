//! Module containing the definition of the NtruTraceKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

use aligned_vec::ABox;
use tfhe_fft::c64;
use std::collections::HashMap;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruTraceKey<Scalar: UnsignedInteger, C: Container<Element = c64>> {
    auto_keys: HashMap<usize, FourierNtruAutomorphismKey<C>>,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
    ciphertext_modulus: CiphertextModulus<Scalar>,
}

pub type NtruTraceKeyOwned<Scalar> = NtruTraceKey<Scalar, ABox<[c64]>>;

impl<Scalar: UnsignedInteger, C: Container<Element = c64>> NtruTraceKey<Scalar, C> {
    pub fn get_automorphism_keys(&self) -> &HashMap<usize, FourierNtruAutomorphismKey<C>> {
        &self.auto_keys
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

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = c64>> NtruTraceKey<Scalar, C> {
    pub fn get_mut_automorphism_keys(&mut self) -> &mut HashMap<usize, FourierNtruAutomorphismKey<C>> {
        &mut self.auto_keys
    }
}

impl<Scalar: UnsignedInteger> NtruTraceKeyOwned<Scalar> {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        fft_type: FftType,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            auto_keys: HashMap::new(),
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
            ciphertext_modulus,
        }
    }
}
