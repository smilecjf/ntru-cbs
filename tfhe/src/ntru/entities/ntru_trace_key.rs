//! Module containing the definition of the NtruTraceKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

use std::collections::HashMap;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruTraceKey<C: Container>
    where C::Element: UnsignedInteger,
{
    ntru_auto_keys: HashMap<usize, NtruAutomorphismKey<C>>,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

pub type NtruTraceKeyOwned<Scalar> = NtruTraceKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruTraceKey<C> {
    pub fn get_automorphism_keys(&self) -> &HashMap<usize, NtruAutomorphismKey<C>> {
        &self.ntru_auto_keys
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

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruTraceKey<C> {
    pub fn get_mut_automorphism_keys(&mut self) -> &mut HashMap<usize, NtruAutomorphismKey<C>> {
        &mut self.ntru_auto_keys
    }
}

impl<Scalar: UnsignedInteger> NtruTraceKeyOwned<Scalar> {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let mut ntru_auto_keys = HashMap::new();
        for k in 1..=polynomial_size.0.ilog2() {
            let auto_index = AutomorphismIndex((1 << k) + 1);
            let ntru_auto_key = NtruAutomorphismKey::new(
                Scalar::ZERO,
                auto_index,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                ciphertext_modulus,
            );
            ntru_auto_keys.insert(auto_index.0, ntru_auto_key);
        }

        Self {
            ntru_auto_keys,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        }
    }
}
