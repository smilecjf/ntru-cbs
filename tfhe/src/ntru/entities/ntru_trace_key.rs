//! Module containing the definition of the NtruTraceKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruTraceKey<C: Container>
    where C::Element: UnsignedInteger,
{
    ntru_auto_keys: NtruKeyswitchKeyList<C>,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

pub type NtruTraceKeyOwned<Scalar> = NtruTraceKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruTraceKey<C> {
    pub fn get_automorphism_key(&self, index: usize) -> NtruAutomorphismKeyView<Scalar> {
        let automorphism_key_count = self.automorphism_key_count().0;
        assert!(
            index < automorphism_key_count,
            "Input index {} should be smaller than the number of automorphism keys {}",
            index,
            automorphism_key_count,
        );

        let ntru_auto_key = self.ntru_auto_keys.get(index);
        let auto_index = AutomorphismIndex((1 << (index + 1)) + 1);
        NtruAutomorphismKey::from_container(
            ntru_auto_key.into_container(),
            auto_index,
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn automorphism_key_count(&self) -> NtruKeyswitchKeyCount {
        self.ntru_auto_keys.ntru_keyswitch_key_count()
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
    pub fn get_mut_automorphism_key(&mut self, index: usize) -> NtruAutomorphismKeyMutView<Scalar> {
        let automorphism_key_count = self.automorphism_key_count().0;
        assert!(
            index < automorphism_key_count,
            "Input index {} should be smaller than the number of automorphism keys {}",
            index,
            automorphism_key_count,
        );

        let ntru_auto_key = self.ntru_auto_keys.get_mut(index);
        let auto_index = AutomorphismIndex((1 << (index + 1)) + 1);
        NtruAutomorphismKey::from_container(
            ntru_auto_key.into_container(),
            auto_index,
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger> NtruTraceKeyOwned<Scalar> {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let ntru_auto_keys = NtruKeyswitchKeyList::new(
            Scalar::ZERO,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            NtruKeyswitchKeyCount(polynomial_size.0.ilog2() as usize),
            ciphertext_modulus,
        );

        Self {
            ntru_auto_keys,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        }
    }
}
