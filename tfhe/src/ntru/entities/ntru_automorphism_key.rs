//! Module containing the definition of the NtruAutomorphismKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AutomorphismIndex(pub usize);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruAutomorphismKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    automorphism_index: AutomorphismIndex,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruAutomorphismKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruAutomorphismKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub type NtruAutomorphismKeyOwned<Scalar> = NtruAutomorphismKey<Vec<Scalar>>;
pub type NtruAutomorphismKeyView<'data, Scalar> = NtruAutomorphismKey<&'data [Scalar]>;
pub type NtruAutomorphismKeyMutView<'data, Scalar> = NtruAutomorphismKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruAutomorphismKey<C> {
    pub fn from_container(
        container: C,
        automorphism_index: AutomorphismIndex,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
            It needs to be divisible by polynomial_size. \
            Got container length: {}, polynomial size {polynomial_size:?}.",
            container.container_len(),
        );
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Only support power-of-two modulus currently.",
        );

        Self {
            data: container,
            automorphism_index,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn automorphism_index(&self) -> AutomorphismIndex {
        self.automorphism_index
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(
            self.data.container_len() / self.polynomial_size.0
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn as_view(&self) -> NtruAutomorphismKeyView<'_, Scalar> {
        NtruAutomorphismKey::from_container(
            self.as_ref(),
            self.automorphism_index,
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialList::from_container(
            self.as_ref(),
            self.polynomial_size,
        )
    }

    pub fn as_ntru_ciphertext_list(&self) -> NtruCiphertextListView<'_, Scalar> {
        NtruCiphertextList::from_container(
            self.as_ref(),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn as_ngsw_ciphertext(&self) -> NgswCiphertextView<'_, Scalar> {
        NgswCiphertext::from_container(
            self.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn as_ntru_keyswitch_key(&self) -> NtruKeyswitchKeyView<'_, Scalar> {
        NtruKeyswitchKey::from_container(
            self.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruAutomorphismKey<C> {
    pub fn as_mut_view(&mut self) -> NtruAutomorphismKeyMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let automorphism_index = self.automorphism_index;
        let decomp_base_log = self.decomp_base_log;
        let ciphertext_modulus = self.ciphertext_modulus;

        NtruAutomorphismKey::from_container(
            self.as_mut(),
            automorphism_index,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;

        PolynomialList::from_container(
            self.as_mut(),
            polynomial_size,
        )
    }

    pub fn as_mut_ntru_ciphertext_list(&mut self) -> NtruCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;

        NtruCiphertextList::from_container(
            self.as_mut(),
            polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_ngsw_ciphertext(&mut self) -> NgswCiphertextMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let decomp_base_log = self.decomp_base_log;
        let ciphertext_modulus = self.ciphertext_modulus;

        NgswCiphertext::from_container(
            self.as_mut(),
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_ntru_keyswitch_key(&mut self) -> NtruKeyswitchKeyMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let decomp_base_log = self.decomp_base_log;
        let ciphertext_modulus = self.ciphertext_modulus;

        NtruKeyswitchKey::from_container(
            self.as_mut(),
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger> NtruAutomorphismKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        automorphism_index: AutomorphismIndex,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                polynomial_size.0 * decomp_level_count.0
            ],
            automorphism_index,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}
