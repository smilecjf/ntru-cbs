//! Module containing the definition of the NtruSwitchingKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruSwitchingKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruSwitchingKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruSwitchingKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub type NtruSwitchingKeyOwned<Scalar> = NtruSwitchingKey<Vec<Scalar>>;
pub type NtruSwitchingKeyView<'data, Scalar> = NtruSwitchingKey<&'data [Scalar]>;
pub type NtruSwitchingKeyMutView<'data, Scalar> = NtruSwitchingKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruSwitchingKey<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert_eq!(
            container.container_len(),
            polynomial_size.0 * decomp_level_count.0,
            "The provided container length is not valid. It shoulde be \
            polynomial_size.0 * decomp_level_count.0. Got container length \
            {}, polynomial_size {polynomial_size:?}, and decomp_level_count \
            {decomp_level_count:?}.",
            container.container_len(),
        );
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Only support power-of-two modulus currently.",
        );

        Self {
            data: container,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        }
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

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn as_view(&self) -> NtruSwitchingKeyView<'_, Scalar> {
        NtruSwitchingKey::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.ciphertext_modulus,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialList::from_container(
            self.data.as_ref(),
            self.polynomial_size,
        )
    }

    pub fn as_ntru_ciphertext_list(&self) -> NtruCiphertextListView<'_, Scalar> {
        NtruCiphertextList::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn as_ngsw_ciphertext(&self) -> NgswCiphertextView<'_, Scalar> {
        NgswCiphertext::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn as_ntru_keyswitch_key(&self) -> NtruKeyswitchKeyView<'_, Scalar> {
        NtruKeyswitchKey::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruSwitchingKey<C> {
    pub fn as_mut_view(&mut self) -> NtruSwitchingKeyMutView<'_, Scalar> {
        NtruSwitchingKey::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.ciphertext_modulus,
        )
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        PolynomialList::from_container(
            self.data.as_mut(),
            self.polynomial_size,
        )
    }

    pub fn as_mut_ntru_ciphertext_list(&mut self) -> NtruCiphertextListMutView<'_, Scalar> {
        NtruCiphertextList::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn as_mut_ngsw_ciphertext(&mut self) -> NgswCiphertextMutView<'_, Scalar> {
        NgswCiphertext::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn as_mut_ntru_keyswitch_key(&mut self) -> NtruKeyswitchKeyMutView<'_, Scalar> {
        NtruKeyswitchKey::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger> NtruSwitchingKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
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
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}
