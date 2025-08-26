//! Module containing the definition of RlweSchemeSwitchKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::ntru::entities::NtruToRlweKeyswitchKeyMutView;
use crate::ntru::entities::NtruToRlweKeyswitchKeyView;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RlweSchemeSwitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for RlweSchemeSwitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for RlweSchemeSwitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub type RlweSchemeSwitchKeyOwned<Scalar> = RlweSchemeSwitchKey<Vec<Scalar>>;
pub type RlweSchemeSwitchKeyView<'data, Scalar> = RlweSchemeSwitchKey<&'data [Scalar]>;
pub type RlweSchemeSwitchKeyMutView<'data, Scalar> = RlweSchemeSwitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> RlweSchemeSwitchKey<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GgswCiphertext"
        );
        assert!(
            container.container_len() % (2 * polynomial_size.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by 2 * polynomial_size: {}. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            2 * polynomial_size.0,
            container.container_len()
        );

        Self {
            data: container,
            polynomial_size,
            decomp_base_log,
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
        DecompositionLevelCount(
            self.data.container_len() / (2 * self.polynomial_size.0)
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    pub fn as_glwe_ciphertext_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.data.as_ref(),
            GlweSize(2),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn as_ntru_to_rlwe_keyswitch_key(&self) -> NtruToRlweKeyswitchKeyView<'_, Scalar> {
        NtruToRlweKeyswitchKeyView::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn as_view(&self) -> RlweSchemeSwitchKeyView<'_, Scalar> {
        RlweSchemeSwitchKey::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> RlweSchemeSwitchKey<C> {
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        PolynomialListMutView::from_container(
            self.data.as_mut(),
            self.polynomial_size,
        )
    }

    pub fn as_mut_glwe_ciphertext_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        GlweCiphertextListMutView::from_container(
            self.data.as_mut(),
            GlweSize(2),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn as_mut_ntru_to_rlwe_keyswitch_key(&mut self) -> NtruToRlweKeyswitchKeyMutView<'_, Scalar> {
        NtruToRlweKeyswitchKeyMutView::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn as_mut_view(&mut self) -> RlweSchemeSwitchKeyMutView<'_, Scalar> {
        RlweSchemeSwitchKeyMutView::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger> RlweSchemeSwitchKeyOwned<Scalar> {
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
                decomp_level_count.0 * 2 * polynomial_size.0
            ],
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

