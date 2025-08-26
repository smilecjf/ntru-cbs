//! Module containing the definition of NtruToRlweKeyswitchKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruToRlweKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruToRlweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruToRlweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub type NtruToRlweKeyswitchKeyOwned<Scalar> = NtruToRlweKeyswitchKey<Vec<Scalar>>;
pub type NtruToRlweKeyswitchKeyView<'data, Scalar> = NtruToRlweKeyswitchKey<&'data [Scalar]>;
pub type NtruToRlweKeyswitchKeyMutView<'data, Scalar> = NtruToRlweKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruToRlweKeyswitchKey<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create and NtruToRlweKeyswitchKey"
        );
        assert!(
            container.container_len() % (2 * polynomial_size.0) == 0,
            "The provided container length is not valid. \
            It needs to be divisible by 2 * polynomial_size. \
            Got container length: {}, polynomial size {polynomial_size:?}.",
            container.container_len(),
        );
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Only support power-of-two modulus, currently.",
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

    pub fn as_view(&self) -> NtruToRlweKeyswitchKeyView<'_, Scalar> {
        NtruToRlweKeyswitchKey::from_container(
            self.data.as_ref(),
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
            self.data.as_ref(),
            self.polynomial_size,
        )
    }

    pub fn as_glwe_ciphertext_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextList::from_container(
            self.as_ref(),
            GlweSize(2),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruToRlweKeyswitchKey<C> {
    pub fn as_mut_view(&mut self) -> NtruToRlweKeyswitchKeyMutView<'_, Scalar> {
        NtruToRlweKeyswitchKey::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        PolynomialList::from_container(
            self.data.as_mut(),
            self.polynomial_size,
        )
    }

    pub fn as_mut_glwe_ciphertext_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        GlweCiphertextList::from_container(
            self.data.as_mut(),
            GlweSize(2),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger> NtruToRlweKeyswitchKeyOwned<Scalar> {
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
                2 * polynomial_size.0 * decomp_level_count.0
            ],
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}
