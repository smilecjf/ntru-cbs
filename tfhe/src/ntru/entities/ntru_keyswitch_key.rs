//! Module containing the definition of the NtruKeyswitchKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub type NtruKeyswitchKeyOwned<Scalar> = NtruKeyswitchKey<Vec<Scalar>>;
pub type NtruKeyswitchKeyView<'data, Scalar> = NtruKeyswitchKey<&'data [Scalar]>;
pub type NtruKeyswitchKeyMutView<'data, Scalar> = NtruKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruKeyswitchKey<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an NtruKeyswitchKey"
        );
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
            self.data.container_len() / self.polynomial_size.0
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn as_view(&self) -> NtruKeyswitchKeyView<'_, Scalar> {
        NtruKeyswitchKey::from_container(
            self.as_ref(),
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
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruKeyswitchKey<C> {
    pub fn as_mut_view(&mut self) -> NtruKeyswitchKeyMutView<'_, Scalar> {
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
}

impl<Scalar: UnsignedInteger> NtruKeyswitchKeyOwned<Scalar> {
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
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct NtruKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger> {
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for NtruKeyswitchKey<C>
{
    type Metadata = NtruKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let NtruKeyswitchKeyCreationMetadata {
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for NtruKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = NtruCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = NtruCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = NtruKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this>
        = NtruKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        NtruCiphertextListCreationMetadata {
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.polynomial_size().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        NtruKeyswitchKeyCreationMetadata {
            polynomial_size: self.polynomial_size(),
            decomp_base_log: self.decomposition_base_log(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for NtruKeyswitchKey<C>
{
    type EntityMutView<'this>
        = NtruCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = NtruKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}
