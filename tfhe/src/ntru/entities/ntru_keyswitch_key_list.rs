//! Module containing the definition of the NtruKeyswitchKeyList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::ntru::entities::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtruKeyswitchKeyCount(pub usize);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NtruKeyswitchKeyList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruKeyswitchKeyList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruKeyswitchKeyList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub type NtruKeyswitchKeyListOwned<Scalar> = NtruKeyswitchKeyList<Vec<Scalar>>;
pub type NtruKeyswitchKeyListView<'a, Scalar> = NtruKeyswitchKeyList<&'a [Scalar]>;
pub type NtruKeyswitchKeyListMutView<'a, Scalar> = NtruKeyswitchKeyList<&'a mut [Scalar]>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruKeyswitchKeyList<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            container.container_len()
                % (polynomial_size.0 * decomp_level_count.0) == 0,
            "The provided container length is not valid. \
            It needs to be divisible by polynomial size * decomp_level_count. \
            Got container length: {}, polynomial size {:?}, decomp level count: {:?}.",
            container.container_len(),
            polynomial_size,
            decomp_level_count,
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

    pub fn ntru_keyswitch_key_count(&self) -> NtruKeyswitchKeyCount {
        NtruKeyswitchKeyCount(
            self.data.container_len() / (
                self.polynomial_size.0 * self.decomp_level_count.0
            )
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_view(&self) -> NtruKeyswitchKeyListView<'_, Scalar> {
        NtruKeyswitchKeyList {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    pub fn as_ngsw_ciphertext_list(&self) -> NgswCiphertextListView<'_, Scalar> {
        NgswCiphertextList::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruKeyswitchKeyList<C> {
    pub fn as_mut_view(&mut self) -> NtruKeyswitchKeyListMutView<'_, Scalar> {
        NtruKeyswitchKeyList {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    pub fn as_mut_ngsw_ciphertext_list(&mut self) -> NgswCiphertextListMutView<'_, Scalar> {
        NgswCiphertextList::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger> NtruKeyswitchKeyListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_count: NtruKeyswitchKeyCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with;
                polynomial_size.0 * decomp_level_count.0
                    * ciphertext_count.0
            ],
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct NtruKeyswitchKeyListCreationMetadata<Scalar: UnsignedInteger> {
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for NtruKeyswitchKeyList<C> {
    type Metadata = NtruKeyswitchKeyListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let NtruKeyswitchKeyListCreationMetadata {
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus
        } = meta;
        Self::from_container(
            from,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

impl <Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer for NtruKeyswitchKeyList<C> {
    type Element = C::Element;

    type EntityViewMetadata = NtruKeyswitchKeyCreationMetadata<Self::Element>;

    type EntityView<'this>
        = NtruKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = NtruKeyswitchKeyListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = NtruKeyswitchKeyListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        NtruKeyswitchKeyCreationMetadata {
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.polynomial_size.0 * self.decomp_level_count.0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        NtruKeyswitchKeyListCreationMetadata {
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for NtruKeyswitchKeyList<C>
{
    type EntityMutView<'this>
        = NtruKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = NtruKeyswitchKeyListMutView<'this, Self::Element>
    where
        Self: 'this;
}
