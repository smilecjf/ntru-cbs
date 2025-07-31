//! Module containing the definition of the NgswCiphertext

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::ntru::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NgswCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NgswCiphertext<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a NgswCiphertext"
        );
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid.\
            It needs to be divisible by polynomial_size.\
            Got container length: {:?} and polynomial_size: {:?}.",
            container.container_len(),
            polynomial_size.0,
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
        DecompositionLevelCount(self.data.container_len() / self.polynomial_size.0)
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn as_view(&self) -> NgswCiphertextView<'_, Scalar> {
        NgswCiphertextView::from_container(
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
        PolynomialListView::from_container(
            self.as_ref(),
            self.polynomial_size,
        )
    }

    pub fn as_ntru_ciphertext_list(&self) -> NtruCiphertextListView<'_, Scalar> {
        NtruCiphertextListView::from_container(
            self.as_ref(),
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NgswCiphertext<C> {
    pub fn as_mut_view(&mut self) -> NgswCiphertextMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let decomp_base_log = self.decomp_base_log;
        let ciphertext_modulus = self.ciphertext_modulus;
        NgswCiphertextMutView::from_container(
            self.as_mut(),
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(
            self.as_mut(),
            polynomial_size,
        )
    }

    pub fn as_mut_ntru_ciphertext_list(&mut self) -> NtruCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        NtruCiphertextListMutView::from_container(
            self.as_mut(),
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

pub type NgswCiphertextOwned<Scalar> = NgswCiphertext<Vec<Scalar>>;
pub type NgswCiphertextView<'data, Scalar> = NgswCiphertext<&'data [Scalar]>;
pub type NgswCiphertextMutView<'data, Scalar> = NgswCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NgswCiphertextOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; polynomial_size.0 * decomp_level_count.0],
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct NgswCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for NgswCiphertext<C> {
    type Metadata = NgswCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let NgswCiphertextCreationMetadata {
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
    for NgswCiphertext<C>
{
    type Element = C::Element;

    type EntityViewMetadata = NtruCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = NtruCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = NgswCiphertextCreationMetadata<Self::Element>;

    type SelfView<'this>
        = NgswCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        NtruCiphertextCreationMetadata {
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.polynomial_size.0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        NgswCiphertextCreationMetadata {
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for NgswCiphertext<C>
{
    type EntityMutView<'this>
        = NtruCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = NgswCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;
}
