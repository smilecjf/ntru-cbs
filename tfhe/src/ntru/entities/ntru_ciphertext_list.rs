use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::ntru::entities::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct NtruCiphertextCount(pub usize);

pub struct NtruCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruCiphertextList<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
            It needs to be dividable by polynomial size. \
            Got container length: {}, polynomial_size: {:?}.",
            container.container_len(),
            polynomial_size,
        );

        Self {
            data: container,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn ntru_ciphertext_count(&self) -> NtruCiphertextCount {
        NtruCiphertextCount(self.data.container_len() / self.polynomial_size.0)
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_view(&self) -> NtruCiphertextList<&'_ [Scalar]> {
        NtruCiphertextList {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruCiphertextList<C> {
    pub fn as_mut_view(&mut self) -> NtruCiphertextList<&'_ mut [Scalar]> {
        NtruCiphertextList {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

pub type NtruCiphertextListOwned<Scalar> = NtruCiphertextList<Vec<Scalar>>;
pub type NtruCiphertextListView<'data, Scalar> = NtruCiphertextList<&'data [Scalar]>;
pub type NtruCiphertextListMutView<'data, Scalar> = NtruCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NtruCiphertextListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        ciphertext_count: NtruCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; ciphertext_count.0],
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct NtruCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for NtruCiphertextList<C> {
    type Metadata = NtruCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let NtruCiphertextListCreationMetadata {
            polynomial_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, polynomial_size, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer for NtruCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = NtruCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = NtruCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = NtruCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = NtruCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        NtruCiphertextCreationMetadata {
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.polynomial_size().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        NtruCiphertextListCreationMetadata {
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for NtruCiphertextList<C>
{
    type EntityMutView<'this>
        = NtruCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = NtruCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
