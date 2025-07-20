//! Module containing the definition of the NtruCiphertext.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruCiphertext<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() == polynomial_size.0,
            "The provided container length {} should be the same as the polynomial size {}.",
            container.container_len(),
            polynomial_size.0,
        );

        assert!(
            ciphertext_modulus.is_power_of_two(),
            "Only supports power-of-two modulus currently"
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

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn as_polynomial(&self) -> PolynomialView<'_, C::Element> {
        PolynomialView::from_container(self.as_ref())
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruCiphertext<C> {
    pub fn as_mut_polynomial(&mut self) -> PolynomialMutView<'_, C::Element> {
        PolynomialMutView::from_container(self.as_mut())
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub type NtruCiphertextOwned<Scalar> = NtruCiphertext<Vec<Scalar>>;
pub type NtruCiphertextView<'data, Scalar> = NtruCiphertext<&'data [Scalar]>;
pub type NtruCiphertextMutView<'data, Scalar> = NtruCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NtruCiphertextOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; polynomial_size.0],
            polynomial_size,
            ciphertext_modulus,
        )
    }
}
