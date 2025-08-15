//! Module containing the definition of the NtruSecretKey.

use crate::ntru::algorithms::*;
use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;

// First half of data contains the secret key polynomial f, and
// the other half contains the inverse 1/f of the secret key polynomimal
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NtruSecretKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NtruSecretKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NtruSecretKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruSecretKey<C> {
    pub fn from_container(container: C, polynomial_size: PolynomialSize, ciphertext_modulus: CiphertextModulus<Scalar>) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a NtruSecretKey"
        );
        assert!(
            container.container_len() == 2 * polynomial_size.0,
            "The provided container length {} is not valid. It should be a double of the polynomial size {}.",
            container.container_len(),
            polynomial_size.0,
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

    pub fn as_view(&self) -> NtruSecretKeyView<'_, Scalar> {
        NtruSecretKey::from_container(self.as_ref(), self.polynomial_size, self.ciphertext_modulus)
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn get_secret_key_polynomial(&self) -> Polynomial<&[C::Element]> {
        Polynomial::from_container(&self.as_ref()[..self.polynomial_size.0])
    }

    pub fn get_secret_key_inverse_polynomial(&self) -> Polynomial<&[C::Element]> {
        Polynomial::from_container(&self.as_ref()[self.polynomial_size.0..])
    }

    pub fn get_secret_key_and_inverse_polynomial(&self)
    -> (Polynomial<&[C::Element]>, Polynomial<&[C::Element]>)
    {
        let (sk_poly, sk_inv_poly) = self.as_ref().split_at(self.polynomial_size.0);

        (
            Polynomial::from_container(sk_poly),
            Polynomial::from_container(sk_inv_poly),
        )
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialList::from_container(
            self.data.as_ref(),
            self.polynomial_size,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruSecretKey<C> {
    pub fn as_mut_view(&mut self) -> NtruSecretKeyMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        NtruSecretKey::from_container(self.as_mut(), polynomial_size, ciphertext_modulus)
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        PolynomialList::from_container(
            self.data.as_mut(),
            self.polynomial_size,
        )
    }
}

pub type NtruSecretKeyOwned<Scalar> = NtruSecretKey<Vec<Scalar>>;
pub type NtruSecretKeyView<'data, Scalar> = NtruSecretKey<&'data [Scalar]>;
pub type NtruSecretKeyMutView<'data, Scalar> = NtruSecretKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NtruSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    pub fn new_empty_key(
        value: Scalar,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                value;
                2 * polynomial_size.0
            ],
            polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn generate_new_binary<Gen>(
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self
    where
        Scalar: UnsignedInteger + RandomGenerable<UniformBinary>,
        Gen: ByteRandomGenerator,
    {
        let mut ntru_sk = Self::new_empty_key(Scalar::ZERO, polynomial_size, ciphertext_modulus);
        generate_binary_ntru_secret_key(&mut ntru_sk, ciphertext_modulus, generator);
        ntru_sk
    }
}
