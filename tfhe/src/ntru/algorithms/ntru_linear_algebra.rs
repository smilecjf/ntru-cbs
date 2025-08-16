use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::traits::*;
use crate::ntru::entities::*;

pub fn ntru_ciphertext_add_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut NtruCiphertext<LhsCont>,
    rhs: &NtruCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
    );

    slice_wrapping_add_assign(lhs.as_mut(), rhs.as_ref());
}
