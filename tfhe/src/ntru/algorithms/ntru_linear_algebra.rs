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

pub fn ntru_ciphertext_round_by_2_assign<C: ContainerMut>(
    input: &mut NtruCiphertext<C>,
) where
    C::Element: UnsignedInteger,
{
    let ciphertext_modulus = input.ciphertext_modulus();

    assert!(
        ciphertext_modulus.is_compatible_with_native_modulus(),
        "Only support power-of-two modulus, currently.",
    );

    let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
    for elt in input.as_mut().iter_mut() {
        let rounding = *elt & torus_scaling;
        *elt = (*elt).wrapping_add(rounding).wrapping_div(C::Element::TWO);
    }
}
