use crate::core_crypto::prelude::*;
use crate::core_crypto::prelude::polynomial_algorithms::*;

// For g = gcd(a, b), return (g, x, y) where ax + by = g
pub fn egcd<Scalar>(a: Scalar, b: Scalar) -> (Scalar, i128, i128)
where
    Scalar: UnsignedInteger + CastInto<i128> + CastFrom<i128>,
{
    let mut prev_x = 1i128;
    let mut x = 0i128;

    let mut prev_y = 0i128;
    let mut y = 1i128;

    let mut a: i128 = a.cast_into();
    let mut b: i128 = b.cast_into();

    while b != 0 {
        let q = a / b;
        let r = a % b;

        a = b;
        b = r;

        // (prev_x, x) <- (x, prev_x - q * x);
        let tmp = x;
        // x = prev_x - q.into_signed() * x;
        x = prev_x - q * x;
        prev_x = tmp;

        // (prev_y, y) <- (y, prev_y - q * y);
        let tmp = y;
        // y = prev_y - q.into_signed() * y;
        y = prev_y - q * y;
        prev_y = tmp;
    }

    return (a.cast_into(), prev_x, prev_y);
}

fn number_of_two_factors<Scalar>(a: Scalar) -> u32
where
    Scalar: UnsignedInteger
{
    if a == Scalar::ZERO {
        return 0;
    }

    let mut ctr = 0;
    let mut a = a;
    while a & Scalar::ONE == Scalar::ZERO {
        ctr += 1;
        a = a >> 1usize;
    }

    return ctr;
}

pub fn is_polynomial_zero<Scalar, InputCont>(input: &Polynomial<InputCont>) -> bool
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
{
    for elem in input.as_ref().iter() {
        if *elem != Scalar::ZERO {
            return false;
        }
    }
    return true;
}

pub fn is_polynomial_one<Scalar, InputCont>(input: &Polynomial<InputCont>) -> bool
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
{
    for elem in input.as_ref().iter().skip(1) {
        if *elem != Scalar::ZERO {
            return false;
        }
    }

    return input.as_ref()[0] == Scalar::ONE;
}

// Return q = lhs / rhs such that rhs * q == lhs (mod 2^power)
// Return 0 if rhs == 0 or there is no such q
pub fn div_mod_power_of_two<Scalar>(lhs: Scalar, rhs: Scalar, power: usize) -> Scalar
where
    Scalar: UnsignedInteger + CastInto<i128> + CastFrom<i128>,
{
    assert!(rhs != Scalar::ZERO, "divide by zero");

    let mut lhs = lhs % (Scalar::ONE << power);
    let mut rhs = rhs % (Scalar::ONE << power);

    let (g, _, _) = egcd(lhs, rhs);
    lhs = lhs / g;
    rhs = rhs / g;

    if number_of_two_factors(rhs) != 0 {
        return Scalar::ZERO;
    }

    let (g, rhs_inv, _) = egcd(rhs, Scalar::ONE << power);
    assert!(g == Scalar::ONE);

    let signed_mod = 1i128 << power;
    let rhs_inv = rhs_inv % signed_mod;
    let rhs_inv: Scalar = if rhs_inv >= 0 {rhs_inv.cast_into()} else {(signed_mod + rhs_inv).cast_into()};
    let q = rhs_inv.wrapping_mul_custom_mod(lhs, Scalar::ONE << power);

    assert!(q.wrapping_mul_custom_mod(rhs, Scalar::ONE << power).wrapping_sub_custom_mod(lhs, Scalar::ONE << power) == Scalar::ZERO);

    return q;
}

pub fn polynomial_nonzero_coeff_idx<Scalar, InputCont>(
    op: &Polynomial<InputCont>,
    upper_bound: usize,
) -> usize
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
{
    let polynomial_size = op.polynomial_size().0;
    let upper_bound = std::cmp::min(upper_bound, polynomial_size);
    for i in (1..upper_bound).rev() {
        if op.as_ref()[i] != Scalar::ZERO {
            return i;
        }
    }
    return 0;
}

pub fn polynomial_wrapping_custom_mod_assign<Scalar, Cont>(
    input: &mut Polynomial<Cont>,
    modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element = Scalar>,
{
    for e in input.as_mut().iter_mut() {
        *e = (*e) % modulus;
    }
}

pub fn polynomial_wrapping_mul_scalar_custom_mod<Scalar, InputCont, OutputCont>(
    input: &Polynomial<InputCont>,
    scalar: Scalar,
    output: &mut Polynomial<OutputCont>,
    modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input.polynomial_size().0 == output.polynomial_size().0,
        "Input polynomial size {:?} is not the same as the output polynomial size {:?}.",
        input.polynomial_size().0,
        output.polynomial_size().0,
    );

    for (dst, src) in output.as_mut().iter_mut()
        .zip(input.as_ref().iter())
    {
        *dst = src.wrapping_mul_custom_mod(scalar, modulus);
    }
}

pub fn polynomial_div_mod_power_of_two<Scalar, OutputCont, InputCont>(
    lhs: &Polynomial<InputCont>,
    rhs: &Polynomial<InputCont>,
    quotient: &mut Polynomial<OutputCont>,
    remainder: &mut Polynomial<OutputCont>,
    power: usize,
) -> bool where
    Scalar: UnsignedInteger + CastInto<i128> + CastFrom<i128>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        quotient.polynomial_size() == lhs.polynomial_size(),
        "Quotient polynomial size {:?} is not the same as the input lhs polynomial {:?}.",
        quotient.polynomial_size(),
        lhs.polynomial_size(),
    );
    assert!(
        quotient.polynomial_size() == rhs.polynomial_size(),
        "Quotient polynomial size {:?} is not the same as the input rhs polynomial {:?}.",
        quotient.polynomial_size(),
        rhs.polynomial_size(),
    );
    assert!(
        remainder.polynomial_size() == lhs.polynomial_size(),
        "Remainder polynomial size {:?} is not the same as the input lhs polynomial {:?}.",
        remainder.polynomial_size(),
        lhs.polynomial_size(),
    );
    assert!(
        remainder.polynomial_size() == rhs.polynomial_size(),
        "Remainder polynomial size {:?} is not the same as the input rhs polynomial {:?}.",
        remainder.polynomial_size(),
        rhs.polynomial_size(),
    );
    assert!(
        power > 0,
        "modulus power should be greater than 0"
    );

    let polynomial_size = lhs.polynomial_size();

    quotient.as_mut().fill(Scalar::ZERO);
    remainder.as_mut().fill(Scalar::ZERO);

    let lhs_degree = polynomial_nonzero_coeff_idx(lhs, polynomial_size.0);
    let rhs_degree = polynomial_nonzero_coeff_idx(rhs,polynomial_size.0);

    let mut target_degree = lhs_degree;
    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);
    remainder.as_mut().clone_from_slice(lhs.as_ref());

    let modulus = Scalar::ONE << power;

    let rhs_coeff = rhs.as_ref()[rhs_degree];
    let mut signed_rhs_coeff = rhs_coeff.into_signed();
    if rhs_coeff > Scalar::ONE << (power - 1) {
        signed_rhs_coeff -= Scalar::ONE.into_signed() << power;
    }

    while target_degree >= rhs_degree {
        let lhs_coeff = remainder.as_ref()[target_degree];
        let mut signed_lhs_coeff = lhs_coeff.into_signed();
        if lhs_coeff > Scalar::ONE << (power - 1) {
            signed_lhs_coeff -= Scalar::ONE.into_signed() << power;
        }

        let quotient_coeff = div_mod_power_of_two(lhs_coeff, rhs_coeff, power);

        if quotient_coeff == Scalar::ZERO {
            break;
        }

        quotient.as_mut()[target_degree - rhs_degree] = quotient_coeff;

        polynomial_wrapping_mul_scalar_custom_mod(&rhs, quotient_coeff, &mut buf, modulus);
        polynomial_wrapping_monic_monomial_mul_assign(&mut buf, MonomialDegree(target_degree - rhs_degree));
        polynomial_wrapping_sub_assign_custom_mod(remainder, &buf, modulus);

        target_degree = polynomial_nonzero_coeff_idx(&remainder, target_degree);
    }

    let remainder_degree = polynomial_nonzero_coeff_idx(remainder, polynomial_size.0);
    return remainder_degree < rhs_degree;
}

pub fn egcd_polynomial_mod_power_of_two<Scalar, Cont>(
    lhs: &Polynomial<Cont>,
    rhs: &Polynomial<Cont>,
    power: usize,
) -> (Polynomial<Vec<Scalar>>, Polynomial<Vec<Scalar>>, Polynomial<Vec<Scalar>>, bool)
where
    Scalar: UnsignedInteger + CastInto<i128> + CastFrom<i128>,
    Cont: Container<Element = Scalar>,
{
    assert!(
        lhs.polynomial_size() == rhs.polynomial_size(),
        "lhs polynomial size {:?} is not the same as the rhs polynomial {:?}",
        lhs.polynomial_size(),
        rhs.polynomial_size(),
    );

    assert!(power > 1 && power < Scalar::BITS);

    let polynomial_size= lhs.polynomial_size();
    let modulus = Scalar::ONE << power;

    let mut x = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut prev_x = Polynomial::new(Scalar::ZERO, polynomial_size);
    prev_x.as_mut()[0] = Scalar::ONE;

    let mut y = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut prev_y = Polynomial::new(Scalar::ZERO, polynomial_size);
    y.as_mut()[0] = Scalar::ONE;


    let mut a = Polynomial::new(Scalar::ZERO, polynomial_size);
    a.as_mut().clone_from_slice(lhs.as_ref());

    let mut b = Polynomial::new(Scalar::ZERO, polynomial_size);
    b.as_mut().clone_from_slice(rhs.as_ref());

    let mut q = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut r = Polynomial::new(Scalar::ZERO, polynomial_size);

    let mut buf1 = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut buf2 = Polynomial::new(Scalar::ZERO, polynomial_size);

    let mut is_divided = true;

    while !is_polynomial_zero(&b) {
        is_divided = polynomial_div_mod_power_of_two(&a, &b, &mut q, &mut r, power);
        if !is_divided {
            break;
        }

        // (a, b) <- (b, r)
        buf1.as_mut().clone_from_slice(b.as_ref());
        b.as_mut().clone_from_slice(r.as_ref());
        a.as_mut().clone_from_slice(buf1.as_ref());

        // (prev_x, x) <- (x, prev_x - q * x)
        buf1.as_mut().clone_from_slice(x.as_ref());
        polynomial_wrapping_mul(&mut buf2, &x, &q);
        polynomial_wrapping_custom_mod_assign(&mut buf2, modulus);
        x.as_mut().clone_from_slice(prev_x.as_ref());
        polynomial_wrapping_sub_assign_custom_mod(&mut x, &buf2, modulus);
        prev_x.as_mut().clone_from_slice(buf1.as_ref());

        // (prev_y, y) <- (y, prev_y - q * y)
        buf1.as_mut().clone_from_slice(y.as_ref());
        polynomial_wrapping_mul(&mut buf2, &y, &q);
        polynomial_wrapping_custom_mod_assign(&mut buf2, modulus);
        y.as_mut().clone_from_slice(prev_y.as_ref());
        polynomial_wrapping_sub_assign_custom_mod(&mut y, &buf2, modulus);
        prev_y.as_mut().clone_from_slice(buf1.as_ref());
    }

    return (a, prev_x, prev_y, is_divided);
}

fn polynomial_swap<Scalar, LhsCont, RhsCont>(lhs: &mut Polynomial<LhsCont>, rhs: &mut Polynomial<RhsCont>)
where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: ContainerMut<Element = Scalar>,
{
    assert!(
        lhs.polynomial_size().0 == rhs.polynomial_size().0,
        "The lhs polynomial size {:?} is different from the rhs polynomial size {:?}",
        lhs.polynomial_size().0,
        rhs.polynomial_size().0,
    );

    let polynomial_size = lhs.polynomial_size();
    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);

    buf.as_mut().clone_from_slice(rhs.as_ref());
    rhs.as_mut().clone_from_slice(lhs.as_ref());
    lhs.as_mut().clone_from_slice(buf.as_ref());
}

pub fn almost_inverse_mod_two<Scalar, InputCont, OutputCont>(
    input: &Polynomial<InputCont>,
    output: &mut Polynomial<OutputCont>,
) -> bool
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input.polynomial_size().0 == output.polynomial_size().0,
        "The input polynomial size {:?} is different from the output polynomial size {:?}",
        input.polynomial_size().0,
        output.polynomial_size().0,
    );

    let polynomial_size = input.polynomial_size().0;
    let inc_polynomial_size = PolynomialSize(polynomial_size + 1);

    let mut a = Polynomial::new(Scalar::ZERO, inc_polynomial_size);
    let mut b = Polynomial::new(Scalar::ZERO, inc_polynomial_size);
    let mut c = Polynomial::new(Scalar::ZERO, inc_polynomial_size);
    let mut g = Polynomial::new(Scalar::ZERO, inc_polynomial_size);
    let mut k = 0usize;

    // Initialize
    // a <- input, b <- 1, c <- 0, g <- X^N + 1
    for i in 0..polynomial_size {
        a.as_mut()[i] = input.as_ref()[i];
    }
    b.as_mut()[0] = Scalar::ONE;
    g.as_mut()[0] = Scalar::ONE;
    g.as_mut()[polynomial_size] = Scalar::ONE;

    while !is_polynomial_zero(&a) {
        while a.as_ref()[0] == Scalar::ZERO {
            polynomial_wrapping_monic_monomial_div_assign(&mut a, MonomialDegree(1));
            polynomial_wrapping_monic_monomial_mul_assign(&mut c, MonomialDegree(1));
            k += 1;
        }
        if is_polynomial_one(&a) {
            for i in 0..polynomial_size {
                output.as_mut()[i] = b.as_ref()[i];
            }
            if k != 0 {
                polynomial_wrapping_monic_monomial_div_assign_custom_mod(
                    output,
                    MonomialDegree(k),
                    Scalar::TWO,
                );
            }
            return true;
        }

        let degree_a = polynomial_nonzero_coeff_idx(&a, inc_polynomial_size.0);
        let degree_g = polynomial_nonzero_coeff_idx(&g, inc_polynomial_size.0);

        if degree_a < degree_g {
            polynomial_swap(&mut a, &mut g);
            polynomial_swap(&mut b, &mut c);
        }

        polynomial_wrapping_add_assign_custom_mod(&mut a, &g, Scalar::TWO);
        polynomial_wrapping_add_assign_custom_mod(&mut b, &c, Scalar::TWO);
    }

    return false;
}
