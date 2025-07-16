use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_for_ntru::*;

pub fn polynomial_to_string_mod_power_of_two<Scalar, InputCont>(input: &Polynomial<InputCont>, power: usize)
-> String
where
    Scalar: UnsignedInteger + ToString,
    InputCont: Container<Element = Scalar>,
{
    assert!(power > 0 && power < Scalar::BITS);

    let degree = polynomial_nonzero_coeff_idx(input, input.polynomial_size().0);

    let mut coeff = input.as_ref()[degree].into_signed();
    if coeff > Scalar::ONE.into_signed() << (power - 1) {
        coeff -= Scalar::ONE.into_signed() << power;
    }
    let mut str = String::from("");
    if coeff < Scalar::ZERO.into_signed() {
        str.push_str("-");
        str.push_str(&(-coeff).into_unsigned().to_string());
    } else {
        str.push_str(&input.as_ref()[degree].to_string());
    }

    if degree > 0 {
        str.push_str(" X^");
        str.push_str(&degree.to_string());
    }

    for i in (0..degree).rev() {
        let mut coeff = input.as_ref()[i].into_signed();
        if coeff > Scalar::ONE.into_signed() << (power - 1) {
            coeff -= Scalar::ONE.into_signed() << power;
        }
        if coeff > Scalar::ZERO.into_signed() {
            str.push_str(" + ");
            str.push_str(&input.as_ref()[i].to_string());
            if i > 0 {
                str.push_str(" X^");
                str.push_str(&i.to_string());
            }
        } else if coeff < Scalar::ZERO.into_signed() {
            str.push_str(" - ");
            str.push_str(&(-coeff).into_unsigned().to_string());
            if i > 0 {
                str.push_str(" X^");
                str.push_str(&i.to_string());
            }
        }
    }

    return str;
}

