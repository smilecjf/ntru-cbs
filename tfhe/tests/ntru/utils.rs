use tfhe::core_crypto::prelude::*;
use tfhe::ntru::algorithms::polynomial_for_ntru::*;

/* -------- Error Tracking -------- */
#[allow(unused)]
pub fn get_max_error<Scalar, PtxtCont, MsgCont>(
    input_plaintext_list: &PlaintextList<PtxtCont>,
    correct_message_list: &PlaintextList<MsgCont>,
    torus_scaling: Scalar,
    delta: Scalar,
) -> Scalar where
    Scalar: UnsignedInteger,
    PtxtCont: Container<Element = Scalar>,
    MsgCont: Container<Element = Scalar>,
{
    assert!(
        input_plaintext_list.plaintext_count().0 == correct_message_list.plaintext_count().0,
        "Mismatch between PlaintextCount of input plaintext and correct message. \
        Got {:?} in input plaintext, and {:?} in message.",
        input_plaintext_list.plaintext_count().0,
        correct_message_list.plaintext_count().0,
    );

    let mut max_err = Scalar::ZERO;
    input_plaintext_list.iter().zip(correct_message_list.iter())
        .for_each(|(input, correct_val)| {
            let input = (*input.0).wrapping_mul(torus_scaling);
            let correct_val = (*correct_val.0)
                .wrapping_mul(delta)
                .wrapping_mul(torus_scaling);

            let abs_err = {
                let d0 = input.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(input);
                std::cmp::min(d0, d1) / torus_scaling
            };
            max_err = std::cmp::max(max_err, abs_err);
        });

    max_err
}

#[allow(unused)]
pub fn get_avg_and_max_error<Scalar, PtxtCont, MsgCont>(
    input_plaintext_list: &PlaintextList<PtxtCont>,
    correct_message_list: &PlaintextList<MsgCont>,
    torus_scaling: Scalar,
    delta: Scalar,
) -> (f64, Scalar) where
    Scalar: UnsignedInteger + CastInto<u128>,
    PtxtCont: Container<Element = Scalar>,
    MsgCont: Container<Element = Scalar>,
{
    assert!(
        input_plaintext_list.plaintext_count().0 == correct_message_list.plaintext_count().0,
        "Mismatch between PlaintextCount of input plaintext and correct message. \
        Got {:?} in input plaintext, and {:?} in message.",
        input_plaintext_list.plaintext_count().0,
        correct_message_list.plaintext_count().0,
    );

    let mut max_err = Scalar::ZERO;
    let mut sum_err = u128::ZERO;
    input_plaintext_list.iter().zip(correct_message_list.iter())
        .for_each(|(input, correct_val)| {
            let input = (*input.0).wrapping_mul(torus_scaling);
            let correct_val = (*correct_val.0)
                .wrapping_mul(delta)
                .wrapping_mul(torus_scaling);

            let abs_err = {
                let d0 = input.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(input);
                std::cmp::min(d0, d1) / torus_scaling
            };

            sum_err = sum_err.wrapping_add(Scalar::cast_into(abs_err));
            max_err = std::cmp::max(max_err, abs_err);
        });

    let avg_err = (sum_err as f64) / (input_plaintext_list.plaintext_count().0 as f64);
    (avg_err, max_err)
}

/* -------- Polynomial to String -------- */
#[allow(unused)]
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

#[allow(unused)]
pub fn polynomial_to_string_native_mod<Scalar, InputCont>(input: &Polynomial<InputCont>)
-> String
where
    Scalar: UnsignedInteger + ToString,
    InputCont: Container<Element = Scalar>,
{
    let degree = polynomial_nonzero_coeff_idx(input, input.polynomial_size().0);

    let coeff = input.as_ref()[degree].into_signed();

    let mut str = String::from("");
    if coeff < Scalar::ZERO.into_signed() {
        str.push_str("-");
        str.push_str(&input.as_ref()[degree].wrapping_neg().to_string());
    } else {
        str.push_str(&input.as_ref()[degree].to_string());
    }

    if degree > 0 {
        str.push_str(" X^");
        str.push_str(&degree.to_string());
    }

    for i in (0..degree).rev() {
        let coeff = input.as_ref()[i].into_signed();
        if coeff > Scalar::ZERO.into_signed() {
            str.push_str(" + ");
            str.push_str(&input.as_ref()[i].to_string());
            if i > 0 {
                str.push_str(" X^");
                str.push_str(&i.to_string());
            }
        } else if coeff < Scalar::ZERO.into_signed() {
            str.push_str( " - ");
            str.push_str(&input.as_ref()[i].wrapping_neg().to_string());
            if i > 0 {
                str.push_str(" X^");
                str.push_str(&i.to_string());
            }
        }
    }

    str
}
