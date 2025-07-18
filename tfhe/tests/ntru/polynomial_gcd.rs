use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
use tfhe::ntru::algorithms::polynomial_for_ntru::*;
mod util;
use util::polynomial_to_string_mod_power_of_two;

pub fn main() {
    type Scalar = u64;
    let polynomial_size = PolynomialSize(16);
    let mut a = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut b = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut q = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut r = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);

    let power = 8usize;
    let modulus = Scalar::ONE << power;

    let num_test = 10000;
    for i in 0..num_test {
        println!("======== Test {} ========", i + 1);
        for i in 0..polynomial_size.0 {
            a.as_mut()[i] = rand::thread_rng().gen_range(0..2);
        }
        for i in 0..polynomial_size.0 {
            b.as_mut()[i] = rand::thread_rng().gen_range(0..2);
        }

        println!("a: {:}", polynomial_to_string_mod_power_of_two(&a, power));
        println!("b: {:}", polynomial_to_string_mod_power_of_two(&b, power));

        let (mut g, x, y, is_gcd) = egcd_polynomial_mod_power_of_two(&a, &b, power);

        println!("g: {:}", polynomial_to_string_mod_power_of_two(&g, power));
        println!("x: {:}", polynomial_to_string_mod_power_of_two(&x, power));
        println!("y: {:}", polynomial_to_string_mod_power_of_two(&y, power));


        if is_gcd {
            let is_divided = polynomial_div_mod_power_of_two(&a, &g, &mut q, &mut r, power);
            if !is_divided || !is_polynomial_zero(&r) {
                println!("a is not divided by g");
                return;
            }

            let is_divided = polynomial_div_mod_power_of_two(&b, &g, &mut q, &mut r, power);
            if !is_divided || !is_polynomial_zero(&r) {
                println!("b is not divided by g");
                return;
            }
        } else {
            println!("g is not gcd");
        }

        polynomial_wrapping_mul(&mut buf, &a, &x);
        polynomial_wrapping_custom_mod_assign(&mut buf, modulus);
        polynomial_wrapping_sub_assign_custom_mod(&mut g, &buf, modulus);
        polynomial_wrapping_mul(&mut buf, &b, &y);
        polynomial_wrapping_custom_mod_assign(&mut buf, modulus);
        polynomial_wrapping_sub_assign_custom_mod(&mut g, &buf, modulus);

        if !is_polynomial_zero(&g) {
            println!("a * x + b * y != g");
            return;
        }

        if is_gcd && is_polynomial_one(&g) {
            return;
        }

        println!();
    }
}
