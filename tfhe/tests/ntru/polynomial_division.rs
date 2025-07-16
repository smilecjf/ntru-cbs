use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
use tfhe::core_crypto::algorithms::polynomial_for_ntru::*;
mod util;
use util::polynomial_to_string_mod_power_of_two;

pub fn main() {
    type Scalar = u64;
    let polynomial_size = PolynomialSize(16);
    let mut a = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut b = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut q = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut r = Polynomial::new(Scalar::ZERO, polynomial_size);

    let power = 8usize;
    let num_test= 1000;
    let modulus = Scalar::ONE << power;

    for i in 0..num_test {
        println!("======== Test {} ========", i + 1);

        for i in 0..polynomial_size.0 {
            a.as_mut()[i] = rand::thread_rng().gen_range(0..(1 << power));
        }
        for i in 0..polynomial_size.0/2 {
            b.as_mut()[i] = rand::thread_rng().gen_range(0..(1 << power));
        }

        let is_divided = polynomial_div_mod_power_of_two(&a, &b, &mut q, &mut r, power);
        if is_divided {
            println!("Divisible");
        } else {
            println!("Not divisible");
        }

        println!("a: {:}", polynomial_to_string_mod_power_of_two(&a, power));
        println!("b: {:}", polynomial_to_string_mod_power_of_two(&b, power));
        println!("q: {:}", polynomial_to_string_mod_power_of_two(&q, power));
        println!("r: {:}", polynomial_to_string_mod_power_of_two(&r, power));

        let mut test = Polynomial::new(Scalar::ZERO, polynomial_size);
        polynomial_wrapping_mul(&mut test, &b, &q);
        polynomial_wrapping_custom_mod_assign(&mut test, modulus);
        polynomial_wrapping_add_assign_custom_mod(&mut test, &r, modulus);
        polynomial_wrapping_sub_assign_custom_mod(&mut test, &a, modulus);
        if !is_polynomial_zero(&test) {
            println!("Incorrect division");
            return;
        } else {
            println!("Correct division");
        }

    println!();
    }
}
