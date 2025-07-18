use rand::Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
use tfhe::ntru::algorithms::polynomial_for_ntru::*;

mod util;
use util::polynomial_to_string_mod_power_of_two;

type Scalar = u32;

pub fn main() {
    let polynomial_size = PolynomialSize(2048);
    let power = 16;
    let modulus = Scalar::ONE << power;

    let mut x = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut y = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut z = Polynomial::new(Scalar::ZERO, polynomial_size);

    let num_test = 1000;
    let mut ctr = 0;

    for idx in 0..num_test {
        println!("======== Test {} ========", idx + 1);

        for coeff in x.as_mut().iter_mut() {
            *coeff = rand::thread_rng().gen_range(0..modulus);
        }

        if polynomial_size.0 <= 16 {
            println!("x: {:}", polynomial_to_string_mod_power_of_two(&x, power));
        }

        // let invertible = almost_inverse_mod_2(&x, &mut y);
        let invertible = polynomial_inverse_mod_power_of_two(&x, &mut y, power);

        if invertible {
            if polynomial_size.0 <= 16 {
                println!("y: {:}", polynomial_to_string_mod_power_of_two(&y, 1));
            }

            polynomial_wrapping_mul(&mut z, &x, &y);
            polynomial_wrapping_custom_mod_assign(&mut z, modulus);
            assert!(is_polynomial_one(&z));
            println!("Invertible");

            ctr += 1;
        } else {
            println!("Not invertible");
        }

        println!();
    }

    println!("# invertible: {ctr} ({} %)", (ctr as f64) / (num_test as f64) * 100f64);
}