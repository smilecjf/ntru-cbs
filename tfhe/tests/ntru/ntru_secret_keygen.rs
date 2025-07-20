use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::prelude::polynomial_algorithms::*;
use tfhe::ntru::algorithms::*;

mod util;
use util::polynomial_to_string_mod_power_of_two;

type Scalar = u32;

pub fn main() {
    let power=  16usize;
    let modulus = Scalar::ONE << power;
    let ciphertext_modulus = CiphertextModulus::try_new_power_of_2(power).unwrap();
    let polynomial_size = PolynomialSize(2048);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let num_test = 1000;
    let mut buf = Polynomial::new(Scalar::ZERO, polynomial_size);

    for idx in 1..=num_test {
        println!("======== Test {idx} ========");
        let ntru_secret_key = allocate_and_generate_new_binary_ntru_secret_key(polynomial_size, ciphertext_modulus, &mut secret_generator);

        let (f, f_inv) = ntru_secret_key.get_secret_key_and_inverse_polynomial();

        if polynomial_size.0 <= 16 {
            println!("sk   : {}", polynomial_to_string_mod_power_of_two(&f, power));
            println!("sk^-1: {}", polynomial_to_string_mod_power_of_two(&f_inv, power));
        }

        polynomial_wrapping_mul(&mut buf, &f, &f_inv);
        polynomial_wrapping_custom_mod_assign(&mut buf, modulus);

        assert!(is_polynomial_one(&buf));
        println!("Correctly generated");
        println!();
    }
}