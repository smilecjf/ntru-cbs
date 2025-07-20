use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::prelude::polynomial_algorithms::*;
use tfhe::ntru::algorithms::*;

mod utils;
use utils::polynomial_to_string_native_mod;

type Scalar = u32;

pub fn main() {
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
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
            println!("sk   : {}", polynomial_to_string_native_mod(&f));
            println!("sk^-1: {}", polynomial_to_string_native_mod(&f_inv));
        }

        polynomial_wrapping_mul(&mut buf, &f, &f_inv);
        // polynomial_wrapping_custom_mod_assign(&mut buf, modulus);

        assert!(is_polynomial_one(&buf));
        println!("Correctly generated");
        println!();
    }
}