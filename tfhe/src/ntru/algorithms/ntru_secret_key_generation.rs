use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::ntru::algorithms::polynomial_inverse_mod_power_of_two;
use crate::ntru::entities::*;

pub fn allocate_and_generate_new_binary_ntru_secret_key<Scalar, Gen>(
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut SecretRandomGenerator<Gen>,
) -> NtruSecretKeyOwned<Scalar>
where
    Scalar: UnsignedInteger + RandomGenerable<UniformBinary>,
    Gen: ByteRandomGenerator,
{
    let mut ntru_secret_key =
        NtruSecretKeyOwned::new_empty_key(Scalar::ZERO, polynomial_size, ciphertext_modulus);

    generate_binary_ntru_secret_key(&mut ntru_secret_key, ciphertext_modulus, generator);

    ntru_secret_key
}

pub fn generate_binary_ntru_secret_key<Scalar, KeyCont, Gen>(
    ntru_secret_key: &mut NtruSecretKey<KeyCont>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedInteger + RandomGenerable<UniformBinary>,
    KeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    // Currently only suuports power-of-two modulus
    assert!(
        ciphertext_modulus.is_compatible_with_native_modulus(),
        "Only supports power-of-two modulus currently"
    );
    let power = ciphertext_modulus.into_modulus_log().0;

    let polynomial_size = ntru_secret_key.polynomial_size();
    let mut is_invertible = false;

    while !is_invertible {
        let mut f = Polynomial::new(Scalar::ZERO, polynomial_size);
        let mut f_inv = Polynomial::new(Scalar::ZERO, polynomial_size);

        generator.fill_slice_with_random_uniform_binary(f.as_mut());

        is_invertible = polynomial_inverse_mod_power_of_two(&f, &mut f_inv, power);

        for i in 0..polynomial_size.0 {
            ntru_secret_key.as_mut()[i] = f.as_ref()[i];
            ntru_secret_key.as_mut()[i + polynomial_size.0] = f_inv.as_ref()[i];
        }
    }
}