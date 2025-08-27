#[cfg(test)]
mod test {
    use tfhe::core_crypto::prelude::*;
    use tfhe::ntru::entities::AutomorphismGroup;

    #[test]
    fn automorphism_group_test() {
        let polynomial_size: PolynomialSize = PolynomialSize(2048);

        let automorphism_group = AutomorphismGroup::new(polynomial_size);
        let modulus = 2 * polynomial_size.0;
        let g = automorphism_group.auto_group_generator();

        let mut g_to_l = 1;

        for l in 0..polynomial_size.0/2 {
            let g_to_l_neg = modulus - g_to_l;

            assert_eq!(
                automorphism_group.get_index(g_to_l),
                (l, true),
                "l: {l}, g^l: {g_to_l}, index: {:?}",
                automorphism_group.get_index(g_to_l),
            );
            assert_eq!(
                automorphism_group.get_index(g_to_l_neg),
                (l, false),
                "l: {l}, -g^l: {g_to_l_neg}, index: {:?}",
                automorphism_group.get_index(g_to_l_neg),
            );

            g_to_l = (g_to_l * g) % modulus;
        }
    }
}
