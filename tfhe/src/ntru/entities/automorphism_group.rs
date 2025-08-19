use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;

pub(crate) const AUTO_GROUP_GENERATOR: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomorphismGroup {
    // index_set[i] = [l, true] implies that (2 * i) + 1 = g^l (mod 2N), and
    // index_set[i] = [l, false] implies that (2 * i) + 1 = -g^l (mod 2N)
    // where N = polynomial_size and g = auto_group_generator
    polynomial_size: PolynomialSize,
    index_set: Vec<(usize, bool)>,
    auto_group_generator: usize,
}

impl AutomorphismGroup {
    pub fn new(
        polynomial_size: PolynomialSize,
    ) -> Self {
        let mut index_set = vec![(0, true); polynomial_size.0];

        let modulus = 2 * polynomial_size.0;
        let mut a = 1;

        for i in 0..polynomial_size.0/2 {
            let index_pos = (a - 1) / 2;
            let index_neg = (modulus - a - 1) / 2;
            index_set[index_pos] = (i, true);
            index_set[index_neg] = (i, false);

            a = (a * AUTO_GROUP_GENERATOR) % modulus;
        }

        Self {
            polynomial_size,
            index_set,
            auto_group_generator: AUTO_GROUP_GENERATOR,
        }
    }

    pub fn get_index(&self, a: usize) -> (usize, bool) {
        assert!(
            a % 2 == 1 && a < 2 * self.polynomial_size.0,
            "[AutomorphismGroup] get_index input should be odd and smaller than 2N. \
            Got {a} as an input, and N is {}.",
            // a < self.polynomial_size.0,
            // "[AutomorphismGroup] get_index input should be smaller than N. \
            // Got {a} as an input, and N is {}.",
            self.polynomial_size.0,
        );

        self.index_set[(a - 1) / 2]
    }

    pub fn group_generator(&self) -> usize {
        self.auto_group_generator
    }

    pub fn get_lwe_index_set<C: Container>(&self, input_lwe: &LweCiphertext<C>)
    -> (Vec<Vec<usize>>, Vec<Vec<usize>>)
    where
        C::Element: UnsignedInteger + CastInto<usize>,
    {
        let mut lwe_index_set_pos = vec![vec![]; self.polynomial_size.0/2];
        let mut lwe_index_set_neg = vec![vec![]; self.polynomial_size.0/2];

        let lwe_mask = input_lwe.get_mask();

        let log_delta_ms = C::Element::BITS - self.polynomial_size.0.ilog2() as usize;
        let delta_ms = 1usize << log_delta_ms;
        // let delta_ms = C::Element::ONE << log_delta_ms;

        for (i, elem) in lwe_mask.as_ref().iter().enumerate() {
            // Modulus switch to N
            let elem:usize = (*elem).cast_into();
            let rounding = (elem & (delta_ms >> 1)) << 1;
            let elem = (elem.wrapping_add(rounding) << (usize::BITS as usize - C::Element::BITS)) >> (usize::BITS - self.polynomial_size.0.ilog2()) as usize;


            // Check with odd input mod 2N
            let (index, is_pos) = self.get_index(2 * elem + 1);
            if is_pos {
                lwe_index_set_pos[index].push(i);
            } else {
                lwe_index_set_neg[index].push(i);
            }
        }

        (lwe_index_set_pos, lwe_index_set_neg)
    }
}
