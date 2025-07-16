use rand::Rng;
use tfhe::core_crypto::prelude::{polynomial_for_ntru::{div_mod_power_of_two, egcd}, UnsignedInteger};

pub fn gcd_test<Scalar>(a: Scalar, b: Scalar) -> Scalar
where
    Scalar: UnsignedInteger
{
    if b == Scalar::ZERO {
        return a;
    }

    return gcd_test(b, a % b);
}

pub fn main() {
    let num_test = 10000;
    let log_mod = 32usize;
    let mut ctr = 0;

    for i in 0..num_test {
        println!("==== Test {i:} ====");
        let a: u64 = rand::thread_rng().gen_range(0..(1 << log_mod));
        let b: u64 = rand::thread_rng().gen_range(0..(1 << log_mod));
        println!("a = {a:}, b = {b:}");

        let (g, x, y) = egcd(a, b);
        let g_test = gcd_test(a, b);

        println!("g = {g:}, x = {x:}, y = {y:}");

        if g != g_test {
            println!("Wrong!");
            return;
        }

        if (a as i128) * x + (b as i128) * y != (g as i128) {
            println!("Wrong!");
            return;
        }

        let a_div_b = div_mod_power_of_two(a, b, log_mod);
        if a_div_b == 0 {
            println!("a is not divisible by b");
        } else {
            println!("a / b mod 2^{log_mod:} = {a_div_b:}");
            assert!((b * a_div_b) % (1 << log_mod) == a);
            ctr += 1;
        }

        println!();
    }

    println!("# divisible: {ctr} ({} %)", (ctr as f64 / num_test as f64) * 100f64);
}
