use crate::core_crypto::prelude::*;
use crate::ntru::entities::*;

pub fn lwe_ciphertext_modulus_switch_lut_many<Scalar, SwitchedScalar, Cont>(
    lwe_in: LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
    log_lut_count: LutCountLog,
) -> LazyLutManyModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, Cont>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
{
    LazyLutManyModulusSwitchedLweCiphertext::from_raw_parts(
        lwe_in,
        Scalar::ZERO,
        log_modulus,
        log_lut_count,
    )
}
