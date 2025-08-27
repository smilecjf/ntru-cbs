use std::marker::PhantomData;

use crate::core_crypto::entities::LweCiphertext;
use crate::core_crypto::prelude::*;
use crate::core_crypto::algorithms::ModulusSwitchedLweCiphertext;

pub fn modulus_switch_lut_many<Scalar: UnsignedInteger>(
    input: Scalar,
    log_modulus: CiphertextModulusLog,
    log_lut_count: LutCountLog,
) -> Scalar {
    assert!(log_modulus.0 <= Scalar::BITS);
    assert!(log_modulus.0 > log_lut_count.0);

    let rounding = Scalar::ONE << (Scalar::BITS - log_modulus.0 + log_lut_count.0 - 1);
    let mut output_to_floor = input.wrapping_add(rounding);

    output_to_floor >>= Scalar::BITS - log_modulus.0 + log_lut_count.0;
    output_to_floor << log_lut_count.0
}

#[derive(Clone, PartialEq, Eq)]
pub struct LazyLutManyModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    C: Container<Element = Scalar>,
{
    lwe_in: LweCiphertext<C>,
    body_correction_to_add_before_switching: Scalar,
    log_modulus: CiphertextModulusLog,
    log_lut_count: LutCountLog,
    // Used to pin SwitchedScalar so that
    // it implements ModulusSwitchedCt<SwitchedScalar> only for SwitchedScalar
    // which helps type inference
    phantom: PhantomData<SwitchedScalar>,
}

impl<Scalar, SwitchedScalar, C> LazyLutManyModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    C: Container<Element = Scalar>,
{
    pub fn into_raw_parts(self) -> (LweCiphertext<C>, Scalar, CiphertextModulusLog, LutCountLog) {
        (
            self.lwe_in,
            self.body_correction_to_add_before_switching,
            self.log_modulus,
            self.log_lut_count,
        )
    }

    pub fn from_raw_parts(
        lwe_in: LweCiphertext<C>,
        body_correction_to_add_before_switching: Scalar,
        log_modulus: CiphertextModulusLog,
        log_lut_count: LutCountLog,
    ) -> Self {
        assert!(log_modulus.0 <= Scalar::BITS);
        assert!(log_modulus.0 > log_lut_count.0);
        assert!(log_modulus.0 <= SwitchedScalar::BITS);

        Self {
            lwe_in,
            body_correction_to_add_before_switching,
            log_modulus,
            log_lut_count,
            phantom: PhantomData,
        }
    }

    pub fn as_view(
        &self
    ) -> LazyLutManyModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, &[Scalar]> {
        LazyLutManyModulusSwitchedLweCiphertext {
            lwe_in: self.lwe_in.as_view(),
            body_correction_to_add_before_switching: self.body_correction_to_add_before_switching,
            log_modulus: self.log_modulus,
            log_lut_count: self.log_lut_count,
            phantom: PhantomData,
        }
    }
}

impl<Scalar, SwitchedScalar, C> ModulusSwitchedLweCiphertext<SwitchedScalar>
    for LazyLutManyModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    C: Container<Element = Scalar>,
{
    fn lwe_dimension(&self) -> LweDimension {
        self.lwe_in.lwe_size().to_lwe_dimension()
    }

    fn body(&self) -> SwitchedScalar {
        modulus_switch_lut_many(
            (*self.lwe_in.get_body().data)
                .wrapping_add(self.body_correction_to_add_before_switching),
            self.log_modulus,
            self.log_lut_count
        )
        .cast_into()
    }

    fn mask(&self) -> impl Iterator<Item = SwitchedScalar> {
        self.lwe_in
            .as_ref()
            .split_last()
            .unwrap()
            .1
            .iter()
            .map(|i| modulus_switch_lut_many(*i, self.log_modulus, self.log_lut_count).cast_into())
    }

    fn log_modulus(&self) -> CiphertextModulusLog {
        self.log_modulus
    }
}
