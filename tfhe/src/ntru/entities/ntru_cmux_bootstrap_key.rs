//! Module containing the definition of the NtruCMuxBootstrapKey.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::ntru::entities::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtruCMuxBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    ngsw_list: NgswCiphertextList<C>,
    ntru_switching_key: NtruSwitchingKey<C>,
}

pub type NtruCMuxBootstrapKeyView<'data, Scalar> = NtruCMuxBootstrapKey<&'data [Scalar]>;
pub type NtruCMuxBootstrapKeyMutView<'data, Scalar> = NtruCMuxBootstrapKey<&'data mut [Scalar]>;
pub type NtruCMuxBootstrapKeyOwned<Scalar> = NtruCMuxBootstrapKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NtruCMuxBootstrapKey<C> {
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.ngsw_list.ngsw_ciphertext_count().0)
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.ngsw_list.polynomial_size().0)
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.ngsw_list.polynomial_size()
    }

    pub fn get_ngsw_list(&self) -> NgswCiphertextListView<'_, Scalar> {
        self.ngsw_list.as_view()
    }

    pub fn get_ntru_switching_key(&self) -> NtruSwitchingKeyView<'_, Scalar> {
        self.ntru_switching_key.as_view()
    }

    pub fn as_view(&self) -> NtruCMuxBootstrapKeyView<'_, Scalar> {
        NtruCMuxBootstrapKeyView::<'_, Scalar> {
            ngsw_list: self.ngsw_list.as_view(),
            ntru_switching_key: self.ntru_switching_key.as_view(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NtruCMuxBootstrapKey<C> {
    pub fn get_mut_ngsw_list(&mut self) -> NgswCiphertextListMutView<'_, Scalar> {
        self.ngsw_list.as_mut_view()
    }

    pub fn get_mut_ntru_switching_key(&mut self) -> NtruSwitchingKeyMutView<'_, Scalar> {
        self.ntru_switching_key.as_mut_view()
    }

    pub fn get_mut_view(&mut self) -> NtruCMuxBootstrapKeyMutView<'_, Scalar> {
        NtruCMuxBootstrapKeyMutView::<'_, Scalar> {
            ngsw_list: self.ngsw_list.as_mut_view(),
            ntru_switching_key: self.ntru_switching_key.as_mut_view(),
        }
    }
}

impl<Scalar: UnsignedInteger> NtruCMuxBootstrapKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        br_decomp_base_log: DecompositionBaseLog,
        br_decomp_level_count: DecompositionLevelCount,
        swk_decomp_base_log: DecompositionBaseLog,
        swk_decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            ngsw_list: NgswCiphertextList::new(
                fill_with,
                polynomial_size,
                br_decomp_base_log,
                br_decomp_level_count,
                NgswCiphertextCount(input_lwe_dimension.0),
                ciphertext_modulus,
            ),
            ntru_switching_key: NtruSwitchingKey::new(
                fill_with,
                polynomial_size,
                swk_decomp_base_log,
                swk_decomp_level_count,
                ciphertext_modulus,
            ),
        }
    }
}
