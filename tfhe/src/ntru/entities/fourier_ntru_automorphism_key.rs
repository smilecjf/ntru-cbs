use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::ntru::entities::*;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruAutomorphismKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    automorphism_index: AutomorphismIndex,
    decomp_base_log: DecompositionBaseLog,
    fft_type: FftType,
}

pub type FourierNtruAutomorphismKeyView<'a> = FourierNtruAutomorphismKey<&'a [c64]>;
pub type FourierNtruAutomorphismKeyMutView<'a> = FourierNtruAutomorphismKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNtruAutomorphismKey<C> {
    pub fn from_container(
        data: C,
        automorphism_index: AutomorphismIndex,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        fft_type: FftType,
    ) -> Self {
        assert!(
            data.container_len() % (
                polynomial_size.to_fourier_polynomial_size().0
                    * fft_type.num_split()
            ) == 0,
            "The provided container length is not valid. \
            It needs to be divisible by polynomial size * fft_type.num_split(). \
            Got container length: {}, polynomial size {:?}, fft_type: {:?}.",
            data.container_len(),
            polynomial_size,
            fft_type,
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            automorphism_index,
            decomp_base_log,
            fft_type,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn automorphism_index(&self) -> AutomorphismIndex {
        self.automorphism_index
    }

    pub(crate) fn set_automorphism_index(&mut self, index: AutomorphismIndex) {
        self.automorphism_index = index;
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(
            self.fourier.data.container_len() / (
                self.fourier.polynomial_size
                    .to_fourier_polynomial_size().0
                    * self.fft_type.num_split()
            )
        )
    }

    pub fn fft_type(&self) -> FftType {
        self.fft_type
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierNtruAutomorphismKeyView<'_>
    where
        C: AsRef<[c64]>
    {
        FourierNtruAutomorphismKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            automorphism_index: self.automorphism_index,
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }

    pub fn as_fourier_ngsw_ciphertext(&self) -> FourierNgswCiphertextView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierNgswCiphertext::from_container(
            self.fourier.data.as_ref(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
    }

    pub fn as_fourier_ntru_keyswitch_key(&self) -> FourierNtruKeyswitchKeyView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierNtruKeyswitchKey::from_container(
            self.fourier.data.as_ref(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
    }

    pub fn as_mut_view(&mut self) -> FourierNtruAutomorphismKeyMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNtruAutomorphismKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            automorphism_index: self.automorphism_index,
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }

    pub fn as_mut_fourier_ngsw_ciphertext(&mut self) -> FourierNgswCiphertextMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNgswCiphertext::from_container(
            self.fourier.data.as_mut(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.fft_type,
        )
    }
}

type FourierNtruAutomorphismKeyOwned = FourierNtruAutomorphismKey<ABox<[c64]>>;

impl FourierNtruAutomorphismKeyOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        fft_type: FftType,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
                * fft_type.num_split()
        ]
        .into_boxed_slice();

        FourierNtruAutomorphismKey::from_container(
            boxed,
            AutomorphismIndex(0),
            polynomial_size,
            decomp_base_log,
            fft_type,
        )
    }
}

#[derive(Clone, Copy)]
pub struct FourierNtruAutomorphismKeyCreationMetadata {
    pub polynomial_size: PolynomialSize,
    pub automorphism_index: AutomorphismIndex,
    pub decomp_base_log: DecompositionBaseLog,
    pub fft_type: FftType,
}

impl<C: Container<Element = c64>> CreateFrom<C> for FourierNtruAutomorphismKey<C> {
    type Metadata = FourierNtruAutomorphismKeyCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let FourierNtruAutomorphismKeyCreationMetadata {
            polynomial_size,
            automorphism_index,
            decomp_base_log,
            fft_type,
        } = meta;
        Self::from_container(
            from,
            automorphism_index,
            polynomial_size,
            decomp_base_log,
            fft_type,
        )
    }
}
