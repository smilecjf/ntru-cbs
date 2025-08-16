use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::ntru::entities::*;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruKeyswitchKeyCount(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNtruKeyswitchKeyList<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
}

impl<C: Container<Element = c64>> AsRef<[c64]> for FourierNtruKeyswitchKeyList<C> {
    fn as_ref(&self) -> &[c64] {
        self.fourier.data.as_ref()
    }
}

impl<C: ContainerMut<Element = c64>> AsMut<[c64]> for FourierNtruKeyswitchKeyList<C> {
    fn as_mut(&mut self) -> &mut [c64] {
        self.fourier.data.as_mut()
    }
}

pub type FourierNtruKeyswitchKeyListView<'a> = FourierNtruKeyswitchKeyList<&'a [c64]>;
pub type FourierNtruKeyswitchKeyListMutView<'a> = FourierNtruKeyswitchKeyList<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNtruKeyswitchKeyList<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        fft_type: FftType,
    ) -> Self {
        assert!(
            data.container_len() % (
                polynomial_size.to_fourier_polynomial_size().0
                    * decomp_level_count.0
                    * fft_type.num_split()
            ) == 0,
            "The provided container length is not valid. \
            It needs to be divisible by polynomial size * decomp_level_count * fft_type.num_split(). \
            Got container length: {}, polynomial size {:?}, \
            decomposition_level_count: {:?}, fft_type: {:?}.",
            data.container_len(),
            polynomial_size,
            decomp_level_count,
            fft_type,
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            decomp_base_log,
            decomp_level_count,
            fft_type,
        }
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn ciphertext_count(&self) -> FourierNtruKeyswitchKeyCount {
        FourierNtruKeyswitchKeyCount(
            self.fourier.data.container_len() / (
                self.fourier.polynomial_size
                    .to_fourier_polynomial_size().0
                    * self.decomp_level_count.0
            )
        )
    }

    pub fn as_view(&self) -> FourierNtruKeyswitchKeyListView<'_> {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_ref(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierNtruKeyswitchKeyListView {
            fourier,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }

    pub fn as_fourier_ngsw_ciphertext_list(&self) -> FourierNgswCiphertextListView<'_> {
        FourierNgswCiphertextList::from_container(
            self.fourier.data.as_ref(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.fft_type,
        )
    }

    pub fn as_mut_view(&mut self) -> FourierNtruKeyswitchKeyListMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_mut(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierNtruKeyswitchKeyListMutView {
            fourier,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }

    pub fn as_mut_ngsw_ciphertext_list(&mut self) -> FourierNgswCiphertextListMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierNgswCiphertextList::from_container(
            self.fourier.data.as_mut(),
            self.fourier.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
            self.fft_type,
        )
    }
}

type FourierNtruKeyswitchKeyListOwned = FourierNtruKeyswitchKeyList<ABox<[c64]>>;

impl FourierNtruKeyswitchKeyListOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_count: FourierNtruKeyswitchKeyCount,
        fft_type: FftType,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
                * ciphertext_count.0
                * fft_type.num_split()
        ]
        .into_boxed_slice();

        FourierNtruKeyswitchKeyList::from_container(
            boxed,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        )
    }
}

#[derive(Clone, Copy)]
pub struct FourierNtruKeyswitchKeyListCreationMetadata {
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub fft_type: FftType,
}

impl<C: Container<Element = c64>> CreateFrom<C> for FourierNtruKeyswitchKeyList<C> {
    type Metadata = FourierNtruKeyswitchKeyListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let FourierNtruKeyswitchKeyListCreationMetadata {
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type
        } = meta;
        Self::from_container(
            from,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        )
    }
}

impl<C: Container<Element = c64>> ContiguousEntityContainer for FourierNtruKeyswitchKeyList<C> {
    type Element = C::Element;

    type EntityViewMetadata = FourierNtruKeyswitchKeyCreationMetadata;

    type EntityView<'this>
        = FourierNtruKeyswitchKeyView<'this>
    where
        Self: 'this;

    type SelfViewMetadata = FourierNtruKeyswitchKeyListCreationMetadata;

    type SelfView<'this>
        = FourierNtruKeyswitchKeyListView<'this>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        FourierNtruKeyswitchKeyCreationMetadata {
            polynomial_size: self.fourier.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }
    
    fn get_entity_view_pod_size(&self) -> usize {
        self.fourier.polynomial_size.to_fourier_polynomial_size().0
            * self.decomp_level_count.0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        FourierNtruKeyswitchKeyListCreationMetadata {
            polynomial_size: self.fourier.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }
}

impl<C: ContainerMut<Element = c64>> ContiguousEntityContainerMut
    for FourierNtruKeyswitchKeyList<C>
{
    type EntityMutView<'this>
        = FourierNtruKeyswitchKeyMutView<'this>
    where
        Self: 'this;

    type SelfMutView<'this>
        = FourierNtruKeyswitchKeyListMutView<'this>
    where
        Self: 'this;
}
