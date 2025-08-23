use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::ntru::entities::*;

use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNgswCiphertextCount(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierNgswCiphertextList<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    fft_type: FftType,
}

impl<C: Container<Element = c64>> AsRef<[c64]> for FourierNgswCiphertextList<C> {
    fn as_ref(&self) -> &[c64] {
        self.fourier.data.as_ref()
    }
}

impl<C: ContainerMut<Element = c64>> AsMut<[c64]> for FourierNgswCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [c64] {
        self.fourier.data.as_mut()
    }
}

pub type FourierNgswCiphertextListView<'a> = FourierNgswCiphertextList<&'a [c64]>;
pub type FourierNgswCiphertextListMutView<'a> = FourierNgswCiphertextList<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierNgswCiphertextList<C> {
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
            decomp_level_count: {:?}, fft_type: {:?}.",
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

    pub fn ciphertext_count(&self) -> FourierNgswCiphertextCount {
        FourierNgswCiphertextCount(
            self.fourier.data.container_len() / (
                self.fourier.polynomial_size
                    .to_fourier_polynomial_size().0
                    * self.decomp_level_count.0
                    * self.fft_type.num_split()
            )
        )
    }

    pub fn as_view(&self) -> FourierNgswCiphertextListView<'_> {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_ref(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierNgswCiphertextListView {
            fourier,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierNgswCiphertextListMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_mut(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierNgswCiphertextListMutView {
            fourier,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }
}

type FourierNgswCiphertextListOwned = FourierNgswCiphertextList<ABox<[c64]>>;

impl FourierNgswCiphertextListOwned {
    pub fn new(
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_count: FourierNgswCiphertextCount,
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

        FourierNgswCiphertextList::from_container(
            boxed,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            fft_type,
        )
    }
}

#[derive(Clone, Copy)]
pub struct FourierNgswCiphertextListCreationMetadata {
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub fft_type: FftType,
}

impl<C: Container<Element = c64>> CreateFrom<C> for FourierNgswCiphertextList<C> {
    type Metadata = FourierNgswCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let FourierNgswCiphertextListCreationMetadata {
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

impl<C: Container<Element = c64>> ContiguousEntityContainer for FourierNgswCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = FourierNgswCiphertextCreationMetadata;

    type EntityView<'this>
        = FourierNgswCiphertextView<'this>
    where
        Self: 'this;

    type SelfViewMetadata = FourierNgswCiphertextListCreationMetadata;

    type SelfView<'this>
        = FourierNgswCiphertextListView<'this>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        FourierNgswCiphertextCreationMetadata {
            polynomial_size: self.fourier.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            fft_type: self.fft_type,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.fourier.polynomial_size.to_fourier_polynomial_size().0
            * self.decomp_level_count.0
            * self.fft_type.num_split()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        FourierNgswCiphertextListCreationMetadata {
            polynomial_size: self.fourier.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            fft_type: self.fft_type,
        }
    }
}

impl<C: ContainerMut<Element = c64>> ContiguousEntityContainerMut
    for FourierNgswCiphertextList<C>
{
    type EntityMutView<'this>
        = FourierNgswCiphertextMutView<'this>
    where
        Self: 'this;

    type SelfMutView<'this>
        = FourierNgswCiphertextListMutView<'this>
    where
        Self: 'this;
}
