use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;

#[derive(Clone, Debug, Copy)]
pub struct NtruCMuxParameters {
    name: &'static str,
    polynomial_size: PolynomialSize,
    input_lwe_dimension: LweDimension,
    log_output_modulus: CiphertextModulusLog,
    log_input_modulus: CiphertextModulusLog,
    ntru_std_dev: f64,
    rlwe_std_dev: f64,
    lwe_std_dev: f64,
    br_decomp_base_log: DecompositionBaseLog,
    br_decomp_level_count: DecompositionLevelCount,
    tr_decomp_base_log: DecompositionBaseLog,
    tr_decomp_level_count: DecompositionLevelCount,
    ksk_decomp_base_log: DecompositionBaseLog,
    ksk_decomp_level_count: DecompositionLevelCount,
    ss_decomp_base_log: DecompositionBaseLog,
    ss_decomp_level_count: DecompositionLevelCount,
}

impl NtruCMuxParameters {
    pub fn new(
        name: &'static str,
        polynomial_size: PolynomialSize,
        input_lwe_dimension: LweDimension,
        log_output_modulus: CiphertextModulusLog,
        log_input_modulus: CiphertextModulusLog,
        ntru_std_dev: f64,
        rlwe_std_dev: f64,
        lwe_std_dev: f64,
        br_decomp_base_log: DecompositionBaseLog,
        br_decomp_level_count: DecompositionLevelCount,
        tr_decomp_base_log: DecompositionBaseLog,
        tr_decomp_level_count: DecompositionLevelCount,
        ksk_decomp_base_log: DecompositionBaseLog,
        ksk_decomp_level_count: DecompositionLevelCount,
        ss_decomp_base_log: DecompositionBaseLog,
        ss_decomp_level_count: DecompositionLevelCount,
    ) -> Self {
        Self {
            name,
            polynomial_size,
            input_lwe_dimension,
            log_output_modulus,
            log_input_modulus,
            ntru_std_dev,
            rlwe_std_dev,
            lwe_std_dev,
            br_decomp_base_log,
            br_decomp_level_count,
            tr_decomp_base_log,
            tr_decomp_level_count,
            ksk_decomp_base_log,
            ksk_decomp_level_count,
            ss_decomp_base_log,
            ss_decomp_level_count,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn ntru_std_dev(&self) -> f64 {
        self.ntru_std_dev
    }

    pub fn torus_ntru_std_dev(&self) -> f64 {
        self.ntru_std_dev / 2.0.powi(self.log_output_modulus.0 as i32)
    }

    pub fn rlwe_std_dev(&self) -> f64 {
        self.rlwe_std_dev
    }

    pub fn torus_rlwe_std_dev(&self) -> f64 {
        self.rlwe_std_dev / 2.0.powi(self.log_output_modulus.0 as i32)
    }

    pub fn lwe_std_dev(&self) -> f64 {
        self.lwe_std_dev
    }

    pub fn torus_lwe_std_dev(&self) -> f64 {
        self.lwe_std_dev / 2.0.powi(self.log_input_modulus.0 as i32)
    }

    pub fn log_output_modulus(&self) -> CiphertextModulusLog {
        self.log_output_modulus
    }

    pub fn log_input_modulus(&self) -> CiphertextModulusLog {
        self.log_input_modulus
    }

    pub fn br_decomp_base_log(&self) -> DecompositionBaseLog {
        self.br_decomp_base_log
    }

    pub fn br_decomp_level_count(&self) -> DecompositionLevelCount {
        self.br_decomp_level_count
    }

    pub fn tr_decomp_base_log(&self) -> DecompositionBaseLog {
        self.tr_decomp_base_log
    }

    pub fn tr_decomp_level_count(&self) -> DecompositionLevelCount {
        self.tr_decomp_level_count
    }

    pub fn ksk_decomp_base_log(&self) -> DecompositionBaseLog {
        self.ksk_decomp_base_log
    }

    pub fn ksk_decomp_level_count(&self) -> DecompositionLevelCount {
        self.ksk_decomp_level_count
    }

    pub fn ss_decomp_base_log(&self) -> DecompositionBaseLog {
        self.ss_decomp_base_log
    }

    pub fn ss_decomp_level_count(&self) -> DecompositionLevelCount {
        self.ss_decomp_level_count
    }

    pub fn print_info(&self) {
        println!("================ {} ================", self.name);
        println!(
            "N: {}, Q: 2^{}, ntru std dev: {} ({:.5e} in torus), rlwe std dev: {} ({:.5e} in torus)",
            self.polynomial_size.0,
            self.log_output_modulus.0,
            self.ntru_std_dev,
            self.torus_ntru_std_dev(),
            self.rlwe_std_dev,
            self.torus_rlwe_std_dev(),
        );
        println!(
            "n: {}, q: 2^{}, lwe std dev: {} ({:.5e} in torus)",
            self.input_lwe_dimension.0,
            self.log_input_modulus.0,
            self.lwe_std_dev,
            self.torus_lwe_std_dev(),
        );
        println!("B_br: 2^{}, l_br: {}", self.br_decomp_base_log.0, self.br_decomp_level_count.0);
        println!("B_tr: 2^{}, l_tr: {}", self.tr_decomp_base_log.0, self.tr_decomp_level_count.0);
        println!("B_ksk: 2^{}, l_ksk: {}", self.ksk_decomp_base_log.0, self.ksk_decomp_level_count.0);
        println!("B_ss: 2^{}, l_ss: {}", self.ss_decomp_base_log.0, self.ss_decomp_level_count.0);
        println!();
    }
}

pub const NTRU_CMUX_STD128B2_PRIME: NtruCMuxParameters = NtruCMuxParameters {
    name: "STD128B2'",
    polynomial_size: PolynomialSize(2048),
    log_output_modulus: CiphertextModulusLog(39),
    ntru_std_dev: 2.96,
    rlwe_std_dev: 2.96,
    input_lwe_dimension: LweDimension(571),
    log_input_modulus: CiphertextModulusLog(12),
    lwe_std_dev: 3.19,
    br_decomp_base_log: DecompositionBaseLog(12),
    br_decomp_level_count: DecompositionLevelCount(2),
    tr_decomp_base_log: DecompositionBaseLog(9),
    tr_decomp_level_count: DecompositionLevelCount(4),
    ksk_decomp_base_log: DecompositionBaseLog(8),
    ksk_decomp_level_count: DecompositionLevelCount(5),
    ss_decomp_base_log: DecompositionBaseLog(8),
    ss_decomp_level_count: DecompositionLevelCount(5),
};

pub const NTRU_CMUX_STD128B2: NtruCMuxParameters = NtruCMuxParameters {
    name: "STD128B2",
    polynomial_size: PolynomialSize(2048),
    log_output_modulus: CiphertextModulusLog(45),
    ntru_std_dev: 23.0,
    rlwe_std_dev: 23.0,
    input_lwe_dimension: LweDimension(571),
    log_input_modulus: CiphertextModulusLog(12),
    lwe_std_dev: 3.19,
    br_decomp_base_log: DecompositionBaseLog(13),
    br_decomp_level_count: DecompositionLevelCount(2),
    tr_decomp_base_log: DecompositionBaseLog(9),
    tr_decomp_level_count: DecompositionLevelCount(4),
    ksk_decomp_base_log: DecompositionBaseLog(9),
    ksk_decomp_level_count: DecompositionLevelCount(3),
    ss_decomp_base_log: DecompositionBaseLog(10),
    ss_decomp_level_count: DecompositionLevelCount(3),
};

pub const NTRU_CMUX_STD128B3: NtruCMuxParameters = NtruCMuxParameters {
    name: "STD128B3",
    polynomial_size: PolynomialSize(2048),
    log_output_modulus: CiphertextModulusLog(45),
    ntru_std_dev: 23.0,
    rlwe_std_dev: 23.0,
    input_lwe_dimension: LweDimension(571),
    log_input_modulus: CiphertextModulusLog(12),
    lwe_std_dev: 3.19,
    br_decomp_base_log: DecompositionBaseLog(10),
    br_decomp_level_count: DecompositionLevelCount(3),
    tr_decomp_base_log: DecompositionBaseLog(9),
    tr_decomp_level_count: DecompositionLevelCount(4),
    ksk_decomp_base_log: DecompositionBaseLog(9),
    ksk_decomp_level_count: DecompositionLevelCount(3),
    ss_decomp_base_log: DecompositionBaseLog(10),
    ss_decomp_level_count: DecompositionLevelCount(3),
};
