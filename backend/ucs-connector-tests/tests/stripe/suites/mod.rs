use ucs_connector_tests::harness::generators::{
    generate_input_variants as build_input_variants, GeneratedInputVariant,
};

pub mod authorize;
pub mod capture;
pub mod get;
pub mod refund;
pub mod void;

const GENERATED_CASES_PER_SCENARIO: usize = 2;

pub(crate) fn generated_input_variants() -> Vec<GeneratedInputVariant> {
    build_input_variants(GENERATED_CASES_PER_SCENARIO)
}
