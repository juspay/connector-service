//! Shared suite helpers for Authorize.Net connector tests.
//!
//! `generated_input_variants()` controls per-test generated iterations and
//! `extract_id()` provides a common identifier extractor used across suites.

use grpc_api_types::payments::{identifier::IdType, Identifier};
use ucs_connector_tests::harness::generators::{
    generate_input_variants as build_input_variants, GeneratedInputVariant,
};

pub mod authorize;
pub mod capture;
pub mod composite;
pub mod create_customer;
pub mod get;
pub mod refund;
pub mod void;

const GENERATED_CASES_PER_SCENARIO: usize = 3;

pub(crate) fn generated_input_variants() -> Vec<GeneratedInputVariant> {
    build_input_variants(GENERATED_CASES_PER_SCENARIO)
}

pub(crate) fn extract_id(identifier: Option<&Identifier>) -> Option<String> {
    identifier
        .and_then(|value| value.id_type.as_ref())
        .and_then(|id_type| match id_type {
            IdType::Id(id) | IdType::EncodedData(id) => Some(id.clone()),
            IdType::NoResponseIdMarker(_) => None,
        })
}
