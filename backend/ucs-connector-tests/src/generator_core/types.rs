//! Core types for the scenario generator

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A single scenario definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    /// Request body template with field values or placeholders
    pub req_body: Value,
    /// Assertions to validate for this scenario
    pub assertions: Assertions,
    /// Services this scenario depends on
    pub depends_on: Vec<String>,
}

/// Assertion configuration for a scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertions {
    /// Expected status values
    pub status: Vec<String>,
    /// Error expectation
    pub error: String,
    /// Fields that must exist in response
    #[serde(default)]
    pub must_exist: Vec<String>,
}

/// The complete spec loaded from generator_specs.json
#[derive(Debug, Clone, Deserialize)]
pub struct GeneratorSpec {
    pub suite: String,
    pub rpc: String,
    pub success: Assertions,
    pub groups: BTreeMap<String, Group>,
}

/// A group containing related fields
#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    pub fields: BTreeMap<String, FieldSpec>,
}

/// Specification for a single field
#[derive(Debug, Clone, Deserialize)]
pub struct FieldSpec {
    pub source: String,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub variants: Option<Variants>,
    #[serde(default)]
    pub assertions: Option<BTreeMap<String, FieldAssertion>>,
    #[serde(default)]
    pub suite: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
}

/// Variants specification (can be array or object with field)
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Variants {
    SimpleArray(Vec<String>),
    WithField { field: String, values: Vec<String> },
}

impl Variants {
    pub fn values(&self) -> &[String] {
        match self {
            Variants::SimpleArray(values) => values,
            Variants::WithField { values, .. } => values,
        }
    }

    pub fn field_name(&self) -> Option<&str> {
        match self {
            Variants::SimpleArray(_) => None,
            Variants::WithField { field, .. } => Some(field),
        }
    }
}

/// Assertion for a specific variant value
#[derive(Debug, Clone, Deserialize)]
pub struct FieldAssertion {
    pub status: Vec<String>,
}

/// Payment methods data loaded from payment_methods.json
pub type PaymentMethodsData = BTreeMap<String, Value>;

/// Error type for generator operations
#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("failed to read spec file: {0}")]
    SpecRead(String),
    #[error("failed to parse spec: {0}")]
    SpecParse(String),
    #[error("failed to read payment methods: {0}")]
    PaymentMethodsRead(String),
    #[error("suite not found: {0}")]
    SuiteNotFound(String),
    #[error("group not found: {0}")]
    GroupNotFound(String),
    #[error("invalid field source: {0}")]
    InvalidSource(String),
}
