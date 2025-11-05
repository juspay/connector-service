// Payu Connector Implementation

use std::fmt::Debug;

use serde::Serialize;
use common_enums::Currency;
use domain_types::router_data_v2::RouterDataV2;
use hyperswitch_masking::Secret;

pub mod constants;
pub mod transformers;

pub use transformers::*;

#[derive(Debug, Clone)]
pub struct Payu<T> {
    pub base_url: Secret<String>,
    pub connector_name: String,
    pub _phantom: std::marker::PhantomData<T>,
}

impl<T> Payu<T> {
    pub fn new(base_url: Secret<String>) -> Self {
        Self {
            base_url,
            connector_name: "payu".to_string(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn base_url(&self, _connector: &domain_types::types::Connectors) -> String {
        self.base_url.expose().clone()
    }
}