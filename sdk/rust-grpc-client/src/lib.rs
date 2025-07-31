//! Pre-compiled gRPC client for Connector Service
//! 
//! This crate provides a type-safe client for interacting with the Connector Service.
//! All code is pre-generated, no build-time proto compilation needed.

#![allow(clippy::large_enum_variant)]
#![allow(clippy::derive_partial_eq_without_eq)]

pub mod gen;

// Re-export commonly used types
pub use gen::payments::*;
pub use gen::health_check::*;

// Re-export tonic for convenience
pub use tonic;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::gen::payments::payment_service_client::PaymentServiceClient;
    pub use crate::gen::payments::refund_service_client::RefundServiceClient;
    pub use crate::gen::payments::dispute_service_client::DisputeServiceClient;
    pub use crate::gen::health_check::health_client::HealthClient;  
    pub use tonic::transport::{Channel, Endpoint};
}
