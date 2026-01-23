//! Default implementations for optional connector traits
//!
//! This file provides empty implementations for traits that are required by `ConnectorServiceTrait`
//! but not all connectors need to implement. Connectors that need specific implementations can
//! override these by implementing the trait in their own file (Rust will use the more specific impl).
//!
//! Pattern: When adding a new connector, add it to the macro invocation list below.
//! If a connector needs a real implementation, add it in the connector's own file.
//!
//! Note: The macro uses types from the invocation site (connectors.rs), not from this file.
//! The imports here are not used - they're just for documentation.

/// Macro to generate empty implementations of VerifyWebhookSourceV2 for connectors
/// that don't need external webhook verification.
///
/// Usage: When a new connector is added, add it to the macro invocation.
/// If a connector needs real implementation (like PayPal), implement it in the connector's file
/// and it will override this empty impl.
macro_rules! default_impl_verify_webhook_source_v2 {
    ($($connector:ident),*) => {
        $(
            impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
                VerifyWebhookSourceV2 for $connector<T>
            {
            }

            impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
                ConnectorIntegrationV2<
                    VerifyWebhookSource,
                    VerifyWebhookSourceFlowData,
                    VerifyWebhookSourceRequestData,
                    VerifyWebhookSourceResponseData,
                > for $connector<T>
            {
            }

            impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
                SourceVerification<
                    VerifyWebhookSource,
                    VerifyWebhookSourceFlowData,
                    VerifyWebhookSourceRequestData,
                    VerifyWebhookSourceResponseData,
                > for $connector<T>
            {
            }
        )*
    };
}

// Export the macro so it can be used in connectors.rs
pub(crate) use default_impl_verify_webhook_source_v2;
