//! Default implementations for optional connector traits
//!
//! This file provides empty implementations for traits that are required by `ConnectorServiceTrait`
//! but not all connectors need to implement. Connectors that need specific implementations can
//! override these by implementing the trait in their own file (Rust will use the more specific impl).
//!
//! Pattern: When adding a new connector, add it to the macro invocation list below.
//! If a connector needs a real implementation, add it in the connector's own file.

use crate::connectors::*;
use domain_types::{
    connector_flow::{InitiateTopup, VerifyWebhookSource},
    connector_types::{
        InitiateTopupData, InitiateTopupResponseData, VerifyWebhookSourceFlowData, WalletFlowData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_request_types::VerifyWebhookSourceRequestData,
    router_response_types::VerifyWebhookSourceResponseData,
};
use interfaces::connector_integration_v2::ConnectorIntegrationV2;
use interfaces::connector_types::VerifyWebhookSourceV2;

/// Macro to generate empty implementations of VerifyWebhookSourceV2 for connectors
/// that don't need external webhook verification.
///
/// Usage: When a new connector is added, add it to the macro invocation below.
/// If a connector needs real implementation (like PayPal), implement it in the connector's file
/// and it will override this empty impl.
#[macro_export]
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
        )*
    };
}

// Generate default implementations for all connectors that don't have custom implementations
// Connectors with real implementations (like PayPal) will override these
default_impl_verify_webhook_source_v2!(
    Adyen,
    Aci,
    Airwallex,
    Authipay,
    Authorizedotnet,
    Bambora,
    Bamboraapac,
    Bankofamerica,
    Barclaycard,
    Billwerk,
    Bluesnap,
    Braintree,
    Calida,
    Cashfree,
    Cashtocode,
    Celero,
    Checkout,
    Cryptopay,
    Cybersource,
    Datatrans,
    Dlocal,
    Elavon,
    Fiserv,
    Fiservcommercehub,
    Fiservemea,
    Fiuu,
    Forte,
    Getnet,
    Gigadat,
    Globalpay,
    Helcim,
    Hipay,
    Hyperpg,
    Iatapay,
    Jpmorgan,
    Loonio,
    Mifinity,
    Mollie,
    Multisafepay,
    Nexinets,
    Nexixpay,
    Nmi,
    Noon,
    Novalnet,
    Nuvei,
    Paybox,
    Payload,
    Payme,
    Paysafe,
    Paytm,
    Payu,
    Phonepe,
    Placetopay,
    Powertranz,
    Rapyd,
    Razorpay,
    RazorpayV2,
    Redsys,
    Revolut,
    Revolv3,
    Finix,
    Shift4,
    Silverflow,
    Stax,
    Stripe,
    Trustpay,
    Trustpayments,
    Tsys,
    Volt,
    Wellsfargo,
    Worldpay,
    Worldpayvantiv,
    Worldpayxml,
    Xendit,
    Zift,
    Ppro
);
// PayPal has its own implementation in paypal.rs

/// Macro to generate empty implementations of InitiateTopupV2 for connectors
/// that don't support the InitiateTopup wallet flow.
///
/// Usage: When a new connector is added, add it to the macro invocation below.
/// If a connector needs a real implementation (like PhonePe), implement it in the connector's
/// own file instead.
#[macro_export]
macro_rules! default_impl_initiate_topup {
    ($($connector:ident),*) => {
        $(
            impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
                ConnectorIntegrationV2<
                    InitiateTopup,
                    WalletFlowData,
                    InitiateTopupData,
                    InitiateTopupResponseData,
                > for $connector<T>
            {
            }
        )*
    };
}

// Generate default (no-op) InitiateTopup implementations for all connectors
// PhonePe has its own real implementation in phonepe.rs
default_impl_initiate_topup!(
    Adyen,
    Aci,
    Airwallex,
    Authipay,
    Authorizedotnet,
    Bambora,
    Bamboraapac,
    Bankofamerica,
    Barclaycard,
    Billwerk,
    Bluesnap,
    Braintree,
    Calida,
    Cashfree,
    Cashtocode,
    Celero,
    Checkout,
    Cryptopay,
    Cybersource,
    Datatrans,
    Dlocal,
    Elavon,
    Fiserv,
    Fiservcommercehub,
    Fiservemea,
    Fiuu,
    Forte,
    Getnet,
    Gigadat,
    Globalpay,
    Helcim,
    Hipay,
    Hyperpg,
    Iatapay,
    Jpmorgan,
    Loonio,
    Mifinity,
    Mollie,
    Multisafepay,
    Nexinets,
    Nexixpay,
    Nmi,
    Noon,
    Novalnet,
    Nuvei,
    Paybox,
    Payload,
    Payme,
    Paysafe,
    Paytm,
    Payu,
    Placetopay,
    Powertranz,
    Rapyd,
    Razorpay,
    RazorpayV2,
    Redsys,
    Revolut,
    Revolv3,
    Finix,
    Shift4,
    Silverflow,
    Stax,
    Stripe,
    Trustpay,
    Trustpayments,
    Tsys,
    Volt,
    Wellsfargo,
    Worldpay,
    Worldpayvantiv,
    Worldpayxml,
    Xendit,
    Zift,
    Ppro,
    Paypal,
    Truelayer,
    Peachpayments
);
