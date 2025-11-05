// Payu Connector Implementation

use std::fmt::Debug;

use hyperswitch_masking::ExposeInterface;
use serde::Serialize;
use interfaces::connector_types::*;
use hyperswitch_masking::Secret;
use interfaces::connector_types::*;

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

// Trait implementations with generic type parameters
impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorServiceTrait<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentAuthorizeV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentSyncV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentSessionToken for Payu<T>
{
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    PaymentAccessToken for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> CreateConnectorCustomer for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentVoidV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> RefundSyncV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> RefundV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentCapture for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> SetupMandateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> AcceptDispute for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> SubmitEvidenceV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> DisputeDefend for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> IncomingWebhook for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentOrderCreate for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ValidationTrait for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> RepeatPaymentV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentTokenV2<T> for Payu<T>
{
}

// Authentication trait implementations
impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentPreAuthenticateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentAuthenticateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentPostAuthenticateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> PaymentVoidPostCaptureV2 for Payu<T>
{
}