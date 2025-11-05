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

// Trait implementations with generic type parameters
impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::ConnectorServiceTrait<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentAuthorizeV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentSyncV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentSessionToken for Payu<T>
{
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    domain_types::connector_types::PaymentAccessToken for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::CreateConnectorCustomer for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentVoidV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::RefundSyncV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::RefundV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentCapture for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::SetupMandateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::AcceptDispute for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::SubmitEvidenceV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::DisputeDefend for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::IncomingWebhook for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentOrderCreate for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::ValidationTrait for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::RepeatPaymentV2 for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentTokenV2<T> for Payu<T>
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
> domain_types::connector_types::PaymentPreAuthenticateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentAuthenticateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentPostAuthenticateV2<T> for Payu<T>
{
}

impl<
    T: domain_types::payment_method_data::PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> domain_types::connector_types::PaymentVoidPostCaptureV2 for Payu<T>
{
}