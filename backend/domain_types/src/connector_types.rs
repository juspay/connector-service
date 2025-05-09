use crate::connector_flow::{
    self, Accept, Authorize, Capture, DefendDispute, PSync, RSync, Refund, SetupMandate,
    SubmitEvidence, Void,
};
use crate::errors::{ApiError, ApplicationErrorResponse};
use crate::types::{
    ConnectorInfo, Connectors, PaymentMethodDataType, PaymentMethodDetails,
    PaymentMethodTypeMetadata, SupportedPaymentMethods,
};
use crate::utils::ForeignTryFrom;
use error_stack::ResultExt;
use hyperswitch_api_models::enums::Currency;
use std::collections::HashSet;

use hyperswitch_common_enums::{
    AttemptStatus, AuthenticationType, CaptureMethod, DisputeStatus, EventClass, PaymentMethod,
    PaymentMethodType,
};
use hyperswitch_common_utils::{
    errors, errors::CustomResult, pii::SecretSerdeValue, types::MinorUnit,
};
use hyperswitch_domain_models::{
    payment_method_data, payment_method_data::PaymentMethodData, router_data::ConnectorAuthType,
    router_request_types::SyncRequestType,
};

use hyperswitch_interfaces::errors::ConnectorError;
use hyperswitch_interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// snake case for enum variants
#[derive(Clone, Debug, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    Adyen,
    Razorpay,
    Fiserv,
    Elavon,
    Checkout,
    Paypal,
    Jpmorgan,
    Airwallex,
}

impl ForeignTryFrom<i32> for ConnectorEnum {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(connector: i32) -> Result<Self, error_stack::Report<Self::Error>> {
        match connector {
            2 => Ok(Self::Adyen),
            68 => Ok(Self::Razorpay),
            28 => Ok(Self::Fiserv),
            778 => Ok(Self::Elavon),
            15 => Ok(Self::Checkout),
            99 => Ok(Self::Paypal),
            NEW_CONNECTOR_ID => Ok(Self::Jpmorgan),
            4 => Ok(Self::Airwallex),
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_CONNECTOR".to_owned(),
                error_identifier: 401,
                error_message: format!("Invalid value for authenticate_by: {}", connector),
                error_object: None,
            })
            .into()),
        }
    }
}

pub trait ConnectorServiceTrait:
    ConnectorCommon
    + ValidationTrait
    + PaymentAuthorizeV2
    + PaymentSyncV2
    + PaymentOrderCreate
    + PaymentVoidV2
    + IncomingWebhook
    + RefundV2
    + PaymentCapture
    + SetupMandateV2
    + AcceptDispute
    + RefundSyncV2
    + DisputeDefend
    + SubmitEvidenceV2
{
}

pub trait PaymentVoidV2:
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
}

pub type BoxedConnector = Box<&'static (dyn ConnectorServiceTrait + Sync)>;

pub trait ValidationTrait {
    fn should_do_order_create(&self) -> bool {
        false
    }
}

pub trait PaymentOrderCreate:
    ConnectorIntegrationV2<
    connector_flow::CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse,
>
{
}

pub trait PaymentAuthorizeV2:
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
}

pub trait PaymentSyncV2:
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
}

pub trait RefundV2:
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
}

pub trait RefundSyncV2:
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
}

pub trait PaymentCapture:
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
}

pub trait SetupMandateV2:
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>
{
}

pub trait AcceptDispute:
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
{
}

pub trait SubmitEvidenceV2:
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
{
}

pub trait RawConnectorResponse {
    fn set_raw_connector_response(&mut self, response: Option<String>);
}

#[derive(Debug, Clone)]
pub struct PaymentFlowData {
    pub merchant_id: hyperswitch_common_utils::id_type::MerchantId,
    pub customer_id: Option<hyperswitch_common_utils::id_type::CustomerId>,
    pub connector_customer: Option<String>,
    pub payment_id: String,
    pub attempt_id: String,
    pub status: AttemptStatus,
    pub payment_method: PaymentMethod,
    pub description: Option<String>,
    pub return_url: Option<String>,
    pub address: hyperswitch_domain_models::payment_address::PaymentAddress,
    pub auth_type: AuthenticationType,
    pub connector_meta_data: Option<hyperswitch_common_utils::pii::SecretSerdeValue>,
    pub amount_captured: Option<i64>,
    // minor amount for amount frameworka
    pub minor_amount_captured: Option<MinorUnit>,
    pub access_token: Option<String>,
    pub session_token: Option<String>,
    pub reference_id: Option<String>,
    pub payment_method_token: Option<String>,
    pub preprocessing_id: Option<String>,
    ///for switching between two different versions of the same connector
    pub connector_api_version: Option<String>,
    /// Contains a reference ID that should be sent in the connector request
    pub connector_request_reference_id: String,
    pub test_mode: Option<bool>,
    pub connector_http_status_code: Option<u16>,
    pub external_latency: Option<u128>,
    pub connectors: Connectors,
    pub raw_connector_response: Option<String>,
}

impl RawConnectorResponse for PaymentFlowData {
    fn set_raw_connector_response(&mut self, response: Option<String>) {
        self.raw_connector_response = response;
    }
}

#[derive(Debug, Clone)]
pub struct PaymentVoidData {
    pub connector_transaction_id: String,
    pub cancellation_reason: Option<String>,
    pub raw_connector_response: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentsAuthorizeData {
    pub payment_method_data: hyperswitch_domain_models::payment_method_data::PaymentMethodData,
    /// total amount (original_amount + surcharge_amount + tax_on_surcharge_amount)
    /// If connector supports separate field for surcharge amount, consider using below functions defined on `PaymentsAuthorizeData` to fetch original amount and surcharge amount separately
    /// ```text
    /// get_original_amount()
    /// get_surcharge_amount()
    /// get_tax_on_surcharge_amount()
    /// get_total_surcharge_amount() // returns surcharge_amount + tax_on_surcharge_amount
    /// ```
    pub amount: i64,
    pub order_tax_amount: Option<MinorUnit>,
    pub email: Option<hyperswitch_common_utils::pii::Email>,
    pub customer_name: Option<String>,
    pub currency: hyperswitch_common_enums::Currency,
    pub confirm: bool,
    pub statement_descriptor_suffix: Option<String>,
    pub statement_descriptor: Option<String>,
    pub capture_method: Option<hyperswitch_common_enums::CaptureMethod>,
    pub router_return_url: Option<String>,
    pub webhook_url: Option<String>,
    pub complete_authorize_url: Option<String>,
    // Mandates
    pub mandate_id: Option<hyperswitch_api_models::payments::MandateIds>,
    pub setup_future_usage: Option<hyperswitch_common_enums::FutureUsage>,
    pub off_session: Option<bool>,
    pub browser_info: Option<hyperswitch_domain_models::router_request_types::BrowserInformation>,
    pub order_category: Option<String>,
    pub session_token: Option<String>,
    pub enrolled_for_3ds: bool,
    pub related_transaction_id: Option<String>,
    pub payment_experience: Option<hyperswitch_common_enums::PaymentExperience>,
    pub payment_method_type: Option<hyperswitch_common_enums::PaymentMethodType>,
    pub customer_id: Option<hyperswitch_common_utils::id_type::CustomerId>,
    pub request_incremental_authorization: bool,
    pub metadata: Option<serde_json::Value>,
    // New amount for amount frame work
    pub minor_amount: MinorUnit,
    /// Merchant's identifier for the payment/invoice. This will be sent to the connector
    /// if the connector provides support to accept multiple reference ids.
    /// In case the connector supports only one reference id, Hyperswitch's Payment ID will be sent as reference.
    pub merchant_order_reference_id: Option<String>,
    pub shipping_cost: Option<MinorUnit>,
    pub merchant_account_id: Option<String>,
    pub merchant_config_currency: Option<hyperswitch_common_enums::Currency>,
    pub all_keys_required: Option<bool>,
}

#[derive(Debug, Default, Clone)]
pub struct PaymentsSyncData {
    pub connector_transaction_id: ResponseId,
    pub encoded_data: Option<String>,
    pub capture_method: Option<hyperswitch_common_enums::CaptureMethod>,
    pub connector_meta: Option<serde_json::Value>,
    pub sync_type: SyncRequestType,
    pub mandate_id: Option<hyperswitch_api_models::payments::MandateIds>,
    pub payment_method_type: Option<hyperswitch_common_enums::PaymentMethodType>,
    pub currency: hyperswitch_common_enums::Currency,
    pub payment_experience: Option<hyperswitch_common_enums::PaymentExperience>,
    pub amount: MinorUnit,
    pub all_keys_required: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ResponseId {
    ConnectorTransactionId(String),
    EncodedData(String),
    #[default]
    NoResponseId,
}
impl ResponseId {
    pub fn get_connector_transaction_id(
        &self,
    ) -> errors::CustomResult<String, errors::ValidationError> {
        match self {
            Self::ConnectorTransactionId(txn_id) => Ok(txn_id.to_string()),
            _ => Err(errors::ValidationError::IncorrectValueProvided {
                field_name: "connector_transaction_id",
            })
            .attach_printable("Expected connector transaction ID not found"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentsResponseData {
    TransactionResponse {
        resource_id: ResponseId,
        redirection_data:
            Box<Option<hyperswitch_domain_models::router_response_types::RedirectForm>>,
        connector_metadata: Option<serde_json::Value>,
        mandate_reference: Box<Option<MandateReference>>,
        network_txn_id: Option<String>,
        connector_response_reference_id: Option<String>,
        incremental_authorization_allowed: Option<bool>,
        raw_connector_response: Option<String>,
    },
    SessionResponse {
        session_token: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct MandateReference {
    pub connector_mandate_id: Option<String>,
    pub payment_method_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PaymentCreateOrderData {
    pub amount: MinorUnit,
    pub currency: Currency,
}

#[derive(Debug, Clone)]
pub struct PaymentCreateOrderResponse {
    pub order_id: String,
}

#[derive(Debug, Default, Clone)]
pub struct RefundSyncData {
    pub connector_transaction_id: String,
    pub connector_refund_id: String,
    pub reason: Option<String>,
    pub refund_connector_metadata: Option<hyperswitch_common_utils::pii::SecretSerdeValue>,
    pub refund_status: hyperswitch_common_enums::RefundStatus,
    pub all_keys_required: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct RefundsResponseData {
    pub connector_refund_id: String,
    pub refund_status: hyperswitch_common_enums::RefundStatus,
    pub raw_connector_response: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefundFlowData {
    pub status: hyperswitch_common_enums::RefundStatus,
    pub refund_id: Option<String>,
    pub connectors: Connectors,
    pub raw_connector_response: Option<String>,
}

impl RawConnectorResponse for RefundFlowData {
    fn set_raw_connector_response(&mut self, response: Option<String>) {
        self.raw_connector_response = response;
    }
}

#[derive(Debug, Clone)]
pub struct WebhookDetailsResponse {
    pub resource_id: Option<ResponseId>,
    pub status: hyperswitch_common_enums::AttemptStatus,
    pub connector_response_reference_id: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefundWebhookDetailsResponse {
    pub connector_refund_id: Option<String>,
    pub status: hyperswitch_common_enums::RefundStatus,
    pub connector_response_reference_id: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DisputeWebhookDetailsResponse {
    pub dispute_id: String,
    pub status: hyperswitch_common_enums::DisputeStatus,
    pub stage: hyperswitch_common_enums::DisputeStage,
    pub connector_response_reference_id: Option<String>,
    pub dispute_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
}

#[derive(Debug, Clone)]
pub struct RequestDetails {
    pub method: HttpMethod,
    pub uri: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub query_params: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectorWebhookSecrets {
    pub secret: String,
    pub additional_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    Payment,
    Refund,
    Dispute,
}

impl ForeignTryFrom<grpc_api_types::payments::EventType> for EventType {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::EventType,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::EventType::Payment => Ok(Self::Payment),
            grpc_api_types::payments::EventType::Refund => Ok(Self::Refund),
            grpc_api_types::payments::EventType::Dispute => Ok(Self::Dispute),
        }
    }
}

impl ForeignTryFrom<EventType> for grpc_api_types::payments::EventType {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(value: EventType) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            EventType::Payment => Ok(Self::Payment),
            EventType::Refund => Ok(Self::Refund),
            EventType::Dispute => Ok(Self::Dispute),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::Method> for HttpMethod {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::Method,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::Method::Get => Ok(Self::Get),
            grpc_api_types::payments::Method::Post => Ok(Self::Post),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::RequestDetails> for RequestDetails {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::RequestDetails,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let method = HttpMethod::foreign_try_from(value.method())?;

        Ok(Self {
            method,
            uri: value.uri,
            headers: value.headers,
            body: value.body,
            query_params: value.query_params,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::ConnectorWebhookSecrets> for ConnectorWebhookSecrets {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::ConnectorWebhookSecrets,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            secret: value.secret,
            additional_secret: value.additional_secret,
        })
    }
}

pub trait IncomingWebhook {
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<ConnectorError>> {
        Ok(false)
    }

    fn get_event_type(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("get_event_type".to_string()).into())
    }

    fn process_payment_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("process_payment_webhook".to_string()).into())
    }

    fn process_refund_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("process_refund_webhook".to_string()).into())
    }
    fn process_dispute_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<DisputeWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("process_dispute_webhook".to_string()).into())
    }
}
#[derive(Debug, Default, Clone)]
pub struct RefundsData {
    pub refund_id: String,
    pub connector_transaction_id: String,
    pub connector_refund_id: Option<String>,
    pub currency: hyperswitch_common_enums::Currency,
    pub payment_amount: i64,
    pub reason: Option<String>,
    pub webhook_url: Option<String>,
    pub refund_amount: i64,
    pub connector_metadata: Option<serde_json::Value>,
    pub refund_connector_metadata: Option<hyperswitch_common_utils::pii::SecretSerdeValue>,
    pub minor_payment_amount: MinorUnit,
    pub minor_refund_amount: MinorUnit,
    pub refund_status: hyperswitch_common_enums::RefundStatus,
    pub merchant_account_id: Option<String>,
    pub capture_method: Option<hyperswitch_common_enums::CaptureMethod>,
}

#[derive(Debug, Clone, Default)]
pub struct MultipleCaptureRequestData {
    pub capture_sequence: i64,
    pub capture_reference: String,
}

#[derive(Debug, Default, Clone)]
pub struct PaymentsCaptureData {
    pub amount_to_capture: i64,
    pub minor_amount_to_capture: MinorUnit,
    pub currency: hyperswitch_common_enums::Currency,
    pub connector_transaction_id: ResponseId,
    pub multiple_capture_data: Option<MultipleCaptureRequestData>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct SetupMandateRequestData {
    pub currency: hyperswitch_common_enums::Currency,
    pub payment_method_data: hyperswitch_domain_models::payment_method_data::PaymentMethodData,
    pub amount: Option<i64>,
    pub confirm: bool,
    pub statement_descriptor_suffix: Option<String>,
    pub statement_descriptor: Option<String>,
    pub customer_acceptance: Option<hyperswitch_domain_models::mandates::CustomerAcceptance>,
    pub mandate_id: Option<hyperswitch_api_models::payments::MandateIds>,
    pub setup_future_usage: Option<hyperswitch_common_enums::FutureUsage>,
    pub off_session: Option<bool>,
    pub setup_mandate_details: Option<hyperswitch_domain_models::mandates::MandateData>,
    pub router_return_url: Option<String>,
    pub webhook_url: Option<String>,
    pub browser_info: Option<hyperswitch_domain_models::router_request_types::BrowserInformation>,
    pub email: Option<hyperswitch_common_utils::pii::Email>,
    pub customer_name: Option<String>,
    pub return_url: Option<String>,
    pub payment_method_type: Option<hyperswitch_common_enums::PaymentMethodType>,
    pub request_incremental_authorization: bool,
    pub metadata: Option<serde_json::Value>,
    pub complete_authorize_url: Option<String>,
    pub capture_method: Option<hyperswitch_common_enums::CaptureMethod>,
    pub merchant_order_reference_id: Option<String>,
    pub minor_amount: Option<MinorUnit>,
    pub shipping_cost: Option<MinorUnit>,
    pub customer_id: Option<hyperswitch_common_utils::id_type::CustomerId>,
}

#[derive(Debug, Default, Clone)]
pub struct AcceptDisputeData {}

#[derive(Debug, Clone)]
pub struct DisputeFlowData {
    pub dispute_id: Option<String>,
    pub connector_dispute_id: String,
    pub connectors: Connectors,
    pub defense_reason_code: Option<String>,
    pub raw_connector_response: Option<String>,
}

impl RawConnectorResponse for DisputeFlowData {
    fn set_raw_connector_response(&mut self, response: Option<String>) {
        self.raw_connector_response = response;
    }
}

#[derive(Debug, Clone)]
pub struct DisputeResponseData {
    pub connector_dispute_id: String,
    pub dispute_status: DisputeStatus,
    pub connector_dispute_status: Option<String>,
    pub raw_connector_response: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SubmitEvidenceData {
    pub dispute_id: Option<String>,
    pub connector_dispute_id: String,
    pub access_activity_log: Option<String>,
    pub billing_address: Option<String>,

    pub cancellation_policy: Option<Vec<u8>>,
    pub cancellation_policy_file_type: Option<String>,
    pub cancellation_policy_provider_file_id: Option<String>,
    pub cancellation_policy_disclosure: Option<String>,
    pub cancellation_rebuttal: Option<String>,

    pub customer_communication: Option<Vec<u8>>,
    pub customer_communication_file_type: Option<String>,
    pub customer_communication_provider_file_id: Option<String>,
    pub customer_email_address: Option<String>,
    pub customer_name: Option<String>,
    pub customer_purchase_ip: Option<String>,

    pub customer_signature: Option<Vec<u8>>,
    pub customer_signature_file_type: Option<String>,
    pub customer_signature_provider_file_id: Option<String>,

    pub product_description: Option<String>,

    pub receipt: Option<Vec<u8>>,
    pub receipt_file_type: Option<String>,
    pub receipt_provider_file_id: Option<String>,

    pub refund_policy: Option<Vec<u8>>,
    pub refund_policy_file_type: Option<String>,
    pub refund_policy_provider_file_id: Option<String>,
    pub refund_policy_disclosure: Option<String>,
    pub refund_refusal_explanation: Option<String>,

    pub service_date: Option<String>,
    pub service_documentation: Option<Vec<u8>>,
    pub service_documentation_file_type: Option<String>,
    pub service_documentation_provider_file_id: Option<String>,

    pub shipping_address: Option<String>,
    pub shipping_carrier: Option<String>,
    pub shipping_date: Option<String>,
    pub shipping_documentation: Option<Vec<u8>>,
    pub shipping_documentation_file_type: Option<String>,
    pub shipping_documentation_provider_file_id: Option<String>,
    pub shipping_tracking_number: Option<String>,

    pub invoice_showing_distinct_transactions: Option<Vec<u8>>,
    pub invoice_showing_distinct_transactions_file_type: Option<String>,
    pub invoice_showing_distinct_transactions_provider_file_id: Option<String>,

    pub recurring_transaction_agreement: Option<Vec<u8>>,
    pub recurring_transaction_agreement_file_type: Option<String>,
    pub recurring_transaction_agreement_provider_file_id: Option<String>,

    pub uncategorized_file: Option<Vec<u8>>,
    pub uncategorized_file_type: Option<String>,
    pub uncategorized_file_provider_file_id: Option<String>,
    pub uncategorized_text: Option<String>,
}

/// The trait that provides specifications about the connector
pub trait ConnectorSpecifications {
    /// Details related to payment method supported by the connector
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        None
    }

    /// Supported webhooks flows
    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        None
    }

    /// About the connector
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        None
    }
}

/// trait ConnectorValidation
pub trait ConnectorValidation: ConnectorCommon + ConnectorSpecifications {
    /// Validate, the payment request against the connector supported features
    fn validate_connector_against_payment_request(
        &self,
        capture_method: Option<CaptureMethod>,
        payment_method: PaymentMethod,
        pmt: Option<hyperswitch_common_enums::PaymentMethodType>,
    ) -> CustomResult<(), ConnectorError> {
        let capture_method = capture_method.unwrap_or_default();
        let is_default_capture_method = [CaptureMethod::Automatic].contains(&capture_method);
        let is_feature_supported = match self.get_supported_payment_methods() {
            Some(supported_payment_methods) => {
                let connector_payment_method_type_info = get_connector_payment_method_type_info(
                    supported_payment_methods,
                    payment_method,
                    pmt,
                    self.id(),
                )?;

                connector_payment_method_type_info
                    .map(|payment_method_type_info| {
                        payment_method_type_info
                            .supported_capture_methods
                            .contains(&capture_method)
                    })
                    .unwrap_or(true)
            }
            None => is_default_capture_method,
        };

        if is_feature_supported {
            Ok(())
        } else {
            Err(ConnectorError::NotSupported {
                message: capture_method.to_string(),
                connector: self.id(),
            }
            .into())
        }
    }

    /// fn validate_mandate_payment
    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        _pm_data: PaymentMethodData,
    ) -> CustomResult<(), ConnectorError> {
        let connector = self.id();
        match pm_type {
            Some(pm_type) => Err(ConnectorError::NotSupported {
                message: format!("{} mandate payment", pm_type),
                connector,
            }
            .into()),
            None => Err(ConnectorError::NotSupported {
                message: " mandate payment".to_string(),
                connector,
            }
            .into()),
        }
    }

    /// fn validate_psync_reference_id
    fn validate_psync_reference_id(
        &self,
        data: &hyperswitch_domain_models::router_request_types::PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<SecretSerdeValue>,
    ) -> CustomResult<(), ConnectorError> {
        data.connector_transaction_id
            .get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)
            .map(|_| ())
    }

    /// fn is_webhook_source_verification_mandatory
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false
    }
}

fn get_connector_payment_method_type_info(
    supported_payment_method: &SupportedPaymentMethods,
    payment_method: PaymentMethod,
    payment_method_type: Option<PaymentMethodType>,
    connector: &'static str,
) -> CustomResult<Option<PaymentMethodDetails>, ConnectorError> {
    let payment_method_details =
        supported_payment_method
            .get(&payment_method)
            .ok_or_else(|| ConnectorError::NotSupported {
                message: payment_method.to_string(),
                connector,
            })?;

    payment_method_type
        .map(|pmt| {
            payment_method_details.get(&pmt).cloned().ok_or_else(|| {
                ConnectorError::NotSupported {
                    message: format!("{} {}", payment_method, pmt),
                    connector,
                }
                .into()
            })
        })
        .transpose()
}

#[macro_export]
macro_rules! capture_method_not_supported {
    ($connector:expr, $capture_method:expr) => {
        Err(errors::ConnectorError::NotSupported {
            message: format!("{} for selected payment method", $capture_method),
            connector: $connector,
        }
        .into())
    };
    ($connector:expr, $capture_method:expr, $payment_method_type:expr) => {
        Err(errors::ConnectorError::NotSupported {
            message: format!("{} for {}", $capture_method, $payment_method_type),
            connector: $connector,
        }
        .into())
    };
}

#[macro_export]
macro_rules! payment_method_not_supported {
    ($connector:expr, $payment_method:expr, $payment_method_type:expr) => {
        Err(errors::ConnectorError::NotSupported {
            message: format!(
                "Payment method {} with type {} is not supported",
                $payment_method, $payment_method_type
            ),
            connector: $connector,
        }
        .into())
    };
}

pub fn is_mandate_supported(
    selected_pmd: PaymentMethodData,
    payment_method_type: Option<PaymentMethodType>,
    mandate_implemented_pmds: HashSet<PaymentMethodDataType>,
    connector: &'static str,
) -> Result<(), error_stack::Report<ConnectorError>> {
    if mandate_implemented_pmds.contains(&PaymentMethodDataType::from(selected_pmd.clone())) {
        Ok(())
    } else {
        match payment_method_type {
            Some(pm_type) => Err(ConnectorError::NotSupported {
                message: format!("{} mandate payment", pm_type),
                connector,
            }
            .into()),
            None => Err(ConnectorError::NotSupported {
                message: "mandate payment".to_string(),
                connector,
            }
            .into()),
        }
    }
}

impl From<PaymentMethodData> for PaymentMethodDataType {
    fn from(pm_data: PaymentMethodData) -> Self {
        match pm_data {
            PaymentMethodData::Card(_) => Self::Card,
            PaymentMethodData::CardRedirect(card_redirect_data) => match card_redirect_data {
                payment_method_data::CardRedirectData::Knet {} => Self::Knet,
                payment_method_data::CardRedirectData::Benefit {} => Self::Benefit,
                payment_method_data::CardRedirectData::MomoAtm {} => Self::MomoAtm,
                payment_method_data::CardRedirectData::CardRedirect {} => Self::CardRedirect,
            },
            PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                payment_method_data::WalletData::AliPayQr(_) => Self::AliPayQr,
                payment_method_data::WalletData::AliPayRedirect(_) => Self::AliPayRedirect,
                payment_method_data::WalletData::AliPayHkRedirect(_) => Self::AliPayHkRedirect,
                payment_method_data::WalletData::MomoRedirect(_) => Self::MomoRedirect,
                payment_method_data::WalletData::KakaoPayRedirect(_) => Self::KakaoPayRedirect,
                payment_method_data::WalletData::GoPayRedirect(_) => Self::GoPayRedirect,
                payment_method_data::WalletData::GcashRedirect(_) => Self::GcashRedirect,
                payment_method_data::WalletData::ApplePay(_) => Self::ApplePay,
                payment_method_data::WalletData::ApplePayRedirect(_) => Self::ApplePayRedirect,
                payment_method_data::WalletData::ApplePayThirdPartySdk(_) => {
                    Self::ApplePayThirdPartySdk
                }
                payment_method_data::WalletData::DanaRedirect {} => Self::DanaRedirect,
                payment_method_data::WalletData::GooglePay(_) => Self::GooglePay,
                payment_method_data::WalletData::GooglePayRedirect(_) => Self::GooglePayRedirect,
                payment_method_data::WalletData::GooglePayThirdPartySdk(_) => {
                    Self::GooglePayThirdPartySdk
                }
                payment_method_data::WalletData::MbWayRedirect(_) => Self::MbWayRedirect,
                payment_method_data::WalletData::MobilePayRedirect(_) => Self::MobilePayRedirect,
                payment_method_data::WalletData::PaypalRedirect(_) => Self::PaypalRedirect,
                payment_method_data::WalletData::PaypalSdk(_) => Self::PaypalSdk,
                payment_method_data::WalletData::SamsungPay(_) => Self::SamsungPay,
                payment_method_data::WalletData::TwintRedirect {} => Self::TwintRedirect,
                payment_method_data::WalletData::VippsRedirect {} => Self::VippsRedirect,
                payment_method_data::WalletData::TouchNGoRedirect(_) => Self::TouchNGoRedirect,
                payment_method_data::WalletData::WeChatPayRedirect(_) => Self::WeChatPayRedirect,
                payment_method_data::WalletData::WeChatPayQr(_) => Self::WeChatPayQr,
                payment_method_data::WalletData::CashappQr(_) => Self::CashappQr,
                payment_method_data::WalletData::SwishQr(_) => Self::SwishQr,
                payment_method_data::WalletData::Mifinity(_) => Self::Mifinity,
            },
            PaymentMethodData::PayLater(pay_later_data) => match pay_later_data {
                payment_method_data::PayLaterData::KlarnaRedirect { .. } => Self::KlarnaRedirect,
                payment_method_data::PayLaterData::KlarnaSdk { .. } => Self::KlarnaSdk,
                payment_method_data::PayLaterData::AffirmRedirect {} => Self::AffirmRedirect,
                payment_method_data::PayLaterData::AfterpayClearpayRedirect { .. } => {
                    Self::AfterpayClearpayRedirect
                }
                payment_method_data::PayLaterData::PayBrightRedirect {} => Self::PayBrightRedirect,
                payment_method_data::PayLaterData::WalleyRedirect {} => Self::WalleyRedirect,
                payment_method_data::PayLaterData::AlmaRedirect {} => Self::AlmaRedirect,
                payment_method_data::PayLaterData::AtomeRedirect {} => Self::AtomeRedirect,
            },
            PaymentMethodData::BankRedirect(bank_redirect_data) => match bank_redirect_data {
                payment_method_data::BankRedirectData::BancontactCard { .. } => {
                    Self::BancontactCard
                }
                payment_method_data::BankRedirectData::Bizum {} => Self::Bizum,
                payment_method_data::BankRedirectData::Blik { .. } => Self::Blik,
                payment_method_data::BankRedirectData::Eps { .. } => Self::Eps,
                payment_method_data::BankRedirectData::Giropay { .. } => Self::Giropay,
                payment_method_data::BankRedirectData::Ideal { .. } => Self::Ideal,
                payment_method_data::BankRedirectData::Interac { .. } => Self::Interac,
                payment_method_data::BankRedirectData::OnlineBankingCzechRepublic { .. } => {
                    Self::OnlineBankingCzechRepublic
                }
                payment_method_data::BankRedirectData::OnlineBankingFinland { .. } => {
                    Self::OnlineBankingFinland
                }
                payment_method_data::BankRedirectData::OnlineBankingPoland { .. } => {
                    Self::OnlineBankingPoland
                }
                payment_method_data::BankRedirectData::OnlineBankingSlovakia { .. } => {
                    Self::OnlineBankingSlovakia
                }
                payment_method_data::BankRedirectData::OpenBankingUk { .. } => Self::OpenBankingUk,
                payment_method_data::BankRedirectData::Przelewy24 { .. } => Self::Przelewy24,
                payment_method_data::BankRedirectData::Sofort { .. } => Self::Sofort,
                payment_method_data::BankRedirectData::Trustly { .. } => Self::Trustly,
                payment_method_data::BankRedirectData::OnlineBankingFpx { .. } => {
                    Self::OnlineBankingFpx
                }
                payment_method_data::BankRedirectData::OnlineBankingThailand { .. } => {
                    Self::OnlineBankingThailand
                }
                payment_method_data::BankRedirectData::LocalBankRedirect {} => {
                    Self::LocalBankRedirect
                }
            },
            PaymentMethodData::BankDebit(bank_debit_data) => match bank_debit_data {
                payment_method_data::BankDebitData::AchBankDebit { .. } => Self::AchBankDebit,
                payment_method_data::BankDebitData::SepaBankDebit { .. } => Self::SepaBankDebit,
                payment_method_data::BankDebitData::BecsBankDebit { .. } => Self::BecsBankDebit,
                payment_method_data::BankDebitData::BacsBankDebit { .. } => Self::BacsBankDebit,
            },
            PaymentMethodData::BankTransfer(bank_transfer_data) => match *bank_transfer_data {
                payment_method_data::BankTransferData::AchBankTransfer { .. } => {
                    Self::AchBankTransfer
                }
                payment_method_data::BankTransferData::SepaBankTransfer { .. } => {
                    Self::SepaBankTransfer
                }
                payment_method_data::BankTransferData::BacsBankTransfer { .. } => {
                    Self::BacsBankTransfer
                }
                payment_method_data::BankTransferData::MultibancoBankTransfer { .. } => {
                    Self::MultibancoBankTransfer
                }
                payment_method_data::BankTransferData::PermataBankTransfer { .. } => {
                    Self::PermataBankTransfer
                }
                payment_method_data::BankTransferData::BcaBankTransfer { .. } => {
                    Self::BcaBankTransfer
                }
                payment_method_data::BankTransferData::BniVaBankTransfer { .. } => {
                    Self::BniVaBankTransfer
                }
                payment_method_data::BankTransferData::BriVaBankTransfer { .. } => {
                    Self::BriVaBankTransfer
                }
                payment_method_data::BankTransferData::CimbVaBankTransfer { .. } => {
                    Self::CimbVaBankTransfer
                }
                payment_method_data::BankTransferData::DanamonVaBankTransfer { .. } => {
                    Self::DanamonVaBankTransfer
                }
                payment_method_data::BankTransferData::MandiriVaBankTransfer { .. } => {
                    Self::MandiriVaBankTransfer
                }
                payment_method_data::BankTransferData::Pix { .. } => Self::Pix,
                payment_method_data::BankTransferData::Pse {} => Self::Pse,
                payment_method_data::BankTransferData::LocalBankTransfer { .. } => {
                    Self::LocalBankTransfer
                }
            },
            PaymentMethodData::Crypto(_) => Self::Crypto,
            PaymentMethodData::MandatePayment => Self::MandatePayment,
            PaymentMethodData::Reward => Self::Reward,
            PaymentMethodData::Upi(_) => Self::Upi,
            PaymentMethodData::Voucher(voucher_data) => match voucher_data {
                payment_method_data::VoucherData::Boleto(_) => Self::Boleto,
                payment_method_data::VoucherData::Efecty => Self::Efecty,
                payment_method_data::VoucherData::PagoEfectivo => Self::PagoEfectivo,
                payment_method_data::VoucherData::RedCompra => Self::RedCompra,
                payment_method_data::VoucherData::RedPagos => Self::RedPagos,
                payment_method_data::VoucherData::Alfamart(_) => Self::Alfamart,
                payment_method_data::VoucherData::Indomaret(_) => Self::Indomaret,
                payment_method_data::VoucherData::Oxxo => Self::Oxxo,
                payment_method_data::VoucherData::SevenEleven(_) => Self::SevenEleven,
                payment_method_data::VoucherData::Lawson(_) => Self::Lawson,
                payment_method_data::VoucherData::MiniStop(_) => Self::MiniStop,
                payment_method_data::VoucherData::FamilyMart(_) => Self::FamilyMart,
                payment_method_data::VoucherData::Seicomart(_) => Self::Seicomart,
                payment_method_data::VoucherData::PayEasy(_) => Self::PayEasy,
            },
            PaymentMethodData::RealTimePayment(real_time_payment_data) => {
                match *real_time_payment_data {
                    payment_method_data::RealTimePaymentData::DuitNow {} => Self::DuitNow,
                    payment_method_data::RealTimePaymentData::Fps {} => Self::Fps,
                    payment_method_data::RealTimePaymentData::PromptPay {} => Self::PromptPay,
                    payment_method_data::RealTimePaymentData::VietQr {} => Self::VietQr,
                }
            }
            PaymentMethodData::GiftCard(gift_card_data) => match *gift_card_data {
                payment_method_data::GiftCardData::Givex(_) => Self::Givex,
                payment_method_data::GiftCardData::PaySafeCard {} => Self::PaySafeCar,
            },
            PaymentMethodData::CardToken(_) => Self::CardToken,
            PaymentMethodData::OpenBanking(data) => match data {
                payment_method_data::OpenBankingData::OpenBankingPIS {} => Self::OpenBanking,
            },
        }
    }
}

pub trait DisputeDefend:
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
{
}

#[derive(Default, Debug, Clone)]
pub struct DisputeDefendData {
    pub dispute_id: String,
    pub connector_dispute_id: String,
    pub defense_reason_code: String,
}

pub trait SupportedPaymentMethodsExt {
    fn add(
        &mut self,
        payment_method: PaymentMethod,
        payment_method_type: PaymentMethodType,
        payment_method_details: PaymentMethodDetails,
    );
}

impl SupportedPaymentMethodsExt for SupportedPaymentMethods {
    fn add(
        &mut self,
        payment_method: PaymentMethod,
        payment_method_type: PaymentMethodType,
        payment_method_details: PaymentMethodDetails,
    ) {
        if let Some(payment_method_data) = self.get_mut(&payment_method) {
            payment_method_data.insert(payment_method_type, payment_method_details);
        } else {
            let mut payment_method_type_metadata = PaymentMethodTypeMetadata::new();
            payment_method_type_metadata.insert(payment_method_type, payment_method_details);

            self.insert(payment_method, payment_method_type_metadata);
        }
    }
}
