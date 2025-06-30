use crate::types::ResponseRouterData;
use cards::CardNumberStrategy;
use common_enums::{self, enums, AttemptStatus, RefundStatus};
use common_utils::ext_traits::{OptionExt, ValueExt};
use common_utils::{consts, pii::Email};
use domain_types::errors::ConnectorError;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
// Alias to make the transition easier
type HsInterfacesConnectorError = ConnectorError;
use super::AuthorizedotnetRouterData;
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret, StrongSecret};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::str::FromStr;

type Error = error_stack::Report<domain_types::errors::ConnectorError>;

// Re-export common enums for use in this file
pub mod api_enums {
    pub use common_enums::Currency;
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MerchantAuthentication {
    name: Secret<String>,
    transaction_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for MerchantAuthentication {
    type Error = Error;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                name: api_key.clone(),
                transaction_key: key1.clone(),
            }),
            _ => Err(error_stack::report!(ConnectorError::FailedToObtainAuthType)),
        }
    }
}

impl ForeignTryFrom<serde_json::Value> for Vec<UserField> {
    type Error = Error;
    fn foreign_try_from(metadata: serde_json::Value) -> Result<Self, Self::Error> {
        let mut vector = Self::new();

        if let serde_json::Value::Object(obj) = metadata {
            for (key, value) in obj {
                vector.push(UserField {
                    name: key,
                    value: match value {
                        serde_json::Value::String(s) => s,
                        _ => value.to_string(),
                    },
                });
            }
        }

        Ok(vector)
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardDetails {
    card_number: StrongSecret<String, CardNumberStrategy>,
    expiration_date: Secret<String>, // YYYY-MM
    card_code: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PaymentDetails {
    CreditCard(CreditCardDetails),
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TransactionType {
    AuthOnlyTransaction,
    AuthCaptureTransaction,
    PriorAuthCaptureTransaction,
    VoidTransaction,
    RefundTransaction,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    invoice_number: String,
    description: String,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillTo {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    address: Option<Secret<String>>,
    city: Option<String>,
    state: Option<Secret<String>>,
    zip: Option<Secret<String>>,
    country: Option<enums::CountryAlpha2>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShipTo {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    company: Option<String>,
    address: Option<Secret<String>>,
    city: Option<String>,
    state: Option<String>,
    zip: Option<Secret<String>>,
    country: Option<enums::CountryAlpha2>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerDetails {
    id: String,
    email: Option<Email>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserField {
    name: String,
    value: String,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFields {
    user_field: Vec<UserField>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingOptions {
    is_subsequent_auth: bool,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubsequentAuthInformation {
    original_network_trans_id: Secret<String>,
    reason: Reason,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    Resubmission,
    #[serde(rename = "delayedCharge")]
    DelayedCharge,
    Reauthorization,
    #[serde(rename = "noShow")]
    NoShow,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationIndicator {
    Final,
    Pre,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationIndicatorType {
    authorization_indicator: AuthorizationIndicator,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum ProfileDetails {
    CreateProfileDetails(CreateProfileDetails),
    CustomerProfileDetails(CustomerProfileDetails),
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateProfileDetails {
    create_profile: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CustomerProfileDetails {
    customer_profile_id: Secret<String>,
    payment_profile: PaymentProfileDetails,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct PaymentProfileDetails {
    payment_profile_id: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionRequest {
    // General structure for transaction details in Authorize
    transaction_type: TransactionType,
    amount: Option<String>,
    currency_code: Option<api_enums::Currency>,
    payment: Option<PaymentDetails>,
    profile: Option<ProfileDetails>,
    order: Option<Order>,
    customer: Option<CustomerDetails>,
    bill_to: Option<BillTo>,
    user_fields: Option<UserFields>,
    processing_options: Option<ProcessingOptions>,
    subsequent_auth_information: Option<SubsequentAuthInformation>,
    authorization_indicator_type: Option<AuthorizationIndicatorType>,
    ref_trans_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSettings {
    setting: Vec<TransactionSetting>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSetting {
    setting_name: String,
    setting_value: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRequest {
    // Used by Authorize Flow, wraps the general transaction request
    merchant_authentication: AuthorizedotnetAuthType,
    transaction_request: AuthorizedotnetTransactionRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetPaymentsRequest {
    // Top-level wrapper for Authorize Flow
    create_transaction_request: CreateTransactionRequest,
}

// Implementation for owned RouterData that doesn't depend on reference version
impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for AuthorizedotnetPaymentsRequest
{
    type Error = Error;
    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let card_data = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(ConnectorError::RequestEncodingFailed),
        }?;

        let expiry_month = card_data.card_exp_month.peek().clone();
        let year = card_data.card_exp_year.peek().clone();
        let expiry_year = if year.len() == 2 {
            format!("20{}", year)
        } else {
            year
        };
        let expiration_date = format!("{}-{}", expiry_year, expiry_month);

        let credit_card_details = CreditCardDetails {
            card_number: StrongSecret::new(card_data.card_number.peek().to_string()),
            expiration_date: Secret::new(expiration_date),
            card_code: Some(card_data.card_cvc.clone()),
        };

        let payment_details = PaymentDetails::CreditCard(credit_card_details);

        let transaction_type = match item.router_data.request.capture_method {
            Some(enums::CaptureMethod::Manual) => TransactionType::AuthOnlyTransaction,
            Some(enums::CaptureMethod::Automatic) | None => TransactionType::AuthCaptureTransaction,
            Some(_) => {
                return Err(error_stack::report!(ConnectorError::NotSupported {
                    message: "Capture method not supported".to_string(),
                    connector: "authorizedotnet",
                }))
            }
        };

        let order_description = item
            .router_data
            .resource_common_data
            .description
            .clone()
            .unwrap_or_else(|| "Payment".to_string());

        // Truncate invoice number to 20 characters (Authorize.Net limit)
        let invoice_number = item
            .router_data
            .request
            .merchant_order_reference_id
            .clone()
            .unwrap_or_else(|| item.router_data.resource_common_data.payment_id.clone());
        let truncated_invoice_number = if invoice_number.len() > 20 {
            invoice_number[0..20].to_string()
        } else {
            invoice_number
        };

        let order = Order {
            invoice_number: truncated_invoice_number,
            description: order_description,
        };

        // Extract user fields from metadata
        let user_fields: Option<UserFields> = match item.router_data.request.metadata.clone() {
            Some(metadata) => Some(UserFields {
                user_field: Vec::<UserField>::foreign_try_from(metadata)?,
            }),
            None => None,
        };

        // Process billing address
        let billing_address = item
            .router_data
            .resource_common_data
            .address
            .get_payment_billing();
        let bill_to =
            billing_address.as_ref().map(|billing| {
                let first_name = billing.address.as_ref().and_then(|a| a.first_name.clone());
                let last_name = billing.address.as_ref().and_then(|a| a.last_name.clone());

                BillTo {
                    first_name,
                    last_name,
                    address: billing.address.as_ref().and_then(|a| a.line1.clone()),
                    city: billing.address.as_ref().and_then(|a| a.city.clone()),
                    state: billing.address.as_ref().and_then(|a| a.state.clone()),
                    zip: billing.address.as_ref().and_then(|a| a.zip.clone()),
                    country: billing.address.as_ref().and_then(|a| a.country).and_then(
                        |api_country| enums::CountryAlpha2::from_str(&api_country.to_string()).ok(),
                    ),
                }
            });

        let customer_id_string: String = item
            .router_data
            .request
            .customer_id
            .as_ref()
            .map(|cid| cid.get_string_repr().to_owned())
            .unwrap_or_else(|| "anonymous_customer".to_string());

        let customer_details = CustomerDetails {
            id: customer_id_string,
            email: item.router_data.request.email.clone(),
        };

        let currency_str = item.router_data.request.currency.to_string();
        let currency = api_enums::Currency::from_str(&currency_str)
            .map_err(|_| error_stack::report!(ConnectorError::RequestEncodingFailed))?;

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let transaction_request_auth = AuthorizedotnetTransactionRequest {
            transaction_type,
            amount: Some(item.router_data.request.amount.to_string().clone()),
            currency_code: Some(currency),
            payment: Some(payment_details),
            profile: None,
            order: Some(order),
            customer: Some(customer_details),
            bill_to,
            user_fields,
            processing_options: None,
            subsequent_auth_information: None,
            authorization_indicator_type: None,
            ref_trans_id: None, // Not used for initial auth
        };

        let create_transaction_request = CreateTransactionRequest {
            merchant_authentication,
            transaction_request: transaction_request_auth,
        };

        Ok(AuthorizedotnetPaymentsRequest {
            create_transaction_request,
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCaptureTransactionInternal {
    // Specific transaction details for Capture
    transaction_type: TransactionType,
    amount: String,
    ref_trans_id: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCaptureTransactionRequest {
    // Used by Capture Flow, wraps specific capture transaction details
    merchant_authentication: AuthorizedotnetAuthType,
    transaction_request: AuthorizedotnetCaptureTransactionInternal,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCaptureRequest {
    // Top-level wrapper for Capture Flow
    create_transaction_request: CreateCaptureTransactionRequest,
}

// New direct implementation for capture without relying on the reference version
impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
        >,
    > for AuthorizedotnetCaptureRequest
{
    type Error = Error;
    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let original_connector_txn_id = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id"
                    }
                ));
            }
        };

        let transaction_request_payload = AuthorizedotnetCaptureTransactionInternal {
            transaction_type: TransactionType::PriorAuthCaptureTransaction,
            amount: item
                .router_data
                .request
                .amount_to_capture
                .to_string()
                .clone(),
            ref_trans_id: original_connector_txn_id,
        };

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let create_transaction_request_payload = CreateCaptureTransactionRequest {
            merchant_authentication,
            transaction_request: transaction_request_payload,
        };

        Ok(Self {
            create_transaction_request: create_transaction_request_payload,
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionVoidDetails {
    // Specific transaction details for Void
    transaction_type: TransactionType,
    ref_trans_id: String,
    amount: Option<f64>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionVoidRequest {
    // Used by Void Flow, wraps specific void transaction details
    merchant_authentication: AuthorizedotnetAuthType,
    ref_id: Option<String>,
    transaction_request: AuthorizedotnetTransactionVoidDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetVoidRequest {
    // Top-level wrapper for Void Flow
    create_transaction_request: CreateTransactionVoidRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetAuthType {
    name: Secret<String>,
    transaction_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AuthorizedotnetAuthType {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            Ok(Self {
                name: api_key.to_owned(),
                transaction_key: key1.to_owned(),
            })
        } else {
            Err(ConnectorError::FailedToObtainAuthType)?
        }
    }
}

impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
        >,
    > for AuthorizedotnetVoidRequest
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        // Generate a unique reference ID for the void transaction
        let ref_id = Some(format!(
            "void_req_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));

        // Extract transaction ID from the connector_transaction_id string
        // This transaction ID comes from the authorization response
        let transaction_id = match router_data.request.connector_transaction_id.as_str() {
            "" => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id"
                    }
                ));
            }
            id => id.to_string(),
        };

        let transaction_void_details = AuthorizedotnetTransactionVoidDetails {
            transaction_type: TransactionType::VoidTransaction,
            ref_trans_id: transaction_id,
            amount: None,
        };

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&router_data.connector_auth_type)?;

        let create_transaction_void_request = CreateTransactionVoidRequest {
            merchant_authentication,
            ref_id,
            transaction_request: transaction_void_details,
        };

        Ok(Self {
            create_transaction_request: create_transaction_void_request,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDetails {
    pub merchant_authentication: MerchantAuthentication,
    #[serde(rename = "transId")]
    pub transaction_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCreateSyncRequest {
    pub get_transaction_details_request: TransactionDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRSyncRequest {
    pub get_transaction_details_request: TransactionDetails,
}

impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for AuthorizedotnetCreateSyncRequest
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract connector_transaction_id from the request
        let connector_transaction_id = match &item.router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id"
                    }
                ))
            }
        };

        let merchant_authentication =
            MerchantAuthentication::try_from(&item.router_data.connector_auth_type)?;

        let payload = Self {
            get_transaction_details_request: TransactionDetails {
                merchant_authentication,
                transaction_id: Some(connector_transaction_id),
            },
        };
        Ok(payload)
    }
}

// Implementation for the RSync flow to support refund synchronization
impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for AuthorizedotnetRSyncRequest
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract connector_refund_id from the request
        let connector_refund_id = if !item.router_data.request.connector_refund_id.is_empty() {
            item.router_data.request.connector_refund_id.clone()
        } else {
            return Err(error_stack::report!(
                HsInterfacesConnectorError::MissingRequiredField {
                    field_name: "connector_refund_id"
                }
            ));
        };

        let merchant_authentication =
            MerchantAuthentication::try_from(&item.router_data.connector_auth_type)?;

        let payload = Self {
            get_transaction_details_request: TransactionDetails {
                merchant_authentication,
                transaction_id: Some(connector_refund_id),
            },
        };
        Ok(payload)
    }
}

// Refund-related structs and implementations
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundCardDetails {
    card_number: Secret<String>,
    expiration_date: Secret<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
enum AuthorizedotnetRefundPaymentDetails {
    CreditCard(CreditCardDetails),
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundTransactionDetails {
    transaction_type: TransactionType,
    amount: String,
    payment: PaymentDetails,
    ref_trans_id: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundRequest {
    create_transaction_request: CreateTransactionRefundRequest,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRefundRequest {
    merchant_authentication: AuthorizedotnetAuthType,
    ref_id: Option<String>,
    transaction_request: AuthorizedotnetRefundTransactionDetails,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardPayment {
    credit_card: CreditCardInfo,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardInfo {
    card_number: String,
    expiration_date: String,
}

impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for AuthorizedotnetRefundRequest
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Get connector metadata which contains payment details
        let payment_details = item
            .router_data
            .request
            .refund_connector_metadata
            .as_ref()
            .get_required_value("refund_connector_metadata")
            .change_context(HsInterfacesConnectorError::MissingRequiredField {
                field_name: "refund_connector_metadata",
            })?
            .clone();

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        // Handle the payment details which might be a JSON string or a serde_json::Value
        // We need to peek into the Secret to get the actual Value
        let payment_details_inner = payment_details.peek();
        let payment_details_value = match payment_details_inner {
            serde_json::Value::String(s) => {
                // If it's a string, try to parse it as JSON first
                serde_json::from_str::<serde_json::Value>(s.as_str())
                    .change_context(HsInterfacesConnectorError::RequestEncodingFailed)?
            }
            _ => payment_details_inner.clone(),
        };

        // Build the refund transaction request with parsed payment details
        let transaction_request = AuthorizedotnetRefundTransactionDetails {
            transaction_type: TransactionType::RefundTransaction,
            amount: item.router_data.request.minor_refund_amount.to_string(),
            payment: payment_details_value
                .parse_value("PaymentDetails")
                .change_context(HsInterfacesConnectorError::MissingRequiredField {
                    field_name: "payment_details",
                })?,
            ref_trans_id: item.router_data.request.connector_transaction_id.clone(),
        };

        Ok(Self {
            create_transaction_request: CreateTransactionRefundRequest {
                merchant_authentication,
                ref_id: Some(format!(
                    "refund_{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                )),
                transaction_request,
            },
        })
    }
}

// Refund request struct is fully implemented above

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TransactionResponse {
    AuthorizedotnetTransactionResponse(Box<AuthorizedotnetTransactionResponse>),
    AuthorizedotnetTransactionResponseError(Box<AuthorizedotnetTransactionResponseError>),
}

// Base transaction response - used internally
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionResponse {
    response_code: AuthorizedotnetPaymentStatus,
    #[serde(rename = "transId")]
    transaction_id: String,
    transaction_status: Option<String>,
    network_trans_id: Option<Secret<String>>,
    pub(super) account_number: Option<Secret<String>>,
    pub(super) errors: Option<Vec<ErrorMessage>>,
    secure_acceptance: Option<SecureAcceptance>,
}

// Create flow-specific response types
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetAuthorizeResponse(pub AuthorizedotnetPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetCaptureResponse(pub AuthorizedotnetPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetVoidResponse(pub AuthorizedotnetPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetRefundResponse(pub AuthorizedotnetPaymentsResponse);

// PSync response wrapper - Using direct structure instead of wrapping AuthorizedotnetPaymentsResponse
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetPSyncResponse {
    pub transaction: Option<SyncTransactionResponse>,
    pub messages: ResponseMessages,
}

// Implement From/TryFrom for the response types
impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetAuthorizeResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetCaptureResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetVoidResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetRefundResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

// We no longer need the From implementation for AuthorizedotnetPSyncResponse since we're using the direct structure

// TryFrom implementations for the router data conversions

impl<F> TryFrom<ResponseRouterData<AuthorizedotnetAuthorizeResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Use our helper function to convert the response
        let (status, response_result) = convert_to_payments_response_data_or_error(
            &response.0,
            http_code,
            Operation::Authorize,
            router_data.request.capture_method,
        )
        .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = response_result;

        Ok(new_router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<AuthorizedotnetCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Use our helper function to convert the response
        let (status, response_result) = convert_to_payments_response_data_or_error(
            &response.0,
            http_code,
            Operation::Capture,
            None,
        )
        .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = response_result;

        Ok(new_router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<AuthorizedotnetVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Use our helper function to convert the response
        let (status, response_result) = convert_to_payments_response_data_or_error(
            &response.0,
            http_code,
            Operation::Void,
            None,
        )
        .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = response_result;

        Ok(new_router_data)
    }
}

impl TryFrom<ResponseRouterData<AuthorizedotnetRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Use our refund helper function directly
        let (_attempt_status, refund_response) =
            convert_to_refund_response_data_or_error(&response.0, http_code)
                .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;

        // Set the status based on the refund result
        let refund_status = match &refund_response {
            Ok(refund_data) => refund_data.refund_status,
            Err(_) => RefundStatus::Failure,
        };

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = refund_status;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = refund_response;

        Ok(new_router_data)
    }
}

// Implementation for PSync flow
impl<F> TryFrom<ResponseRouterData<AuthorizedotnetPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // No need to transform the response since we're using the direct structure
        // Use the clean approach with the From trait implementation
        match response.transaction {
            Some(transaction) => {
                let payment_status = AttemptStatus::from(transaction.transaction_status);

                // Create a new RouterDataV2 with updated fields
                let mut new_router_data = router_data;

                // Update the status in resource_common_data
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = payment_status;
                new_router_data.resource_common_data = resource_common_data;

                // Set the response
                new_router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        transaction.transaction_id.clone(),
                    ),
                    redirection_data: Box::new(None),
                    mandate_reference: Box::new(None),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(transaction.transaction_id.clone()),
                    incremental_authorization_allowed: None,
                    raw_connector_response: None,
                });

                Ok(new_router_data)
            }
            None => {
                // Handle missing transaction response
                let status = match response.messages.result_code {
                    ResultCode::Error => AttemptStatus::Failure,
                    ResultCode::Ok => AttemptStatus::Pending,
                };

                let error_response = ErrorResponse {
                    status_code: http_code,
                    code: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.code.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.text.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: None,
                    attempt_status: Some(status),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };

                // Update router data with status and error response
                let mut new_router_data = router_data;
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = status;
                new_router_data.resource_common_data = resource_common_data;
                new_router_data.response = Err(error_response);

                Ok(new_router_data)
            }
        }
    }
}

// Helper function is no longer needed since we're using the direct structure

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub enum AuthorizedotnetPaymentStatus {
    #[serde(rename = "1")]
    Approved,
    #[serde(rename = "2")]
    Declined,
    #[serde(rename = "3")]
    Error,
    #[serde(rename = "4")]
    #[default]
    HeldForReview,
    #[serde(rename = "5")]
    RequiresAction, // Maps to hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorMessage {
    pub error_code: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthorizedotnetTransactionResponseError {
    _supplemental_data_qualification_indicator: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecureAcceptance {
    // Define fields for SecureAcceptance if it's actually used and its structure is known
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMessage {
    pub code: String,
    pub text: String,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ResultCode {
    #[default]
    Ok,
    Error,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMessages {
    result_code: ResultCode,
    pub message: Vec<ResponseMessage>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetPaymentsResponse {
    pub transaction_response: Option<TransactionResponse>,
    pub profile_response: Option<AuthorizedotnetNonZeroMandateResponse>,
    pub messages: ResponseMessages,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetNonZeroMandateResponse {
    customer_profile_id: Option<String>,
    customer_payment_profile_id_list: Option<Vec<String>>,
    pub messages: ResponseMessages,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Operation {
    Authorize,
    Capture,
    Void,
    Refund,
}

fn get_hs_status(
    response: &AuthorizedotnetPaymentsResponse,
    _http_status_code: u16,
    operation: Operation,
    capture_method: Option<enums::CaptureMethod>,
) -> AttemptStatus {
    match response.messages.result_code {
        ResultCode::Error => AttemptStatus::Failure,
        ResultCode::Ok => {
            match response.transaction_response {
                Some(ref trans_res_enum) => {
                    match trans_res_enum {
                        TransactionResponse::AuthorizedotnetTransactionResponse(trans_res) => {
                            match trans_res.response_code {
                                AuthorizedotnetPaymentStatus::Approved => match operation {
                                    // For Authorize operation, check the capture method
                                    Operation::Authorize => {
                                        // Check capture method to determine status
                                        match capture_method {
                                            // Manual capture -> Authorized status
                                            Some(enums::CaptureMethod::Manual) => {
                                                AttemptStatus::Authorized
                                            }
                                            // Automatic capture (or None) -> Charged status
                                            Some(enums::CaptureMethod::Automatic) | None => {
                                                AttemptStatus::Charged
                                            }
                                            // Any other method -> Charged (for backward compatibility)
                                            _ => AttemptStatus::Charged,
                                        }
                                    }
                                    Operation::Capture => AttemptStatus::Charged,
                                    Operation::Void => AttemptStatus::Voided,
                                    // For refunds, map Approved to Charged
                                    Operation::Refund => AttemptStatus::Charged,
                                },
                                AuthorizedotnetPaymentStatus::Declined => AttemptStatus::Failure,
                                AuthorizedotnetPaymentStatus::Error => AttemptStatus::Failure,
                                AuthorizedotnetPaymentStatus::HeldForReview => {
                                    AttemptStatus::Pending
                                }
                                AuthorizedotnetPaymentStatus::RequiresAction => {
                                    AttemptStatus::AuthenticationPending
                                }
                            }
                        }
                        TransactionResponse::AuthorizedotnetTransactionResponseError(_) => {
                            AttemptStatus::Failure
                        }
                    }
                }
                None => match operation {
                    Operation::Void => AttemptStatus::Voided, // Ensure this is returning Voided for void operations
                    Operation::Authorize | Operation::Capture => AttemptStatus::Pending,
                    Operation::Refund => AttemptStatus::Failure,
                },
            }
        }
    }
}

pub fn convert_to_payments_response_data_or_error(
    response: &AuthorizedotnetPaymentsResponse,
    http_status_code: u16,
    operation: Operation,
    capture_method: Option<enums::CaptureMethod>,
) -> Result<(AttemptStatus, Result<PaymentsResponseData, ErrorResponse>), HsInterfacesConnectorError>
{
    // Pass the capture_method from the payment request
    let status = get_hs_status(response, http_status_code, operation, capture_method);

    let response_payload_result = match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            if status == AttemptStatus::Authorized
                || status == AttemptStatus::Pending
                || status == AttemptStatus::AuthenticationPending
                || status == AttemptStatus::Charged
                || status == AttemptStatus::Voided
            {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        trans_res.transaction_id.clone(),
                    ),
                    redirection_data: Box::new(None),
                    connector_metadata: None,
                    mandate_reference: Box::new(None),
                    network_txn_id: trans_res
                        .network_trans_id
                        .as_ref()
                        .map(|s| s.peek().clone()),
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    raw_connector_response: None,
                })
            } else {
                // Failure status or other non-successful/active statuses handled by specific error mapping
                let error_code = trans_res
                    .errors
                    .as_ref()
                    .and_then(|e_list| e_list.first().map(|e| e.error_code.clone()))
                    .or_else(|| response.messages.message.first().map(|m| m.code.clone()))
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
                let error_message = trans_res
                    .errors
                    .as_ref()
                    .and_then(|e_list| e_list.first().map(|e| e.error_text.clone()))
                    .or_else(|| response.messages.message.first().map(|m| m.text.clone()))
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());

                Err(ErrorResponse {
                    status_code: http_status_code,
                    code: error_code,
                    message: error_message,
                    reason: None,
                    attempt_status: Some(status),
                    connector_transaction_id: Some(trans_res.transaction_id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                })
            }
        }
        Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_err_res)) => {
            Err(ErrorResponse {
                status_code: http_status_code,
                code: response
                    .messages
                    .message
                    .first()
                    .map(|m| m.code.clone())
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                message: response
                    .messages
                    .message
                    .first()
                    .map(|m| m.text.clone())
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: None,
                attempt_status: Some(status),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        }
        None => {
            if status == AttemptStatus::Voided && operation == Operation::Void {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::NoResponseId,
                    redirection_data: Box::new(None),
                    connector_metadata: None,
                    mandate_reference: Box::new(None),
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    raw_connector_response: None,
                })
            } else {
                Err(ErrorResponse {
                    status_code: http_status_code,
                    code: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.code.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.text.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: None,
                    attempt_status: Some(status),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                })
            }
        }
    };
    Ok((status, response_payload_result))
}

pub fn convert_to_refund_response_data_or_error(
    response: &AuthorizedotnetPaymentsResponse,
    http_status_code: u16,
) -> Result<(AttemptStatus, Result<RefundsResponseData, ErrorResponse>), HsInterfacesConnectorError>
{
    // Operation is implicitly Refund for this function
    let api_call_attempt_status = match response.messages.result_code {
        ResultCode::Error => AttemptStatus::Failure,
        ResultCode::Ok => match response.transaction_response {
            Some(TransactionResponse::AuthorizedotnetTransactionResponse(ref trans_res)) => {
                match trans_res.response_code {
                    AuthorizedotnetPaymentStatus::Approved => AttemptStatus::Charged,
                    AuthorizedotnetPaymentStatus::Declined => AttemptStatus::Failure,
                    AuthorizedotnetPaymentStatus::Error => AttemptStatus::Failure,
                    AuthorizedotnetPaymentStatus::HeldForReview => AttemptStatus::Pending,
                    AuthorizedotnetPaymentStatus::RequiresAction => {
                        AttemptStatus::AuthenticationPending
                    }
                }
            }
            Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_)) => {
                AttemptStatus::Failure
            }
            None => AttemptStatus::Pending,
        },
    };

    let refund_status = match api_call_attempt_status {
        AttemptStatus::Charged => RefundStatus::Success,
        AttemptStatus::Failure => RefundStatus::Failure,
        _ => RefundStatus::Pending,
    };

    match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            if refund_status == RefundStatus::Success || refund_status == RefundStatus::Pending {
                let response_data = RefundsResponseData {
                    connector_refund_id: trans_res.transaction_id.clone(),
                    refund_status,
                    raw_connector_response: None,
                };
                Ok((api_call_attempt_status, Ok(response_data)))
            } else {
                let error_code = trans_res
                    .errors
                    .as_ref()
                    .and_then(|e_list| e_list.first().map(|e| e.error_code.clone()))
                    .or_else(|| response.messages.message.first().map(|m| m.code.clone()))
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
                let error_message = trans_res
                    .errors
                    .as_ref()
                    .and_then(|e_list| e_list.first().map(|e| e.error_text.clone()))
                    .or_else(|| response.messages.message.first().map(|m| m.text.clone()))
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());

                let error_response = ErrorResponse {
                    code: error_code,
                    message: error_message,
                    reason: None,
                    status_code: http_status_code,
                    attempt_status: Some(api_call_attempt_status),
                    connector_transaction_id: Some(trans_res.transaction_id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };
                Ok((api_call_attempt_status, Err(error_response)))
            }
        }
        Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_)) | None => {
            if refund_status == RefundStatus::Success {
                let error_response = ErrorResponse {
                    code: consts::NO_ERROR_CODE.to_string(),
                    message: "Refund successful but connector_refund_id is missing from response."
                        .to_string(),
                    reason: Some(
                        "Successful refund response did not contain a transaction ID.".to_string(),
                    ),
                    status_code: http_status_code,
                    attempt_status: Some(api_call_attempt_status),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };
                return Ok((api_call_attempt_status, Err(error_response)));
            }
            let error_code = response
                .messages
                .message
                .first()
                .map(|m| m.code.clone())
                .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
            let error_message = response
                .messages
                .message
                .first()
                .map(|m| m.text.clone())
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());
            let error_response = ErrorResponse {
                code: error_code,
                message: error_message,
                reason: None,
                status_code: http_status_code,
                attempt_status: Some(api_call_attempt_status),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            };
            Ok((api_call_attempt_status, Err(error_response)))
        }
    }
}

// Transaction details for sync response used in PSync implementation

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncStatus {
    CapturedPendingSettlement,
    SettledSuccessfully,
    AuthorizedPendingCapture,
    Declined,
    Voided,
    CouldNotVoid,
    GeneralError,
    RefundSettledSuccessfully,
    RefundPendingSettlement,
    FDSPendingReview,
    FDSAuthorizedPendingReview,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTransactionResponse {
    #[serde(rename = "transId")]
    pub transaction_id: String,
    #[serde(rename = "transactionStatus")]
    pub transaction_status: SyncStatus,
    pub response_code: Option<u8>,
    pub response_reason_code: Option<u8>,
    pub response_reason_description: Option<String>,
    pub network_trans_id: Option<String>,
    // Additional fields available but not needed for our implementation
}

impl From<SyncStatus> for enums::AttemptStatus {
    fn from(transaction_status: SyncStatus) -> Self {
        match transaction_status {
            SyncStatus::SettledSuccessfully | SyncStatus::CapturedPendingSettlement => {
                Self::Charged
            }
            SyncStatus::AuthorizedPendingCapture => Self::Authorized,
            SyncStatus::Declined => Self::AuthenticationFailed,
            SyncStatus::Voided => Self::Voided,
            SyncStatus::CouldNotVoid => Self::VoidFailed,
            SyncStatus::GeneralError => Self::Failure,
            SyncStatus::RefundSettledSuccessfully
            | SyncStatus::RefundPendingSettlement
            | SyncStatus::FDSPendingReview
            | SyncStatus::FDSAuthorizedPendingReview => Self::Pending,
        }
    }
}

// Removing duplicate implementation

// RSync related types for Refund Sync
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RSyncStatus {
    RefundSettledSuccessfully,
    RefundPendingSettlement,
    Declined,
    GeneralError,
    Voided,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RSyncTransactionResponse {
    #[serde(rename = "transId")]
    transaction_id: String,
    transaction_status: RSyncStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetRSyncResponse {
    transaction: Option<RSyncTransactionResponse>,
    messages: ResponseMessages,
}

impl From<RSyncStatus> for enums::RefundStatus {
    fn from(transaction_status: RSyncStatus) -> Self {
        match transaction_status {
            RSyncStatus::RefundSettledSuccessfully => Self::Success,
            RSyncStatus::RefundPendingSettlement => Self::Pending,
            RSyncStatus::Declined | RSyncStatus::GeneralError | RSyncStatus::Voided => {
                Self::Failure
            }
        }
    }
}

impl TryFrom<ResponseRouterData<AuthorizedotnetRSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;

    fn try_from(
        value: ResponseRouterData<AuthorizedotnetRSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        match response.transaction {
            Some(transaction) => {
                let refund_status = enums::RefundStatus::from(transaction.transaction_status);

                // Create a new RouterDataV2 with updated fields
                let mut new_router_data = router_data;

                // Update the status in resource_common_data
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = refund_status;
                new_router_data.resource_common_data = resource_common_data;

                // Set the response
                new_router_data.response = Ok(RefundsResponseData {
                    connector_refund_id: transaction.transaction_id,
                    refund_status,
                    raw_connector_response: None,
                });

                Ok(new_router_data)
            }
            None => {
                // Handle error response
                let error_response = ErrorResponse {
                    status_code: http_code,
                    code: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.code.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.text.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };

                // Update router data with error response
                let mut new_router_data = router_data;
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = RefundStatus::Failure;
                new_router_data.resource_common_data = resource_common_data;
                new_router_data.response = Err(error_response);

                Ok(new_router_data)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetErrorResponse {
    pub messages: ResponseMessages,
}
