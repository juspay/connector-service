use crate::types::ResponseRouterData;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
};
use domain_types::{
    connector_flow::{PSync, Refund},
    connector_types::{RefundFlowData, RefundsData, RefundsResponseData},
};
use hyperswitch_api_models::enums as api_enums;
use hyperswitch_cards::CardNumberStrategy;
use hyperswitch_common_enums::enums;
use hyperswitch_common_utils::pii::Email;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::{consts, errors::ConnectorError};
// Alias to make the transition easier
type HsInterfacesConnectorError = ConnectorError;
use super::AuthorizedotnetRouterData;
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret, StrongSecret};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::str::FromStr;

type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

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
            _ => Err(error_stack::report!(
                hyperswitch_interfaces::errors::ConnectorError::FailedToObtainAuthType
            )),
        }
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
    #[serde(rename = "authOnlyTransaction")]
    AuthOnlyTransaction,
    #[serde(rename = "authCaptureTransaction")]
    AuthCaptureTransaction,
    #[serde(rename = "priorAuthCaptureTransaction")]
    PriorAuthCaptureTransaction,
    #[serde(rename = "voidTransaction")]
    VoidTransaction,
    #[serde(rename = "refundTransaction")]
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
    country: Option<String>,
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
    #[serde(rename = "transactionType")]
    transaction_type: TransactionType,
    amount: Option<String>,
    #[serde(rename = "currencyCode")]
    currency_code: Option<api_enums::Currency>,
    payment: Option<PaymentDetails>,
    profile: Option<ProfileDetails>,
    order: Option<Order>,
    customer: Option<CustomerDetails>,
    #[serde(rename = "billTo")]
    bill_to: Option<BillTo>,
    #[serde(rename = "shipTo")]
    ship_to: Option<ShipTo>,
    #[serde(rename = "customerIP")]
    customer_ip: Option<String>,
    #[serde(rename = "transactionSettings")]
    transaction_settings: Option<TransactionSettings>,
    #[serde(rename = "userFields")]
    user_fields: Option<UserFields>,
    #[serde(rename = "processingOptions")]
    processing_options: Option<ProcessingOptions>,
    #[serde(rename = "subsequentAuthInformation")]
    subsequent_auth_information: Option<SubsequentAuthInformation>,
    #[serde(rename = "authorizationIndicatorType")]
    authorization_indicator_type: Option<AuthorizationIndicatorType>,
    #[serde(rename = "refTransId")]
    ref_trans_id: Option<String>,
    #[serde(rename = "poNumber")]
    po_number: Option<String>,
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
                return Err(error_stack::report!(
                    hyperswitch_interfaces::errors::ConnectorError::NotSupported {
                        message: "Capture method not supported".to_string(),
                        connector: "authorizedotnet",
                    }
                ))
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

        // Extract metadata from connector_metadata string
        let metadata = match &item.router_data.request.metadata {
            Some(meta) => meta.clone(),
            None => serde_json::Value::Object(serde_json::Map::new()),
        };

        // Extract customer IP and poNumber from metadata
        let customer_ip = metadata
            .get("customerIP")
            .and_then(|v| v.as_str())
            .map(String::from);
        let po_number = metadata
            .get("poNumber")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Extract user fields from metadata
        let user_fields = metadata.get("userFields").and_then(|uf| {
            if uf.is_object() {
                let mut fields = Vec::new();
                if let Some(obj) = uf.as_object() {
                    for (key, value) in obj {
                        if let Some(val_str) = value.as_str() {
                            fields.push(UserField {
                                name: key.clone(),
                                value: val_str.to_string(),
                            });
                        }
                    }
                }
                if !fields.is_empty() {
                    Some(UserFields { user_field: fields })
                } else {
                    None
                }
            } else {
                None
            }
        });

        // Set up transaction settings
        let transaction_settings = Some(TransactionSettings {
            setting: vec![TransactionSetting {
                setting_name: "testRequest".to_string(),
                setting_value: "false".to_string(),
            }],
        });

        // Process billing address
        let billing_address = item.router_data.address.get_payment_billing();
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

        // Process shipping address
        let shipping_address = item.router_data.address.get_shipping();
        let ship_to = shipping_address.as_ref().map(|shipping| {
            let first_name = shipping.address.as_ref().and_then(|a| a.first_name.clone());
            let last_name = shipping.address.as_ref().and_then(|a| a.last_name.clone());

            ShipTo {
                first_name,
                last_name,
                company: shipping
                    .address
                    .as_ref()
                    .and_then(|a| a.line2.clone().map(|s| s.peek().clone()))
                    .or_else(|| Some("".to_string())),
                address: shipping.address.as_ref().and_then(|a| a.line1.clone()),
                city: shipping.address.as_ref().and_then(|a| a.city.clone()),
                state: shipping
                    .address
                    .as_ref()
                    .and_then(|a| a.state.clone().map(|s| s.peek().clone()))
                    .or_else(|| Some("".to_string())),
                zip: shipping.address.as_ref().and_then(|a| a.zip.clone()),
                country: shipping
                    .address
                    .as_ref()
                    .and_then(|a| a.country)
                    .map(|c| c.to_string()),
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
            ship_to,
            customer_ip,
            transaction_settings,
            user_fields,
            processing_options: None,
            subsequent_auth_information: None,
            authorization_indicator_type: None,
            ref_trans_id: None, // Not used for initial auth
            po_number,          // Add the poNumber from metadata
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
    #[serde(rename = "refTransId")]
    ref_trans_id: String,
    #[serde(rename = "poNumber")]
    po_number: Option<String>,
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

        let po_number = None;

        let transaction_request_payload = AuthorizedotnetCaptureTransactionInternal {
            transaction_type: TransactionType::PriorAuthCaptureTransaction,
            amount: item
                .router_data
                .request
                .amount_to_capture
                .to_string()
                .clone(),
            ref_trans_id: original_connector_txn_id,
            po_number,
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
    #[serde(rename = "refTransId")]
    ref_trans_id: String,
    amount: Option<f64>,
    #[serde(rename = "poNumber")]
    po_number: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionVoidRequest {
    // Used by Void Flow, wraps specific void transaction details
    merchant_authentication: AuthorizedotnetAuthType,
    #[serde(rename = "refId")]
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
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            Ok(Self {
                name: api_key.to_owned(),
                transaction_key: key1.to_owned(),
            })
        } else {
            Err(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainAuthType)?
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

        // No metadata available in void flow
        let po_number = None;

        // Create a reference ID for the void transaction
        let ref_id = Some("123456".to_string());

        let transaction_void_details = AuthorizedotnetTransactionVoidDetails {
            transaction_type: TransactionType::VoidTransaction,
            ref_trans_id: router_data.request.connector_transaction_id.clone(),
            amount: None,
            po_number,
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

// The following refund-related structs and implementations are commented out as they require L2 changes
/*
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
    payment: CreditCardPayment,
    #[serde(rename = "refTransId")]
    reference_transaction_id: String,
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
    #[serde(rename = "refId")]
    ref_id: Option<String>,
    transaction_request: AuthorizedotnetRefundTransactionDetails,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardPayment {
    credit_card: CreditCardInfo,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardInfo {
    card_number: String,
    expiration_date: String,
}

impl<'a> TryFrom<AuthorizedotnetRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>> for AuthorizedotnetRefundRequest {
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let req = &router_data.request;

        let amount_str = to_major_unit_string(req.minor_refund_amount, req.currency)?;

        let ref_trans_id = router_data.request.connector_transaction_id.clone();

        // Create a reference ID for the refund transaction
        let ref_id = Some(router_data.request.refund_id.clone());

        // For refunds in Authorize.net:
        // 1. We need the payment object with full card details
        // 2. We need to use the full card number for refunds, not just last 4 digits
        // 3. The expiration date should be in YYYY-MM format
        let credit_card_payment = CreditCardPayment {
            credit_card: CreditCardInfo {
                card_number: "5424000000000015".to_string(), // Test card number
                expiration_date: "2025-12".to_string(), // YYYY-MM format
            },
        };

        let transaction_request_details = AuthorizedotnetRefundTransactionDetails {
            transaction_type: TransactionType::RefundTransaction,
            amount: amount_str,
            payment: credit_card_payment,
            reference_transaction_id: ref_trans_id,
        };

        let merchant_authentication = AuthorizedotnetAuthType::try_from(&router_data.connector_auth_type)?;


        let create_transaction_req = CreateTransactionRefundRequest {
            merchant_authentication,
            ref_id,
            transaction_request: transaction_request_details,
        };


        Ok(Self {
            create_transaction_request: create_transaction_req,
        })
    }
}
*/

// Empty struct placeholder for refund functionality - will be implemented with L2 changes
#[derive(Debug, Serialize)]
pub struct AuthorizedotnetRefundRequest {}

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
            Err(_) => hyperswitch_common_enums::enums::RefundStatus::Failure,
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
                let payment_status = enums::AttemptStatus::from(transaction.transaction_status);

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
                });

                Ok(new_router_data)
            }
            None => {
                // Handle missing transaction response
                let status = match response.messages.result_code {
                    ResultCode::Error => enums::AttemptStatus::Failure,
                    ResultCode::Ok => enums::AttemptStatus::Pending,
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
) -> hyperswitch_common_enums::enums::AttemptStatus {
    match response.messages.result_code {
        ResultCode::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
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
                                                hyperswitch_common_enums::enums::AttemptStatus::Authorized
                                            },
                                            // Automatic capture (or None) -> Charged status
                                            Some(enums::CaptureMethod::Automatic) | None => {
                                                hyperswitch_common_enums::enums::AttemptStatus::Charged
                                            },
                                            // Any other method -> Charged (for backward compatibility)
                                            _ => hyperswitch_common_enums::enums::AttemptStatus::Charged
                                        }
                                    },
                                    Operation::Capture => hyperswitch_common_enums::enums::AttemptStatus::Charged,
                                    Operation::Void => hyperswitch_common_enums::enums::AttemptStatus::Voided,
                                    // For refunds, map Approved to Charged
                                    Operation::Refund => hyperswitch_common_enums::enums::AttemptStatus::Charged,
                                },
                                AuthorizedotnetPaymentStatus::Declined => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                                AuthorizedotnetPaymentStatus::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                                AuthorizedotnetPaymentStatus::HeldForReview => hyperswitch_common_enums::enums::AttemptStatus::Pending,
                                AuthorizedotnetPaymentStatus::RequiresAction => hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending,
                            }
                        }
                        TransactionResponse::AuthorizedotnetTransactionResponseError(_) => {
                            hyperswitch_common_enums::enums::AttemptStatus::Failure
                        }
                    }
                }
                None => match operation {
                    Operation::Void => hyperswitch_common_enums::enums::AttemptStatus::Voided,
                    Operation::Authorize | Operation::Capture => {
                        hyperswitch_common_enums::enums::AttemptStatus::Pending
                    }
                    Operation::Refund => hyperswitch_common_enums::enums::AttemptStatus::Failure,
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
) -> Result<
    (
        hyperswitch_common_enums::enums::AttemptStatus,
        Result<PaymentsResponseData, ErrorResponse>,
    ),
    HsInterfacesConnectorError,
> {
    // Pass the capture_method from the payment request
    let status = get_hs_status(response, http_status_code, operation, capture_method);

    let response_payload_result = match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            if status == hyperswitch_common_enums::enums::AttemptStatus::Authorized
                || status == hyperswitch_common_enums::enums::AttemptStatus::Pending
                || status == hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending
                || status == hyperswitch_common_enums::enums::AttemptStatus::Charged
                || status == hyperswitch_common_enums::enums::AttemptStatus::Voided
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
            })
        }
        None => {
            if status == hyperswitch_common_enums::enums::AttemptStatus::Voided
                && operation == Operation::Void
            {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::NoResponseId,
                    redirection_data: Box::new(None),
                    connector_metadata: None,
                    mandate_reference: Box::new(None),
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
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
                })
            }
        }
    };
    Ok((status, response_payload_result))
}

pub fn convert_to_refund_response_data_or_error(
    response: &AuthorizedotnetPaymentsResponse,
    http_status_code: u16,
) -> Result<
    (
        hyperswitch_common_enums::enums::AttemptStatus,
        Result<RefundsResponseData, ErrorResponse>,
    ),
    HsInterfacesConnectorError,
> {
    // Operation is implicitly Refund for this function
    let api_call_attempt_status = match response.messages.result_code {
        ResultCode::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
        ResultCode::Ok => match response.transaction_response {
            Some(TransactionResponse::AuthorizedotnetTransactionResponse(ref trans_res)) => {
                match trans_res.response_code {
                    AuthorizedotnetPaymentStatus::Approved => {
                        hyperswitch_common_enums::enums::AttemptStatus::Charged
                    }
                    AuthorizedotnetPaymentStatus::Declined => {
                        hyperswitch_common_enums::enums::AttemptStatus::Failure
                    }
                    AuthorizedotnetPaymentStatus::Error => {
                        hyperswitch_common_enums::enums::AttemptStatus::Failure
                    }
                    AuthorizedotnetPaymentStatus::HeldForReview => {
                        hyperswitch_common_enums::enums::AttemptStatus::Pending
                    }
                    AuthorizedotnetPaymentStatus::RequiresAction => {
                        hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending
                    }
                }
            }
            Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_)) => {
                hyperswitch_common_enums::enums::AttemptStatus::Failure
            }
            None => hyperswitch_common_enums::enums::AttemptStatus::Pending,
        },
    };

    let refund_status = match api_call_attempt_status {
        hyperswitch_common_enums::enums::AttemptStatus::Charged => {
            hyperswitch_common_enums::enums::RefundStatus::Success
        }
        hyperswitch_common_enums::enums::AttemptStatus::Failure => {
            hyperswitch_common_enums::enums::RefundStatus::Failure
        }
        _ => hyperswitch_common_enums::enums::RefundStatus::Pending,
    };

    match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            if refund_status == hyperswitch_common_enums::enums::RefundStatus::Success
                || refund_status == hyperswitch_common_enums::enums::RefundStatus::Pending
            {
                let response_data = RefundsResponseData {
                    connector_refund_id: trans_res.transaction_id.clone(),
                    refund_status,
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
                };
                Ok((api_call_attempt_status, Err(error_response)))
            }
        }
        Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_)) | None => {
            if refund_status == hyperswitch_common_enums::enums::RefundStatus::Success {
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetErrorResponse {
    pub messages: ResponseMessages,
}
