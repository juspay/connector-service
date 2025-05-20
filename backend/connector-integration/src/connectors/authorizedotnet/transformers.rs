use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, ResponseId},
};
use domain_types::{
    connector_flow::Refund,
    connector_types::{RefundFlowData, RefundsData, RefundsResponseData},
};
use hyperswitch_api_models::enums as api_enums;
use hyperswitch_common_enums::enums;
use hyperswitch_common_utils::{
    types::MinorUnit, pii::Email
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_cards::CardNumberStrategy;
use hyperswitch_interfaces::{
    api, consts, errors::{ConnectorError as HsInterfacesConnectorError}
};
use hyperswitch_masking::{PeekInterface, Secret, StrongSecret};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::str::FromStr;

// Helper to convert minor units to f64 major units
// Authorize.net expects amounts as strings representing major units (e.g., "12.34")
fn to_major_unit_string(amount: MinorUnit, _curr: api_enums::Currency) -> Result<String, HsInterfacesConnectorError> {
    let val = amount.get_amount_as_i64();
    Ok(format!("{}.{:02}", val / 100, val % 100))
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

//============= AUTH STRUCTS =====================
#[skip_serializing_none]
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MerchantAuthentication {
    name: Secret<String>,
    transaction_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for MerchantAuthentication {
    type Error = HsInterfacesConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                name: api_key.clone(),
                transaction_key: key1.clone(),
            }),
            _ => Err(HsInterfacesConnectorError::FailedToObtainAuthType),
        }
    }
}

//============= ROUTER DATA =====================
#[derive(Debug, Serialize)]
pub struct AuthorizedotnetRouterData<T> {
    pub amount: String,
    pub router_data: T,
    pub merchant_auth: MerchantAuthentication,
}

impl<T> TryFrom<(&api::CurrencyUnit, api_enums::Currency, MinorUnit, T, MerchantAuthentication)> for AuthorizedotnetRouterData <T>
{
    type Error = HsInterfacesConnectorError;
    fn try_from(
        (_currency_unit, currency, minor_amount, item, merchant_auth): (
            &api::CurrencyUnit,
            api_enums::Currency,
            MinorUnit,
            T,
            MerchantAuthentication,
        ),
    ) -> Result<Self, Self::Error> {
        let amount_str = to_major_unit_string(minor_amount, currency)?;
        // let amount =get_amount_as_f64(_currency_unit, minor_amount, currency)?;
        Ok(Self {
            amount: amount_str,
            router_data: item,
            merchant_auth,
        })
    }
}


//============= REQUEST STRUCTS (COMMON) =====================

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardDetails {
    card_number: StrongSecret<String, CardNumberStrategy>,
    expiration_date: Secret<String>, // YYYY-MM
    card_code: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
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
    original_network_trans_id:  Secret<String>,
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
pub struct AuthorizedotnetTransactionRequest { // General structure for transaction details in Authorize
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

//============= AUTHORIZE REQUEST STRUCTS =====================

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRequest { // Used by Authorize Flow, wraps the general transaction request
    merchant_authentication: MerchantAuthentication,
    transaction_request: AuthorizedotnetTransactionRequest, 
    ref_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizedotnetPaymentsRequest { // Top-level wrapper for Authorize Flow
    create_transaction_request: CreateTransactionRequest,
}

impl<'a> TryFrom<&AuthorizedotnetRouterData<&'a RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>> for AuthorizedotnetPaymentsRequest {
    type Error = HsInterfacesConnectorError;
    fn try_from(item: &AuthorizedotnetRouterData<&'a RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        let router_data_ref = item.router_data;
        let card_data = match &router_data_ref.request.payment_method_data {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(HsInterfacesConnectorError::RequestEncodingFailed), 
        }?;

        let expiry_month = card_data.card_exp_month.peek().clone();
        let year = card_data.card_exp_year.peek().clone();
        let expiry_year = if year.len() == 2 { format!("20{}", year) } else { year };
        let expiration_date = format!("{}-{}", expiry_year, expiry_month);

        let credit_card_details = CreditCardDetails {
            card_number: StrongSecret::new(card_data.card_number.peek().to_string()),
            expiration_date: Secret::new(expiration_date),
            card_code: Some(card_data.card_cvc.clone()),
        };

        let payment_details = PaymentDetails::CreditCard(credit_card_details);

        let transaction_type = match router_data_ref.request.capture_method {
            Some(enums::CaptureMethod::Manual) => TransactionType::AuthOnlyTransaction,
            Some(enums::CaptureMethod::Automatic) | None => TransactionType::AuthCaptureTransaction,
            Some(_) => return Err(HsInterfacesConnectorError::NotSupported { 
                message: "Capture method not supported".to_string(),
                connector: "authorizedotnet",
            }),
        };

        let merchant_auth = item.merchant_auth.clone();
        
        let order_description = router_data_ref.resource_common_data.description.clone().unwrap_or_else(|| "Payment".to_string());
        
        let order = Order {
            invoice_number: router_data_ref.request.merchant_order_reference_id.clone().unwrap_or_else(|| router_data_ref.resource_common_data.payment_id.clone()),
            description: order_description,
        };

        let billing_address = router_data_ref.address.get_payment_billing();
        let bill_to = billing_address.as_ref().map(|billing| {
            let first_name = billing.address.as_ref().and_then(|a| a.first_name.clone());
            let last_name = billing.address.as_ref().and_then(|a| a.last_name.clone());

            BillTo {
                first_name,
                last_name,
                address: billing.address.as_ref().and_then(|a| a.line1.clone()),
                city: billing.address.as_ref().and_then(|a| a.city.clone()),
                state: billing.address.as_ref().and_then(|a| a.state.clone()),
                zip: billing.address.as_ref().and_then(|a| a.zip.clone()),
                country: billing.address.as_ref().and_then(|a| a.country).and_then(|api_country| {
                    enums::CountryAlpha2::from_str(&api_country.to_string()).ok()
                }),
            }
        });
        
        let customer_id_string: String = router_data_ref.request.customer_id.as_ref()
            .map(|cid| cid.get_string_repr().to_owned())
            .unwrap_or_else(|| "anonymous_customer".to_string()); // Placeholder for now

        let customer_details = CustomerDetails {
            id: customer_id_string,
            email: router_data_ref.request.email.clone(),
        };

        let currency_str = router_data_ref.request.currency.to_string();
        let currency = api_enums::Currency::from_str(&currency_str)
            .map_err(|_| HsInterfacesConnectorError::RequestEncodingFailed)?;

        let transaction_request_auth = AuthorizedotnetTransactionRequest {
            transaction_type,
            amount: Some(item.amount.clone()),
            currency_code: Some(currency),
            payment: Some(payment_details),
            profile: None,
            order: Some(order),
            customer: Some(customer_details),
            bill_to,
            user_fields: None,
            processing_options: None,
            subsequent_auth_information: None,
            authorization_indicator_type: None,
            ref_trans_id: None, // Not used for initial auth
        };

        let create_transaction_request = CreateTransactionRequest {
            merchant_authentication: merchant_auth,
            transaction_request: transaction_request_auth,
            ref_id: Some(router_data_ref.resource_common_data.payment_id.clone()),
        };

        Ok(AuthorizedotnetPaymentsRequest {
            create_transaction_request,
        })
    }
}

//============= CAPTURE REQUEST STRUCTS =====================

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCaptureTransactionInternal { // Specific transaction details for Capture
    transaction_type: TransactionType,
    amount: String,
    ref_trans_id: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCaptureTransactionRequest { // Used by Capture Flow, wraps specific capture transaction details
    merchant_authentication: MerchantAuthentication,
    transaction_request: AuthorizedotnetCaptureTransactionInternal,
}

#[derive(Debug, Serialize)]
pub struct AuthorizedotnetCaptureRequest { // Top-level wrapper for Capture Flow
    create_transaction_request: CreateCaptureTransactionRequest,
}

impl<'a> TryFrom<&AuthorizedotnetRouterData<&'a RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>> for AuthorizedotnetCaptureRequest {
    type Error = HsInterfacesConnectorError;
    fn try_from(item: &AuthorizedotnetRouterData<&'a RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        let router_data_ref = item.router_data;

        let original_connector_txn_id = match &router_data_ref.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(HsInterfacesConnectorError::MissingRequiredField { field_name: "connector_transaction_id" }),
        };
        
        let transaction_request_payload = AuthorizedotnetCaptureTransactionInternal {
            transaction_type: TransactionType::PriorAuthCaptureTransaction,
            amount: item.amount.clone(), 
            ref_trans_id: original_connector_txn_id,
        };

        let create_transaction_request_payload = CreateCaptureTransactionRequest {
            merchant_authentication: item.merchant_auth.clone(),
            transaction_request: transaction_request_payload,
        };

        Ok(Self {
            create_transaction_request: create_transaction_request_payload,
        })
    }
}

//============= VOID REQUEST STRUCTS =====================

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionVoidDetails { // Specific transaction details for Void
    transaction_type: TransactionType,
    ref_trans_id: String, 
    amount: Option<f64>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionVoidRequest { // Used by Void Flow, wraps specific void transaction details
    merchant_authentication: MerchantAuthentication,
    transaction_request: AuthorizedotnetTransactionVoidDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetVoidRequest { // Top-level wrapper for Void Flow
    create_transaction_request: CreateTransactionVoidRequest,
}

impl<'a> TryFrom<(&'a RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>, MerchantAuthentication)> for AuthorizedotnetVoidRequest {
    type Error = HsInterfacesConnectorError;

    fn try_from(
        item: (&'a RouterDataV2<domain_types::connector_flow::Void, PaymentFlowData, domain_types::connector_types::PaymentVoidData, PaymentsResponseData>, MerchantAuthentication),
    ) -> Result<Self, Self::Error> {
        let (router_data, merchant_auth) = item;

        let transaction_void_details = AuthorizedotnetTransactionVoidDetails {
            transaction_type: TransactionType::VoidTransaction,
            ref_trans_id: router_data.request.connector_transaction_id.clone(),
            amount: None,
        };

        let create_transaction_void_request = CreateTransactionVoidRequest {
            merchant_authentication: merchant_auth,
            transaction_request: transaction_void_details,
        };

        Ok(Self {
            create_transaction_request: create_transaction_void_request,
        })
    }
} 

//============= REFUND REQUEST STRUCTS =====================

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
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundTransactionDetails {
    transaction_type: TransactionType,
    amount: String,
    currency_code: String,
    reference_transaction_id: String,
    payment: Option<AuthorizedotnetRefundPaymentDetails>,
    order: Option<Order>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRefundRequest {
    merchant_authentication: MerchantAuthentication,
    transaction_request: AuthorizedotnetRefundTransactionDetails,
}

#[derive(Debug, Serialize)]
pub struct AuthorizedotnetRefundRequest {
    create_transaction_request: CreateTransactionRefundRequest,
}

impl<'a> TryFrom<(&'a RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, MerchantAuthentication)> for AuthorizedotnetRefundRequest {
    type Error = HsInterfacesConnectorError;

    fn try_from(
        item: (&'a RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, MerchantAuthentication),
    ) -> Result<Self, Self::Error> {
        let (router_data, merchant_auth) = item;
        let req = &router_data.request;

        let amount_str = to_major_unit_string(req.minor_refund_amount, req.currency)?;

        let ref_trans_id = router_data.request.connector_transaction_id.clone();

        let refund_payment_details: Option<AuthorizedotnetRefundPaymentDetails> = None;
        
        let order_details = Some(Order {
            invoice_number: req.refund_id.clone(),
            description: format!("Refund for {}", req.refund_id),
        });

        let transaction_request_details = AuthorizedotnetRefundTransactionDetails {
            transaction_type: TransactionType::RefundTransaction,
            amount: amount_str,
            currency_code: req.currency.to_string(),
            reference_transaction_id: ref_trans_id,
            payment: refund_payment_details,
            order: order_details,
        };

        let create_transaction_req = CreateTransactionRefundRequest {
            merchant_authentication: merchant_auth,
            transaction_request: transaction_request_details,
        };

        Ok(Self {
            create_transaction_request: create_transaction_req,
        })
    }
}

//============= RESPONSE STRUCTS =====================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TransactionResponse {
    AuthorizedotnetTransactionResponse(Box<AuthorizedotnetTransactionResponse>),
    AuthorizedotnetTransactionResponseError(Box<AuthorizedotnetTransactionResponseError>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionResponse {
    response_code: AuthorizedotnetPaymentStatus,
    #[serde(rename = "transId")]
    transaction_id: String,
    network_trans_id: Option<Secret<String>>,
    pub(super) account_number: Option<Secret<String>>,
    pub(super) errors: Option<Vec<ErrorMessage>>,
    secure_acceptance: Option<SecureAcceptance>,
}

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

#[derive(Debug,Default, Clone, Deserialize,PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMessage { 
    pub code: String,
    pub text: String,
}

#[derive(Debug,Default, Clone, Deserialize, PartialEq, Serialize)]
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

fn get_hs_status(response: &AuthorizedotnetPaymentsResponse, _http_status_code: u16, operation: Operation) -> hyperswitch_common_enums::enums::AttemptStatus {
    match response.messages.result_code {
        ResultCode::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
        ResultCode::Ok => {
            match response.transaction_response {
                Some(ref trans_res_enum) => {
                    match trans_res_enum {
                        TransactionResponse::AuthorizedotnetTransactionResponse(trans_res) => {
                            match trans_res.response_code {
                                AuthorizedotnetPaymentStatus::Approved => match operation {
                                    Operation::Authorize => hyperswitch_common_enums::enums::AttemptStatus::Authorized,
                                    Operation::Capture => hyperswitch_common_enums::enums::AttemptStatus::Charged,
                                    Operation::Void => hyperswitch_common_enums::enums::AttemptStatus::Voided,
                                    Operation::Refund => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                                },
                                AuthorizedotnetPaymentStatus::Declined => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                                AuthorizedotnetPaymentStatus::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                                AuthorizedotnetPaymentStatus::HeldForReview => hyperswitch_common_enums::enums::AttemptStatus::Pending,
                                AuthorizedotnetPaymentStatus::RequiresAction => hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending,
                            }
                        }
                        TransactionResponse::AuthorizedotnetTransactionResponseError(_) => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                    }
                }
                None => {
                    match operation {
                        Operation::Void => hyperswitch_common_enums::enums::AttemptStatus::Voided,
                        Operation::Authorize | Operation::Capture => hyperswitch_common_enums::enums::AttemptStatus::Pending,
                        Operation::Refund => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                    }
                }
            }
        }
    }
}

pub fn convert_to_payments_response_data_or_error(
    response: &AuthorizedotnetPaymentsResponse,
    http_status_code: u16,
    operation: Operation,
) -> Result<(hyperswitch_common_enums::enums::AttemptStatus, Result<PaymentsResponseData, ErrorResponse>), HsInterfacesConnectorError> {
    let status = get_hs_status(response, http_status_code, operation);

    let response_payload_result = match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            if status == hyperswitch_common_enums::enums::AttemptStatus::Authorized || 
               status == hyperswitch_common_enums::enums::AttemptStatus::Pending || 
               status == hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending ||
               status == hyperswitch_common_enums::enums::AttemptStatus::Charged ||
               status == hyperswitch_common_enums::enums::AttemptStatus::Voided
            {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(trans_res.transaction_id.clone()),
                    redirection_data: Box::new(None), 
                    connector_metadata: None, 
                    mandate_reference: Box::new(None), 
                    network_txn_id: trans_res.network_trans_id.as_ref().map(|s| s.peek().clone()),
                    connector_response_reference_id: None, 
                    incremental_authorization_allowed: None, 
                })
            } else { // Failure status or other non-successful/active statuses handled by specific error mapping
                let error_code = trans_res.errors.as_ref()
                    .and_then(|e_list| e_list.first().map(|e| e.error_code.clone()))
                    .or_else(|| response.messages.message.first().map(|m| m.code.clone()))
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
                let error_message = trans_res.errors.as_ref()
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
                code: response.messages.message.first().map(|m| m.code.clone()).unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                message: response.messages.message.first().map(|m| m.text.clone()).unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: None,
                attempt_status: Some(status),
                connector_transaction_id: None, 
            })
        }
        None => {
            if status == hyperswitch_common_enums::enums::AttemptStatus::Voided && operation == Operation::Void {
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
                    code: response.messages.message.first().map(|m| m.code.clone()).unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: response.messages.message.first().map(|m| m.text.clone()).unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
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
) -> Result<(hyperswitch_common_enums::enums::AttemptStatus, Result<RefundsResponseData, ErrorResponse>), HsInterfacesConnectorError> {
    // Operation is implicitly Refund for this function
    let api_call_attempt_status = match response.messages.result_code {
        ResultCode::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
        ResultCode::Ok => {
            match response.transaction_response {
                Some(TransactionResponse::AuthorizedotnetTransactionResponse(ref trans_res)) => {
                    match trans_res.response_code {
                        AuthorizedotnetPaymentStatus::Approved => hyperswitch_common_enums::enums::AttemptStatus::Charged,
                        AuthorizedotnetPaymentStatus::Declined => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                        AuthorizedotnetPaymentStatus::Error => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                        AuthorizedotnetPaymentStatus::HeldForReview => hyperswitch_common_enums::enums::AttemptStatus::Pending,
                        AuthorizedotnetPaymentStatus::RequiresAction => hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending,
                    }
                }
                Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_)) => hyperswitch_common_enums::enums::AttemptStatus::Failure,
                None => hyperswitch_common_enums::enums::AttemptStatus::Pending,
            }
        }
    };

    let refund_status = match api_call_attempt_status {
        hyperswitch_common_enums::enums::AttemptStatus::Charged => hyperswitch_common_enums::enums::RefundStatus::Success,
        hyperswitch_common_enums::enums::AttemptStatus::Failure => hyperswitch_common_enums::enums::RefundStatus::Failure,
        _ => hyperswitch_common_enums::enums::RefundStatus::Pending,
    };

    match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            if refund_status == hyperswitch_common_enums::enums::RefundStatus::Success || refund_status == hyperswitch_common_enums::enums::RefundStatus::Pending {
                let response_data = RefundsResponseData {
                    connector_refund_id: trans_res.transaction_id.clone(),
                    refund_status,
                };
                Ok((api_call_attempt_status, Ok(response_data)))
            } else {
                let error_code = trans_res.errors.as_ref()
                    .and_then(|e_list| e_list.first().map(|e| e.error_code.clone()))
                    .or_else(|| response.messages.message.first().map(|m| m.code.clone()))
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
                let error_message = trans_res.errors.as_ref()
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
                    message: "Refund successful but connector_refund_id is missing from response.".to_string(),
                    reason: Some("Successful refund response did not contain a transaction ID.".to_string()),
                    status_code: http_status_code,
                    attempt_status: Some(api_call_attempt_status),
                    connector_transaction_id: None,
                };
                return Ok((api_call_attempt_status, Err(error_response)));
            }
            let error_code = response.messages.message.first().map(|m| m.code.clone()).unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
            let error_message = response.messages.message.first().map(|m| m.text.clone()).unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetErrorResponse {
    pub messages: ResponseMessages,
}

// Implementation of ForeignTryFrom for payment flows (Authorize, Capture, Void)
impl<Flow, ReqBody> ForeignTryFrom<(
    AuthorizedotnetPaymentsResponse, // The parsed connector response
    RouterDataV2<Flow, PaymentFlowData, ReqBody, PaymentsResponseData>, // The incoming RouterData, used for cloning
    u16, // http_status_code
    Operation, // The operation type (Authorize, Capture, Void)
)> for RouterDataV2<Flow, PaymentFlowData, ReqBody, PaymentsResponseData>
where
    Flow: Clone,
    ReqBody: Clone,
    // PaymentFlowData needs to be constructible and updatable with new status.
    // It's part of RouterDataV2's resource_common_data field.
    // Let's assume PaymentFlowData itself is cloneable and can be updated field by field or reconstructed.
    domain_types::connector_types::PaymentFlowData: Clone, // Specify PaymentFlowData from domain_types
{
    type Error = HsInterfacesConnectorError;

    fn foreign_try_from(
        item: (
            AuthorizedotnetPaymentsResponse,
            RouterDataV2<Flow, PaymentFlowData, ReqBody, PaymentsResponseData>,
            u16,
            Operation,
        ),
    ) -> Result<Self, Self::Error> {
        let (connector_response, router_data_in, http_code, operation) = item;

        let current_status = get_hs_status(&connector_response, http_code, operation);

        let response_payload_result = match &connector_response.transaction_response {
            Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
                if current_status == hyperswitch_common_enums::enums::AttemptStatus::Authorized || 
                   current_status == hyperswitch_common_enums::enums::AttemptStatus::Pending || 
                   current_status == hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending ||
                   current_status == hyperswitch_common_enums::enums::AttemptStatus::Charged ||
                   current_status == hyperswitch_common_enums::enums::AttemptStatus::Voided
                {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(trans_res.transaction_id.clone()),
                        redirection_data: Box::new(None), 
                        connector_metadata: None, 
                        mandate_reference: Box::new(None), 
                        network_txn_id: trans_res.network_trans_id.as_ref().map(|s| s.peek().clone()),
                        connector_response_reference_id: None, 
                        incremental_authorization_allowed: None, 
                    })
                } else {
                    let error_code = trans_res.errors.as_ref()
                        .and_then(|e_list| e_list.first().map(|e| e.error_code.clone()))
                        .or_else(|| connector_response.messages.message.first().map(|m| m.code.clone()))
                        .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
                    let error_message = trans_res.errors.as_ref()
                        .and_then(|e_list| e_list.first().map(|e| e.error_text.clone()))
                        .or_else(|| connector_response.messages.message.first().map(|m| m.text.clone()))
                        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());

                    Err(ErrorResponse {
                        status_code: http_code,
                        code: error_code,
                        message: error_message,
                        reason: None,
                        attempt_status: Some(current_status),
                        connector_transaction_id: Some(trans_res.transaction_id.clone()),
                    })
                }
            }
            Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_err_res)) => {
                Err(ErrorResponse {
                    status_code: http_code,
                    code: connector_response.messages.message.first().map(|m| m.code.clone()).unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: connector_response.messages.message.first().map(|m| m.text.clone()).unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: None,
                    attempt_status: Some(current_status),
                    connector_transaction_id: None, 
                })
            }
            None => { 
                if current_status == hyperswitch_common_enums::enums::AttemptStatus::Voided && operation == Operation::Void {
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
                        status_code: http_code,
                        code: connector_response.messages.message.first().map(|m| m.code.clone()).unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                        message: connector_response.messages.message.first().map(|m| m.text.clone()).unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                        reason: Some("Transaction response missing for non-void OK operation".to_string()),
                        attempt_status: Some(current_status), 
                        connector_transaction_id: None,
                    })
                }
            }
        };

        let mut router_data_out = router_data_in.clone();
        router_data_out.resource_common_data.status = current_status;
        router_data_out.response = response_payload_result;

        Ok(router_data_out)
    }
} 