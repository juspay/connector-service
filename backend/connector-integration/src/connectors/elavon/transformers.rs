use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId as DomainResponseId}};
use error_stack::{report, ResultExt};
use hyperswitch_cards::CardNumber;
use hyperswitch_common_utils::types::StringMajorUnit;
use hyperswitch_domain_models::{
    payment_address::PaymentAddress,
    payment_method_data::{Card, PaymentMethodData},
    router_data_v2::RouterDataV2,
    router_data::{ConnectorAuthType, ErrorResponse, PaymentMethodToken},
};
use hyperswitch_interfaces::{
    errors::{self},
    consts as hs_interface_consts,
};
use hyperswitch_common_enums::{
    AttemptStatus as HyperswitchAttemptStatus,
    CaptureMethod as HyperswitchCaptureMethod,
    Currency,
    FutureUsage,
    RefundStatus as HyperswitchRefundStatus,
};

use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use serde::de::{self, Deserializer};

#[derive(Debug, Clone, Serialize)]
pub struct ElavonAuthType {
    pub(super) ssl_merchant_id: Secret<String>,
    pub(super) ssl_user_id: Secret<String>,
    pub(super) ssl_pin: Secret<String>,
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

impl TryFrom<&ConnectorAuthType> for ElavonAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret } => Ok(Self {
                ssl_merchant_id: api_key.clone(),
                ssl_user_id: key1.clone(),
                ssl_pin: api_secret.clone(),
            }),
            _ => Err(report!(errors::ConnectorError::FailedToObtainAuthType)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransactionType {
    CcSale, 
    CcAuthOnly,
    CcComplete,
    CcReturn,
    TxnQuery,
}

#[derive(Debug)]
pub struct ElavonRouterData<T> {
    pub amount: StringMajorUnit,
    pub router_data: T,
}

impl<T> TryFrom<(StringMajorUnit, T)> for ElavonRouterData<T> {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from((amount, item): (StringMajorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize)] pub struct CardPaymentRequest {
    pub ssl_transaction_type: TransactionType,
    pub ssl_account_id: Secret<String>,
    pub ssl_user_id: Secret<String>,
    pub ssl_pin: Secret<String>,
    pub ssl_amount: StringMajorUnit,
    pub ssl_card_number: CardNumber,
    pub ssl_exp_date: Secret<String>,
    pub ssl_cvv2cvc2: Option<Secret<String>>,
    pub ssl_cvv2cvc2_indicator: Option<i32>,
    pub ssl_email: Option<hyperswitch_common_utils::pii::Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_add_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_token_source: Option<String>,
    pub ssl_get_token: Option<String>,
    pub ssl_transaction_currency: Currency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_avs_address: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_avs_zip: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_customer_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_invoice_number: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ElavonPaymentsRequest {
    Card(CardPaymentRequest),

}


fn get_avs_details_from_payment_address(payment_address: Option<&PaymentAddress>) -> (Option<Secret<String>>, Option<Secret<String>>) {
    payment_address.and_then(|addr| { 
        addr.get_payment_billing().as_ref().and_then(|billing_api_address| { 
            billing_api_address.address.as_ref().map(|detailed_address| {
                (detailed_address.line1.clone(), detailed_address.zip.clone())
            })
        })
    }).unwrap_or((None, None))
}

impl
    TryFrom<
        &ElavonRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for ElavonPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &ElavonRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => Self::try_from((item, card)),
            _ => Err(report!(errors::ConnectorError::NotImplemented(
                "Only card payments are supported for Elavon".to_string()
            ))),
        }
    }
}

impl
    TryFrom<(
        &ElavonRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
        &Card,
    )> for ElavonPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (item, card): (
            &ElavonRouterData<
                &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            >,
            &Card,
        ),
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let request_data = &router_data.request;
        let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;

        let transaction_type = match request_data.capture_method {
            Some(HyperswitchCaptureMethod::Manual) => TransactionType::CcAuthOnly,
            Some(HyperswitchCaptureMethod::Automatic) => TransactionType::CcSale,
            None => TransactionType::CcSale, 
            Some(other_capture_method) => Err(report!(errors::ConnectorError::FlowNotSupported {
                 flow: format!("Capture method: {:?}", other_capture_method),
                 connector: "Elavon".to_string()
            }))?,
        };

        let exp_month = card.card_exp_month.peek().to_string();
        let formatted_exp_month = format!("{:0>2}", exp_month);
        
        let exp_year = card.card_exp_year.peek().to_string();
        let formatted_exp_year = if exp_year.len() == 4 { &exp_year[2..] } else { &exp_year };
        let exp_date = format!("{}{}", formatted_exp_month, formatted_exp_year);

        let (avs_address, avs_zip) = get_avs_details_from_payment_address(Some(&router_data.resource_common_data.address));

        let cvv_indicator = if card.card_cvc.peek().is_empty() { Some(0) } else { Some(1) };

        let customer_id_str = request_data.customer_id.as_ref().map(|c| c.get_string_repr().to_string());

        let add_token = request_data.setup_future_usage
            .as_ref()
            .and_then(|sfu: &FutureUsage| {
                if *sfu == FutureUsage::OnSession || *sfu == FutureUsage::OffSession {
                    Some("ADD".to_string())
                } else {
                    None
                }
            });
        let token_source = add_token.as_ref().map(|_| "ECOMMERCE".to_string()); 

        let card_req = CardPaymentRequest {
            ssl_transaction_type: transaction_type,
            ssl_account_id: auth_type.ssl_merchant_id.clone(),
            ssl_user_id: auth_type.ssl_user_id.clone(),
            ssl_pin: auth_type.ssl_pin.clone(),
            ssl_amount: item.amount.clone(),
            ssl_card_number: card.card_number.clone(),
            ssl_exp_date: Secret::new(exp_date),
            ssl_cvv2cvc2: if cvv_indicator == Some(1) { Some(card.card_cvc.clone()) } else { None },
            ssl_cvv2cvc2_indicator: cvv_indicator,
            ssl_email: request_data.email.clone(),
            ssl_transaction_currency: request_data.currency,
            ssl_avs_address: avs_address,
            ssl_avs_zip: avs_zip,
            ssl_customer_code: customer_id_str,
            ssl_invoice_number: Some(router_data.resource_common_data.payment_id.clone()),
            ssl_add_token: add_token,
            ssl_token_source: token_source,
            ssl_get_token: None, 
        };
        Ok(ElavonPaymentsRequest::Card(card_req))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SslResult {
    #[serde(rename = "0")]
    Approved,
    #[serde(rename = "1")]
    Declined,
    Other(String), 
}

impl TryFrom<String> for SslResult {
    type Error = errors::ConnectorError; 
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "0" => Ok(SslResult::Approved),
            "1" => Ok(SslResult::Declined),
            _ => Ok(SslResult::Other(value)),
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub ssl_result: SslResult,
    pub ssl_txn_id: String,
    pub ssl_result_message: String,
    pub ssl_token: Option<Secret<String>>,
    pub ssl_approval_code: Option<String>,
    pub ssl_transaction_type: Option<String>,
    pub ssl_cvv2_response: Option<String>,
    pub ssl_avs_response: Option<String>,
    pub ssl_token_response: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElavonErrorResponse {
    pub error_code: Option<String>,
    pub error_message: String,
    pub error_name: Option<String>,
    pub ssl_txn_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ElavonResult {
    Success(PaymentResponse),
    Error(ElavonErrorResponse),
}

#[derive(Debug, Clone, Serialize)]
pub struct ElavonPaymentsResponse {
    pub result: ElavonResult,
}

impl<'de> Deserialize<'de> for ElavonPaymentsResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(rename = "txn")]
        struct XmlIshResponse {
            #[serde(default)]
            error_code: Option<String>,
            #[serde(default)]
            error_message: Option<String>,
            #[serde(default)]
            error_name: Option<String>,
            #[serde(default)]
            ssl_result: Option<String>,
            #[serde(default)]
            ssl_txn_id: Option<String>,
            #[serde(default)]
            ssl_result_message: Option<String>,
            #[serde(default)]
            ssl_token: Option<String>,
            #[serde(default)]
            ssl_token_response: Option<String>,
            #[serde(default)]
            ssl_approval_code: Option<String>,
            #[serde(default)]
            ssl_transaction_type: Option<String>,
            #[serde(default)]
            ssl_cvv2_response: Option<String>,
            #[serde(default)]
            ssl_avs_response: Option<String>,
        }

        let flat_res = XmlIshResponse::deserialize(deserializer)?;

        let result = {
            if flat_res.ssl_result.as_deref() == Some("0") {
                 ElavonResult::Success(PaymentResponse {
                    ssl_result: SslResult::try_from(flat_res.ssl_result.expect("ssl_result checked to be Some(\\\"0\\\")"))
                        .map_err(de::Error::custom)?,
                    ssl_txn_id: flat_res.ssl_txn_id.ok_or_else(|| de::Error::missing_field("ssl_txn_id"))?,
                    ssl_result_message: flat_res.ssl_result_message.ok_or_else(|| de::Error::missing_field("ssl_result_message"))?,
                    ssl_token: flat_res.ssl_token.map(Secret::new),
                    ssl_approval_code: flat_res.ssl_approval_code,
                    ssl_transaction_type: flat_res.ssl_transaction_type,
                    ssl_cvv2_response: flat_res.ssl_cvv2_response,
                    ssl_avs_response: flat_res.ssl_avs_response,
                    ssl_token_response: flat_res.ssl_token_response,
                })
            } else if flat_res.error_message.is_some() {
                ElavonResult::Error(ElavonErrorResponse {
                    error_code: flat_res.error_code.or(flat_res.ssl_result.clone()),
                    error_message: flat_res.error_message.expect("error_message checked"),
                    error_name: flat_res.error_name,
                    ssl_txn_id: flat_res.ssl_txn_id,
                })
            } else if flat_res.ssl_result.is_some() {
                 ElavonResult::Error(ElavonErrorResponse {
                    error_code: flat_res.ssl_result.clone(),
                    error_message: flat_res.ssl_result_message.unwrap_or_else(|| "Transaction resulted in an error".to_string()),
                    error_name: None,
                    ssl_txn_id: flat_res.ssl_txn_id,
                })
            } else {
                return Err(de::Error::custom(
                    "Invalid Response from Elavon - cannot determine success or error state, missing critical fields.",
                ));
            }
        };
        Ok(Self { result })
    }
}

fn get_elavon_attempt_status(
    elavon_result: &ElavonResult,
    http_code: u16, 
) -> (HyperswitchAttemptStatus, Option<ErrorResponse>) {
    match elavon_result {
        ElavonResult::Success(payment_response) => {
           
            let status = match payment_response.ssl_transaction_type.as_deref() {
                Some("ccauthonly") => HyperswitchAttemptStatus::Authorized, 
                Some("ccsale") | Some("cccomplete") => HyperswitchAttemptStatus::Charged,
                _ => { 
                    match payment_response.ssl_result {
                        SslResult::Approved => HyperswitchAttemptStatus::Charged, 
                        _ => HyperswitchAttemptStatus::Failure, 
                    }
                }
            };
            (status, None)
        }
        ElavonResult::Error(error_resp) => {
            (HyperswitchAttemptStatus::Failure, Some(ErrorResponse {
                status_code: http_code,
                code: error_resp.error_code.clone().unwrap_or_else(|| hs_interface_consts::NO_ERROR_CODE.to_string()),
                message: error_resp.error_message.clone(),
                reason: error_resp.error_name.clone(), 
                attempt_status: Some(HyperswitchAttemptStatus::Failure),
                connector_transaction_id: error_resp.ssl_txn_id.clone(),
            }))
        }
    }
}

impl
    ForeignTryFrom<(
        ElavonResult, 
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        u16, 
        Option<HyperswitchCaptureMethod>, 
        bool,
        Option<hyperswitch_api_models::enums::PaymentMethodType>,

    )> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        item: (
            ElavonResult,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16, 
            Option<HyperswitchCaptureMethod>, 
            bool,
            Option<hyperswitch_api_models::enums::PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let (elavon_result, original_router_data, http_code, _capture_method, _, _) = item;

        let (attempt_status, error_response) = get_elavon_attempt_status(&elavon_result, http_code);

        let payment_method_token = match &elavon_result {
            ElavonResult::Success(payment_resp_struct) => {
              
                if payment_resp_struct.ssl_token_response.as_deref() == Some("SUCCESS") {
                    payment_resp_struct.ssl_token.clone().map(PaymentMethodToken::Token)
                } else {
                    None
                }
            }
            ElavonResult::Error(_) => None,
        };
        
        let payments_response_data = match (&elavon_result, error_response) {
            (ElavonResult::Success(payment_resp_struct), None) => {
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: DomainResponseId::ConnectorTransactionId(payment_resp_struct.ssl_txn_id.clone()),
                    redirection_data: Box::new(None),
                    connector_metadata: None,
                    network_txn_id: payment_resp_struct.ssl_approval_code.clone(),
                    connector_response_reference_id: None, 
                    incremental_authorization_allowed: None, 
                    mandate_reference: Box::new(None), 
                })
            }
            (_, Some(err_resp)) => Err(err_resp),
            (ElavonResult::Error(error_payload), None) => { 
                 Err(ErrorResponse { 
                    status_code: http_code,
                    code: error_payload.error_code.clone().unwrap_or_else(|| hs_interface_consts::NO_ERROR_CODE.to_string()),
                    message: error_payload.error_message.clone(),
                    reason: error_payload.error_name.clone(),
                    attempt_status: Some(HyperswitchAttemptStatus::Failure),
                    connector_transaction_id: error_payload.ssl_txn_id.clone(),
                })
            }
        };

        Ok(Self {
            response: payments_response_data,
            resource_common_data: PaymentFlowData {
                status: attempt_status,
                payment_method_token: payment_method_token.map(|t| match t {
                    PaymentMethodToken::Token(s) => s.expose(), 
                    _ => String::new(), 
                }),
                ..original_router_data.resource_common_data
            },
            ..original_router_data
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct ElavonCaptureRequest {
    pub ssl_transaction_type: TransactionType,
    pub ssl_account_id: Secret<String>,
    pub ssl_user_id: Secret<String>,
    pub ssl_pin: Secret<String>,
    pub ssl_amount: StringMajorUnit,        
    pub ssl_txn_id: String,                 

}

impl TryFrom<&ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>>> for ElavonCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;

        let previous_connector_txn_id = match &router_data.request.connector_transaction_id {
            DomainResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(report!(errors::ConnectorError::MissingConnectorTransactionID))
                       .attach_printable("Missing connector_transaction_id for Elavon Capture"),
        };

        Ok(Self {
            ssl_transaction_type: TransactionType::CcComplete,
            ssl_account_id: auth_type.ssl_merchant_id,
            ssl_user_id: auth_type.ssl_user_id,
            ssl_pin: auth_type.ssl_pin,
            ssl_amount: item.amount.clone(),
            ssl_txn_id: previous_connector_txn_id,
        })
    }
}

impl
    ForeignTryFrom<(
        ElavonResult,
        RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>,
        u16, 
    )> for RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        item: (
            ElavonResult,
            RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        let (elavon_response_result, router_data_in, http_code) = item;

        let (initial_status, error_response_opt) =
            get_elavon_attempt_status(&elavon_response_result, http_code);
        
        match elavon_response_result {
            ElavonResult::Success(success_payload) => {
               
                let final_status = match success_payload.ssl_transaction_type.as_deref() {
                    Some("cccomplete") | Some("ccsale") => {
                        match success_payload.ssl_result {
                            SslResult::Approved => HyperswitchAttemptStatus::Charged,
                            _ => HyperswitchAttemptStatus::Failure, 
                        }
                    },
                    _ => initial_status,
                };

                let response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: DomainResponseId::ConnectorTransactionId(success_payload.ssl_txn_id.clone()),
                    redirection_data: Box::new(None), 
                    mandate_reference: Box::new(None), 
                    connector_metadata: Some(serde_json::to_value(success_payload.clone()).unwrap_or(serde_json::Value::Null)),
                    network_txn_id: None,
                    connector_response_reference_id: success_payload.ssl_approval_code.clone(),
                    incremental_authorization_allowed: None, 
                };
                
                Ok(RouterDataV2 {
                    response: Ok(response_data),
                    resource_common_data: PaymentFlowData {
                        status: final_status,
                        ..router_data_in.resource_common_data
                    },
                    ..router_data_in
                })
            }
            ElavonResult::Error(error_payload_struct) => { 
                 let final_error_response = error_response_opt.unwrap_or_else(|| ErrorResponse {
                    code: error_payload_struct.error_code.clone().unwrap_or(hs_interface_consts::NO_ERROR_CODE.to_string()),
                    message: error_payload_struct.error_message.clone(),
                    reason: error_payload_struct.error_name.clone(),
                    status_code: http_code,
                    attempt_status: Some(initial_status), 
                    connector_transaction_id: error_payload_struct.ssl_txn_id.clone(),
                });
                Ok(RouterDataV2 {
                    response: Err(final_error_response),
                    resource_common_data: PaymentFlowData {
                        status: initial_status,
                        ..router_data_in.resource_common_data
                    },
                    ..router_data_in
                })
            }
        }
    }
}


#[skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct ElavonRefundRequest {
    pub ssl_transaction_type: TransactionType,
    pub ssl_account_id: Secret<String>,
    pub ssl_user_id: Secret<String>,
    pub ssl_pin: Secret<String>,
    pub ssl_amount: StringMajorUnit,   
    pub ssl_txn_id: String,
}

impl TryFrom<&ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>>> for ElavonRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &ElavonRouterData<&RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let request_data = &router_data.request;
        let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;

        let original_connector_txn_id =  &request_data.connector_transaction_id;
        Ok(Self {
            ssl_transaction_type: TransactionType::CcReturn,
            ssl_account_id: auth_type.ssl_merchant_id,
            ssl_user_id: auth_type.ssl_user_id,
            ssl_pin: auth_type.ssl_pin,
            ssl_amount: item.amount.clone(), 
            ssl_txn_id: original_connector_txn_id.to_string(),
        })
    }
}

impl ForeignTryFrom<(
    ElavonResult,
    RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
    u16,
)> for RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        item: (
            ElavonResult,
            RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
            u16, 
        ),
    ) -> Result<Self, Self::Error> {
        let (elavon_response_result, router_data_in, http_code) = item;



        let (attempt_status, error_response_opt) =
            get_elavon_attempt_status(&elavon_response_result, http_code);
        
        match elavon_response_result {
            ElavonResult::Success(success_payload) => {
               
                let refund_status = match success_payload.ssl_transaction_type.as_deref() {
                    Some("ccreturn") => { 
                        match success_payload.ssl_result {
                            SslResult::Approved => hyperswitch_common_enums::RefundStatus::Success,
                             SslResult::Declined => hyperswitch_common_enums::RefundStatus::Failure, 
                            SslResult::Other(_) => {
                                hyperswitch_common_enums::RefundStatus::Pending
                            }
                        }
                    },
                    _ => {
                        hyperswitch_common_enums::RefundStatus::Pending
                    }
                };

                let response_data = domain_types::connector_types::RefundsResponseData {
                    connector_refund_id: success_payload.ssl_txn_id.clone(), 
                    refund_status,
                };
                
                Ok(RouterDataV2 {
                    response: Ok(response_data),
                   
                    resource_common_data: domain_types::connector_types::RefundFlowData {
                        status: refund_status, 
                        ..router_data_in.resource_common_data
                    },
                    ..router_data_in
                })
            }
            ElavonResult::Error(error_payload_struct) => {
                 let final_error_response = error_response_opt.unwrap_or_else(|| ErrorResponse {
                    code: error_payload_struct.error_code.clone().unwrap_or(hs_interface_consts::NO_ERROR_CODE.to_string()),
                    message: error_payload_struct.error_message.clone(),
                    reason: error_payload_struct.error_name.clone(),
                    status_code: http_code,
                    attempt_status: Some(attempt_status), 
                    connector_transaction_id: error_payload_struct.ssl_txn_id.clone(),
                });
                Ok(RouterDataV2 {
                    response: Err(final_error_response),
                    resource_common_data: domain_types::connector_types::RefundFlowData {
                        status: hyperswitch_common_enums::RefundStatus::Failure, 
                        ..router_data_in.resource_common_data
                    },
                    ..router_data_in
                })
            }
        }
    }
}


#[skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct ElavonPsyncRequest {
    pub ssl_transaction_type: TransactionType,
    pub ssl_account_id: Secret<String>,
    pub ssl_user_id: Secret<String>,
    pub ssl_pin: Secret<String>,
    pub ssl_txn_id: String, 
}


impl TryFrom<&RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>> for ElavonPsyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        router_data: &RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let request_data = &router_data.request;
        let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;

        let connector_txn_id = match &request_data.connector_transaction_id {
            DomainResponseId::ConnectorTransactionId(id) => id.clone(),
            
            _ => return Err(report!(errors::ConnectorError::MissingConnectorTransactionID))
                       .attach_printable("Missing connector_transaction_id for Elavon PSync"),
        };

        Ok(Self {
            ssl_transaction_type: TransactionType::TxnQuery,
            ssl_account_id: auth_type.ssl_merchant_id,
            ssl_user_id: auth_type.ssl_user_id,
            ssl_pin: auth_type.ssl_pin,
            ssl_txn_id: connector_txn_id,
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ElavonPSyncResponse {
    pub ssl_trans_status: TransactionSyncStatus,
    pub ssl_transaction_type: SyncTransactionType,
    pub ssl_txn_id: String,
   
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TransactionSyncStatus {
    PEN, 
    OPN, 
    REV, 
    STL, 
    PST, 
    FPR, 
    PRE, 
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SyncTransactionType {
    Sale,
    AuthOnly,
    Return,
}



impl
    ForeignTryFrom<(
        ElavonPSyncResponse,
        RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>,
        u16, 
        Option<HyperswitchCaptureMethod>, 
        bool, 
        Option<hyperswitch_api_models::enums::PaymentMethodType>,
    )> for RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        item: (
            ElavonPSyncResponse,
            RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>,
            u16, 
            Option<HyperswitchCaptureMethod>,
            bool,
            Option<hyperswitch_api_models::enums::PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let (psync_response, router_data_in, _http_code, _capture_method, _is_multiple_capture_sync, _pmt) = item;

      
        let final_status = match psync_response.ssl_trans_status {
            TransactionSyncStatus::STL => { 
                match psync_response.ssl_transaction_type {
                    SyncTransactionType::Sale => HyperswitchAttemptStatus::Charged,
                    SyncTransactionType::AuthOnly => HyperswitchAttemptStatus::Charged,
                    SyncTransactionType::Return => HyperswitchAttemptStatus::AutoRefunded,
                }
            }
            TransactionSyncStatus::OPN => { 
                match psync_response.ssl_transaction_type {
                    SyncTransactionType::AuthOnly => HyperswitchAttemptStatus::Authorized,
                    SyncTransactionType::Sale => HyperswitchAttemptStatus::Pending,
                    SyncTransactionType::Return => HyperswitchAttemptStatus::Pending,
                }
            }
            TransactionSyncStatus::PEN | TransactionSyncStatus::REV => HyperswitchAttemptStatus::Pending,
            TransactionSyncStatus::PST | TransactionSyncStatus::FPR | TransactionSyncStatus::PRE => {
               
                if psync_response.ssl_transaction_type == SyncTransactionType::AuthOnly && psync_response.ssl_trans_status == TransactionSyncStatus::PRE {
                    HyperswitchAttemptStatus::AuthenticationFailed
                } else {
                    HyperswitchAttemptStatus::Failure
                }
            }
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: DomainResponseId::ConnectorTransactionId(psync_response.ssl_txn_id.clone()),
            redirection_data: Box::new(None),
            mandate_reference: Box::new(None),
            connector_metadata: Some(serde_json::json!(psync_response)), 
            network_txn_id: None,
            connector_response_reference_id: None, 
            incremental_authorization_allowed: None,
        };

        Ok(RouterDataV2 {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status: final_status,
                ..router_data_in.resource_common_data
            },
            ..router_data_in
        })
    }
} 

#[derive(Debug, Serialize)]
pub struct ElavonRSyncRequest {
    pub ssl_transaction_type: TransactionType,
    pub ssl_account_id: Secret<String>,
    pub ssl_user_id: Secret<String>,
    pub ssl_pin: Secret<String>,
    pub ssl_txn_id: String, 
}

impl TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>> for ElavonRSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_type = ElavonAuthType::try_from(&router_data.connector_auth_type)?;
       
        let connector_refund_id = router_data.request.connector_refund_id.clone();

        Ok(Self {
            ssl_transaction_type: TransactionType::TxnQuery,
            ssl_account_id: auth_type.ssl_merchant_id,
            ssl_user_id: auth_type.ssl_user_id,
            ssl_pin: auth_type.ssl_pin,
            ssl_txn_id: connector_refund_id,
        })
    }
}


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ElavonRSyncResponse {
    pub ssl_trans_status: TransactionSyncStatus,
    pub ssl_transaction_type: SyncTransactionType,
    pub ssl_txn_id: String,
  
}


fn get_refund_status_from_elavon_sync_response(
    elavon_response: &ElavonRSyncResponse,
) -> HyperswitchRefundStatus {
    match elavon_response.ssl_transaction_type {
        SyncTransactionType::Return => { 
            match elavon_response.ssl_trans_status {
                TransactionSyncStatus::STL => HyperswitchRefundStatus::Success, 
                TransactionSyncStatus::PEN => HyperswitchRefundStatus::Pending, 
                TransactionSyncStatus::OPN => HyperswitchRefundStatus::Pending, 
                TransactionSyncStatus::REV => HyperswitchRefundStatus::ManualReview, 
                TransactionSyncStatus::PST | TransactionSyncStatus::FPR | TransactionSyncStatus::PRE => {
                    HyperswitchRefundStatus::Failure
                }
            }
        }
        _ => HyperswitchRefundStatus::Pending,
    }
}


impl
    ForeignTryFrom<(
        ElavonRSyncResponse,
        RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
        u16,
    )> for RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        item: (
            ElavonRSyncResponse,
            RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        let (elavon_response, router_data_in, _http_status_code) = item;

        let refund_status = get_refund_status_from_elavon_sync_response(&elavon_response);

        let mut router_data_out = router_data_in.clone();

        router_data_out.response = Ok(domain_types::connector_types::RefundsResponseData {
            refund_status,
            connector_refund_id: elavon_response.ssl_txn_id.clone(),
        });
        
        router_data_out.resource_common_data.status = refund_status;
        Ok(router_data_out)
    }
} 