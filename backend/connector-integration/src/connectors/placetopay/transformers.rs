use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PaymentMethodToken, PSync, RSync, RepeatPayment, SetupMandate, Void, Capture, Refund},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, 
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, 
        RefundsResponseData, RepeatPaymentData, ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret, PeekInterface};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::types::ResponseRouterData;
use crate::connectors::placetopay::PlacetopayRouterData as MacroPlacetopayRouterData;

#[derive(Debug, Serialize)]
pub struct PlacetopayRouterData<T, U> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub payment_method_data: std::marker::PhantomData<U>,
}

impl<T, U> TryFrom<(MinorUnit, T)> for PlacetopayRouterData<T, U> {
    type Error = domain_types::errors::ConnectorError;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
            payment_method_data: std::marker::PhantomData,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayAuthType {
    pub(super) login: Secret<String>,
    pub(super) tran_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PlacetopayAuthType {
    type Error = domain_types::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                login: api_key.to_owned(),
                tran_key: key1.to_owned(),
            }),
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayAuth {
    login: Secret<String>,
    tran_key: Secret<String>,
    nonce: Secret<String>,
    seed: String,
}

impl TryFrom<&ConnectorAuthType> for PlacetopayAuth {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Starting auth generation");
        let placetopay_auth = PlacetopayAuthType::try_from(auth_type)?;
        let nonce_bytes: [u8; 16] = common_utils::crypto::generate_cryptographically_secure_random_bytes();
        let now = common_utils::date_time::date_as_yyyymmddthhmmssmmmz()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let seed = format!("{}+00:00", now.split_at(now.len() - 5).0);
        
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&nonce_bytes);
        hasher.update(seed.as_bytes());
        hasher.update(placetopay_auth.tran_key.peek().as_bytes());
        let encoded_digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hasher.finish());
        let nonce = Secret::new(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_bytes));
        
        println!("PlaceToPay: Auth generation completed successfully");
        Ok(Self {
            login: placetopay_auth.login,
            tran_key: encoded_digest.into(),
            nonce,
            seed,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    auth: PlacetopayAuth,
    payment: PlacetopayPayment,
    instrument: PlacetopayInstrument<T>,
    ip_address: Secret<String, common_utils::pii::IpAddress>,
    user_agent: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPayment {
    reference: String,
    description: String,
    amount: PlacetopayAmount,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayAmount {
    currency: common_enums::Currency,
    total: MinorUnit,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayInstrument<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    card: PlacetopayCard<T>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    number: RawCardNumber<T>,
    expiration: Secret<String>,
    cvv: Secret<String>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PlacetopayPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Starting request transformation");
        let browser_info = item.router_data.request.get_browser_info()
            .unwrap_or_else(|_| {
                println!("PlaceToPay: Browser info not available, using defaults");
                domain_types::router_request_types::BrowserInformation::default()
            });
        let ip_address = browser_info.get_ip_address()
            .unwrap_or_else(|_| {
                println!("PlaceToPay: IP address not available, using default");
                Secret::new("127.0.0.1".to_string())
            });
        let user_agent = browser_info.get_user_agent()
            .unwrap_or_else(|_| {
                println!("PlaceToPay: User agent not available, using default");
                "PlaceToPay-Connector/1.0".to_string()
            });
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_auth_type)?;
        let description = item.router_data.resource_common_data.get_description()
            .unwrap_or_else(|_| "Payment transaction".to_string());
        let payment = PlacetopayPayment {
            reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            description,
            amount: PlacetopayAmount {
                currency: item.router_data.request.currency,
                total: item.amount,
            },
        };
        println!("PlaceToPay: Payment object created successfully");
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let card = PlacetopayCard {
                    number: req_card.card_number.clone(),
                    expiration: format!("{}/{}", req_card.card_exp_month.peek(), req_card.card_exp_year.peek()).into(),
                    cvv: req_card.card_cvc.clone(),
                };
                println!("PlaceToPay: Request transformation completed successfully");
                Ok(Self {
                    ip_address,
                    user_agent,
                    auth,
                    payment,
                    instrument: PlacetopayInstrument {
                        card: card.to_owned(),
                    },
                })
            }
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Placetopay"),
                )
                .into())
            }
        }
    }
}

// TryFrom implementation for macro-generated PlacetopayRouterData type
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        MacroPlacetopayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PlacetopayPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: MacroPlacetopayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting macro-generated RouterData to PlacetopayPaymentsRequest");
        // Convert macro type to our transformers type
        let amount = MinorUnit::new(item.router_data.request.amount);
        let transformers_item = PlacetopayRouterData {
            amount,
            router_data: item.router_data,
            payment_method_data: std::marker::PhantomData,
        };
        println!("PlaceToPay: Calling transformers implementation");
        // Use existing implementation
        let result = Self::try_from(transformers_item);
        match &result {
            Ok(_) => println!("PlaceToPay: Request transformation successful"),
            Err(e) => println!("PlaceToPay: Request transformation failed: {:?}", e),
        }
        result
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlacetopayTransactionStatus {
    Ok,
    Failed,
    Approved,
    Rejected,
    Pending,
    PendingValidation,
    PendingProcess,
    Error,
}

impl From<PlacetopayTransactionStatus> for common_enums::AttemptStatus {
    fn from(item: PlacetopayTransactionStatus) -> Self {
        let status = match item {
            PlacetopayTransactionStatus::Approved | PlacetopayTransactionStatus::Ok => {
                Self::Charged
            }
            PlacetopayTransactionStatus::Failed
            | PlacetopayTransactionStatus::Rejected
            | PlacetopayTransactionStatus::Error => Self::Failure,
            PlacetopayTransactionStatus::Pending
            | PlacetopayTransactionStatus::PendingValidation
            | PlacetopayTransactionStatus::PendingProcess => Self::Pending,
        };
        println!("PlaceToPay: Status mapping - {:?} -> {:?}", item, status);
        status
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayStatusResponse {
    status: PlacetopayTransactionStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPaymentsResponse {
    status: PlacetopayStatusResponse,
    internal_reference: u64,
    authorization: Option<String>,
}

// Type alias for RSync to avoid macro conflicts
pub type PlacetopayRSyncResponse = PlacetopayRefundResponse;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            PlacetopayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            PlacetopayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Processing response - raw status: {:?}", item.response.status.status);
        
        // Check capture method to determine correct status
        let capture_method = item.router_data.request.capture_method.unwrap_or(common_enums::CaptureMethod::Automatic);
        println!("PlaceToPay: Capture method: {:?}", capture_method);
        
        let status = match (item.response.status.status, capture_method) {
            (PlacetopayTransactionStatus::Approved | PlacetopayTransactionStatus::Ok, common_enums::CaptureMethod::Manual) => {
                println!("PlaceToPay: Manual capture - mapping to Authorized");
                common_enums::AttemptStatus::Authorized
            },
            (PlacetopayTransactionStatus::Approved | PlacetopayTransactionStatus::Ok, _) => {
                println!("PlaceToPay: Auto capture - mapping to Charged");
                common_enums::AttemptStatus::Charged
            },
            (other_status, _) => {
                println!("PlaceToPay: Other status - using default mapping");
                common_enums::AttemptStatus::from(other_status)
            }
        };
        
        println!("PlaceToPay: Final mapped status: {:?}", status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.internal_reference.to_string(),
                ),
                redirection_data: None,
                connector_metadata: item
                    .response
                    .authorization
                    .clone()
                    .map(|authorization| serde_json::json!(authorization)),
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayPsyncRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
}

// Type alias for PSync to avoid macro conflicts
pub type PlacetopayPSyncResponse = PlacetopayPaymentsResponse;

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>> for PlacetopayPsyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting PSync request");
        let auth = PlacetopayAuth::try_from(&item.connector_auth_type)?;
        let internal_reference = item
            .request
            .get_connector_transaction_id()?
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        println!("PlaceToPay: PSync request created with internal_reference: {}", internal_reference);
        Ok(Self {
            auth,
            internal_reference,
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PlacetopayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PlacetopayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.status.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.internal_reference.to_string(),
                ),
                redirection_data: None,
                connector_metadata: item
                    .response
                    .authorization
                    .clone()
                    .map(|authorization| serde_json::json!(authorization)),
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayNextActionRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
    action: PlacetopayNextAction,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlacetopayNextAction {
    Refund,
    Reverse,
    Void,
    Process,
    Checkout,
}

impl TryFrom<PlacetopayRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, ()>> for PlacetopayNextActionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: PlacetopayRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, ()>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting capture request");
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_auth_type)?;
        let internal_reference = item
            .router_data
            .request
            .get_connector_transaction_id()?
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let action = PlacetopayNextAction::Checkout;
        println!("PlaceToPay: Capture request created with internal_reference: {}", internal_reference);
        Ok(Self {
            auth,
            internal_reference,
            action,
        })
    }
}

// Add TryFrom for macro-generated RouterData
impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>> for PlacetopayNextActionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting macro capture request");
        let auth = PlacetopayAuth::try_from(&item.connector_auth_type)?;
        let internal_reference = item
            .request
            .get_connector_transaction_id()?
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let action = PlacetopayNextAction::Checkout;
        println!("PlaceToPay: Macro capture request created with internal_reference: {}", internal_reference);
        Ok(Self {
            auth,
            internal_reference,
            action,
        })
    }
}

impl TryFrom<PlacetopayRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, ()>> for PlacetopayNextActionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: PlacetopayRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, ()>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting void request");
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_auth_type)?;
        let internal_reference = item
            .router_data
            .request
            .connector_transaction_id
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let action = PlacetopayNextAction::Void;
        println!("PlaceToPay: Void request created with internal_reference: {}", internal_reference);
        Ok(Self {
            auth,
            internal_reference,
            action,
        })
    }
}

// Add TryFrom for macro-generated RouterData
impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>> for PlacetopayNextActionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting macro void request");
        let auth = PlacetopayAuth::try_from(&item.connector_auth_type)?;
        let internal_reference = item
            .request
            .connector_transaction_id
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let action = PlacetopayNextAction::Void;
        println!("PlaceToPay: Macro void request created with internal_reference: {}", internal_reference);
        Ok(Self {
            auth,
            internal_reference,
            action,
        })
    }
}

// REFUND TYPES
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRefundRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
    action: PlacetopayNextAction,
    authorization: Option<String>,
}

impl<F> TryFrom<PlacetopayRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, ()>> for PlacetopayRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: PlacetopayRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, ()>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting refund request");
        if item.router_data.request.minor_refund_amount == item.router_data.request.minor_payment_amount {
            let auth = PlacetopayAuth::try_from(&item.router_data.connector_auth_type)?;

            let internal_reference = item
                .router_data
                .request
                .connector_transaction_id
                .parse::<u64>()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            let action = PlacetopayNextAction::Reverse;
            let authorization = match item.router_data.request.connector_metadata.clone() {
                Some(metadata) => metadata.as_str().map(|auth| auth.to_string()),
                None => None,
            };
            println!("PlaceToPay: Refund request created with internal_reference: {}", internal_reference);
            Ok(Self {
                auth,
                internal_reference,
                action,
                authorization,
            })
        } else {
            Err(errors::ConnectorError::NotSupported {
                message: "Partial Refund".to_string(),
                connector: "placetopay",
            }
            .into())
        }
    }
}

// Add TryFrom for macro-generated RouterData
impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>> for PlacetopayRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting macro refund request");
        if item.request.minor_refund_amount == item.request.minor_payment_amount {
            let auth = PlacetopayAuth::try_from(&item.connector_auth_type)?;

            let internal_reference = item
                .request
                .connector_transaction_id
                .parse::<u64>()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            let action = PlacetopayNextAction::Reverse;
            let authorization = match item.request.connector_metadata.clone() {
                Some(metadata) => metadata.as_str().map(|auth| auth.to_string()),
                None => None,
            };
            println!("PlaceToPay: Macro refund request created with internal_reference: {}", internal_reference);
            Ok(Self {
                auth,
                internal_reference,
                action,
                authorization,
            })
        } else {
            Err(errors::ConnectorError::NotSupported {
                message: "Partial Refund".to_string(),
                connector: "placetopay",
            }
            .into())
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlacetopayRefundStatus {
    Ok,
    Failed,
    Approved,
    Rejected,
    Pending,
    PendingValidation,
    PendingProcess,
    Refunded,
    Error,
}

impl From<PlacetopayRefundStatus> for common_enums::RefundStatus {
    fn from(item: PlacetopayRefundStatus) -> Self {
        match item {
            PlacetopayRefundStatus::Ok
            | PlacetopayRefundStatus::Approved
            | PlacetopayRefundStatus::Refunded => Self::Success,
            PlacetopayRefundStatus::Failed
            | PlacetopayRefundStatus::Rejected
            | PlacetopayRefundStatus::Error => Self::Failure,
            PlacetopayRefundStatus::Pending
            | PlacetopayRefundStatus::PendingProcess
            | PlacetopayRefundStatus::PendingValidation => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRefundStatusResponse {
    status: PlacetopayRefundStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRefundResponse {
    status: PlacetopayRefundStatusResponse,
    internal_reference: u64,
}

impl<F> TryFrom<ResponseRouterData<PlacetopayRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PlacetopayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.internal_reference.to_string(),
                refund_status: common_enums::RefundStatus::from(item.response.status.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayRsyncRequest {
    auth: PlacetopayAuth,
    internal_reference: u64,
}

impl TryFrom<PlacetopayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, ()>> for PlacetopayRsyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: PlacetopayRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, ()>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting RSync request");
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_auth_type)?;
        let internal_reference = item
            .router_data
            .request
            .connector_transaction_id
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        println!("PlaceToPay: RSync request created with internal_reference: {}", internal_reference);
        Ok(Self {
            auth,
            internal_reference,
        })
    }
}

// Add TryFrom for macro-generated RouterData
impl TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>> for PlacetopayRsyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>) -> Result<Self, Self::Error> {
        println!("PlaceToPay: Converting macro RSync request");
        let auth = PlacetopayAuth::try_from(&item.connector_auth_type)?;
        let internal_reference = item
            .request
            .connector_transaction_id
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        println!("PlaceToPay: Macro RSync request created with internal_reference: {}", internal_reference);
        Ok(Self {
            auth,
            internal_reference,
        })
    }
}

impl<F> TryFrom<ResponseRouterData<PlacetopayRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PlacetopayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.internal_reference.to_string(),
                refund_status: common_enums::RefundStatus::from(item.response.status.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayErrorResponse {
    pub status: PlacetopayError,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayError {
    pub status: PlacetopayErrorStatus,
    pub message: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlacetopayErrorStatus {
    Failed,
}

// TOKEN TYPES
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayTokenRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    auth: PlacetopayAuth,
    instrument: PlacetopayInstrument<T>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacetopayTokenResponse {
    status: PlacetopayStatusResponse,
    token: Option<String>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PlacetopayRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for PlacetopayTokenRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: PlacetopayRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PlacetopayAuth::try_from(&item.router_data.connector_auth_type)?;
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let card = PlacetopayCard {
                    number: req_card.card_number.clone(),
                    expiration: format!("{}/{}", req_card.card_exp_month.peek(), req_card.card_exp_year.peek()).into(),
                    cvv: req_card.card_cvc.clone(),
                };
                Ok(Self {
                    auth,
                    instrument: PlacetopayInstrument {
                        card: card.to_owned(),
                    },
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Placetopay"),
            )
            .into()),
        }
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            PlacetopayTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    > for RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            PlacetopayTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.status.status);
        
        Ok(Self {
            response: Ok(PaymentMethodTokenResponse {
                token: item.response.token.unwrap_or_default(),
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}