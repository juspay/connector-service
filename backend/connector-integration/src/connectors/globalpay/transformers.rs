use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, CreateAccessToken, PSync, RSync, Refund, Void},
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct GlobalpayAuthType {
    pub app_id: Secret<String>,
    pub app_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for GlobalpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                app_id: api_key.to_owned(),
                app_key: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalpayErrorResponse {
    #[serde(alias = "error_code", alias = "code", alias = "detailed_error_code")]
    pub code: Option<String>,
    #[serde(
        alias = "error_message",
        alias = "message",
        alias = "detailed_error_description"
    )]
    pub message: Option<String>,
    #[serde(flatten)]
    pub extra: Option<serde_json::Value>,
}

// ===== OAUTH / ACCESS TOKEN FLOW STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct GlobalpayAccessTokenRequest {
    pub app_id: String,
    pub nonce: String,
    pub secret: String,
    pub grant_type: String,
}

impl TryFrom<&ConnectorAuthType> for GlobalpayAccessTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            use sha2::{Digest, Sha512};

            // Generate nonce using current timestamp in milliseconds
            let nonce = (OffsetDateTime::now_utc().unix_timestamp() * 1000).to_string();

            // Create secret: SHA512(nonce + app_key)
            let secret_input = format!("{}{}", nonce, key1.peek());

            // Generate SHA-512 hash
            let mut hasher = Sha512::new();
            hasher.update(secret_input.as_bytes());
            let result = hasher.finalize();
            let secret_hex = hex::encode(result);

            Ok(Self {
                app_id: api_key.peek().clone(),
                nonce,
                secret: secret_hex,
                grant_type: "client_credentials".to_string(),
            })
        } else {
            Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            ))
        }
    }
}

impl
    TryFrom<
        &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    > for GlobalpayAccessTokenRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.connector_auth_type)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalpayAccessTokenResponse {
    pub token: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub seconds_to_expire: i64,
}

impl<F, T>
    TryFrom<
        ResponseRouterData<
            GlobalpayAccessTokenResponse,
            RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GlobalpayAccessTokenResponse,
            RouterDataV2<F, PaymentFlowData, T, AccessTokenResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(AccessTokenResponseData {
                access_token: item.response.token,
                token_type: Some(item.response.type_),
                expires_in: Some(item.response.seconds_to_expire),
            }),
            ..item.router_data
        })
    }
}

// ===== PAYMENT FLOW STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct GlobalpayPaymentsRequest<T: PaymentMethodDataTypes> {
    pub account_name: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub channel: String,
    pub amount: String,
    pub currency: String,
    pub reference: String,
    pub country: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_mode: Option<String>,
    pub payment_method: GlobalpayPaymentMethod<T>,
}

#[derive(Debug, Serialize)]
pub struct GlobalpayPaymentMethod<T: PaymentMethodDataTypes> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Secret<String>>,
    pub entry_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<GlobalpayCard<T>>,
}

#[derive(Debug, Serialize)]
pub struct GlobalpayCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvv: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvv_indicator: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for GlobalpayPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => GlobalpayPaymentMethod {
                name: item.request.customer_name.clone().map(Secret::new),
                entry_mode: "ECOM".to_string(),
                card: Some(GlobalpayCard {
                    number: card_data.card_number.clone(),
                    expiry_month: card_data.card_exp_month.clone(),
                    expiry_year: card_data.card_exp_year.clone(),
                    cvv: card_data.card_cvc.clone(),
                    cvv_indicator: Some("PRESENT".to_string()),
                }),
            },
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Payment method not supported".to_string()
                    )
                ))
            }
        };

        // Determine capture_mode based on capture_method
        let capture_mode = match item.request.capture_method {
            Some(common_enums::CaptureMethod::Manual) => Some("LATER".to_string()),
            _ => None, // AUTO is default, no need to send
        };

        // Get country from billing address or use default
        let country = item
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|billing| billing.address.as_ref())
            .and_then(|addr| addr.country.as_ref())
            .map(|c| c.to_string())
            .unwrap_or_else(|| "US".to_string());

        Ok(Self {
            account_name: "transaction_processing".to_string(),
            transaction_type: "SALE".to_string(),
            channel: "CNP".to_string(),
            amount: item.request.minor_amount.get_amount_as_i64().to_string(),
            currency: item.request.currency.to_string(),
            reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            country,
            capture_mode,
            payment_method,
        })
    }
}

// Capture Request Structure
#[derive(Debug, Serialize)]
pub struct GlobalpayCaptureRequest {
    pub amount: String,
    pub currency: String,
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for GlobalpayCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Validate that we have a connector transaction ID
        let _transaction_id = item
            .request
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(Self {
            amount: item
                .request
                .minor_amount_to_capture
                .get_amount_as_i64()
                .to_string(),
            currency: item.request.currency.to_string(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalpayPaymentsResponse {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<GlobalpayPaymentMethodResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalpayPaymentMethodResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<GlobalpayCardResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalpayCardResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masked_number_last4: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Map GlobalPay statuses to UCS AttemptStatus
        // Based on tech spec: CAPTURED, PREAUTHORIZED, DECLINED, FUNDED, FAILED, REJECTED,
        // FOR_REVIEW, INITIATED, PENDING, REVERSED
        let status = match item.response.status.as_str() {
            "CAPTURED" => AttemptStatus::Charged,
            "PREAUTHORIZED" => AttemptStatus::Authorized,
            "DECLINED" => AttemptStatus::Failure,
            "FAILED" => AttemptStatus::Failure,
            "REJECTED" => AttemptStatus::Failure,
            "PENDING" => AttemptStatus::Pending,
            "INITIATED" => AttemptStatus::Pending,
            "FOR_REVIEW" => AttemptStatus::Pending,
            "FUNDED" => AttemptStatus::Charged,
            "REVERSED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
                incremental_authorization_allowed: None,
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

// PSync flow - reuses the same GlobalpayPaymentsResponse structure
impl
    TryFrom<
        ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map GlobalPay statuses to UCS AttemptStatus
        // Same status mapping as Authorize flow
        let status = match item.response.status.as_str() {
            "CAPTURED" => AttemptStatus::Charged,
            "PREAUTHORIZED" => AttemptStatus::Authorized,
            "DECLINED" => AttemptStatus::Failure,
            "FAILED" => AttemptStatus::Failure,
            "REJECTED" => AttemptStatus::Failure,
            "PENDING" => AttemptStatus::Pending,
            "INITIATED" => AttemptStatus::Pending,
            "FOR_REVIEW" => AttemptStatus::Pending,
            "FUNDED" => AttemptStatus::Charged,
            "REVERSED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
                incremental_authorization_allowed: None,
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

// Capture flow - reuses the same GlobalpayPaymentsResponse structure
impl
    TryFrom<
        ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map GlobalPay statuses to UCS AttemptStatus
        // Same status mapping as Authorize and PSync flows
        let status = match item.response.status.as_str() {
            "CAPTURED" => AttemptStatus::Charged,
            "PREAUTHORIZED" => AttemptStatus::Authorized,
            "DECLINED" => AttemptStatus::Failure,
            "FAILED" => AttemptStatus::Failure,
            "REJECTED" => AttemptStatus::Failure,
            "PENDING" => AttemptStatus::Pending,
            "INITIATED" => AttemptStatus::Pending,
            "FOR_REVIEW" => AttemptStatus::Pending,
            "FUNDED" => AttemptStatus::Charged,
            "REVERSED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
                incremental_authorization_allowed: None,
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

// ===== REFUND FLOW STRUCTURES =====

// Refund Request - Based on tech spec, refunds can be with amount or empty body
// Following Pattern 2 from pattern_refund.md - Amount-Required Refunds
#[derive(Debug, Clone, Serialize)]
pub struct GlobalpayRefundRequest {
    pub amount: String,
    pub currency: String,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for GlobalpayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item
                .request
                .minor_refund_amount
                .get_amount_as_i64()
                .to_string(),
            currency: item.request.currency.to_string(),
        })
    }
}

// Refund Response - Based on tech spec, refund response is similar to transaction response
// The refund endpoint returns a transaction object with status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalpayRefundResponse {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            GlobalpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GlobalpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map GlobalPay refund statuses to UCS RefundStatus
        // Based on tech spec section 4: Refund a Sale
        // Refund statuses should be similar to transaction statuses
        let refund_status = match item.response.status.as_str() {
            "CAPTURED" | "FUNDED" => RefundStatus::Success,
            "PENDING" | "INITIATED" | "FOR_REVIEW" => RefundStatus::Pending,
            "DECLINED" | "FAILED" | "REJECTED" => RefundStatus::Failure,
            _ => RefundStatus::Pending, // Default to pending for unknown statuses
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// RSync Response - Reuses the same GlobalpayRefundResponse structure
impl
    TryFrom<
        ResponseRouterData<
            GlobalpayRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GlobalpayRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Same status mapping as Refund flow
        let refund_status = match item.response.status.as_str() {
            "CAPTURED" | "FUNDED" => RefundStatus::Success,
            "PENDING" | "INITIATED" | "FOR_REVIEW" => RefundStatus::Pending,
            "DECLINED" | "FAILED" | "REJECTED" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== VOID FLOW STRUCTURES =====

// Void Request - Based on tech spec, /transactions/{transaction_id}/reverse endpoint
// The API doesn't specify required request body fields, so we use an empty struct
#[derive(Debug, Clone, Serialize)]
pub struct GlobalpayVoidRequest {}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for GlobalpayVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Validate that we have a connector transaction ID (required for URL construction)
        if item.request.connector_transaction_id.is_empty() {
            return Err(error_stack::report!(
                errors::ConnectorError::MissingConnectorTransactionID
            ));
        }

        // Return empty request body
        Ok(Self {})
    }
}

// Void Response - Reuses GlobalpayPaymentsResponse structure
// The response is similar to transaction response with REVERSED status
impl
    TryFrom<
        ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            GlobalpayPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map GlobalPay void statuses to UCS AttemptStatus
        // Based on tech spec: REVERSED status indicates successful void
        let status = match item.response.status.as_str() {
            "REVERSED" => AttemptStatus::Voided,
            "PENDING" | "INITIATED" => AttemptStatus::Pending,
            "DECLINED" | "FAILED" | "REJECTED" => AttemptStatus::VoidFailed,
            _ => AttemptStatus::VoidFailed, // Conservative default for unknown statuses
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
                incremental_authorization_allowed: None,
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
