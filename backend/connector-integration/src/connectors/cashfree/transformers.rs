use error_stack::report;
use common_enums;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::PeekInterface;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// ============================================================================
// Authentication
// ============================================================================

#[derive(Debug, Clone)]
pub struct CashfreeAuthType {
    pub app_id: hyperswitch_masking::Secret<String>,     // X-Client-Id
    pub secret_key: hyperswitch_masking::Secret<String>, // X-Client-Secret
}

impl TryFrom<&ConnectorAuthType> for CashfreeAuthType {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                app_id: key1.to_owned(),
                secret_key: api_key.to_owned(),
            }),
            ConnectorAuthType::SignatureKey {
                api_key: _,
                key1,
                api_secret,
            } => Ok(Self {
                app_id: key1.to_owned(),
                secret_key: api_secret.to_owned(),
            }),
            _ => Err(report!(ConnectorError::FailedToObtainAuthType)),
        }
    }
}

// ============================================================================
// Error Response
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashfreeErrorResponse {
    pub message: String,
    pub code: String,
    #[serde(rename = "type")]
    pub error_type: String,
}

// ============================================================================
// Payment Authorization (UPI Only)
// ============================================================================

#[derive(Debug, Serialize)]
pub struct CashfreePaymentsRequest {
    pub payment_session_id: String, // From order creation response
    pub payment_method: CashfreePaymentMethod,
    pub payment_surcharge: Option<CashfreePaymentSurcharge>,
}

#[derive(Debug, Serialize)]
pub struct CashfreePaymentMethod {
    pub upi: Option<CashfreeUpiDetails>,
    // All other payment methods set to None for UPI-only implementation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<()>, // CashFreeAPPType - None for UPI-only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netbanking: Option<()>, // CashFreeNBType - None for UPI-only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<()>, // CashFreeCARDType - None for UPI-only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emi: Option<()>, // CashfreeEmiType - None for UPI-only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paypal: Option<()>, // CashfreePaypalType - None for UPI-only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paylater: Option<()>, // CashFreePaylaterType - None for UPI-only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardless_emi: Option<()>, // CashFreeCardlessEmiType - None for UPI-only
}

#[derive(Debug, Serialize)]
pub struct CashfreeUpiDetails {
    pub channel: String, // "link" for Intent, "collect" for Collect
    #[serde(skip_serializing_if = "String::is_empty")]
    pub upi_id: String, // VPA for collect, empty for intent
}

#[derive(Debug, Serialize)]
pub struct CashfreePaymentSurcharge {
    pub surcharge_amount: f64,
    pub surcharge_percentage: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreePaymentsResponse {
    pub payment_method: String,
    pub channel: String,
    pub action: String,
    pub data: CashfreeResponseData,
    pub cf_payment_id: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreeResponseData {
    pub url: Option<String>,
    pub payload: Option<CashfreePayloadData>,
    pub content_type: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreePayloadData {
    #[serde(rename = "default")]
    pub default_link: String, // Universal deep link for Intent
    pub gpay: Option<String>,
    pub phonepe: Option<String>,
    pub paytm: Option<String>,
    pub bhim: Option<String>,
}

// ============================================================================
// Payment Sync (PSync)
// ============================================================================

#[derive(Debug, Serialize)]
pub struct CashfreePaymentsSyncRequest {
    // Empty request for GET /pg/orders/{order_id}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreePaymentsSyncResponse {
    pub order_id: String,
    pub order_amount: f64,
    pub order_currency: String,
    pub order_status: String,
    pub payment_status: Option<String>,
    pub cf_payment_id: Option<serde_json::Value>,
    pub payment_time: Option<String>,
    pub payment_method: Option<String>,
    pub error_message: Option<String>,
}

// ============================================================================
// Order Creation (Phase 1) - For compatibility
// ============================================================================

#[derive(Debug, Serialize)]
pub struct CashfreeOrderCreateRequest {
    pub order_id: String,
    pub order_amount: String, // String from StringMinorUnit converter
    pub order_currency: String,
    pub customer_details: CashfreeCustomerDetails,
    pub order_meta: CashfreeOrderMeta,
    pub order_note: Option<String>,
    pub order_expiry_time: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreeCustomerDetails {
    pub customer_id: String,
    pub customer_email: Option<String>,
    pub customer_phone: String,
    pub customer_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreeOrderMeta {
    pub return_url: String,
    pub notify_url: String,
    pub payment_methods: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CashfreeOrderCreateResponse {
    pub payment_session_id: String, // KEY: Used in Authorize flow
    pub cf_order_id: i64,
    pub order_id: String,
    pub entity: String,
    pub order_amount: f64,
    pub order_currency: String,
    pub order_status: String,
    pub order_expiry_time: String,
    pub order_note: Option<String>,
    pub customer_details: CashfreeCustomerDetails,
    pub order_meta: CashfreeOrderMeta,
}

// ============================================================================
// Stub Types for Unsupported Flows
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeVoidRequest;
#[derive(Debug, Clone)]
pub struct CashfreeVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeCaptureRequest;
#[derive(Debug, Clone)]
pub struct CashfreeCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeRefundRequest;
#[derive(Debug, Clone)]
pub struct CashfreeRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct CashfreeRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct CashfreeSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct CashfreeSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct CashfreeRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct CashfreeAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct CashfreeSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct CashfreeDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct CashfreeDefendDisputeResponse;

// ============================================================================
// Helper Functions
// ============================================================================

fn get_cashfree_payment_method_data(
    payment_method_data: &PaymentMethodData<impl PaymentMethodDataTypes>,
) -> Result<CashfreePaymentMethod, ConnectorError> {
    match payment_method_data {
        PaymentMethodData::Upi(upi_data) => {
            match upi_data {
                domain_types::payment_method_data::UpiData::UpiCollect(collect_data) => {
                    // Extract VPA for collect flow - maps to upi_id field in Cashfree
                    let vpa = collect_data
                        .vpa_id
                        .as_ref()
                        .map(|vpa| vpa.peek().to_string())
                        .unwrap_or_default();

                    if vpa.is_empty() {
                        return Err(ConnectorError::MissingRequiredField {
                            field_name: "vpa_id for UPI collect",
                        });
                    }

                    Ok(CashfreePaymentMethod {
                        upi: Some(CashfreeUpiDetails {
                            channel: "collect".to_string(),
                            upi_id: vpa,
                        }),
                        app: None,
                        netbanking: None,
                        card: None,
                        emi: None,
                        paypal: None,
                        paylater: None,
                        cardless_emi: None,
                    })
                }
                domain_types::payment_method_data::UpiData::UpiIntent(_) => {
                    // Intent flow: channel = "link", no UPI ID needed
                    Ok(CashfreePaymentMethod {
                        upi: Some(CashfreeUpiDetails {
                            channel: "link".to_string(),
                            upi_id: "".to_string(),
                        }),
                        app: None,
                        netbanking: None,
                        card: None,
                        emi: None,
                        paypal: None,
                        paylater: None,
                        cardless_emi: None,
                    })
                }
            }
        }
        _ => Err(ConnectorError::NotSupported {
            message: "Only UPI payment methods are supported for Cashfree V3".to_string(),
            connector: "Cashfree",
        }),
    }
}

// ============================================================================
// Request Transformations
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        crate::connectors::cashfree::CashfreeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for CashfreePaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        wrapper: crate::connectors::cashfree::CashfreeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&wrapper.router_data)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for CashfreePaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract payment_session_id from reference_id (set by CreateOrder response)
        let payment_session_id = item.resource_common_data.reference_id.clone().ok_or(
            ConnectorError::MissingRequiredField {
                field_name: "payment_session_id",
            },
        )?;

        // Get Cashfree payment method data directly
        let payment_method = get_cashfree_payment_method_data(&item.request.payment_method_data)?;

        Ok(Self {
            payment_session_id,
            payment_method,
            payment_surcharge: None, // TODO: Add surcharge logic if needed
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        crate::connectors::cashfree::CashfreeRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for CashfreePaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _wrapper: crate::connectors::cashfree::CashfreeRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Empty request for PSync
        Ok(Self {})
    }
}

impl
    TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for CashfreePaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Empty request for PSync
        Ok(Self {})
    }
}

// ============================================================================
// Response Transformations
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        ResponseRouterData<
            CashfreePaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            CashfreePaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        let (status, redirection_data) = match response.channel.as_str() {
            "link" => {
                // Intent flow - extract deep link from payload._default
                let deep_link = response.data.payload.map(|p| p.default_link).ok_or(
                    ConnectorError::MissingRequiredField {
                        field_name: "intent_link",
                    },
                )?;

                // Trim deep link at "?" as per Haskell: truncateIntentLink "?" link
                let trimmed_link = if let Some(pos) = deep_link.find('?') {
                    &deep_link[(pos + 1)..]
                } else {
                    &deep_link
                };

                // Create UPI intent redirection
                let redirection_data = Some(Box::new(Some(
                    domain_types::router_response_types::RedirectForm::Uri {
                        uri: trimmed_link.to_string(),
                    },
                )));

                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    redirection_data,
                )
            }
            "collect" => {
                // Collect flow - return without redirection, status Pending
                (common_enums::AttemptStatus::Pending, None)
            }
            _ => (common_enums::AttemptStatus::Failure, None),
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response
                        .cf_payment_id
                        .as_ref()
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                ),
                redirection_data: redirection_data.and_then(|data| *data).map(Box::new),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.cf_payment_id.map(|id| id.to_string()),
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

impl
    TryFrom<
        ResponseRouterData<
            CashfreePaymentsSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            CashfreePaymentsSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = item.response;

        // Map Cashfree order status to AttemptStatus
        let status = match response.order_status.as_str() {
            "PAID" | "SUCCESS" => common_enums::AttemptStatus::Charged,
            "PENDING" | "ACTIVE" => common_enums::AttemptStatus::Pending,
            "FAILED" | "CANCELLED" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response
                        .cf_payment_id
                        .as_ref()
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.cf_payment_id.map(|id| id.to_string()),
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

// Order creation response transformation (for compatibility)
impl TryFrom<CashfreeOrderCreateResponse> for domain_types::connector_types::PaymentCreateOrderResponse {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: CashfreeOrderCreateResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            order_id: response.payment_session_id,
        })
    }
}