use domain_types::payment_method_data::UpiData;
use hyperswitch_masking::ExposeInterface;
use serde::{Deserialize, Serialize};
use error_stack::Report;
use crate::types::ResponseRouterData;

// Request structures for PayTMv2 API

#[derive(Debug, Clone, Serialize)]
pub struct Paytmv2PaymentsRequest {
    pub body: Paytmv2PaymentsRequestBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct Paytmv2PaymentsRequestBody {
    pub mid: String,
    pub order_id: String,
    pub txn_amount: Paytmv2TxnAmount,
    pub user_info: Paytmv2UserInfo,
    pub payment_method: Paytmv2PaymentMethod,
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paytmv2TxnAmount {
    pub value: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Paytmv2UserInfo {
    pub cust_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Paytmv2PaymentMethod {
    pub upi: Option<Paytmv2Upi>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Paytmv2Upi {
    pub vpa: String,
    pub flow: String,
}

// Sync request structures

#[derive(Debug, Clone, Serialize)]
pub struct Paytmv2PaymentsSyncRequest {
    pub body: Paytmv2PaymentsSyncRequestBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct Paytmv2PaymentsSyncRequestBody {
    pub mid: String,
    pub order_id: String,
}

// Response structures for PayTMv2 API

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Paytmv2PaymentsResponse {
    pub head: Paytmv2ResponseHead,
    pub body: Paytmv2PaymentsResponseBody,
    pub status_code: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Paytmv2ResponseHead {
    pub response_timestamp: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Paytmv2PaymentsResponseBody {
    pub result_info: Paytmv2ResultInfo,
    pub mid: String,
    pub order_id: String,
    pub txn_id: String,
    pub bank_txn_id: Option<String>,
    pub txn_amount: Paytmv2TxnAmount,
    pub status: String,
    pub resp_code: Option<String>,
    pub resp_msg: String,
    pub txn_url: Option<String>,
    pub created_at: String,
    pub payment_mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Paytmv2ResultInfo {
    pub result_status: String,
    pub result_code: Option<String>,
    pub result_msg: Option<String>,
}

// Sync response structures

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Paytmv2PaymentsSyncResponse {
    pub head: Paytmv2ResponseHead,
    pub body: Paytmv2PaymentsSyncResponseBody,
    pub status_code: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Paytmv2PaymentsSyncResponseBody {
    pub result_info: Paytmv2ResultInfo,
    pub mid: String,
    pub order_id: String,
    pub txn_id: String,
    pub bank_txn_id: Option<String>,
    pub txn_amount: Paytmv2TxnAmount,
    pub status: String,
    pub resp_code: Option<String>,
    pub resp_msg: String,
    pub created_at: String,
    pub payment_mode: Option<String>,
}

// Error response structure

#[derive(Debug, Clone, Deserialize)]
pub struct Paytmv2ErrorResponse {
    pub head: Paytmv2ErrorHead,
    pub body: Option<Paytmv2ErrorBody>,
    pub status_code: Option<u16>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Paytmv2ErrorHead {
    pub response_timestamp: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Paytmv2ErrorBody {
    pub result_info: Paytmv2ResultInfo,
    pub extra_params_map: Option<serde_json::Value>,
}

// TryFrom implementations for data transformation

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize> 
    TryFrom<crate::connectors::paytmv2::Paytmv2RouterData<domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>, T>> 
    for Paytmv2PaymentsRequest 
{
    type Error = Report<domain_types::errors::ConnectorError>;

    fn try_from(
        router_data: crate::connectors::paytmv2::Paytmv2RouterData<domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>, T>
    ) -> Result<Self, Self::Error> {
        let connector = router_data.connector;
        let amount = connector.amount_converter.convert(
            router_data.router_data.request.minor_amount, 
            router_data.router_data.request.currency
        ).map_err(|_| domain_types::errors::ConnectorError::ParsingFailed)?;
        
        let payment_method_data = match &router_data.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => upi_data,
            _ => {
                return Err(domain_types::errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "Paytmv2",
                }.into())
            }
        };

        let upi_vpa = match payment_method_data {
            domain_types::payment_method_data::UpiData::UpiCollect(upi_collect) => {
                upi_collect.vpa_id.clone().unwrap_or_default().expose().clone()
            },
            domain_types::payment_method_data::UpiData::UpiIntent(_) => {
                return Err(domain_types::errors::ConnectorError::NotSupported {
                    message: "UPI Intent not supported".to_string(),
                    connector: "Paytmv2",
                }.into())
            },
        };

        Ok(Paytmv2PaymentsRequest {
            body: Paytmv2PaymentsRequestBody {
                mid: "test_merchant".to_string(), // TODO: Get from config
                order_id: router_data.router_data.resource_common_data.payment_id.clone(),
                txn_amount: Paytmv2TxnAmount {
                    value: amount.get_amount_as_string(),
                    currency: router_data.router_data.request.currency.to_string(),
                },
                user_info: Paytmv2UserInfo {
                    cust_id: format!("{:?}", router_data.router_data.request.customer_id.clone().unwrap_or_default()),
                },
                payment_method: Paytmv2PaymentMethod {
                    upi: Some(Paytmv2Upi {
                        vpa: upi_vpa,
                        flow: "COLLECT".to_string(),
                    }),
                },
                callback_url: router_data.router_data.request.webhook_url.clone(),
            },
        })
    }
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize> 
    TryFrom<crate::connectors::paytmv2::Paytmv2RouterData<domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>, T>> 
    for Paytmv2PaymentsSyncRequest 
{
    type Error = Report<domain_types::errors::ConnectorError>;

    fn try_from(
        router_data: crate::connectors::paytmv2::Paytmv2RouterData<domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>, T>
    ) -> Result<Self, Self::Error> {
        Ok(Paytmv2PaymentsSyncRequest {
            body: Paytmv2PaymentsSyncRequestBody {
                mid: "test_merchant".to_string(), // TODO: Get from config
                order_id: router_data.router_data.resource_common_data.payment_id.clone(),
            },
        })
    }
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize> 
    TryFrom<ResponseRouterData<Paytmv2PaymentsResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>>> 
    for domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData> 
{
    type Error = Report<domain_types::errors::ConnectorError>;

    fn try_from(
        response_data: ResponseRouterData<Paytmv2PaymentsResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>>
    ) -> Result<Self, Self::Error> {
        let response = response_data.response;
        let mut router_data = response_data.router_data;
        
        match response.body.status.as_str() {
            "PENDING" => {
                router_data.response = Ok(domain_types::connector_types::PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: Some(Box::new(domain_types::router_response_types::RedirectForm::Form {
                        endpoint: response.body.txn_url.clone().unwrap_or_default(),
                        method: common_utils::Method::Get,
                        form_fields: std::collections::HashMap::new(),
                    })),
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                });
            },
            "SUCCESS" => {
                router_data.response = Ok(domain_types::connector_types::PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                });
            },
            "FAILURE" => {
                router_data.response = Err(domain_types::router_data::ErrorResponse {
                    code: "FAILURE".to_string(),
                    message: response.body.resp_msg.clone(),
                    reason: None,
                    status_code: response.status_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            },
            _ => {
                router_data.response = Err(domain_types::router_data::ErrorResponse {
                    code: "UE_00".to_string(),
                    message: format!("Unexpected status: {}", response.body.status),
                    reason: None,
                    status_code: response.status_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            },
        }
        
        Ok(router_data)
    }
}

impl TryFrom<ResponseRouterData<Paytmv2PaymentsSyncResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>>> 
    for domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData> 
{
    type Error = Report<domain_types::errors::ConnectorError>;

    fn try_from(
        response_data: ResponseRouterData<Paytmv2PaymentsSyncResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>>
    ) -> Result<Self, Self::Error> {
        let response = response_data.response;
        let mut router_data = response_data.router_data;
        
        match response.body.status.as_str() {
            "SUCCESS" => {
                router_data.response = Ok(domain_types::connector_types::PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                });
            },
            "PENDING" => {
                router_data.response = Ok(domain_types::connector_types::PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                });
            },
            "FAILURE" => {
                router_data.response = Err(domain_types::router_data::ErrorResponse {
                    code: "FAILURE".to_string(),
                    message: response.body.resp_msg.clone(),
                    reason: None,
                    status_code: response.status_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            },
            _ => {
                router_data.response = Err(domain_types::router_data::ErrorResponse {
                    code: "UE_00".to_string(),
                    message: format!("Unexpected status: {}", response.body.status),
                    reason: None,
                    status_code: response.status_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            },
        }
        
        Ok(router_data)
    }
}

impl TryFrom<UpiData> for Paytmv2Upi {
    type Error = domain_types::errors::ConnectorError;

    fn try_from(upi_data: UpiData) -> Result<Self, Self::Error> {
        match upi_data {
            domain_types::payment_method_data::UpiData::UpiCollect(upi_collect) => {
                let vpa = upi_collect.vpa_id
                    .map(|v| v.expose().clone())
                    .unwrap_or_default();
                Ok(Self {
                    vpa,
                    flow: "COLLECT".to_string(),
                })
            },
            domain_types::payment_method_data::UpiData::UpiIntent(_) => {
                Err(domain_types::errors::ConnectorError::NotSupported {
                    message: "UPI Intent not supported".to_string(),
                    connector: "Paytmv2",
                }.into())
            },
        }
    }
}

impl TryFrom<Paytmv2PaymentsResponseBody> for domain_types::connector_types::PaymentsResponseData {
    type Error = domain_types::errors::ConnectorError;

    fn try_from(response_body: Paytmv2PaymentsResponseBody) -> Result<Self, Self::Error> {
        use domain_types::connector_types::{ResponseId, PaymentsResponseData};

        match response_body.status.as_str() {
            "SUCCESS" => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response_body.txn_id),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: response_body.bank_txn_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: 200,
            }),
            "PENDING" => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response_body.txn_id),
                redirection_data: response_body.txn_url.map(|url| {
                    Box::new(domain_types::router_response_types::RedirectForm::Form {
                        endpoint: url,
                        method: common_utils::Method::Get,
                        form_fields: std::collections::HashMap::new(),
                    })
                }),
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: response_body.bank_txn_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: 200,
            }),
            "FAILURE" => Err(domain_types::errors::ConnectorError::FailedAtConnector {
                message: response_body.resp_msg,
                code: "FAILURE".to_string(),
            }),
            _ => Err(domain_types::errors::ConnectorError::UnexpectedResponseError(
                format!("Unexpected status: {}", response_body.status).into()
            )),
        }
    }
}

impl TryFrom<Paytmv2PaymentsSyncResponseBody> for domain_types::connector_types::PaymentsResponseData {
    type Error = domain_types::errors::ConnectorError;

    fn try_from(response_body: Paytmv2PaymentsSyncResponseBody) -> Result<Self, Self::Error> {
        use domain_types::connector_types::{ResponseId, PaymentsResponseData};

        match response_body.status.as_str() {
            "SUCCESS" => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response_body.txn_id),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: response_body.bank_txn_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: 200,
            }),
            "PENDING" => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response_body.txn_id),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: response_body.bank_txn_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: 200,
            }),
            "FAILURE" => Err(domain_types::errors::ConnectorError::FailedAtConnector {
                message: response_body.resp_msg,
                code: "FAILURE".to_string(),
            }),
            _ => Err(domain_types::errors::ConnectorError::UnexpectedResponseError(
                format!("Unexpected status: {}", response_body.status).into()
            )),
        }
    }
}

// Helper functions for status mapping

pub fn map_paytmv2_status_to_attempt_status(status: &str) -> common_enums::AttemptStatus {
    match status {
        "SUCCESS" => common_enums::AttemptStatus::Charged,
        "PENDING" => common_enums::AttemptStatus::Pending,
        "FAILURE" => common_enums::AttemptStatus::Failure,
        "TXN_FAILURE" => common_enums::AttemptStatus::Failure,
        "OPEN" => common_enums::AttemptStatus::Pending,
        _ => common_enums::AttemptStatus::AuthenticationPending,
    }
}

pub fn map_paytmv2_error_code_to_connector_error(error_code: &str) -> domain_types::errors::ConnectorError {
    match error_code {
        "1001" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Invalid merchant ID".to_string(),
            code: "1001".to_string(),
        },
        "1002" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Invalid order ID".to_string(),
            code: "1002".to_string(),
        },
        "1003" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Invalid transaction amount".to_string(),
            code: "1003".to_string(),
        },
        "1004" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Invalid customer ID".to_string(),
            code: "1004".to_string(),
        },
        "1005" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Invalid payment method".to_string(),
            code: "1005".to_string(),
        },
        "2001" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Authentication failed".to_string(),
            code: "2001".to_string(),
        },
        "2002" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Invalid checksum".to_string(),
            code: "2002".to_string(),
        },
        "3001" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Transaction declined by bank".to_string(),
            code: "3001".to_string(),
        },
        "3002" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Insufficient funds".to_string(),
            code: "3002".to_string(),
        },
        "3003" => domain_types::errors::ConnectorError::FailedAtConnector {
            message: "Invalid UPI ID".to_string(),
            code: "3003".to_string(),
        },
        "4001" => domain_types::errors::ConnectorError::RequestTimeoutReceived,
        "5001" => domain_types::errors::ConnectorError::FailedToObtainIntegrationUrl,
        _ => domain_types::errors::ConnectorError::UnexpectedResponseError(
            format!("Unknown error code: {}", error_code).into()
        ),
    }
}