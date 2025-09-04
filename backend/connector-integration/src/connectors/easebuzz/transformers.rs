use common_enums as enums;
use common_utils::{crypto::{GenerateDigest, Sha512}, types::MinorUnit};
use url::Url;
use domain_types::{
    connector_types::{
        PaymentFlowData, PaymentsSyncData, PaymentsAuthorizeData, PaymentsResponseData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// ================================================================================================
// EaseBuzz Authentication
// ================================================================================================

#[derive(Debug, Clone)]
pub struct EasebuzzAuthType {
    pub api_key: Secret<String>,
    pub merchant_key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EasebuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_key: Secret::new("".to_string()), // Will be set from merchant account
                salt: Secret::new("".to_string()), // Will be set from merchant account
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_key: key1.to_owned(),
                salt: Secret::new("".to_string()), // Will be set from merchant account
            }),
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_key: key1.to_owned(),
                salt: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ================================================================================================
// EaseBuzz Router Data
// ================================================================================================

#[derive(Debug, Clone)]
pub struct EasebuzzRouterData<T> {
    pub amount: String,
    pub router_data: T,
}

impl<T> TryFrom<(String, T)> for EasebuzzRouterData<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((amount, router_data): (String, T)) -> Result<Self, Self::Error> {
        Ok(Self { amount, router_data })
    }
}

// ================================================================================================
// Payment Request Types
// ================================================================================================

#[derive(Debug, Serialize)]
pub struct EasebuzzPaymentsRequest {
    pub txnid: String,
    pub amount: String,
    pub productinfo: String,
    pub firstname: String,
    pub email: String,
    pub phone: String,
    pub surl: String,
    pub furl: String,
    pub hash: String,
    pub key: String,
    // UPI specific fields
    pub upi_va: Option<String>,
    pub payment_category: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub split_payments: Option<String>,
    pub merchant_logo: Option<String>,
    pub show_payment_mode: Option<String>,
    pub payment_mode_order: Option<String>,
    pub auto_redirect: Option<String>,
    pub merchant_sms_permission: Option<String>,
    pub request_flow: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> TryFrom<crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>> for EasebuzzPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(wrapper: crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;
        let auth = EasebuzzAuthType::try_from(&router_data.connector_auth_type)?;
        
        let txnid = router_data.request.related_transaction_id.clone().unwrap_or_default();
        let amount = wrapper.router_data.request.minor_amount.to_string();
        let email = router_data.request.get_email()?.clone();
        let phone = router_data.resource_common_data.get_billing_phone()?.number
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "billing.phone.number",
            })?
            .clone()
            .expose();
        let firstname = router_data.resource_common_data.get_billing_first_name()?.expose();
        
        // UPI specific handling
        let (upi_va, payment_category, request_flow) = match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    UpiData::UpiCollect(collect_data) => {
                        (Some(collect_data.vpa_id.as_ref().unwrap_or(&Secret::new(String::new())).peek().to_string()), Some("UPI".to_string()), Some("COLLECT".to_string()))
                    },
                    UpiData::UpiIntent(_) => {
                        (None, Some("UPI".to_string()), Some("INTENT".to_string()))
                    },
                }
            },
            _ => (None, None, None),
        };

        // Generate hash for request integrity
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            auth.api_key.peek(),
            txnid,
            amount,
            "Payment",
            firstname,
            email.clone().expose().expose(),
            "||||||||||",
            auth.salt.peek()
        );
        let hash = Sha512.generate_digest(hash_string.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            txnid,
            amount,
            productinfo: "Payment".to_string(),
            firstname,
            email: email.expose().expose(),
            phone,
            surl: router_data.request.get_router_return_url()?,
            furl: router_data.request.get_router_return_url()?,
            hash: hex::encode(hash),
            key: auth.api_key.peek().to_string(),
            upi_va,
            payment_category,
            sub_merchant_id: None,
            split_payments: None,
            merchant_logo: None,
            show_payment_mode: Some("UPI".to_string()),
            payment_mode_order: Some("UPI".to_string()),
            auto_redirect: Some("1".to_string()),
            merchant_sms_permission: Some("1".to_string()),
            request_flow,
        })
    }
}

// ================================================================================================
// Payment Response Types
// ================================================================================================

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzPaymentsResponse {
    pub status: Option<bool>,
    pub data: Option<String>,
    pub error_desc: Option<String>,
    pub easebuzz_id: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub payment_source: Option<String>,
    pub PG_TYPE: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error: Option<String>,
    pub error_Message: Option<String>,
    pub net_amount_debit: Option<String>,
    pub addedon: Option<String>,
    pub payment_mode: Option<String>,
    pub cash_back_percentage: Option<String>,
    pub deduction_percentage: Option<String>,
    pub upi_va: Option<String>,
    pub name_on_card: Option<String>,
    pub cardnum: Option<String>,
    pub issuing_bank: Option<String>,
    pub card_type: Option<String>,
    pub merchant_logo: Option<String>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub udf6: Option<String>,
    pub udf7: Option<String>,
    pub udf8: Option<String>,
    pub udf9: Option<String>,
    pub udf10: Option<String>,
    pub hash: Option<String>,
    pub unmappedstatus: Option<String>,
    pub mode: Option<String>,
    pub upi_qr: Option<String>,
    pub qr_link: Option<String>,
    pub msg_title: Option<String>,
    pub msg_desc: Option<String>,
}

impl<T> TryFrom<ResponseRouterData<EasebuzzPaymentsResponse, RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, T, PaymentsResponseData>>> for RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, T, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<EasebuzzPaymentsResponse, RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, T, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        let response = &item.response;
        
        let _status = match response.status {
            Some(true) => {
                if response.qr_link.is_some() || response.upi_qr.is_some() {
                    enums::AttemptStatus::AuthenticationPending
                } else {
                    enums::AttemptStatus::Charged
                }
            },
            Some(false) => {
                if let Some(error_desc) = &response.error_desc {
                    if error_desc.contains("pending") || error_desc.contains("initiated") {
                        enums::AttemptStatus::Pending
                    } else {
                        enums::AttemptStatus::Failure
                    }
                } else {
                    enums::AttemptStatus::Failure
                }
            },
            None => enums::AttemptStatus::Pending,
        };

        let _connector_transaction_id = response.easebuzz_id.clone()
            .or_else(|| response.txnid.clone());

        let redirection_data = if let Some(qr_link) = &response.qr_link {
            let url = Url::parse(qr_link)
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Some(domain_types::router_response_types::RedirectForm::from((
                url,
                common_utils::request::Method::Get,
            )))
        } else {
            None
        };

        let _amount_received = response.amount.as_ref()
            .and_then(|amt| amt.parse::<f64>().ok())
            .map(|amt| MinorUnit::new((amt * 100.0) as i64));

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.txnid.clone().unwrap_or_default()),
                redirection_data: redirection_data.map(Box::new),
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: response.bank_ref_num.clone(),
                connector_response_reference_id: response.bank_ref_num.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ================================================================================================
// Payment Sync Request Types
// ================================================================================================

#[derive(Debug, Serialize)]
pub struct EasebuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub key: String,
    pub hash: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> TryFrom<crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>> for EasebuzzPaymentsSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(wrapper: crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = EasebuzzAuthType::try_from(&item.connector_auth_type)?;
        
        let txnid = item.request.connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        
        let amount = item.request.amount.to_string();
        // For sync requests, we don't have access to email/phone from PaymentsSyncData
        // Generate hash for sync request without email/phone
        let hash_string = format!(
            "{}|{}|{}|{}",
            auth.api_key.peek(),
            txnid,
            amount,
            auth.salt.peek()
        );
        let hash = Sha512.generate_digest(hash_string.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            txnid,
            amount,
            email: "".to_string(), // Not available in sync data
            phone: "".to_string(), // Not available in sync data
            key: auth.api_key.peek().to_string(),
            hash: hex::encode(hash),
        })
    }
}

// ================================================================================================
// Payment Sync Response Types
// ================================================================================================

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzPaymentsSyncResponse {
    pub status: Option<bool>,
    pub msg: Option<EasebuzzSyncMessage>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzSyncMessage {
    Success(EasebuzzPaymentsResponse),
    Error(String),
}

impl TryFrom<ResponseRouterData<EasebuzzPaymentsSyncResponse, RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>> for RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<EasebuzzPaymentsSyncResponse, RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        let response = &item.response;
        
        let (_status, _connector_transaction_id, _amount_received, payment_id) = match &response.msg {
            Some(EasebuzzSyncMessage::Success(payment_response)) => {
                let status = match payment_response.status {
                    Some(true) => enums::AttemptStatus::Charged,
                    Some(false) => {
                        if let Some(error_desc) = &payment_response.error_desc {
                            if error_desc.contains("pending") || error_desc.contains("initiated") {
                                enums::AttemptStatus::Pending
                            } else {
                                enums::AttemptStatus::Failure
                            }
                        } else {
                            enums::AttemptStatus::Failure
                        }
                    },
                    None => enums::AttemptStatus::Pending,
                };

                let connector_transaction_id = payment_response.easebuzz_id.clone()
                    .or_else(|| payment_response.txnid.clone());

                let amount_received = payment_response.amount.as_ref()
                    .and_then(|amt| amt.parse::<f64>().ok())
                    .map(|amt| MinorUnit::new((amt * 100.0) as i64));

                let payment_id = payment_response.txnid.clone();

                (status, connector_transaction_id, amount_received, payment_id)
            },
            Some(EasebuzzSyncMessage::Error(_)) | None => {
                (enums::AttemptStatus::Failure, None, None, None)
            },
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment_id.unwrap_or_default()),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ================================================================================================
// Refund Request Types
// ================================================================================================

#[derive(Debug, Serialize)]
pub struct EasebuzzRefundRequest {
    pub txnid: String,
    pub refund_amount: String,
    pub phone: String,
    pub email: String,
    pub amount: String,
    pub key: String,
    pub hash: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> TryFrom<crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>> for EasebuzzRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(wrapper: crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;
        let auth = EasebuzzAuthType::try_from(&router_data.connector_auth_type)?;
        
        let txnid = router_data.request.connector_transaction_id.clone();
        let refund_amount = wrapper.router_data.request.refund_amount.to_string();
        let amount = router_data.request.payment_amount.to_string();
        // For refunds, we don't have access to email/phone from RefundsData
        // Generate hash for refund request without email/phone
        let hash_string = format!(
            "{}|{}|{}|{}",
            auth.api_key.peek(),
            txnid,
            refund_amount,
            auth.salt.peek()
        );
        let hash = Sha512.generate_digest(hash_string.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            txnid,
            refund_amount,
            phone: "".to_string(), // Not available in refund data
            email: "".to_string(), // Not available in refund data
            amount,
            key: auth.api_key.peek().to_string(),
            hash: hex::encode(hash),
        })
    }
}

// ================================================================================================
// Refund Response Types
// ================================================================================================

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzRefundResponse {
    pub status: Option<bool>,
    pub reason: Option<String>,
    pub easebuzz_id: Option<String>,
    pub refund_id: Option<String>,
    pub refund_amount: Option<String>,
    pub error_desc: Option<String>,
}

impl TryFrom<ResponseRouterData<EasebuzzRefundResponse, RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>>> for RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<EasebuzzRefundResponse, RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>>) -> Result<Self, Self::Error> {
        let response = &item.response;
        
        let status = match response.status {
            Some(true) => enums::RefundStatus::Success,
            Some(false) => {
                if let Some(reason) = &response.reason {
                    if reason.contains("pending") || reason.contains("initiated") {
                        enums::RefundStatus::Pending
                    } else {
                        enums::RefundStatus::Failure
                    }
                } else {
                    enums::RefundStatus::Failure
                }
            },
            None => enums::RefundStatus::Pending,
        };

        let connector_refund_id = response.refund_id.clone()
            .or_else(|| response.easebuzz_id.clone());

        let _refund_amount = response.refund_amount.as_ref()
            .and_then(|amt| amt.parse::<f64>().ok())
            .map(|amt| MinorUnit::new((amt * 100.0) as i64));

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: connector_refund_id.unwrap_or_default(),
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ================================================================================================
// Refund Sync Request Types
// ================================================================================================

#[derive(Debug, Serialize)]
pub struct EasebuzzRefundSyncRequest {
    pub key: String,
    pub easebuzz_id: String,
    pub hash: String,
    pub merchant_refund_id: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> TryFrom<crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>> for EasebuzzRefundSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(wrapper: crate::connectors::easebuzz::EasebuzzRouterData<RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let auth = EasebuzzAuthType::try_from(&item.connector_auth_type)?;
        
        let easebuzz_id = item.request.connector_refund_id.clone();
        let merchant_refund_id = item.request.connector_transaction_id.clone();

        // Generate hash for refund sync request
        let hash_string = format!(
            "{}|{}|{}",
            auth.api_key.peek(),
            easebuzz_id,
            auth.salt.peek()
        );
        let hash = Sha512.generate_digest(hash_string.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            key: auth.api_key.peek().to_string(),
            easebuzz_id,
            hash: hex::encode(hash),
            merchant_refund_id,
        })
    }
}



// ================================================================================================
// Refund Sync Response Types
// ================================================================================================

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzRefundSyncResponse {
    pub code: Option<i32>,
    pub status: Option<String>,
    pub response: Option<EasebuzzRefundSyncData>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EasebuzzRefundSyncData {
    Success(EasebuzzRefundSyncSuccessResponse),
    Failure(EasebuzzRefundSyncFailureResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzRefundSyncSuccessResponse {
    pub txnid: Option<String>,
    pub easebuzz_id: Option<String>,
    pub net_amount_debit: Option<String>,
    pub amount: Option<String>,
    pub refunds: Option<Vec<RefundSyncType>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzRefundSyncFailureResponse {
    pub status: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefundSyncType {
    pub refund_id: Option<String>,
    pub refund_status: Option<String>,
    pub merchant_refund_id: Option<String>,
    pub merchant_refund_date: Option<String>,
    pub refund_settled_date: Option<String>,
    pub refund_amount: Option<String>,
    pub arn_number: Option<String>,
}

impl TryFrom<ResponseRouterData<EasebuzzRefundSyncResponse, RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>> for RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<EasebuzzRefundSyncResponse, RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>) -> Result<Self, Self::Error> {
        let response = &item.response;
        
        let (status, connector_refund_id, _refund_amount, _reason) = match &response.response {
            Some(EasebuzzRefundSyncData::Success(success_response)) => {
                let status = if let Some(refunds) = &success_response.refunds {
                    if let Some(refund) = refunds.first() {
                        match refund.refund_status.as_deref() {
                            Some("success") | Some("Success") => enums::RefundStatus::Success,
                            Some("pending") | Some("Pending") => enums::RefundStatus::Pending,
                            Some("failed") | Some("Failed") => enums::RefundStatus::Failure,
                            _ => enums::RefundStatus::Pending,
                        }
                    } else {
                        enums::RefundStatus::Pending
                    }
                } else {
                    enums::RefundStatus::Pending
                };

                let connector_refund_id = success_response.refunds.as_ref()
                    .and_then(|refunds| refunds.first())
                    .and_then(|refund| refund.refund_id.clone())
                    .or_else(|| success_response.easebuzz_id.clone());

                let refund_amount = success_response.refunds.as_ref()
                    .and_then(|refunds| refunds.first())
                    .and_then(|refund| refund.refund_amount.as_ref())
                    .and_then(|amt| amt.parse::<f64>().ok())
                    .map(|amt| MinorUnit::new((amt * 100.0) as i64));

                (status, connector_refund_id, refund_amount, None)
            },
            Some(EasebuzzRefundSyncData::Failure(failure_response)) => {
                (enums::RefundStatus::Failure, None, None, failure_response.message.clone())
            },
            None => {
                (enums::RefundStatus::Failure, None, None, Some("No response data".to_string()))
            },
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: connector_refund_id.unwrap_or_default(),
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ================================================================================================
// Error Response Types
// ================================================================================================

#[derive(Debug, Deserialize, Serialize)]
pub struct EasebuzzErrorResponse {
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
    pub reason: Option<String>,
    pub status: Option<bool>,
    pub message: Option<String>,
}

// ================================================================================================
// Helper Functions
// ================================================================================================

impl EasebuzzPaymentsRequest {
    pub fn get_payment_method_type(&self) -> Option<String> {
        self.payment_category.clone()
    }

    pub fn is_upi_payment(&self) -> bool {
        self.payment_category.as_deref() == Some("UPI")
    }

    pub fn is_upi_collect(&self) -> bool {
        self.is_upi_payment() && self.upi_va.is_some()
    }

    pub fn is_upi_intent(&self) -> bool {
        self.is_upi_payment() && self.request_flow.as_deref() == Some("INTENT")
    }
}

impl EasebuzzPaymentsResponse {
    pub fn get_payment_status(&self) -> Option<String> {
        if let Some(status) = self.status {
            if status {
                Some("success".to_string())
            } else {
                Some("failure".to_string())
            }
        } else {
            Some("pending".to_string())
        }
    }

    pub fn get_failure_reason(&self) -> Option<String> {
        self.error_desc.clone()
            .or_else(|| self.error.clone())
            .or_else(|| self.error_Message.clone())
    }

    pub fn is_upi_payment(&self) -> bool {
        self.payment_mode.as_deref() == Some("UPI") || 
        self.PG_TYPE.as_deref() == Some("UPI") ||
        self.upi_va.is_some()
    }

    pub fn has_qr_code(&self) -> bool {
        self.qr_link.is_some() || self.upi_qr.is_some()
    }
}

// ================================================================================================
// Additional Helper Traits
// ================================================================================================

pub trait EasebuzzPaymentMethodExt<T: PaymentMethodDataTypes> {
    fn get_upi_data(&self) -> Option<&UpiData>;
    fn is_upi_payment(&self) -> bool;
}

impl<T: PaymentMethodDataTypes> EasebuzzPaymentMethodExt<T> for PaymentMethodData<T> {
    fn get_upi_data(&self) -> Option<&UpiData> {
        match self {
            PaymentMethodData::Upi(upi_data) => Some(upi_data),
            _ => None,
        }
    }

    fn is_upi_payment(&self) -> bool {
        matches!(self, PaymentMethodData::Upi(_))
    }
}

// ================================================================================================
// Constants
// ================================================================================================

pub mod constants {
    pub const UPI_PAYMENT_CATEGORY: &str = "UPI";
    pub const UPI_COLLECT_FLOW: &str = "COLLECT";
    pub const UPI_INTENT_FLOW: &str = "INTENT";
    pub const DEFAULT_PRODUCT_INFO: &str = "Payment";
    pub const AUTO_REDIRECT_ENABLED: &str = "1";
    pub const SMS_PERMISSION_ENABLED: &str = "1";
}