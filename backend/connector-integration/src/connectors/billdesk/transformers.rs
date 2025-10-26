use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    request::Method,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    paydata: Option<String>,
    ipaddress: Option<String>,
    useragent: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    msg: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundSyncRequest {
    msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponseData {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskRdataResponse>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRdataResponse {
    pub parameters: Option<HashMap<String, String>>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    pub _MerchantID: String,
    pub _CustomerID: String,
    pub _TxnReferenceNo: String,
    pub _BankReferenceNo: String,
    pub _TxnAmount: String,
    pub _BankID: String,
    pub _TxnType: Option<String>,
    pub _CurrencyType: String,
    pub _ItemCode: String,
    pub _TxnDate: Option<String>,
    pub _AuthStatus: String,
    pub _AdditionalInfo1: Option<String>,
    pub _AdditionalInfo2: Option<String>,
    pub _AdditionalInfo3: Option<String>,
    pub _AdditionalInfo4: Option<String>,
    pub _AdditionalInfo5: Option<String>,
    pub _AdditionalInfo6: Option<String>,
    pub _AdditionalInfo7: Option<String>,
    pub _ErrorStatus: String,
    pub _ErrorDescription: String,
    pub _Checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundSyncResponse {
    pub _RequestType: String,
    pub _MerchantID: String,
    pub _RefundId: String,
    pub _TxnReferenceNo: String,
    pub _TxnDate: String,
    pub _CustomerID: String,
    pub _TxnCurrency: String,
    pub _TxnAmount: String,
    pub _RefAmount: String,
    pub _RefDateTime: String,
    pub _RefStatus: String,
    pub _MerchantRefNo: String,
    pub _RefARN: String,
    pub _RefARNTimeStamp: String,
    pub _ErrorCode: String,
    pub _ErrorReason: String,
    pub _ProcessStatus: String,
    pub _Checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct BilldeskVoidRequest;
#[derive(Debug, Clone)]
pub struct BilldeskVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCaptureRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRefundRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BilldeskPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
}

impl From<BilldeskPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BilldeskPaymentStatus) -> Self {
        match item {
            BilldeskPaymentStatus::Success => Self::Charged,
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
            BilldeskPaymentStatus::Failure => Self::Failure,
        }
    }
}

fn build_billdesk_message<T>(
    router_data: &BilldeskRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
    is_sync: bool,
) -> CustomResult<String, errors::ConnectorError>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    let customer_id = router_data.router_data.resource_common_data.get_customer_id()?;
    let amount = router_data
        .connector
        .amount_converter
        .convert(
            router_data.router_data.request.minor_amount,
            router_data.router_data.request.currency,
        )
        .change_context(ConnectorError::RequestEncodingFailed)?;

    let mut message_data = HashMap::new();
    
    if is_sync {
        // For sync requests, we need the transaction reference
        message_data.insert("MerchantID".to_string(), get_merchant_id(&router_data.router_data.connector_auth_type)?);
        message_data.insert("CustomerID".to_string(), customer_id.get_string_repr().to_string());
        message_data.insert("TxnReferenceNo".to_string(), router_data.router_data.resource_common_data.connector_request_reference_id.clone());
    } else {
        // For payment initiation
        message_data.insert("MerchantID".to_string(), get_merchant_id(&router_data.router_data.connector_auth_type)?);
        message_data.insert("CustomerID".to_string(), customer_id.get_string_repr().to_string());
        message_data.insert("TxnAmount".to_string(), amount.to_string());
        message_data.insert("Currency".to_string(), router_data.router_data.request.currency.to_string());
        message_data.insert("TxnType".to_string(), "UPI".to_string());
        message_data.insert("ItemCode".to_string(), "DIRECT".to_string());
        
        // Add UPI specific data if available
        if matches!(router_data.router_data.resource_common_data.payment_method, common_enums::PaymentMethod::Upi) {
            if let Some(upi_data) = &router_data.router_data.request.payment_method_data {
                if let Some(upi) = upi_data.get_upi() {
                    if let Some(vpa) = &upi.vpa {
                        message_data.insert("VPA".to_string(), vpa.clone());
                    }
                }
            }
        }
    }

    // Convert HashMap to JSON string
    serde_json::to_string(&message_data)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

fn get_merchant_id(auth_type: &ConnectorAuthType) -> CustomResult<String, errors::ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => Ok(api_key.peek().clone()),
        _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
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
        BilldeskRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let msg = build_billdesk_message(&item, false)?;
        
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // For UPI payments, we might need additional payment data
        let paydata = if matches!(item.router_data.resource_common_data.payment_method, common_enums::PaymentMethod::Upi) {
            Some("UPI".to_string())
        } else {
            None
        };

        Ok(Self {
            msg,
            paydata,
            ipaddress: Some(ip_address),
            useragent: Some(user_agent),
        })
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
        BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let msg = build_billdesk_message(&item, true)?;
        
        Ok(Self { msg })
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
        BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BilldeskRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;

        let mut message_data = HashMap::new();
        message_data.insert("MerchantID".to_string(), merchant_id);
        message_data.insert("CustomerID".to_string(), customer_id.get_string_repr());
        message_data.insert("RefundId".to_string(), item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?);
        message_data.insert("RequestType".to_string(), "REFUND_STATUS".to_string());

        let msg = serde_json::to_string(&message_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self { msg })
    }
}

fn get_redirect_form_data(
    response_data: BilldeskPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    if let Some(rdata) = response_data.rdata {
        if let Some(url) = rdata.url {
            Ok(RedirectForm::Form {
                endpoint: url,
                method: Method::Post,
                form_fields: rdata.parameters.unwrap_or_default(),
            })
        } else {
            Err(errors::ConnectorError::MissingRequiredField {
                field_name: "url",
            }
            .into())
        }
    } else {
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "rdata",
        }
        .into())
    }
}

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            BilldeskPaymentsResponse::BilldeskError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_description.clone(),
                    reason: Some(error_data.error_description),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsResponse::BilldeskData(response_data) => {
                let redirection_data = get_redirect_form_data(response_data)?;
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: Some(Box::new(redirection_data)),
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response._AuthStatus.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::AuthenticationPending,
            "0398" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response._TxnReferenceNo),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: Some(response._BankReferenceNo),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<BilldeskRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskRefundSyncResponse) -> Result<Self, Self::Error> {
        let status = match response._RefStatus.as_str() {
            "SUCCESS" => common_enums::AttemptStatus::Charged,
            "PENDING" => common_enums::AttemptStatus::Pending,
            "FAILURE" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            refund_id: Some(response._RefundId),
            connector_transaction_id: Some(response._TxnReferenceNo),
            status,
            amount_captured: Some(
                common_utils::types::MinorUnit::new(
                    (response._RefAmount.parse::<f64>().unwrap_or(0.0) * 100.0) as i64,
                ),
            ),
            currency: Some(response._TxnCurrency.parse().unwrap_or(common_enums::Currency::INR)),
            error_code: Some(response._ErrorCode),
            error_message: Some(response._ErrorReason),
            connector_response_reference_id: Some(response._RefARN),
            refund_arn: Some(response._RefARN),
            connector_metadata: None,
        })
    }
}