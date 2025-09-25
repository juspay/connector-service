use common_utils::{
    pii,
    types::MinorUnit,
};
use domain_types::{
    payment_method_data::{PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    connector_flow::{Authorize, Capture, Refund, SetupMandate},
    connector_types::{
        PaymentFlowData, RefundFlowData, PaymentsAuthorizeData, PaymentsSyncData,
        PaymentsCaptureData, PaymentVoidData, RefundsData,
        SetupMandateRequestData, PaymentsResponseData, RefundsResponseData,
        ResponseId,
    },
    errors::ConnectorError,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use common_enums::AttemptStatus;

pub struct DatatransAuthType {
    pub(super) merchant_id: Secret<String>,
    pub(super) passcode: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for DatatransAuthType {
    type Error = domain_types::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_id: key1.clone(),
                passcode: api_key.clone(),
            }),
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DatatransRouterData<T, U> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub payment_method_data: std::marker::PhantomData<U>,
}

impl<T, U> TryFrom<(MinorUnit, T)> for DatatransRouterData<T, U> {
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
pub struct DatatransPaymentsRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    pub amount: Option<MinorUnit>,
    pub currency: common_enums::Currency,
    pub card: DataTransPaymentDetails<T>,
    pub refno: String,
    #[serde(rename = "autoSettle")]
    pub auto_settle: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectUrls>,
    pub option: Option<DataTransCreateAlias>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataTransCreateAlias {
    pub create_alias: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectUrls {
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub error_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum DataTransPaymentDetails<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    Cards(PlainCardDetails<T>),
    Mandate(MandateDetails),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlainCardDetails<
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
> {
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvv: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3D")]
    pub three_ds: Option<ThreeDSecureData>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MandateDetails {
    #[serde(rename = "type")]
    pub res_type: String,
    pub alias: String,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ThreeDSecureData {
    Cardholder(ThreedsInfo),
    Authentication(ThreeDSData),
}

#[derive(Debug, Serialize)]
pub struct ThreedsInfo {
    cardholder: CardHolder,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreeDSData {
    #[serde(rename = "threeDSTransactionId")]
    pub three_ds_transaction_id: Option<Secret<String>>,
    pub cavv: Secret<String>,
    pub eci: Option<String>,
    pub xid: Option<Secret<String>>,
    #[serde(rename = "threeDSVersion")]
    pub three_ds_version: Option<String>,
    #[serde(rename = "authenticationResponse")]
    pub authentication_response: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardHolder {
    cardholder_name: Secret<String>,
    email: pii::Email,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DatatransResponse {
    TransactionResponse(DatatransSuccessResponse),
    ErrorResponse(DatatransError),
    ThreeDSResponse(Datatrans3DSResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatatransSuccessResponse {
    pub transaction_id: String,
    pub acquirer_authorization_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Datatrans3DSResponse {
    pub transaction_id: String,
    #[serde(rename = "3D")]
    pub three_ds_enrolled: ThreeDSEnolled,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreeDSEnolled {
    pub enrolled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DatatransSyncResponse {
    Error(DatatransError),
    Response(SyncResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyncResponse {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "merchantId")]
    pub merchant_id: Option<String>,
    #[serde(rename = "type")]
    pub res_type: Option<TransactionType>,
    pub status: TransactionStatus,
    pub currency: Option<String>,
    pub refno: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub card: Option<SyncCardDetails>,
    pub history: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Payment,
    Credit,
    CardCheck,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Initialized,
    Authenticated,
    Authorized,
    Settled,
    Canceled,
    Transmitted,
    Failed,
    ChallengeOngoing,
    ChallengeRequired,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDetails {
    pub init: Option<InitDetails>,
    pub authorize: Option<AuthorizeDetails>,
    pub fail: Option<FailDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitDetails {
    pub expires: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeDetails {
    pub amount: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailDetails {
    reason: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncCardDetails {
    pub alias: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DatatransRefundRequest {
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub refno: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DatatransRefundsResponse {
    Success(DatatransSuccessResponse),
    Error(DatatransError),
}

#[derive(Debug, Serialize)]
pub struct DataPaymentCaptureRequest {
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub refno: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DataTransCaptureResponse {
    Error(DatatransError),
    Empty,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DataTransCancelResponse {
    Error(DatatransError),
    Empty,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct DatatransError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DatatransSyncRequest {
    // Empty struct for GET requests
}

#[derive(Debug, Serialize)]
pub struct DatatransVoidRequest {
    // Empty struct for POST requests
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct DatatransErrorResponse {
    pub error: DatatransError,
}

// Transformation implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<DatatransRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for DatatransPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DatatransRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let payment_method_data = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                DataTransPaymentDetails::Cards(PlainCardDetails {
                    number: card_data.card_number.clone(),
                    expiry_month: card_data.card_exp_month.clone(),
                    expiry_year: {
                        let year = card_data.card_exp_year.peek();
                        if year.len() == 4 {
                            year[2..].to_string().into()
                        } else {
                            card_data.card_exp_year.clone()
                        }
                    },
                    cvv: card_data.card_cvc.clone(),
                    three_ds: None,
                })
            }
            _ => return Err(ConnectorError::NotImplemented("Payment method not supported".to_string()).into()),
        };

        Ok(Self {
            amount: Some(item.amount),
            currency: item.router_data.request.currency,
            card: payment_method_data,
            refno: {
                let ref_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
                if ref_id.is_empty() {
                    item.router_data.resource_common_data.payment_id.chars().take(40).collect()
                } else {
                    ref_id.chars().take(40).collect()
                }
            },
            auto_settle: matches!(item.router_data.request.capture_method, Some(common_enums::CaptureMethod::Automatic)),
            redirect: item.router_data.request.router_return_url.as_ref().map(|return_url| {
                RedirectUrls {
                    success_url: Some(return_url.clone()),
                    cancel_url: Some(return_url.clone()),
                    error_url: Some(return_url.clone()),
                }
            }),
            option: Some(DataTransCreateAlias {
                create_alias: item.router_data.request.setup_future_usage.is_some(),
            }),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<DatatransRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>>
    for DatatransPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DatatransRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let payment_method_data = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                DataTransPaymentDetails::Cards(PlainCardDetails {
                    number: card_data.card_number.clone(),
                    expiry_month: card_data.card_exp_month.clone(),
                    expiry_year: {
                        let year = card_data.card_exp_year.peek();
                        if year.len() == 4 {
                            year[2..].to_string().into()
                        } else {
                            card_data.card_exp_year.clone()
                        }
                    },
                    cvv: card_data.card_cvc.clone(),
                    three_ds: None,
                })
            }
            _ => return Err(ConnectorError::NotImplemented("Payment method not supported".to_string()).into()),
        };

        Ok(Self {
            amount: Some(item.amount),
            currency: item.router_data.request.currency,
            card: payment_method_data,
            refno: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            auto_settle: false, // Setup mandate should not auto-settle
            redirect: item.router_data.request.router_return_url.as_ref().map(|return_url| {
                RedirectUrls {
                    success_url: Some(return_url.clone()),
                    cancel_url: Some(return_url.clone()),
                    error_url: Some(return_url.clone()),
                }
            }),
            option: Some(DataTransCreateAlias {
                create_alias: true, // Always create alias for mandate setup
            }),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<DatatransRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for DataPaymentCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DatatransRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount,
            currency: item.router_data.request.currency,
            refno: item.router_data.resource_common_data.connector_request_reference_id.clone(),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<DatatransRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for DatatransRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: DatatransRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount,
            currency: item.router_data.request.currency,
            refno: item.router_data.request.refund_id.clone(),
        })
    }
}

// Response transformations
use crate::types::ResponseRouterData;

// Specific implementation for PaymentsAuthorizeData to handle capture_method
impl<F, T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<DatatransResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DatatransResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        println!("datatrans: *** USING SPECIFIC PaymentsAuthorizeData IMPLEMENTATION ***");
        println!("datatrans: Starting authorize response transformation");
        println!("datatrans: HTTP status code: {}", item.http_code);
        println!("datatrans: Response type: {:?}", item.response);
        
        let (_status, connector_transaction_id) = match item.response {
            DatatransResponse::TransactionResponse(response) => {
                println!("datatrans: Received TransactionResponse - mapping to Charged status");
                println!("datatrans: Transaction ID: {}", response.transaction_id);
                (
                    AttemptStatus::Charged,
                    Some(response.transaction_id),
                )
            },
            DatatransResponse::ThreeDSResponse(response) => {
                println!("datatrans: Received ThreeDSResponse - analyzing capture method");
                println!("datatrans: Transaction ID: {}", response.transaction_id);
                println!("datatrans: 3DS Enrolled: {}", response.three_ds_enrolled.enrolled);
                
                // Check capture method from router data
                let capture_method = item.router_data.request.capture_method;
                println!("datatrans: *** CAPTURE METHOD FROM REQUEST: {:?} ***", capture_method);
                
                // For manual capture with 3DS enrolled, we should return Authorized status
                // because the payment will be authorized after 3DS completion
                let status = match capture_method {
                    Some(common_enums::CaptureMethod::Manual) => {
                        println!("datatrans: Manual capture detected - mapping ThreeDSResponse to Authorized status");
                        AttemptStatus::Authorized
                    },
                    Some(common_enums::CaptureMethod::Automatic) 
                    | Some(common_enums::CaptureMethod::SequentialAutomatic) 
                    | None => {
                        println!("datatrans: Automatic capture detected - mapping ThreeDSResponse to AuthenticationPending status");
                        AttemptStatus::AuthenticationPending
                    },
                    Some(common_enums::CaptureMethod::ManualMultiple) => {
                        println!("datatrans: Manual multiple capture detected - mapping ThreeDSResponse to Authorized status");
                        AttemptStatus::Authorized
                    },
                    Some(common_enums::CaptureMethod::Scheduled) => {
                        println!("datatrans: Scheduled capture detected - mapping ThreeDSResponse to Authorized status");
                        AttemptStatus::Authorized
                    },
                };
                
                (
                    status,
                    Some(response.transaction_id),
                )
            },
            DatatransResponse::ErrorResponse(_error) => {
                println!("datatrans: Received ErrorResponse - mapping to Failure status");
                (
                    AttemptStatus::Failure,
                    None,
                )
            },
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    connector_transaction_id.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Implementation for PaymentsSyncData
impl<F>
    TryFrom<ResponseRouterData<DatatransResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DatatransResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        println!("datatrans: *** USING PaymentsSyncData IMPLEMENTATION ***");
        println!("datatrans: Starting sync response transformation");
        println!("datatrans: HTTP status code: {}", item.http_code);
        println!("datatrans: Response type: {:?}", item.response);
        
        let (_status, connector_transaction_id) = match item.response {
            DatatransResponse::TransactionResponse(response) => {
                println!("datatrans: Received TransactionResponse - mapping to Charged status");
                println!("datatrans: Transaction ID: {}", response.transaction_id);
                (
                    AttemptStatus::Charged,
                    Some(response.transaction_id),
                )
            },
            DatatransResponse::ThreeDSResponse(response) => {
                println!("datatrans: Received ThreeDSResponse - mapping to AuthenticationPending status");
                println!("datatrans: Transaction ID: {}", response.transaction_id);
                println!("datatrans: 3DS Enrolled: {}", response.three_ds_enrolled.enrolled);
                
                // For sync flows, default to AuthenticationPending for 3DS
                (
                    AttemptStatus::AuthenticationPending,
                    Some(response.transaction_id),
                )
            },
            DatatransResponse::ErrorResponse(_error) => {
                println!("datatrans: Received ErrorResponse - mapping to Failure status");
                (
                    AttemptStatus::Failure,
                    None,
                )
            },
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    connector_transaction_id.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// NOTE: PaymentsCaptureData response transformation is handled directly in the connector's handle_response_v2 method
// The DataTransCaptureResponse implementation below is the correct one to use

impl<F, T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<DatatransSyncResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DatatransSyncResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let (status, connector_transaction_id) = match item.response {
            DatatransSyncResponse::Response(response) => {
                let response_status = match response.status {
                    TransactionStatus::Authorized => AttemptStatus::Authorized,
                    TransactionStatus::Settled => AttemptStatus::Charged,
                    TransactionStatus::Failed => AttemptStatus::Failure,
                    TransactionStatus::Canceled => AttemptStatus::Voided,
                    _ => AttemptStatus::Pending,
                };
                (response_status, Some(response.transaction_id))
            }
            DatatransSyncResponse::Error(_) => (AttemptStatus::Failure, None),
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    connector_transaction_id.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl<F>
    TryFrom<ResponseRouterData<DataTransCaptureResponse, RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DataTransCaptureResponse, RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        println!("datatrans: *** USING DataTransCaptureResponse TRANSFORMER IMPLEMENTATION ***");
        println!("datatrans: Capture response transformation - HTTP status: {}", item.http_code);
        println!("datatrans: Capture response type: {:?}", item.response);
        println!("datatrans: *** TRANSFORMER CALLED - THIS SHOULD APPEAR IN LOGS ***");
        
        let status = match item.response {
            DataTransCaptureResponse::Empty => {
                println!("datatrans: Capture response is Empty - mapping to Charged status");
                AttemptStatus::Charged
            },
            DataTransCaptureResponse::Error(ref error) => {
                println!("datatrans: Capture response is Error - mapping to Failure status: {:?}", error);
                AttemptStatus::Failure
            },
        };
        
        // Get the transaction ID from the router data (it should be available from the original request)
        let connector_transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)?
            .to_string();
        
        println!("datatrans: Setting capture status to: {:?}", status);
        println!("datatrans: Status as u32: {}", status as u32);
        println!("datatrans: Using transaction ID: {}", connector_transaction_id);
        println!("datatrans: About to create PaymentsResponseData with status: {:?}", status);

        let result = Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: domain_types::connector_types::PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        };
        
        println!("datatrans: Final RouterDataV2 status: {:?}", result.resource_common_data.status);
        println!("datatrans: Final RouterDataV2 status as u32: {}", result.resource_common_data.status as u32);
        println!("datatrans: *** CAPTURE TRANSFORMER COMPLETED SUCCESSFULLY ***");
        
        Ok(result)
    }
}

impl<F>
    TryFrom<ResponseRouterData<DataTransCancelResponse, RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DataTransCancelResponse, RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        println!("datatrans: *** USING DataTransCancelResponse IMPLEMENTATION ***");
        println!("datatrans: Void response transformation - HTTP status: {}", item.http_code);
        println!("datatrans: Void response type: {:?}", item.response);
        
        let status = match item.response {
            DataTransCancelResponse::Empty => {
                println!("datatrans: Void response is Empty - mapping to Voided status");
                AttemptStatus::Voided
            },
            DataTransCancelResponse::Error(ref error) => {
                println!("datatrans: Void response is Error - mapping to VoidFailed status: {:?}", error);
                AttemptStatus::VoidFailed
            },
        };
        
        // Get the transaction ID from the router data (it should be available from the original request)
        let connector_transaction_id = item.router_data.request.connector_transaction_id.clone();
        
        println!("datatrans: Setting void status to: {:?}", status);
        println!("datatrans: Using transaction ID: {}", connector_transaction_id);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: domain_types::connector_types::PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<F>
    TryFrom<ResponseRouterData<DatatransRefundsResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<DatatransRefundsResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        println!("datatrans: *** USING DatatransRefundsResponse IMPLEMENTATION ***");
        println!("datatrans: Refund response transformation - HTTP status: {}", item.http_code);
        println!("datatrans: Refund response type: {:?}", item.response);
        
        let (status, connector_refund_id) = match item.response {
            DatatransRefundsResponse::Success(response) => {
                println!("datatrans: Refund Success response - transaction ID: {}", response.transaction_id);
                (
                    common_enums::RefundStatus::Success,
                    Some(response.transaction_id),
                )
            },
            DatatransRefundsResponse::Error(ref error) => {
                println!("datatrans: Refund Error response: {:?}", error);
                (common_enums::RefundStatus::Failure, None)
            },
        };
        
        let final_refund_id = connector_refund_id.clone().unwrap_or_else(|| {
            // Fallback: use the original refund ID from the request
            let fallback_id = item.router_data.request.refund_id.clone();
            println!("datatrans: No connector refund ID from response, using request refund ID: {}", fallback_id);
            fallback_id
        });
        
        println!("datatrans: Final refund status: {:?}", status);
        println!("datatrans: Final refund ID: {}", final_refund_id);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: final_refund_id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}