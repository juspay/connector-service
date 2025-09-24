use std::{
    fmt::Debug, 
    marker::{Send, Sync, PhantomData},
};

use common_enums::{
    AttemptStatus, CaptureMethod, CardNetwork, EventClass, PaymentMethod, PaymentMethodType,
};
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, pii::SecretSerdeValue, types::StringMinorUnit,
    request::{Method, RequestContent},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{self, ConnectorValidation, HealthCheck, CommonErrors},
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData,
        RefundWebhookDetailsResponse, RefundsData, RefundsResponseData, RequestDetails, ResponseId,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData, SupportedPaymentMethodsExt, WebhookDetailsResponse,
    },
    errors,
    payment_method_data::{DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        self, CardSpecificFeatures, ConnectorInfo, Connectors, FeatureStatus,
        PaymentMethodDataType, PaymentMethodDetails, PaymentMethodSpecificFeatures,
        SupportedPaymentMethods, MandateData,
    },
    utils,
};
use error_stack::report;
use hyperswitch_masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    events::connector_api_logs::ConnectorEvent,
};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskMetaData {
    pub additional_info_1: Option<String>,
    pub additional_info_2: Option<String>,
    pub additional_info_3: Option<String>,
    pub additional_info_4: Option<String>,
    pub additional_info_5: Option<String>,
    pub additional_info_6: Option<String>,
    pub additional_info_7: Option<String>,
    pub end_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BilldeskResponse {
    #[serde(rename = "BILLDESKINITNB")]
    NbInitiate(BilldeskNBInitiateResponse),
    #[serde(rename = "BILLDESKAU")]
    Authorization(BilldeskAuthorizationResponse),
    #[serde(rename = "BILLDESKINITCARD")]
    CardInitiate(Params),
    #[serde(rename = "BILLDESKREC")]
    Recurring(BilldeskRecurringResponse),
    #[serde(rename = "SuccessSyncResponse")]
    SuccessSync(StatusResponseMsg),
    #[serde(rename = "ErrorSyncResponse")]
    ErrorSync(BilldeskErrorResponse),
    #[serde(rename = "BilldeskAuthzErrResponse")]
    AuthzError(InvalidRequestResponse),
    #[serde(rename = "BilldeskRewardAuth")]
    RewardAuth(BilldeskRewardAuthResp),
    #[serde(rename = "BilldeskTxnAuthzResponse")]
    TxnAuthz(TransactionResponse),
    #[serde(rename = "BilldeskMandateAuthzResponse")]
    MandateAuthz(PgMandateObject),
    #[serde(rename = "BilldeskInternalValidationResp")]
    InternalValidation(InternalValidationResponse),
    #[serde(rename = "BilldeskRecurringResp")]
    Recurring(RecurringTxnResponse),
    #[serde(rename = "BilldeskUpdateTxnResp")]
    UpdateTxn(UpdateTxnResp),
    #[serde(rename = "BilldeskCardAndPointSyncResp")]
    CardAndPointSync(CardAndPointsSyncResponse),
    #[serde(rename = "BilldeskInitNonCard")]
    NonCardInit(BilldeskV2NonCardResponse),
    #[serde(rename = "BilldeskFrictionless")]
    Frictionless(CreateTxnResp),
    #[serde(rename = "BilldeskEnachResp")]
    Enach(BilldeskEnachResponse),
    #[serde(rename = "BilldeskEnachDecryptResp")]
    EnachDecrypt(BilldeskEnachDecryptResponse),
    #[serde(rename = "BilldeskRecurringEnachResp")]
    RecurringEnach(RecurringEnachTxnResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskNBInitiateResponse {
    pub url: Option<String>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskAuthorizationResponse {
    pub status: Option<String>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    pub param1: Option<String>,
    pub param2: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskRecurringResponse {
    pub recurring_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponseMsg {
    pub status: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidRequestResponse {
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskRewardAuthResp {
    pub reward_points: Option<i32>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub transaction_status: Option<String>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgMandateObject {
    pub mandate_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalValidationResponse {
    pub validation_status: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurringTxnResponse {
    pub recurring_transaction_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTxnResp {
    pub update_status: Option<String>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardAndPointsSyncResponse {
    pub card_status: Option<String>,
    pub points_balance: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskV2NonCardResponse {
    pub non_card_transaction_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTxnResp {
    pub transaction_created: bool,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskEnachResponse {
    pub enach_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskEnachDecryptResponse {
    pub decrypted_data: Option<String>,
    pub enach_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurringEnachTxnResponse {
    pub recurring_enach_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskPaymentsRequest {
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub redirect_url: String,
    pub cancellation_url: String,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskNBInitiateRequest {
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub bank_code: String,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskCardInitiateRequest {
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub card_number: SecretSerdeValue,
    pub card_expiry_month: String,
    pub card_expiry_year: String,
    pub card_cvv: SecretSerdeValue,
    pub card_holder_name: String,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskRecurringRequest {
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub frequency: String,
    pub start_date: String,
    pub end_date: Option<String>,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskEnachRequest {
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub customer_account_number: SecretSerdeValue,
    pub customer_ifsc: String,
    pub customer_account_holder_name: String,
    pub mandate_type: String,
    pub start_date: String,
    pub end_date: Option<String>,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskMandateRequest {
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub mandate_type: String,
    pub amount: f64,
    pub currency: String,
    pub start_date: String,
    pub end_date: Option<String>,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskSyncRequest {
    pub merchant_id: String,
    pub order_id: String,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskEnachDecryptRequest {
    pub merchant_id: String,
    pub enach_response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskFrictionlessRequest {
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub amount: f64,
    pub currency: String,
    pub payment_method_type: String,
    pub payment_method_data: serde_json::Value,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskAuthFlowRequest {
    pub request_type: String,
    pub merchant_id: String,
    pub customer_id: String,
    pub order_id: String,
    pub additional_info: Option<BilldeskMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilldeskRouterData<F, T> {
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub router_data: RouterDataV2<F, T, PaymentsAuthorizeData, BilldeskResponse>,
    pub metadata: Option<BilldeskMetaData>,
}

pub struct Billdesk<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    pub connector_auth: ConnectorAuthType,
    pub base_url: String,
    phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    connector_types::SetupMandateV2<T> for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    connector_types::AcceptDispute for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    connector_types::SubmitEvidenceV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    connector_types::DisputeDefend for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    connector_types::RepeatPaymentV2 for Billdesk<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon for Billdesk<T> {
    fn id(&self) -> &str {
        "billdesk"
    }

    fn get_base_url(&self) -> &str {
        &self.base_url
    }

    fn get_auth_header(&self, _req: &ConnectorAuthType) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        match &self.connector_auth {
            ConnectorAuthType::BodyKey { api_key } => Ok(vec![(
                "Authorization".to_string(),
                format!("Bearer {}", api_key.peek()).into(),
            )]),
            _ => Err(report!(errors::ConnectorError::AuthenticationFailed)),
        }
    }

    fn get_error_message(
        &self,
        error_response: ErrorResponse,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(error_response.message)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> Billdesk<T> {
    pub fn new(connector_auth: ConnectorAuthType, base_url: String) -> Self {
        Self {
            connector_auth,
            base_url,
            phantom: std::marker::PhantomData,
        }
    }
}

macros::create_all_prerequisites!(
    connector_name: Billdesk,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: BilldeskPaymentsRequest,
            response_body: BilldeskResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: BilldeskSyncRequest,
            response_body: BilldeskResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: BilldeskPaymentsRequest,
            response_body: BilldeskResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: BilldeskSyncRequest,
            response_body: BilldeskResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: BilldeskPaymentsRequest,
            response_body: BilldeskResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: BilldeskMandateRequest,
            response_body: BilldeskResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: CreateSessionToken,
            request_body: BilldeskAuthFlowRequest,
            response_body: BilldeskResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        )
    ],
    amount_converters: [
        amount_converter_webhooks: StringMinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                "Content-Type".to_string(),
                "application/json".to_string().into(),
            )];
            let mut auth_header = self.get_auth_header_conn(&ConnectorAuthType::BodyKey {
                api_key: "dummy".to_string().into(),
            })?;
            header.append(&mut auth_header);
            Ok(header)
        }
        
        fn get_auth_header_conn(
            &self,
            auth_type: &ConnectorAuthType,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            match auth_type {
                ConnectorAuthType::BodyKey { api_key } => Ok(vec![(
                    "Authorization".to_string(),
                    format!("Bearer {}", api_key.peek()).into(),
                )]),
                _ => Err(report!(errors::ConnectorError::AuthenticationFailed)),
            }
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> CommonErrors for Billdesk<T> {
    fn get_error_response(
        &self,
        response: bytes::Bytes,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let error_response: BilldeskErrorResponse = response
            .parse_struct(std::any::type_name::<BilldeskErrorResponse>())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        Ok(ErrorResponse {
            code: error_response.error_code.unwrap_or_else(|| "UNKNOWN".to_string()),
            message: error_response.error_message.unwrap_or_else(|| "Unknown error".to_string()),
            reason: None,
            status_code: None,
            attempt_status: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorValidation for Billdesk<T> {
    fn validate_capture_method(
        &self,
        _capture_method: Option<CaptureMethod>,
        _payment_method: PaymentMethod,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }

    fn validate_mandate_payment(
        &self,
        payment_method_details: &PaymentMethodDetails,
        _mandate_details: &domain_types::MandateData,
    ) -> CustomResult<(), errors::ConnectorError> {
        match payment_method_details {
            PaymentMethodDetails::Card(_) | PaymentMethodDetails::Wallet(_) => Ok(()),
            _ => Err(report!(errors::ConnectorError::NotSupported)),
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> HealthCheck for Billdesk<T> {
    async fn health_check(
        &self,
        opts: &domain_types::types::HealthCheckOpts,
    ) -> CustomResult<(), errors::ConnectorError> {
        let health_check_url = format!("{}health", self.base_url);
        let headers = self.build_headers(&RouterDataV2 {
            flow: PhantomData,
            flow_common_data: PhantomData,
            data: PhantomData,
            response: PhantomData,
        })?;
        
        let client = utils::clients::build_client(opts, None)?;
        
        let _response = client
            .get(&health_check_url)
            .headers(utils::encode_headers(headers)?)
            .send()
            .await
            .map_err(|err| report!(errors::ConnectorError::RequestEncodingFailed).attach_printable(err))?;
        
        Ok(())
    }
}