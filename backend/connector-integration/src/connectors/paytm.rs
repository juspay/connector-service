pub mod transformers;

use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
<<<<<<< HEAD
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
=======
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
>>>>>>> d637bc4 (clippy-fixes)
    },
    errors,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent, verification,
};

use paytm::constants;
use transformers as paytm;

#[derive(Clone)]
pub struct Paytm {
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Paytm {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}

impl connector_types::ValidationTrait for Paytm {
    fn should_do_session_token(&self) -> bool {
        true // Enable CreateSessionToken flow for Paytm's initiate step
    }

    fn should_do_order_create(&self) -> bool {
        false // Paytm doesn't require separate order creation
    }
}

// Service trait implementations
impl connector_types::ConnectorServiceTrait for Paytm {}
impl connector_types::PaymentAuthorizeV2 for Paytm {}
impl connector_types::PaymentSessionToken for Paytm {}
impl connector_types::PaymentSyncV2 for Paytm {}
impl connector_types::PaymentOrderCreate for Paytm {}
impl connector_types::RefundV2 for Paytm {}
impl connector_types::RefundSyncV2 for Paytm {}
impl connector_types::RepeatPaymentV2 for Paytm {}
impl connector_types::PaymentCapture for Paytm {}
impl connector_types::PaymentVoidV2 for Paytm {}
impl connector_types::SetupMandateV2 for Paytm {}
impl connector_types::AcceptDispute for Paytm {}
impl connector_types::DisputeDefend for Paytm {}
impl connector_types::SubmitEvidenceV2 for Paytm {}
impl connector_types::IncomingWebhook for Paytm {}

impl ConnectorCommon for Paytm {
    fn id(&self) -> &'static str {
        "paytm"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.paytm.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let _auth = paytm::PaytmAuthType::try_from(auth_type)?;
        Ok(vec![(
            constants::CONTENT_TYPE_HEADER.to_string(),
            constants::CONTENT_TYPE_JSON.into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        // First try to parse as session token error response format
        if let Ok(session_error_response) = res
            .response
            .parse_struct::<paytm::PaytmSessionTokenErrorResponse>("PaytmSessionTokenErrorResponse")
        {
            if let Some(event) = event_builder {
                event.set_error_response_body(&session_error_response);
            }

            return Ok(domain_types::router_data::ErrorResponse {
                code: session_error_response.body.result_info.result_code,
                message: session_error_response.body.result_info.result_msg,
                reason: None,
                status_code: res.status_code,
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
            });
        }

        // Try to parse as callback error response format
        if let Ok(callback_response) = res
            .response
            .parse_struct::<paytm::PaytmCallbackErrorResponse>("PaytmCallbackErrorResponse")
        {
            if let Some(event) = event_builder {
                event.set_error_response_body(&callback_response);
            }

            return Ok(domain_types::router_data::ErrorResponse {
                code: callback_response
                    .body
                    .txn_info
                    .resp_code
                    .unwrap_or(callback_response.body.result_info.result_code),
                message: callback_response
                    .body
                    .txn_info
                    .resp_msg
                    .unwrap_or(callback_response.body.result_info.result_msg),
                reason: None,
                status_code: res.status_code,
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: callback_response.body.txn_info.order_id,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
            });
        }

        // Fallback to original error response format
        let response: paytm::PaytmErrorResponse =
            res.response
                .parse_struct("PaytmErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event) = event_builder {
            event.set_error_response_body(&response);
        }

        Ok(domain_types::router_data::ErrorResponse {
            code: response.error_code.unwrap_or_default(),
            message: response.error_message.unwrap_or_default(),
            reason: response.error_description,
            status_code: res.status_code,
            attempt_status: Some(AttemptStatus::Failure),
            connector_transaction_id: response.transaction_id,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

// Service trait implementations (initially empty)
impl interfaces::connector_types::ConnectorServiceTrait for Paytm {}
impl interfaces::connector_types::PaymentAuthorizeV2 for Paytm {}
impl interfaces::connector_types::PaymentSessionToken for Paytm {}
impl interfaces::connector_types::PaymentSyncV2 for Paytm {}
impl interfaces::connector_types::PaymentOrderCreate for Paytm {}
impl interfaces::connector_types::RefundV2 for Paytm {}
impl interfaces::connector_types::RefundSyncV2 for Paytm {}
impl interfaces::connector_types::PaymentCapture for Paytm {}
impl interfaces::connector_types::PaymentVoidV2 for Paytm {}
impl interfaces::connector_types::SetupMandateV2 for Paytm {}
impl interfaces::connector_types::AcceptDispute for Paytm {}
impl interfaces::connector_types::DisputeDefend for Paytm {}
impl interfaces::connector_types::SubmitEvidenceV2 for Paytm {}
impl interfaces::connector_types::IncomingWebhook for Paytm {}

// SourceVerification implementations for all flows
impl
    verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paytm
{
}
impl
    verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Paytm
{
}
impl verification::SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paytm
{
}
impl verification::SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Paytm
{
}
impl verification::SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Paytm
{
}
impl
    verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paytm
{
}

// Stub implementations for compilation
<<<<<<< HEAD
// CreateSessionToken flow implementation - manual implementation for Paytm initiate transaction
impl
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paytm
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            constants::CONTENT_TYPE_HEADER.to_string(),
            constants::CONTENT_TYPE_JSON.to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek();
        let order_id = &req.resource_common_data.connector_request_reference_id;

        Ok(format!(
            "{base_url}theia/api/v1/initiateTransaction?mid={merchant_id}&orderId={order_id}"
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = paytm::PaytmRouterData::try_from(req)?;
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;
        let connector_req = paytm::PaytmInitiateTxnRequest::try_from_with_auth(
            &connector_router_data,
            &auth,
            self.amount_converter,
        )?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        mut event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        errors::ConnectorError,
    > {
        // First check if this is a session token error response (even with 200 status)
        if let Ok(session_error_response) = res
            .response
            .parse_struct::<paytm::PaytmSessionTokenErrorResponse>("PaytmSessionTokenErrorResponse")
        {
            if let Some(event) = event_builder.as_mut() {
                event.set_response_body(&session_error_response);
            }

            // Check if it's a failure response
            if session_error_response.body.result_info.result_status == "F" {
                // Return error response instead of generic error
                let error_response = domain_types::router_data::ErrorResponse {
                    code: session_error_response.body.result_info.result_code,
                    message: session_error_response.body.result_info.result_msg,
                    reason: None,
                    status_code: res.status_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                let mut response_data = data.clone();
                response_data.response = Err(error_response);
                return Ok(response_data);
            }
        }

        // Check if this is a callback error response (even with 200 status)
        if let Ok(callback_response) = res
            .response
            .parse_struct::<paytm::PaytmCallbackErrorResponse>("PaytmCallbackErrorResponse")
        {
            if let Some(event) = event_builder.as_mut() {
                event.set_response_body(&callback_response);
            }

            // Check if it's a failure response
            if callback_response.body.result_info.result_status == "F"
                || callback_response
                    .body
                    .txn_info
                    .status
                    .as_ref()
                    .map_or(false, |s| s == "TXN_FAILURE")
            {
                return Err(errors::ConnectorError::ResponseHandlingFailed.into());
            }
        }

        // Try to parse as regular initiate transaction response
        let response: paytm::PaytmInitiateTxnResponse = res
            .response
            .parse_struct("PaytmInitiateTxnResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event) = event_builder {
            event.set_response_body(&response);
        }

        match response.body {
            paytm::PaytmResBodyTypes::SuccessBody(success_body) => {
                if success_body.result_info.result_code == constants::SUCCESS_CODE
                    || success_body.result_info.result_code == constants::DUPLICATE_CODE
                {
                    let session_response = SessionTokenResponseData {
                        session_token: success_body.txn_token.clone(),
                    };

                    let mut response_data = data.clone();
                    response_data.response = Ok(session_response);
                    Ok(response_data)
                } else {
                    // For success body with failure status, check result status
                    if success_body.result_info.result_status == "F" {
                        let error_response = domain_types::router_data::ErrorResponse {
                            code: success_body.result_info.result_code,
                            message: success_body.result_info.result_msg,
                            reason: None,
                            status_code: res.status_code,
                            attempt_status: Some(AttemptStatus::Failure),
                            connector_transaction_id: None,
                            network_decline_code: None,
                            network_advice_code: None,
                            network_error_message: None,
                            raw_connector_response: Some(
                                String::from_utf8_lossy(&res.response).to_string(),
                            ),
                        };

                        let mut response_data = data.clone();
                        response_data.response = Err(error_response);
                        Ok(response_data)
                    } else {
                        Err(errors::ConnectorError::ResponseHandlingFailed.into())
                    }
                }
            }
            paytm::PaytmResBodyTypes::FailureBody(failure_body) => {
                // Handle regular failure body
                if failure_body.result_info.result_status == "F" {
                    let error_response = domain_types::router_data::ErrorResponse {
                        code: failure_body.result_info.result_code,
                        message: failure_body.result_info.result_msg,
                        reason: None,
                        status_code: res.status_code,
                        attempt_status: Some(AttemptStatus::Failure),
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                        raw_connector_response: Some(
                            String::from_utf8_lossy(&res.response).to_string(),
                        ),
                    };

                    let mut response_data = data.clone();
                    response_data.response = Err(error_response);
                    Ok(response_data)
                } else {
                    Err(errors::ConnectorError::ResponseHandlingFailed.into())
                }
            }
        }
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Authorize flow implementation - using manual implementation due to complex UPI flow logic
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Paytm
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            constants::CONTENT_TYPE_HEADER.to_string(),
            constants::CONTENT_TYPE_JSON.to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek();
        let order_id = &req.resource_common_data.connector_request_reference_id;

        // Determine UPI flow type to route to correct endpoint
        let upi_flow = paytm::determine_upi_flow(&req.request.payment_method_data)?;

        match upi_flow {
            paytm::UpiFlowType::Intent | paytm::UpiFlowType::Collect => Ok(format!(
                "{base_url}theia/api/v1/processTransaction?mid={merchant_id}&orderId={order_id}"
            )),
        }
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = paytm::PaytmAuthorizeRouterData::try_from(req)?;
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;

        // Determine UPI flow type and create appropriate request
        let upi_flow = paytm::determine_upi_flow(&req.request.payment_method_data)?;

        match upi_flow {
            paytm::UpiFlowType::Intent => {
                let connector_req = paytm::PaytmProcessTxnRequest::try_from_with_auth(
                    &connector_router_data,
                    &auth,
                )?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
            paytm::UpiFlowType::Collect => {
                let connector_req = paytm::PaytmNativeProcessTxnRequest::try_from_with_auth(
                    &connector_router_data,
                    &auth,
                )?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
        }
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        mut event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // Check if this is a success transaction response
        if let Ok(success_transaction_response) = res
            .response
            .parse_struct::<paytm::PaytmSuccessTransactionResponse>(
                "PaytmSuccessTransactionResponse",
            )
        {
            if let Some(event) = event_builder.as_mut() {
                event.set_response_body(&success_transaction_response);
            }

            // Check if it's a successful transaction
            if success_transaction_response.body.result_info.result_status == "S"
                && success_transaction_response
                    .body
                    .txn_info
                    .status
                    .as_ref()
                    .map_or(false, |s| s == "TXN_SUCCESS")
            {
                let payments_response = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        success_transaction_response
                            .body
                            .txn_info
                            .txn_id
                            .clone()
                            .unwrap_or_else(|| {
                                success_transaction_response
                                    .body
                                    .txn_info
                                    .order_id
                                    .clone()
                                    .unwrap_or_default()
                            }),
                    ),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: success_transaction_response
                        .body
                        .txn_info
                        .bank_txn_id
                        .clone(),
                    connector_response_reference_id: success_transaction_response
                        .body
                        .txn_info
                        .order_id
                        .clone(),
                    incremental_authorization_allowed: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                let mut response_data = data.clone();
                response_data.response = Ok(payments_response);
                return Ok(response_data);
            }
        }

        // Check if this is a bank form redirect response
        if let Ok(bank_form_response) = res
            .response
            .parse_struct::<paytm::PaytmBankFormResponse>("PaytmBankFormResponse")
        {
            if let Some(event) = event_builder.as_mut() {
                event.set_response_body(&bank_form_response);
            }

            // Check if it's a successful response
            if bank_form_response.body.result_info.result_status == "S"
                && bank_form_response.body.result_info.result_code == constants::SUCCESS_CODE
            {
                let redirect_form = domain_types::router_response_types::RedirectForm::Form {
                    endpoint: bank_form_response
                        .body
                        .bank_form
                        .redirect_form
                        .action_url
                        .clone(),
                    method: common_utils::request::Method::Post,
                    form_fields: bank_form_response
                        .body
                        .bank_form
                        .redirect_form
                        .content
                        .clone(),
                };

                let payments_response = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        bank_form_response
                            .body
                            .bank_form
                            .redirect_form
                            .content
                            .get("orderId")
                            .cloned()
                            .unwrap_or_else(|| {
                                data.resource_common_data
                                    .connector_request_reference_id
                                    .clone()
                            }),
                    ),
                    redirection_data: Some(Box::new(redirect_form)),
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: bank_form_response
                        .body
                        .bank_form
                        .redirect_form
                        .content
                        .get("externalSrNo")
                        .cloned(),
                    connector_response_reference_id: bank_form_response
                        .body
                        .bank_form
                        .redirect_form
                        .content
                        .get("orderId")
                        .cloned(),
                    incremental_authorization_allowed: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                let mut response_data = data.clone();
                response_data.response = Ok(payments_response);
                // Set status to AuthenticationPending for bank form redirect (user needs to complete authentication)
                response_data.resource_common_data.status =
                    domain_types::connector_types::Status::Attempt(
                        AttemptStatus::AuthenticationPending,
                    );
                return Ok(response_data);
            }
        }

        // Check if this is a callback error response (even with 200 status)
        if let Ok(callback_response) = res
            .response
            .parse_struct::<paytm::PaytmCallbackErrorResponse>("PaytmCallbackErrorResponse")
        {
            if let Some(event) = event_builder.as_mut() {
                event.set_response_body(&callback_response);
            }

            // Check if it's a failure response
            if callback_response.body.result_info.result_status == "F"
                || callback_response
                    .body
                    .txn_info
                    .status
                    .as_ref()
                    .map_or(false, |s| s == "TXN_FAILURE")
            {
                let error_response = domain_types::router_data::ErrorResponse {
                    code: callback_response
                        .body
                        .txn_info
                        .resp_code
                        .unwrap_or(callback_response.body.result_info.result_code),
                    message: callback_response
                        .body
                        .txn_info
                        .resp_msg
                        .unwrap_or(callback_response.body.result_info.result_msg),
                    reason: None,
                    status_code: res.status_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: callback_response.body.txn_info.order_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                let mut response_data = data.clone();
                response_data.response = Err(error_response);
                return Ok(response_data);
            }
        }

        let upi_flow = paytm::determine_upi_flow(&data.request.payment_method_data)?;

        match upi_flow {
            paytm::UpiFlowType::Intent => {
                let response: paytm::PaytmProcessTxnResponse = res
                    .response
                    .parse_struct("PaytmProcessTxnResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                if let Some(event) = event_builder {
                    event.set_response_body(&response);
                }

                match response.body {
                    paytm::PaytmProcessRespBodyTypes::SuccessBody(success_resp) => {
                        if success_resp.result_info.result_code == constants::SUCCESS_CODE {
                            let redirect_form =
                                domain_types::router_response_types::RedirectForm::Uri {
                                    uri: success_resp.deep_link_info.deep_link.clone(),
                                };

                            let payments_response = PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    success_resp.deep_link_info.order_id.clone(),
                                ),
                                redirection_data: Box::new(Some(redirect_form)),
                                connector_metadata: None,
                                mandate_reference: Box::new(None),
                                network_txn_id: None,
                                connector_response_reference_id: Some(
                                    success_resp.deep_link_info.cashier_request_id.clone(),
                                ),
                                incremental_authorization_allowed: None,
                                raw_connector_response: Some(
                                    String::from_utf8_lossy(&res.response).to_string(),
                                ),
                            };

                            let mut response_data = data.clone();
                            response_data.response = Ok(payments_response);
                            // Set status to AuthenticationPending for UPI Intent redirect (user needs to complete authentication)
                            response_data.resource_common_data.status =
                                domain_types::connector_types::Status::Attempt(
                                    AttemptStatus::AuthenticationPending,
                                );
                            Ok(response_data)
                        } else {
                            Err(errors::ConnectorError::ResponseHandlingFailed.into())
                        }
                    }
                    paytm::PaytmProcessRespBodyTypes::FailureBody(_) => {
                        Err(errors::ConnectorError::ResponseHandlingFailed.into())
                    }
                }
            }
            paytm::UpiFlowType::Collect => {
                let response: paytm::PaytmNativeProcessTxnResponse = res
                    .response
                    .parse_struct("PaytmNativeProcessTxnResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                if let Some(event) = event_builder {
                    event.set_response_body(&response);
                }

                match response.body {
                    paytm::PaytmNativeProcessRespBodyTypes::SuccessBody(success_resp) => {
                        if success_resp.result_info.result_code == constants::SUCCESS_CODE {
                            let payments_response = PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(
                                    success_resp.trans_id.clone(),
                                ),
                                redirection_data: Box::new(None),
                                connector_metadata: None,
                                mandate_reference: Box::new(None),
                                network_txn_id: None,
                                connector_response_reference_id: Some(
                                    success_resp.order_id.clone(),
                                ),
                                incremental_authorization_allowed: None,
                                raw_connector_response: Some(
                                    String::from_utf8_lossy(&res.response).to_string(),
                                ),
                            };

                            let mut response_data = data.clone();
                            response_data.response = Ok(payments_response);
                            // Set status to AuthenticationPending for UPI Intent redirect (user needs to complete authentication)
                            response_data.resource_common_data.status =
                                domain_types::connector_types::Status::Attempt(
                                    AttemptStatus::AuthenticationPending,
                                );
                            Ok(response_data)
                        } else {
                            Err(errors::ConnectorError::ResponseHandlingFailed.into())
                        }
                    }
                    paytm::PaytmNativeProcessRespBodyTypes::FailureBody(_) => {
                        Err(errors::ConnectorError::ResponseHandlingFailed.into())
                    }
                }
            }
        }
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// PSync flow implementation - manual implementation for transaction status inquiry
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paytm
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            constants::CONTENT_TYPE_HEADER.to_string(),
            constants::CONTENT_TYPE_JSON.to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        Ok(format!("{base_url}/v3/order/status"))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = paytm::PaytmSyncRouterData::try_from(req)?;
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;
        let connector_req = paytm::PaytmTransactionStatusRequest::try_from_with_auth(
            &connector_router_data,
            &auth,
        )?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: paytm::PaytmTransactionStatusResponse = res
            .response
            .parse_struct("PaytmTransactionStatusResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event) = event_builder {
            event.set_response_body(&response);
        }

        match response.body {
            paytm::PaytmTransactionStatusRespBodyTypes::SuccessBody(success_resp) => {
                // Check if this is actually a failure based on result status
                if success_resp.result_info.result_status == "TXN_FAILURE"
                    || success_resp.result_info.result_status == "F"
                {
                    // Return error response for failure status
                    let error_response = domain_types::router_data::ErrorResponse {
                        code: success_resp.result_info.result_code,
                        message: success_resp.result_info.result_msg,
                        reason: None,
                        status_code: res.status_code,
                        attempt_status: Some(AttemptStatus::Failure),
                        connector_transaction_id: success_resp.order_id.clone(),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                        raw_connector_response: Some(
                            String::from_utf8_lossy(&res.response).to_string(),
                        ),
                    };

                    let mut response_data = data.clone();
                    response_data.response = Err(error_response);
                    return Ok(response_data);
                }

                // Check for success status - must have both TXN_SUCCESS status and 01 code
                let attempt_status = if success_resp.result_info.result_status == "TXN_SUCCESS"
                    && success_resp.result_info.result_code == "01"
                {
                    AttemptStatus::Charged
                } else {
                    paytm::map_paytm_status_to_attempt_status(&success_resp.result_info.result_code)
                };

                let connector_transaction_id = success_resp
                    .txn_id
                    .or_else(|| success_resp.order_id.clone())
                    .unwrap_or_else(|| {
                        data.resource_common_data
                            .connector_request_reference_id
                            .clone()
                    });

                let payments_response = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        connector_transaction_id.clone(),
                    ),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: success_resp.bank_txn_id.clone(),
                    connector_response_reference_id: success_resp.order_id.clone(),
                    incremental_authorization_allowed: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                let mut response_data = data.clone();
                response_data.response = Ok(payments_response);
                // Set the proper attempt status in PaymentFlowData
                response_data.resource_common_data.status =
                    domain_types::connector_types::Status::Attempt(attempt_status);
                Ok(response_data)
            }
            paytm::PaytmTransactionStatusRespBodyTypes::FailureBody(failure_resp) => {
                // Return error response for failure body
                let error_response = domain_types::router_data::ErrorResponse {
                    code: failure_resp.result_info.result_code,
                    message: failure_resp.result_info.result_msg,
                    reason: None,
                    status_code: res.status_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                let mut response_data = data.clone();
                response_data.response = Err(error_response);
                Ok(response_data)
            }
        }
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Empty implementations for flows not yet implemented
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Paytm
{
}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paytm
{
}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Paytm {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Paytm {}
impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Paytm
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Paytm
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Paytm
{
}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Paytm
{
}
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paytm
{
}
impl ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Paytm
{
}

// SourceVerification implementations for all flows
impl
    verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paytm
{
}
impl
    verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Paytm
{
}
impl verification::SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paytm
{
}
impl verification::SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Paytm
{
}
impl verification::SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Paytm
{
}
impl
    verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Paytm
{
}
pub mod transformers;

use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    router_data::ConnectorAuthType,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
    events::connector_api_logs::ConnectorEvent, verification,
};

use paytm::constants;
use transformers as paytm;

#[derive(Clone)]
pub struct Paytm {
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Paytm {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}

impl interfaces::connector_types::ValidationTrait for Paytm {
    fn should_do_session_token(&self) -> bool {
        true // Enable CreateSessionToken flow for Paytm's initiate step
    }

    fn should_do_order_create(&self) -> bool {
        false // Paytm doesn't require separate order creation
    }
}

impl ConnectorCommon for Paytm {
    fn id(&self) -> &'static str {
        "paytm"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.paytm.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let _auth = paytm::PaytmAuthType::try_from(auth_type)?;
        Ok(vec![(
            constants::CONTENT_TYPE_HEADER.to_string(),
            constants::CONTENT_TYPE_JSON.into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        let response: paytm::PaytmErrorResponse =
            res.response
                .parse_struct("PaytmErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event) = event_builder {
            event.set_error_response_body(&response);
        }

        Ok(domain_types::router_data::ErrorResponse {
            code: response.error_code.unwrap_or_default(),
            message: response.error_message.unwrap_or_default(),
            reason: response.error_description,
            status_code: res.status_code,
            attempt_status: Some(AttemptStatus::Failure),
            connector_transaction_id: response.transaction_id,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

// Service trait implementations (initially empty)
impl interfaces::connector_types::ConnectorServiceTrait for Paytm {}
impl interfaces::connector_types::PaymentAuthorizeV2 for Paytm {}
impl interfaces::connector_types::PaymentSessionToken for Paytm {}
impl interfaces::connector_types::PaymentSyncV2 for Paytm {}
impl interfaces::connector_types::PaymentOrderCreate for Paytm {}
impl interfaces::connector_types::RefundV2 for Paytm {}
impl interfaces::connector_types::RefundSyncV2 for Paytm {}
impl interfaces::connector_types::PaymentCapture for Paytm {}
impl interfaces::connector_types::PaymentVoidV2 for Paytm {}
impl interfaces::connector_types::SetupMandateV2 for Paytm {}
impl interfaces::connector_types::AcceptDispute for Paytm {}
impl interfaces::connector_types::DisputeDefend for Paytm {}
impl interfaces::connector_types::SubmitEvidenceV2 for Paytm {}
impl interfaces::connector_types::IncomingWebhook for Paytm {}

// SourceVerification implementations for all flows
impl
    verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paytm
{
}
impl
    verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Paytm
{
}
impl verification::SourceVerification<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paytm
{
}
impl verification::SourceVerification<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Paytm
{
}
impl verification::SourceVerification<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Paytm
{
}
impl
    verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paytm
{
}
impl
    verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paytm
{
}

// Stub implementations for compilation
=======
>>>>>>> d637bc4 (clippy-fixes)
impl
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paytm
{
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            constants::CONTENT_TYPE_HEADER.to_string(),
            constants::CONTENT_TYPE_JSON.to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek();
        let order_id = &req.resource_common_data.connector_request_reference_id;

        Ok(format!(
            "{base_url}theia/api/v1/initiateTransaction?mid={merchant_id}&orderId={order_id}"
        ))
    }

    fn get_request_body(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = paytm::PaytmRouterData::try_from(req)?;
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;
        let connector_req = paytm::PaytmInitiateTxnRequest::try_from_with_auth(
            &connector_router_data,
            &auth,
            self.amount_converter,
        )?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        errors::ConnectorError,
    > {
        let response: paytm::PaytmInitiateTxnResponse = res
            .response
            .parse_struct("PaytmInitiateTxnResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event) = event_builder {
            event.set_response_body(&response);
        }

        match response.body {
            paytm::PaytmResBodyTypes::SuccessBody(success_body) => {
                if success_body.result_info.result_code == constants::SUCCESS_CODE
                    || success_body.result_info.result_code == constants::DUPLICATE_CODE
                {
                    let session_response = SessionTokenResponseData {
                        session_token: success_body.txn_token.clone(),
                    };

                    let mut response_data = data.clone();
                    response_data.response = Ok(session_response);
                    Ok(response_data)
                } else {
                    Err(errors::ConnectorError::ResponseHandlingFailed.into())
                }
            }
            paytm::PaytmResBodyTypes::FailureBody(_) => {
                Err(errors::ConnectorError::ResponseHandlingFailed.into())
            }
        }
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}
impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
    for Paytm
{
    fn get_headers(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            constants::CONTENT_TYPE_HEADER.to_string(),
            constants::CONTENT_TYPE_JSON.to_string().into(),
        )];
        let mut auth_headers = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_headers);
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&req.resource_common_data.connectors);
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;
        let merchant_id = auth.merchant_id.peek();
        let order_id = &req.resource_common_data.connector_request_reference_id;

<<<<<<< HEAD
<<<<<<< HEAD
        // Both UPI Intent and UPI Collect use the same processTransaction endpoint
        // The difference is in the request structure, not the URL
        Ok(format!(
            "{}theia/api/v1/processTransaction?mid={}&orderId={}",
            base_url, merchant_id, order_id
        ))
=======
        // Determine UPI flow type to route to correct endpoint
        let upi_flow = paytm::determine_upi_flow(&req.request.payment_method_data)?;

        match upi_flow {
            paytm::UpiFlowType::Intent | paytm::UpiFlowType::Collect => {
                // Both UPI Intent and UPI Collect use the same processTransaction endpoint
                // The difference is in the request structure, not the URL
                Ok(format!("{base_url}theia/api/v1/processTransaction?mid={merchant_id}&orderId={order_id}"))
            } // paytm::UpiFlowType::QrCode => {
              //     // UPI QR uses a different endpoint for QR creation
              //     Ok(format!("{}paymentservices/qr/create", base_url))
              // }
        }
>>>>>>> d637bc4 (clippy-fixes)
=======
        // Both UPI Intent and UPI Collect use the same processTransaction endpoint
        // The difference is in the request structure, not the URL
        Ok(format!(
            "{base_url}theia/api/v1/processTransaction?mid={merchant_id}&orderId={order_id}"
        ))
>>>>>>> 5ca1ae8 (remove-unnecessary-code)
    }

    fn get_request_body(
        &self,
        req: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let connector_router_data = paytm::PaytmAuthorizeRouterData::try_from(req)?;
        let auth = paytm::PaytmAuthType::try_from(&req.connector_auth_type)?;

        // Create appropriate request based on payment method data
        match &req.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(
                domain_types::payment_method_data::UpiData::UpiCollect(collect_data),
            ) => {
                if collect_data.vpa_id.is_some() {
                    // UPI Collect flow with VPA
                    let connector_req = paytm::PaytmNativeProcessTxnRequest::try_from_with_auth(
                        &connector_router_data,
                        &auth,
                    )?;
                    Ok(Some(RequestContent::Json(Box::new(connector_req))))
                } else {
                    // UPI Collect without VPA - invalid
                    Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "vpa_id",
                    }
                    .into())
                }
            }
            domain_types::payment_method_data::PaymentMethodData::Upi(
                domain_types::payment_method_data::UpiData::UpiIntent(_),
            ) => {
                // UPI Intent flow
                let connector_req = paytm::PaytmProcessTxnRequest::try_from_with_auth(
                    &connector_router_data,
                    &auth,
                )?;
                Ok(Some(RequestContent::Json(Box::new(connector_req))))
            }
            _ => {
                // Unsupported payment method for Paytm
                Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported by Paytm connector".to_string(),
                    connector: "Paytm",
                }
                .into())
            }
        }
    }

    fn handle_response_v2(
        &self,
        data: &domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        domain_types::router_data_v2::RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        errors::ConnectorError,
    > {
        // Handle response based on payment method data
        match &data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(
                domain_types::payment_method_data::UpiData::UpiIntent(_),
            ) => {
                // Parse as UPI Intent response
                let response: paytm::PaytmProcessTxnResponse = res
                    .response
                    .parse_struct("PaytmProcessTxnResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                if let Some(event) = event_builder {
                    event.set_response_body(&response);
                }

                match response.body {
                    paytm::PaytmProcessRespBodyTypes::SuccessBody(success_resp) => {
                        if success_resp.result_info.result_code == constants::SUCCESS_CODE {
                            let trimmed_link = if let Some(pos) =
                                success_resp.deep_link_info.deep_link.find('?')
                            {
                                &success_resp.deep_link_info.deep_link[(pos + 1)..]
                            } else {
                                &success_resp.deep_link_info.deep_link
                            };
                            let redirect_form =
                                domain_types::router_response_types::RedirectForm::Uri {
                                    uri: trimmed_link.to_string(),
                                };

                            let payments_response = PaymentsResponseData::TransactionResponse {
                                resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                                    success_resp.deep_link_info.trans_id.clone()
                                ),
                                redirection_data: Box::new(Some(redirect_form)),
                                connector_metadata: None,
                                mandate_reference: Box::new(None),
                                network_txn_id: None,
                                connector_response_reference_id: Some(
                                    success_resp.deep_link_info.cashier_request_id.clone()
                                ),
                                incremental_authorization_allowed: None,
                                raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
                            };

                            let mut response_data = data.clone();
                            response_data.response = Ok(payments_response);
                            Ok(response_data)
                        } else {
                            Err(errors::ConnectorError::ResponseHandlingFailed.into())
                        }
                    }
                    paytm::PaytmProcessRespBodyTypes::FailureBody(_) => {
                        Err(errors::ConnectorError::ResponseHandlingFailed.into())
                    }
                }
            }
            domain_types::payment_method_data::PaymentMethodData::Upi(
                domain_types::payment_method_data::UpiData::UpiCollect(collect_data),
            ) => {
                if collect_data.vpa_id.is_none() {
                    return Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "vpa_id",
                    }
                    .into());
                }
                // Parse as UPI Collect response
                let response: paytm::PaytmNativeProcessTxnResponse = res
                    .response
                    .parse_struct("PaytmNativeProcessTxnResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

                if let Some(event) = event_builder {
                    event.set_response_body(&response);
                }

                match response.body {
                    paytm::PaytmNativeProcessRespBodyTypes::SuccessBody(success_resp) => {
                        if success_resp.result_info.result_code == constants::SUCCESS_CODE {
                            let payments_response = PaymentsResponseData::TransactionResponse {
                                resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                                    success_resp.trans_id.clone()
                                ),
                                redirection_data: Box::new(None), // No redirection for UPI Collect
                                connector_metadata: None,
                                mandate_reference: Box::new(None),
                                network_txn_id: None,
                                connector_response_reference_id: Some(success_resp.order_id.clone()),
                                incremental_authorization_allowed: None,
                                raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
                            };

                            let mut response_data = data.clone();
                            response_data.response = Ok(payments_response);
                            Ok(response_data)
                        } else {
                            Err(errors::ConnectorError::ResponseHandlingFailed.into())
                        }
                    }
                    paytm::PaytmNativeProcessRespBodyTypes::FailureBody(_) => {
                        Err(errors::ConnectorError::ResponseHandlingFailed.into())
                    }
                }
            }
            _ => {
                // Unsupported payment method for Paytm
                Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported by Paytm connector".to_string(),
                    connector: "Paytm",
                }
                .into())
            }
        }
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}
impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Paytm
{
}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Paytm
{
}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Paytm
{
}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Paytm {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Paytm {}
impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Paytm
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Paytm
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Paytm
{
}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Paytm
{
}
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paytm
{
}
