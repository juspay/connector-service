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
        event_builder: Option<&mut ConnectorEvent>,
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
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
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
                                    success_resp.deep_link_info.trans_id.clone(),
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
                let _attempt_status = paytm::map_paytm_status_to_attempt_status(
                    &success_resp.result_info.result_code,
                );

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
                Ok(response_data)
            }
            paytm::PaytmTransactionStatusRespBodyTypes::FailureBody(failure_resp) => {
                let _attempt_status = paytm::map_paytm_status_to_attempt_status(
                    &failure_resp.result_info.result_code,
                );

                // For failure cases, we should still return the transaction response but with appropriate status
                let payments_response = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        data.resource_common_data
                            .connector_request_reference_id
                            .clone(),
                    ),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    raw_connector_response: Some(
                        String::from_utf8_lossy(&res.response).to_string(),
                    ),
                };

                let mut response_data = data.clone();
                response_data.response = Ok(payments_response);
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
            "{}theia/api/v1/initiateTransaction?mid={}&orderId={}",
            base_url, merchant_id, order_id
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
                Ok(format!(
                    "{}theia/api/v1/processTransaction?mid={}&orderId={}",
                    base_url, merchant_id, order_id
                ))
            } // paytm::UpiFlowType::QrCode => {
              //     // UPI QR uses a different endpoint for QR creation
              //     Ok(format!("{}paymentservices/qr/create", base_url))
              // }
        }
>>>>>>> d637bc4 (clippy-fixes)
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
            } // paytm::UpiFlowType::QrCode => {
              //     let connector_req = paytm::PaytmQRRequest::try_from_with_auth(&connector_router_data, &auth)?;
              //     Ok(Some(RequestContent::Json(Box::new(connector_req))))
              // }
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
        let upi_flow = paytm::determine_upi_flow(&data.request.payment_method_data)?;

        match upi_flow {
            paytm::UpiFlowType::Intent => {
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
                            let redirect_form =
                                domain_types::router_response_types::RedirectForm::Uri {
                                    uri: success_resp.deep_link_info.deep_link.clone(),
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
            paytm::UpiFlowType::Collect => {
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
            } // paytm::UpiFlowType::QrCode => {
              //     // Parse as UPI QR response
              //     let response: paytm::PaytmQRResponse = res
              //         .response
              //         .parse_struct("PaytmQRResponse")
              //         .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

              //     if let Some(event) = event_builder {
              //         event.set_response_body(&response);
              //     }

              //     match response.body {
              //         paytm::PaytmQRRespBodyTypes::SuccessBody(success_resp) => {
              //             if success_resp.result_info.result_code == constants::QR_SUCCESS_CODE {
              //                 // For QR, we return the QR data in connector metadata
              //                 let qr_metadata = serde_json::json!({
              //                     "qr_code_id": success_resp.qr_code_id,
              //                     "qr_data": success_resp.qr_data,
              //                     "qr_image": success_resp.image
              //                 });

              //                 let payments_response = PaymentsResponseData::TransactionResponse {
              //                     resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
              //                         success_resp.qr_code_id.clone()
              //                     ),
              //                     redirection_data: Box::new(None), // No redirection for QR
              //                     connector_metadata: Some(qr_metadata),
              //                     mandate_reference: Box::new(None),
              //                     network_txn_id: None,
              //                     connector_response_reference_id: Some(success_resp.qr_code_id.clone()),
              //                     incremental_authorization_allowed: None,
              //                     raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
              //                 };

              //                 let mut response_data = data.clone();
              //                 response_data.response = Ok(payments_response);
              //                 Ok(response_data)
              //             } else {
              //                 Err(errors::ConnectorError::ResponseHandlingFailed.into())
              //             }
              //         },
              //         paytm::PaytmQRRespBodyTypes::FailureBody(_) => {
              //             Err(errors::ConnectorError::ResponseHandlingFailed.into())
              //         }
              //     }
              // }
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
