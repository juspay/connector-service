pub mod transformers;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
    StringMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, IncrementalAuthorization, MandateRevoke,
        PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment,
        SdkSessionToken, SetupMandate, SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        MandateRevokeRequestData, MandateRevokeResponseData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthenticateData,
        PaymentsAuthorizeData, PaymentsCancelPostCaptureData, PaymentsCaptureData,
        PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, WalletData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, ExposeOptionInterface, Mask, Maskable, Secret};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    verification::SourceVerification,
};
use serde::Serialize;
use std::fmt::{Debug, Write};

use super::macros;
use crate::{
    connectors::paypal::transformers::{
        self as paypal, auth_headers, PaypalAuthResponse, PaypalAuthUpdateRequest,
        PaypalAuthUpdateResponse, PaypalCaptureResponse, PaypalPaymentsCancelResponse,
        PaypalPaymentsCaptureRequest, PaypalPaymentsRequest, PaypalRefundRequest,
        PaypalRepeatPaymentRequest, PaypalRepeatPaymentResponse, PaypalSetupMandatesResponse,
        PaypalSyncResponse, PaypalZeroMandateRequest, RefundResponse, RefundSyncResponse,
    },
    types::ResponseRouterData,
    utils::{self, ConnectorErrorType, ConnectorErrorTypeMapping},
    with_error_response_body,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Paypal<T>
{
    fn should_do_access_token(&self, _payment_method: common_enums::PaymentMethod) -> bool {
        true
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Paypal<T>
{
}

macros::create_all_prerequisites!(
    connector_name: Paypal,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: PaypalPaymentsRequest<T>,
            response_body: PaypalAuthResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: PaypalSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PaypalPaymentsCaptureRequest,
            response_body: PaypalCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            response_body: PaypalPaymentsCancelResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: CreateAccessToken,
            request_body: PaypalAuthUpdateRequest,
            response_body: PaypalAuthUpdateResponse,
            router_data: RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ),
        (
            flow: Refund,
            request_body: PaypalRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: RefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: PaypalZeroMandateRequest,
            response_body: PaypalSetupMandatesResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: PaypalRepeatPaymentRequest<T>,
            response_body: PaypalRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers(
            &self,
            access_token: &str,
            connector_request_reference_id: &str,
            connector_auth_type: &ConnectorAuthType,
            connector_metadata: Option<&serde_json::Value>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let auth = paypal::PaypalAuthType::try_from(connector_auth_type)?;
            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().to_string().into(),
                ),
                (
                    headers::AUTHORIZATION.to_string(),
                    format!("Bearer {access_token}").into_masked(),
                ),
                (
                    auth_headers::PREFER.to_string(),
                    "return=representation".to_string().into(),
                ),
                (
                    auth_headers::PAYPAL_REQUEST_ID.to_string(),
                    connector_request_reference_id.to_string().into_masked(),
                ),
            ];
            if let Ok(paypal::PaypalConnectorCredentials::PartnerIntegration(credentials)) =
                auth.get_credentials()
            {
                let auth_assertion_header =
                    construct_auth_assertion_header(&credentials.payer_id, &credentials.client_id);

                let partner_attribution_id = connector_metadata
                    .and_then(|metadata| metadata.get("paypal_partner_attribution_id"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("HyperSwitchPPCP_SP");

                headers.extend(vec![
                    (
                        auth_headers::PAYPAL_AUTH_ASSERTION.to_string(),
                        auth_assertion_header.to_string().into_masked(),
                    ),
                    (
                        auth_headers::PAYPAL_PARTNER_ATTRIBUTION_ID.to_string(),
                        partner_attribution_id.to_string().into(),
                    ),
                ])
            } else {
                let legacy_attribution_id = connector_metadata
                    .and_then(|metadata| metadata.get("paypal_legacy_partner_attribution_id"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("HyperSwitchlegacy_Ecom");

                headers.extend(vec![(
                    auth_headers::PAYPAL_PARTNER_ATTRIBUTION_ID.to_string(),
                    legacy_attribution_id.to_string().into(),
                )])
            }
            Ok(headers)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.paypal.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.paypal.base_url
        }

     pub fn get_order_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        //Handled error response separately for Orders as the end point is different for Orders - (Authorize) and Payments - (Capture, void, refund, rsync).
        //Error response have different fields for Orders and Payments.
        let response: paypal::PaypalOrderErrorResponse = res
            .response
            .parse_struct("Paypal ErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let error_reason = response.details.clone().map(|order_errors| {
            order_errors
                .iter()
                .map(|error| {
                    let mut reason = format!("description - {}", error.description);
                    if let Some(value) = &error.value {
                        reason.push_str(&format!(", value - {value}"));
                    }
                    if let Some(field) = error
                        .field
                        .as_ref()
                        .and_then(|field| field.split('/').next_back())
                    {
                        reason.push_str(&format!(", field - {field}"));
                    }
                    reason.push(';');
                    reason
                })
                .collect::<String>()
        });
        let errors_list = response.details.unwrap_or_default();
        let option_error_code_message =
            utils::get_error_code_error_message_based_on_priority(
                self.clone(),
                errors_list
                    .into_iter()
                    .map(|errors| errors.into())
                    .collect(),
            );
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: option_error_code_message
                .clone()
                .map(|error_code_message| error_code_message.error_code)
                .unwrap_or(NO_ERROR_CODE.to_string()),
            message: option_error_code_message
                .map(|error_code_message| error_code_message.error_message)
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason: error_reason.or(Some(response.message)),
            attempt_status: None,
            connector_transaction_id: response.debug_id,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
    }
);

// Manual implementation for Authorize with conditional request body
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Paypal<T>
{
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Post
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let access_token = req
            .resource_common_data
            .access_token
            .clone()
            .ok_or(ConnectorError::FailedToObtainAuthType)?;
        let connector_metadata = req
            .resource_common_data
            .connector_meta_data
            .as_ref()
            .map(|secret| secret.clone().expose());
        self.build_headers(
            &access_token.access_token,
            &req.resource_common_data.connector_request_reference_id,
            &req.connector_auth_type,
            connector_metadata.as_ref(),
        )
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, ConnectorError> {
        // Determine the action based on capture method
        let action = if req.request.is_auto_capture()? {
            "capture"
        } else {
            "authorize"
        };

        let base = self.connector_base_url_payments(req);

        let path = if let PaymentMethodData::Wallet(WalletData::PaypalSdk(paypal_wallet_data)) =
            &req.request.payment_method_data
        {
            // Case 1: PaypalSdk wallet - complete order using SDK token
            format!("v2/checkout/orders/{}/{}", paypal_wallet_data.token, action)
        } else if let Some(order_id) = &req.resource_common_data.reference_id {
            // Case 2: Completing existing order
            format!("v2/checkout/orders/{order_id}/{action}")
        } else {
            // Case 3: Creating new order
            "v2/checkout/orders".to_owned()
        };

        Ok(format!("{base}{path}"))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, ConnectorError> {
        // No body needed when completing existing order (PaypalSdk or after redirect)
        let body = if req.resource_common_data.reference_id.is_some()
            || matches!(
                req.request.payment_method_data,
                PaymentMethodData::Wallet(WalletData::PaypalSdk(_))
            ) {
            None
        } else {
            // Build full request body for creating new order (like HS Authorize)
            let connector_router_data = PaypalRouterData {
                connector: self.to_owned(),
                router_data: req.to_owned(),
            };
            let connector_req = PaypalPaymentsRequest::try_from(connector_router_data)?;

            Some(common_utils::request::RequestContent::Json(Box::new(
                connector_req,
            )))
        };

        Ok(body)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ConnectorError,
    > {
        let response: PaypalAuthResponse = res
            .response
            .parse_struct("PaypalAuthResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event) = event_builder {
            event.set_connector_response(&response)
        }

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.get_order_error_response(res, event_builder)
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_request: FormUrlEncoded(PaypalAuthUpdateRequest),
    curl_response: PaypalAuthUpdateResponse,
    flow_name: CreateAccessToken,
    resource_common_data: PaymentFlowData,
    flow_request: AccessTokenRequestData,
    flow_response: AccessTokenResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let auth = paypal::PaypalAuthType::try_from(&req.connector_auth_type)?;
            let credentials = auth.get_credentials()?;
            let auth_val = credentials.generate_authorization_value();

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/x-www-form-urlencoded".to_string().into(),
                ),
                (headers::AUTHORIZATION.to_string(), auth_val.into_masked()),
            ])
        }
        fn get_url(
            &self,
            req: &RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}v1/oauth2/token", self.connector_base_url_payments(req)))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_response: PaypalSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(ConnectorError::FailedToObtainAuthType)?;
            let connector_metadata = req.resource_common_data.connector_meta_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            let reference_id = req.resource_common_data.get_reference_id()?;
            self.build_headers(
                &access_token.access_token,
                &reference_id,
                &req.connector_auth_type,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(req.request.connector_metadata.clone().map(|m| m.expose()))?;
        match req.resource_common_data.payment_method {
            common_enums::PaymentMethod::Wallet | common_enums::PaymentMethod::BankRedirect => Ok(format!(
                "{}v2/checkout/orders/{}",
                self.connector_base_url_payments(req),
                req.request
                    .connector_transaction_id
                    .get_connector_transaction_id()
                    .change_context(ConnectorError::MissingConnectorTransactionID)?
            )),
            _ => {
                let psync_url = match paypal_meta.psync_flow {
                    transformers::PaypalPaymentIntent::Authorize => {
                        let authorize_id = paypal_meta.authorize_id.ok_or(
                            ConnectorError::RequestEncodingFailedWithReason(
                                "Missing Authorize id".to_string(),
                            ),
                        )?;
                        format!("v2/payments/authorizations/{authorize_id}")
                    }
                    transformers::PaypalPaymentIntent::Capture => {
                        let capture_id = paypal_meta.capture_id.ok_or(
                            ConnectorError::RequestEncodingFailedWithReason(
                                "Missing Capture id".to_string(),
                            ),
                        )?;
                        format!("v2/payments/captures/{capture_id}")
                    }
                    // only set when payment is done through card 3DS
                    //because no authorize or capture id is generated during payment authorize call for card 3DS
                    transformers::PaypalPaymentIntent::Authenticate => {
                        format!(
                            "v2/checkout/orders/{}",
                            req.request
                                .connector_transaction_id
                                .get_connector_transaction_id()
                                .change_context(
                                    ConnectorError::MissingConnectorTransactionID
                                )?
                        )
                    }
                };
                Ok(format!("{}{psync_url}", self.connector_base_url_payments(req)))
            }
        }
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_request: Json(PaypalPaymentsCaptureRequest),
    curl_response: PaypalCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(ConnectorError::FailedToObtainAuthType)?;
            let connector_metadata = req.resource_common_data.connector_meta_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token,
                &req.resource_common_data.connector_request_reference_id,
                &req.connector_auth_type,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(req.request.connector_metadata.clone().map(|m| m.expose()))?;
            let authorize_id = paypal_meta.authorize_id.ok_or(
                ConnectorError::RequestEncodingFailedWithReason(
                    "Missing Authorize id".to_string(),
                ),
            )?;
            Ok(format!(
                "{}v2/payments/authorizations/{}/capture",
                self.connector_base_url_payments(req),
                authorize_id
            ))
            }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_response: PaypalPaymentsCancelResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(ConnectorError::FailedToObtainAuthType)?;
            let connector_metadata = req.resource_common_data.connector_meta_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token,
                &req.resource_common_data.connector_request_reference_id,
                &req.connector_auth_type,
                connector_metadata.as_ref(),
            )
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let connector_metadata_value = req.request.connector_metadata.clone().map(|secret| secret.expose());
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(connector_metadata_value)?;
            let authorize_id = paypal_meta.authorize_id.ok_or(
                ConnectorError::RequestEncodingFailedWithReason(
                    "Missing Authorize id".to_string(),
                ),
            )?;
            Ok(format!(
                "{}v2/payments/authorizations/{}/void",
                self.connector_base_url_payments(req),
                authorize_id,
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_request: Json(PaypalRefundRequest),
    curl_response: RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(ConnectorError::FailedToObtainAuthType)?;
            let connector_metadata = req.resource_common_data.connector_meta_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token,
                &req.resource_common_data.connector_request_reference_id,
                &req.connector_auth_type,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            let paypal_meta: paypal::PaypalMeta = utils::to_connector_meta(req.request.connector_metadata.clone().expose_option())?;
            let capture_id = paypal_meta.capture_id.ok_or(
                ConnectorError::RequestEncodingFailedWithReason(
                    "Missing Capture id".to_string(),
                ),
            )?;
            Ok(format!(
                "{}v2/payments/captures/{}/refund",
                self.connector_base_url_refunds(req),
                capture_id,
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_response: RefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(ConnectorError::FailedToObtainAuthType)?;
            let connector_metadata = req.resource_common_data.connector_meta_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token,
                &req.resource_common_data.connector_request_reference_id,
                &req.connector_auth_type,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!(
                "{}v2/payments/refunds/{}",
                self.connector_base_url_refunds(req),
                req.request.connector_refund_id
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_request: Json(PaypalZeroMandateRequest),
    curl_response: PaypalSetupMandatesResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(ConnectorError::FailedToObtainAuthType)?;
            let connector_metadata = req.resource_common_data.connector_meta_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token,
                &req.resource_common_data.connector_request_reference_id,
                &req.connector_auth_type,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!(
                "{}v3/vault/payment-tokens/",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Paypal,
    curl_request: Json(PaypalRepeatPaymentRequest<T>),
    curl_response: PaypalRepeatPaymentResponse,
    flow_name: RepeatPayment,
    resource_common_data: PaymentFlowData,
    flow_request: RepeatPaymentData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let access_token = req.resource_common_data
                .access_token
                .clone()
                .ok_or(ConnectorError::FailedToObtainAuthType)?;
            let connector_metadata = req.resource_common_data.connector_meta_data
                .as_ref()
                .map(|secret| secret.clone().expose());
            self.build_headers(
                &access_token.access_token,
                &req.resource_common_data.connector_request_reference_id,
                &req.connector_auth_type,
                connector_metadata.as_ref(),
            )
        }
        fn get_url(
            &self,
            req: &RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}v2/checkout/orders", self.connector_base_url_payments(req)))
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Paypal<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Paypal<T>
{
}
// PostAuthenticate implementation to fetch order details (like HS PreProcessing)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Paypal<T>
{
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_http_method(&self) -> common_utils::request::Method {
        common_utils::request::Method::Get
    }

    fn get_headers(
        &self,
        req: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let access_token = req
            .resource_common_data
            .access_token
            .clone()
            .ok_or(ConnectorError::FailedToObtainAuthType)?;
        let connector_metadata = req
            .resource_common_data
            .connector_meta_data
            .as_ref()
            .map(|secret| secret.clone().expose());
        self.build_headers(
            &access_token.access_token,
            &req.resource_common_data.connector_request_reference_id,
            &req.connector_auth_type,
            connector_metadata.as_ref(),
        )
    }

    fn get_url(
        &self,
        req: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, ConnectorError> {
        let order_id = req.resource_common_data.reference_id.clone().ok_or(
            ConnectorError::MissingRequiredField {
                field_name: "reference_id (order_id)",
            },
        )?;

        Ok(format!(
            "{}v2/checkout/orders/{}?fields=payment_source",
            self.connector_base_url_payments(req),
            order_id
        ))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<common_utils::request::RequestContent>, ConnectorError> {
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut events::Event>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<
            PostAuthenticate,
            PaymentFlowData,
            PaymentsPostAuthenticateData<T>,
            PaymentsResponseData,
        >,
        ConnectorError,
    > {
        let response: transformers::PaypalPostAuthenticateResponse = res
            .response
            .parse_struct("PaypalPostAuthenticateResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        if let Some(event) = event_builder {
            event.set_connector_response(&response)
        }

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Paypal<T>
{
}

// SourceVerification implementations for all flows

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Paypal<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorErrorTypeMapping for Paypal<T>
{
    fn get_connector_error_type(
        &self,
        error_code: String,
        _error_message: String,
    ) -> ConnectorErrorType {
        match error_code.as_str() {
            "CANNOT_BE_NEGATIVE" => ConnectorErrorType::UserError,
            "CANNOT_BE_ZERO_OR_NEGATIVE" => ConnectorErrorType::UserError,
            "CARD_EXPIRED" => ConnectorErrorType::UserError,
            "DECIMAL_PRECISION" => ConnectorErrorType::UserError,
            "DUPLICATE_INVOICE_ID" => ConnectorErrorType::UserError,
            "INSTRUMENT_DECLINED" => ConnectorErrorType::BusinessError,
            "INTERNAL_SERVER_ERROR" => ConnectorErrorType::TechnicalError,
            "INVALID_ACCOUNT_STATUS" => ConnectorErrorType::BusinessError,
            "INVALID_CURRENCY_CODE" => ConnectorErrorType::UserError,
            "INVALID_PARAMETER_SYNTAX" => ConnectorErrorType::UserError,
            "INVALID_PARAMETER_VALUE" => ConnectorErrorType::UserError,
            "INVALID_RESOURCE_ID" => ConnectorErrorType::UserError,
            "INVALID_STRING_LENGTH" => ConnectorErrorType::UserError,
            "MISSING_REQUIRED_PARAMETER" => ConnectorErrorType::UserError,
            "PAYER_ACCOUNT_LOCKED_OR_CLOSED" => ConnectorErrorType::BusinessError,
            "PAYER_ACCOUNT_RESTRICTED" => ConnectorErrorType::BusinessError,
            "PAYER_CANNOT_PAY" => ConnectorErrorType::BusinessError,
            "PERMISSION_DENIED" => ConnectorErrorType::BusinessError,
            "INVALID_ARRAY_MAX_ITEMS" => ConnectorErrorType::UserError,
            "INVALID_ARRAY_MIN_ITEMS" => ConnectorErrorType::UserError,
            "INVALID_COUNTRY_CODE" => ConnectorErrorType::UserError,
            "NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "PAYPAL_REQUEST_ID_REQUIRED" => ConnectorErrorType::UserError,
            "MALFORMED_REQUEST_JSON" => ConnectorErrorType::UserError,
            "PERMISSION_DENIED_FOR_DONATION_ITEMS" => ConnectorErrorType::BusinessError,
            "MALFORMED_REQUEST" => ConnectorErrorType::TechnicalError,
            "AMOUNT_MISMATCH" => ConnectorErrorType::UserError,
            "BILLING_ADDRESS_INVALID" => ConnectorErrorType::UserError,
            "CITY_REQUIRED" => ConnectorErrorType::UserError,
            "DONATION_ITEMS_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "DUPLICATE_REFERENCE_ID" => ConnectorErrorType::UserError,
            "INVALID_PAYER_ID" => ConnectorErrorType::UserError,
            "ITEM_TOTAL_REQUIRED" => ConnectorErrorType::UserError,
            "MAX_VALUE_EXCEEDED" => ConnectorErrorType::UserError,
            "MISSING_PICKUP_ADDRESS" => ConnectorErrorType::UserError,
            "MULTI_CURRENCY_ORDER" => ConnectorErrorType::BusinessError,
            "MULTIPLE_ITEM_CATEGORIES" => ConnectorErrorType::UserError,
            "MULTIPLE_SHIPPING_ADDRESS_NOT_SUPPORTED" => ConnectorErrorType::UserError,
            "MULTIPLE_SHIPPING_TYPE_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "PAYEE_ACCOUNT_INVALID" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_LOCKED_OR_CLOSED" => ConnectorErrorType::UserError,
            "REFERENCE_ID_REQUIRED" => ConnectorErrorType::UserError,
            "PAYMENT_SOURCE_CANNOT_BE_USED" => ConnectorErrorType::BusinessError,
            "PAYMENT_SOURCE_DECLINED_BY_PROCESSOR" => ConnectorErrorType::BusinessError,
            "PAYMENT_SOURCE_INFO_CANNOT_BE_VERIFIED" => ConnectorErrorType::BusinessError,
            "POSTAL_CODE_REQUIRED" => ConnectorErrorType::UserError,
            "SHIPPING_ADDRESS_INVALID" => ConnectorErrorType::UserError,
            "TAX_TOTAL_MISMATCH" => ConnectorErrorType::UserError,
            "TAX_TOTAL_REQUIRED" => ConnectorErrorType::UserError,
            "UNSUPPORTED_INTENT" => ConnectorErrorType::BusinessError,
            "UNSUPPORTED_PAYMENT_INSTRUCTION" => ConnectorErrorType::UserError,
            "SHIPPING_TYPE_NOT_SUPPORTED_FOR_CLIENT" => ConnectorErrorType::BusinessError,
            "UNSUPPORTED_SHIPPING_TYPE" => ConnectorErrorType::BusinessError,
            "PREFERRED_SHIPPING_OPTION_AMOUNT_MISMATCH" => ConnectorErrorType::UserError,
            "CARD_CLOSED" => ConnectorErrorType::BusinessError,
            "ORDER_CANNOT_BE_SAVED" => ConnectorErrorType::BusinessError,
            "SAVE_ORDER_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "FIELD_NOT_PATCHABLE" => ConnectorErrorType::UserError,
            "AMOUNT_NOT_PATCHABLE" => ConnectorErrorType::UserError,
            "INVALID_PATCH_OPERATION" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_NOT_SUPPORTED" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_NOT_VERIFIED" => ConnectorErrorType::UserError,
            "PAYEE_NOT_CONSENTED" => ConnectorErrorType::UserError,
            "INVALID_JSON_POINTER_FORMAT" => ConnectorErrorType::BusinessError,
            "INVALID_PARAMETER" => ConnectorErrorType::UserError,
            "NOT_PATCHABLE" => ConnectorErrorType::BusinessError,
            "PATCH_VALUE_REQUIRED" => ConnectorErrorType::UserError,
            "PATCH_PATH_REQUIRED" => ConnectorErrorType::UserError,
            "REFERENCE_ID_NOT_FOUND" => ConnectorErrorType::UserError,
            "SHIPPING_OPTION_NOT_SELECTED" => ConnectorErrorType::UserError,
            "SHIPPING_OPTIONS_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "MULTIPLE_SHIPPING_OPTION_SELECTED" => ConnectorErrorType::UserError,
            "ORDER_ALREADY_COMPLETED" => ConnectorErrorType::BusinessError,
            "ACTION_DOES_NOT_MATCH_INTENT" => ConnectorErrorType::BusinessError,
            "AGREEMENT_ALREADY_CANCELLED" => ConnectorErrorType::BusinessError,
            "BILLING_AGREEMENT_NOT_FOUND" => ConnectorErrorType::BusinessError,
            "DOMESTIC_TRANSACTION_REQUIRED" => ConnectorErrorType::BusinessError,
            "ORDER_NOT_APPROVED" => ConnectorErrorType::UserError,
            "MAX_NUMBER_OF_PAYMENT_ATTEMPTS_EXCEEDED" => ConnectorErrorType::TechnicalError,
            "PAYEE_BLOCKED_TRANSACTION" => ConnectorErrorType::BusinessError,
            "TRANSACTION_LIMIT_EXCEEDED" => ConnectorErrorType::UserError,
            "TRANSACTION_RECEIVING_LIMIT_EXCEEDED" => ConnectorErrorType::BusinessError,
            "TRANSACTION_REFUSED" => ConnectorErrorType::TechnicalError,
            "ORDER_ALREADY_AUTHORIZED" => ConnectorErrorType::BusinessError,
            "AUTH_CAPTURE_NOT_ENABLED" => ConnectorErrorType::BusinessError,
            "AMOUNT_CANNOT_BE_SPECIFIED" => ConnectorErrorType::BusinessError,
            "AUTHORIZATION_AMOUNT_EXCEEDED" => ConnectorErrorType::UserError,
            "AUTHORIZATION_CURRENCY_MISMATCH" => ConnectorErrorType::UserError,
            "MAX_AUTHORIZATION_COUNT_EXCEEDED" => ConnectorErrorType::BusinessError,
            "ORDER_COMPLETED_OR_VOIDED" => ConnectorErrorType::BusinessError,
            "ORDER_EXPIRED" => ConnectorErrorType::BusinessError,
            "INVALID_PICKUP_ADDRESS" => ConnectorErrorType::UserError,
            "CONSENT_NEEDED" => ConnectorErrorType::UserError,
            "COMPLIANCE_VIOLATION" => ConnectorErrorType::BusinessError,
            "REDIRECT_PAYER_FOR_ALTERNATE_FUNDING" => ConnectorErrorType::TechnicalError,
            "ORDER_ALREADY_CAPTURED" => ConnectorErrorType::UserError,
            "TRANSACTION_BLOCKED_BY_PAYEE" => ConnectorErrorType::BusinessError,
            "NOT_ENABLED_FOR_CARD_PROCESSING" => ConnectorErrorType::BusinessError,
            "PAYEE_NOT_ENABLED_FOR_CARD_PROCESSING" => ConnectorErrorType::BusinessError,
            _ => ConnectorErrorType::UnknownError,
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Paypal<T>
{
    fn id(&self) -> &'static str {
        "paypal"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.paypal.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = paypal::PaypalAuthType::try_from(auth_type)?;
        let credentials = auth.get_credentials()?;

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            credentials.get_client_secret().into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: paypal::PaypalPaymentErrorResponse = res
            .response
            .parse_struct("Paypal ErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let error_reason = response
            .details
            .clone()
            .map(|error_details| {
                error_details
                    .iter()
                    .try_fold(String::new(), |mut acc, error| {
                        if let Some(description) = &error.description {
                            write!(acc, "description - {description} ;")
                                .change_context(ConnectorError::ResponseDeserializationFailed)
                                .attach_printable("Failed to concatenate error details")
                                .map(|_| acc)
                        } else {
                            Ok(acc)
                        }
                    })
            })
            .transpose()?;
        let reason = match error_reason {
            Some(err_reason) => err_reason
                .is_empty()
                .then(|| response.message.to_owned())
                .or(Some(err_reason)),
            None => Some(response.message.to_owned()),
        };
        let errors_list = response.details.unwrap_or_default();
        let option_error_code_message = utils::get_error_code_error_message_based_on_priority(
            self.clone(),
            errors_list
                .into_iter()
                .map(|errors| errors.into())
                .collect(),
        );

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: option_error_code_message
                .clone()
                .map(|error_code_message| error_code_message.error_code)
                .unwrap_or(NO_ERROR_CODE.to_string()),
            message: option_error_code_message
                .map(|error_code_message| error_code_message.error_message)
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason,
            attempt_status: None,
            connector_transaction_id: response.debug_id,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

fn construct_auth_assertion_header(
    payer_id: &Secret<String>,
    client_id: &Secret<String>,
) -> String {
    let algorithm = BASE64_ENGINE.encode("{\"alg\":\"none\"}").to_string();
    let merchant_credentials = format!(
        "{{\"iss\":\"{}\",\"payer_id\":\"{}\"}}",
        client_id.clone().expose(),
        payer_id.clone().expose()
    );
    let encoded_credentials = BASE64_ENGINE.encode(merchant_credentials).to_string();
    format!("{algorithm}.{encoded_credentials}.")
}
