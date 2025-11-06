use base64::Engine;
use common_utils::Maskable;
use common_utils::{consts, errors::CustomResult, ext_traits::BytesExt, types::StringMajorUnit,
    Maskable,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::{Report, ResultExt};
// use crate::masking::{Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};

use serde::Serialize;
use std::fmt::Debug;
pub mod transformers;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
use transformers::{
    self as trustpay, TrustpayAuthUpdateRequest, TrustpayAuthUpdateResponse, TrustpayErrorResponse,
    TrustpayPaymentsResponse as TrustpayPaymentsSyncResponse,
};
use super::macros;
use crate::types::ResponseRouterData;
// Local headers module
mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const X_API_KEY: &str = "X-Api-Key";
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Trustpay<T>
{
    type PaymentAuthorizeV2 = Trustpay<T>;
    type PaymentSyncV2 = Trustpay<T>;
    type PaymentVoidV2 = Trustpay<T>;
    type RefundSyncV2 = Trustpay<T>;
    type RefundV2 = Trustpay<T>;
    type PaymentCapture = Trustpay<T>;
    type ValidationTrait = Trustpay<T>;
    type PaymentOrderCreate = Trustpay<T>;
    type SetupMandateV2 = Trustpay<T>;
    type RepeatPaymentV2 = Trustpay<T>;
    type AcceptDispute = Trustpay<T>;
    type SubmitEvidenceV2 = Trustpay<T>;
    type DisputeDefend = Trustpay<T>;
    type IncomingWebhook = Trustpay<T>;
    type PaymentSessionToken = Trustpay<T>;
    type PaymentAccessToken = Trustpay<T>;
    type CreateConnectorCustomer = Trustpay<T>;
    type PaymentTokenV2 = Trustpay<T>;
    type PaymentPreAuthenticateV2 = Trustpay<T>;
    type PaymentAuthenticateV2 = Trustpay<T>;
    type PaymentPostAuthenticateV2 = Trustpay<T>;
    type PaymentVoidPostCaptureV2 = Trustpay<T>;
    
    fn should_do_access_token(&self) -> bool {
        true
    }
}
macros::create_all_prerequisites!(
    connector_name: Trustpay,
    generic_type: T,
    api: [
        (
            flow: PSync,
            response_body: TrustpayPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: CreateAccessToken,
            request_body: TrustpayAuthUpdateRequest,
            response_body: TrustpayAuthUpdateResponse,
            router_data: RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers_for_payments<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, PaymentFlowData, Req, Res>,
        {
        match req.resource_common_data.payment_method {
            common_enums::PaymentMethod::BankRedirect | common_enums::PaymentMethod::BankTransfer => {
                let token = req
                    .resource_common_data
                    .get_access_token()
                    .change_context(errors::ConnectorError::MissingRequiredField {
                        field_name: "access_token",
                    })?;
                Ok(vec![
                    (
                        headers::CONTENT_TYPE.to_string(),
                        "application/json".to_owned().into(),
                    ),
                        headers::AUTHORIZATION.to_string(),
                        format!("Bearer {token}").into_masked(),
                ])
            }
            _ => {
                let mut header = vec![(
                    headers::CONTENT_TYPE.to_string(),
                    self.get_content_type().to_string().into(),
                )];
                let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
                header.append(&mut api_key);
                Ok(header)
            }
        }
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.trustpay.base_url
        }
        
        pub fn connector_base_url_bank_redirects_payments<'a, F, Req, Res>(
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.trustpay.base_url_bank_redirects
        }
        pub fn get_auth_header(
            auth_type: &ConnectorAuthType,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = trustpay::TrustpayAuthType::try_from(auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
            Ok(vec![(
            headers::X_API_KEY.to_string(),
                auth.api_key.into_masked(),
            )])
        }
    }
);
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Trustpay<T> {
    fn id(&self) -> &'static str {
        "trustpay"
    }
    
    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }
    
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.trustpay.base_url.as_ref()
    }
    
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: Result<TrustpayErrorResponse, Report<common_utils::errors::ParsingError>> =
            res.response.parse_struct("trustpay ErrorResponse");
        match response {
            Ok(response_data) => {
                if let Some(i) = event_builder {
                    i.set_error_response_body(&response_data);
                }
                let reason = response_data.errors.map(|errors| {
                    errors
                        .iter()
                        .map(|error| error.description.clone())
                        .collect::<Vec<String>>()
                        .join(" & ")
                });
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: consts::NO_ERROR_CODE.to_string(),
                    message: consts::NO_ERROR_CODE.to_string(),
                    reason: reason
                        .or(response_data.description)
                        .or(response_data.payment_description),
                    attempt_status: None,
                    connector_transaction_id: response_data.instance_id,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                })
            }
            Err(error_msg) => {
                if let Some(event) = event_builder {
                    event.set_error(serde_json::json!({"error": res.response.escape_ascii().to_string(), "status_code": res.status_code}))
                };
                tracing::error!(deserialization_error =? error_msg);
                domain_types::utils::handle_json_response_deserialization_failure(res, "trustpay")
            }
        }
    }
}
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Trustpay,
    curl_response: TrustpayPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers_for_payments(req)
        }
        
        fn get_url(
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let transaction_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
            
            match req.resource_common_data.payment_method {
                common_enums::PaymentMethod::BankRedirect | common_enums::PaymentMethod::BankTransfer => Ok(format!(
                    "{}{}/{}",
                    self.connector_base_url_bank_redirects_payments(req),
                    "api/Payments/Payment",
                    transaction_id,
                )),
                _ => Ok(format!(
                    "{}{}",
                    self.connector_base_url_payments(req),
                    "api/v1/instance"
                )),
            }
        }
    },
    curl_request: FormUrlEncoded(TrustpayAuthUpdateRequest),
    curl_response: TrustpayAuthUpdateResponse,
    flow_name: CreateAccessToken,
    flow_request: AccessTokenRequestData,
    flow_response: AccessTokenResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            req: &RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = trustpay::TrustpayAuthType::try_from(&req.connector_auth_type)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
            let auth_value = auth
                .project_id
                .zip(auth.secret_key)
                .map(|(project_id, secret_key)| {
                    format!(
                        "Basic {}",
                        BASE64_ENGINE
                            .encode(format!("{project_id}:{secret_key}"))
                    )
                });
            Ok(vec![
                (
                    self.common_get_content_type().to_string().into(),
                ),
                (headers::AUTHORIZATION.to_string(), auth_value.into_masked()),
            ])
        }
        
        fn get_url(
            req: &RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}{}",
                self.connector_base_url_bank_redirects_payments(req), "api/oauth2/token"
            ))
        }
    }
}
);
// Implementation for empty stubs - these will need to be properly implemented later
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
},
// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Trustpay<T>
{
    // Empty implementation
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorSpecifications
    for Trustpay<T>
{
    // Empty implementation
}

// We already have an implementation for ValidationTrait above
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Trustpay<T>
{
    // Empty implementation
}
