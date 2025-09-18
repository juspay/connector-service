use base64::Engine;
use common_utils::{consts, errors::CustomResult, ext_traits::BytesExt, types::StringMajorUnit};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateAccessToken, CreateOrder, CreateSessionToken,
        DefendDispute, PSync, PaymentMethodToken, RSync, Refund, RepeatPayment, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData,
        ConnectorSpecifications, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};

use serde::Serialize;
use std::fmt::Debug;
pub mod transformers;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use transformers::{
    self as trustpay, RefundResponse, RefundResponse as TrustpayRefundSyncResponse,
    TrustpayAuthUpdateRequest, TrustpayAuthUpdateResponse, TrustpayCreateIntentRequest,
    TrustpayCreateIntentResponse, TrustpayErrorResponse, TrustpayPaymentsRequest,
    TrustpayPaymentsResponse, TrustpayPaymentsResponse as TrustpayPaymentsSyncResponse,
    TrustpayRefundRequest,
};

use super::macros;
use crate::{types::ResponseRouterData, with_response_body};

// Local headers module
mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const X_API_KEY: &str = "X-Api-Key";
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Trustpay<T>
{
    fn should_do_access_token(&self) -> bool {
        true
    }

    fn should_do_order_create_for_payment_method(
        &self,
        payment_method: common_enums::PaymentMethod,
    ) -> bool {
        // For TrustPay, enable order creation only for wallet payment methods
        matches!(payment_method, common_enums::PaymentMethod::Wallet)
    }
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Trustpay<T>
{
}

macros::create_all_prerequisites!(
    connector_name: Trustpay,
    generic_type: T,
    api: [
        (
            flow: CreateOrder,
            request_body: TrustpayCreateIntentRequest,
            response_body: TrustpayCreateIntentResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: Authorize,
            request_body: TrustpayPaymentsRequest<T>,
            response_body: TrustpayPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: CreateAccessToken,
            request_body: TrustpayAuthUpdateRequest,
            response_body: TrustpayAuthUpdateResponse,
            router_data: RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ),
        (
            flow: PSync,
            response_body: TrustpayPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: TrustpayRefundRequest,
            response_body: RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: TrustpayRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
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
                    (
                        headers::AUTHORIZATION.to_string(),
                        format!("Bearer {token}").into_masked(),
                    ),
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
        }

        pub fn build_headers_for_refunds<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, RefundFlowData, Req, Res>,
        {
            // For refunds, we'll use the default headers since we can't easily access payment method
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.trustpay.base_url
        }

        pub fn connector_base_url_bank_redirects_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.trustpay.base_url_bank_redirects
        }

         pub fn connector_base_url_bank_redirects_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.trustpay.base_url_bank_redirects
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.trustpay.base_url
        }

        pub fn get_auth_header(
            &self,
            auth_type: &ConnectorAuthType,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = trustpay::TrustpayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::X_API_KEY.to_string(),
            auth.api_key.into_masked(),
        )])
        }

        pub fn extract_payment_method_from_refund_metadata(
            refund_connector_metadata: &Option<hyperswitch_masking::Secret<serde_json::Value>>,
        ) -> CustomResult<common_enums::PaymentMethod, errors::ConnectorError> {
            let payment_method = refund_connector_metadata
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "refund_connector_metadata",
                })?
                .peek()
                .as_str()
                .and_then(|json_str| serde_json::from_str::<serde_json::Value>(json_str).ok())
                .and_then(|json_obj| {
                    json_obj.get("payment_method")
                        .and_then(|pm| pm.as_str())
                        .and_then(|pm_str| match pm_str {
                            "bank_redirect" => Some(common_enums::PaymentMethod::BankRedirect),
                            "bank_transfer" => Some(common_enums::PaymentMethod::BankTransfer),
                            "card" => Some(common_enums::PaymentMethod::Card),
                            "wallet" => Some(common_enums::PaymentMethod::Wallet),
                            _ => None,
                        })
                })
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_method in refund_connector_metadata",
                })?;
            Ok(payment_method)
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Trustpay<T>
{
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
            Err(_) => {
                if let Some(event) = event_builder {
                    event.set_error(serde_json::json!({"error": res.response.escape_ascii().to_string(), "status_code": res.status_code}));
                }
                domain_types::utils::handle_json_response_deserialization_failure(res, "trustpay")
            }
        }
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Trustpay,
    curl_request: FormUrlEncoded(TrustpayCreateIntentRequest),
    curl_response: TrustpayCreateIntentResponse,
    flow_name: CreateOrder,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentCreateOrderData,
    flow_response: PaymentCreateOrderResponse,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}", self.connector_base_url_payments(req), "api/v1/intent"))
        }
    }
);

// Authorize is not implemented using the macro structure because the request is wrapped differently according to the payment method

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers_for_payments(req)
    }
    fn get_url(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<String, errors::ConnectorError> {
        match req.resource_common_data.payment_method {
            common_enums::PaymentMethod::BankRedirect
            | common_enums::PaymentMethod::BankTransfer => Ok(format!(
                "{}{}",
                self.connector_base_url_bank_redirects_payments(req),
                "api/Payments/Payment"
            )),
            _ => Ok(format!(
                "{}{}",
                self.connector_base_url_payments(req),
                "api/v1/purchase"
            )),
        }
    }
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> CustomResult<Option<macro_types::RequestContent>, macro_types::ConnectorError> {
        let bridge = self.authorize;
        let connector_router_data = TrustpayRouterData {
            connector: self.clone(),
            router_data: req.clone(),
        };
        let connector_req = bridge.request_body(connector_router_data)?;
        match req.resource_common_data.payment_method {
            common_enums::PaymentMethod::BankRedirect
            | common_enums::PaymentMethod::BankTransfer => Ok(Some(
                macro_types::RequestContent::Json(Box::new(connector_req)),
            )),
            _ => Ok(Some(macro_types::RequestContent::FormUrlEncoded(Box::new(
                connector_req,
            )))),
        }
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        macro_types::ConnectorError,
    > {
        let response: TrustpayPaymentsResponse = res
            .response
            .parse_struct("trustpay PaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Trustpay,
    curl_request: FormUrlEncoded(TrustpayAuthUpdateRequest),
    curl_response: TrustpayAuthUpdateResponse,
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
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().to_string().into(),
                ),
                (headers::AUTHORIZATION.to_string(), auth_value.into_masked()),
            ])
        }
        fn get_url(
            &self,
            req: &RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
            "{}{}",
            self.connector_base_url_bank_redirects_payments(req), "api/oauth2/token"
        ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Trustpay,
    curl_response: TrustpayPaymentsSyncResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers_for_payments(req)
        }
        fn get_url(
            &self,
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
                "{}{}/{}",
                self.connector_base_url_payments(req),
                "api/v1/instance",
                transaction_id,
            )),
        }
        }
    }
);

// Refund is not implemented using the macro structure because the request is wrapped differently according to the payment method

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for Trustpay<T>
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers_for_refunds(req)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Extract payment method from refund_connector_metadata
        let payment_method = Self::extract_payment_method_from_refund_metadata(
            &req.request.refund_connector_metadata,
        )?;

        match payment_method {
            common_enums::PaymentMethod::BankRedirect
            | common_enums::PaymentMethod::BankTransfer => Ok(format!(
                "{}{}{}{}",
                self.connector_base_url_bank_redirects_refunds(req),
                "api/Payments/Payment/",
                req.request.connector_transaction_id,
                "/Refund"
            )),
            _ => Ok(format!(
                "{}{}",
                self.connector_base_url_refunds(req),
                "api/v1/Refund"
            )),
        }
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<macro_types::RequestContent>, macro_types::ConnectorError> {
        let bridge = self.refund;
        let connector_router_data = TrustpayRouterData {
            connector: self.clone(),
            router_data: req.clone(),
        };
        let connector_req = bridge.request_body(connector_router_data)?;
        // Extract payment method from refund_connector_metadata
        let payment_method = Self::extract_payment_method_from_refund_metadata(
            &req.request.refund_connector_metadata,
        )?;
        match payment_method {
            common_enums::PaymentMethod::BankRedirect
            | common_enums::PaymentMethod::BankTransfer => Ok(Some(
                macro_types::RequestContent::Json(Box::new(connector_req)),
            )),
            _ => Ok(Some(macro_types::RequestContent::FormUrlEncoded(Box::new(
                connector_req,
            )))),
        }
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        macro_types::ConnectorError,
    > {
        let response: trustpay::RefundResponse = res
            .response
            .parse_struct("trustpay RefundResponse")
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        with_response_body!(event_builder, response);

        RouterDataV2::try_from(ResponseRouterData {
            response,
            router_data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Implement RSync to fix the RefundSyncV2 trait requirement
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Trustpay,
    curl_response: TrustpayRefundSyncResponse,
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
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers_for_refunds(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
        let id = req
            .request
            .connector_refund_id.clone();

        let payment_method = req.request.refund_connector_metadata
            .as_ref()
            .and_then(|metadata| {
                let json_value = metadata.peek();
                json_value.get("payment_method")
                    .and_then(|pm| pm.as_str())
                    .and_then(|pm_str| match pm_str {
                        "bank_redirect" => Some(common_enums::PaymentMethod::BankRedirect),
                        "bank_transfer" => Some(common_enums::PaymentMethod::BankTransfer),
                        "card" => Some(common_enums::PaymentMethod::Card),
                        "wallet" => Some(common_enums::PaymentMethod::Wallet),
                        _ => None,
                    })
            })
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method in refund_connector_metadata",
            })?;

        match payment_method {
            common_enums::PaymentMethod::BankRedirect | common_enums::PaymentMethod::BankTransfer => Ok(format!(
                "{}{}/{}",
                self.connector_base_url_bank_redirects_refunds(req), "api/Payments/Payment", id
            )),
            _ => Ok(format!(
                "{}{}/{}",
                self.connector_base_url_refunds(req),
                "api/v1/instance",
                id
            )),
        }
        }
    }
);

// Implementation for empty stubs - these will need to be properly implemented later
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Trustpay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Trustpay<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Trustpay<T>
{
}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorSpecifications
    for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Trustpay<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Trustpay<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Trustpay<T>
{
}

// We already have an implementation for ValidationTrait above

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Trustpay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Trustpay<T>
{
}
