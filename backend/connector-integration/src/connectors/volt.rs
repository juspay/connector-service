mod test;
mod transformers;

use std::sync::LazyLock;

use base64::Engine;
use common_enums::{CaptureMethod, EventClass, PaymentMethod, PaymentMethodType};
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund,
        RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, ResponseId, SetupMandateRequestData, SubmitEvidenceData,
        SupportedPaymentMethodsExt,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{
        self, ConnectorInfo, Connectors, FeatureStatus, PaymentMethodDetails,
        SupportedPaymentMethods,
    },
};
use grpc_api_types::payments::AccessToken;
use hyperswitch_masking::Secret;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{self, is_mandate_supported, ConnectorValidation},
    events::connector_api_logs::ConnectorEvent,
};
use transformers::{
    self as volt,
    VoltPSyncResponse,
    // VoltCaptureRequest, VoltCaptureResponse, VoltRefundRequest, VoltRefundResponse,
    VoltPaymentRequest,
    VoltPaymentResponse,
};

use super::macros;
use crate::{access_token::AccessTokenAuth, types::ResponseRouterData, with_error_response_body};

/// Volt-specific OAuth access token request (password grant)
#[derive(Debug, serde::Serialize)]
struct VoltAccessTokenRequest {
    grant_type: String,
    username: Secret<String>,
    password: Secret<String>,
    client_id: Secret<String>,
    client_secret: Secret<String>,
}

/// Volt-specific OAuth access token response
#[derive(Debug, serde::Deserialize)]
struct VoltAccessTokenResponse {
    access_token: String,
    expires_in: i64,
    token_type: String,
}

impl From<VoltAccessTokenResponse> for AccessToken {
    fn from(response: VoltAccessTokenResponse) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            token: response.access_token,
            expires_in_seconds: current_time + response.expires_in,
            token_type: response.token_type,
        }
    }
}

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::ConnectorServiceTrait<T> for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::PaymentSessionToken for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::PaymentSyncV2 for Volt<T>
{
}
// Empty implementations for required traits - not actually used
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::PaymentVoidV2 for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::RefundSyncV2 for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::RefundV2 for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::PaymentCapture for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::SetupMandateV2<T> for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::RepeatPaymentV2 for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::AcceptDispute for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::SubmitEvidenceV2 for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::DisputeDefend for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::PaymentOrderCreate for Volt<T>
{
}

// Empty implementations for unsupported flows
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    ConnectorIntegrationV2<
        domain_types::connector_flow::CreateSessionToken,
        PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    > for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Volt<T>
{
}
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Volt<T>
{
}

macros::create_all_prerequisites!(
    connector_name: Volt,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: VoltPaymentRequest,
            response_body: VoltPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: VoltPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
        // (
        //     flow: Capture,
        //     request_body: VoltCaptureRequest,
        //     response_body: VoltCaptureResponse,
        //     router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
        // ),
        // (
        //     flow: Refund,
        //     request_body: VoltRefundRequest,
        //     response_body: VoltRefundResponse,
        //     router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
        // )
    ],
    amount_converters: [],
    member_functions: {
        /// Handle access token refresh if needed
        pub async fn ensure_access_token<F, Req, Res>(
            &self,
            router_data: &mut RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<(), errors::ConnectorError> {
            // Check if we need to refresh the access token
            if router_data.resource_common_data.access_token.is_none() {
                tracing::info!("Access token not available, requesting new token from Volt");

                // Get new access token from Volt's OAuth endpoint
                let auth = volt::VoltAuthType::try_from(&router_data.connector_auth_type)?;
                let request = VoltAccessTokenRequest {
                    grant_type: "password".to_string(),
                    username: auth.username,
                    password: auth.password,
                    client_id: auth.client_id,
                    client_secret: auth.client_secret,
                };

                let body = serde_urlencoded::to_string(&[
                    ("grant_type", request.grant_type.as_str()),
                    ("username", &request.username.expose()),
                    ("password", &request.password.expose()),
                    ("client_id", &request.client_id.expose()),
                    ("client_secret", &request.client_secret.expose()),
                ])
                .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

                let url = format!("{}oauth", router_data.resource_common_data.connectors.volt.base_url);

                // Make HTTP request to OAuth endpoint
                let client = reqwest::Client::new();
                let response = client
                    .post(&url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to send OAuth request to Volt: {}", e);
                        errors::ConnectorError::RequestEncodingFailed
                    })?;

                if !response.status().is_success() {
                    let status = response.status();
                    let error_text = response.text().await.unwrap_or_default();
                    tracing::error!("OAuth request failed with status {}: {}", status, error_text);
                    return Err(errors::ConnectorError::RequestEncodingFailed.into());
                }

                let token_response: VoltAccessTokenResponse = response
                    .json()
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to parse OAuth response from Volt: {}", e);
                        errors::ConnectorError::ResponseDeserializationFailed
                    })?;

                // Convert to access token string and store in router_data
                router_data.resource_common_data.access_token = Some(token_response.access_token.clone());

                tracing::info!("Successfully obtained access token from Volt");
            }
            Ok(())
        }

        pub fn build_headers<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut headers = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];

            // Use access token if available, otherwise fallback to basic auth
            if let Some(access_token) = &req.resource_common_data.access_token {
                let auth_header = (
                    headers::AUTHORIZATION.to_string(),
                    format!("Bearer {}", access_token).into_masked(),
                );
                headers.push(auth_header);
            } else {
                let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
                headers.append(&mut api_key);
            }

            Ok(headers)
        }

        pub fn build_headers_refund<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let mut headers = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];

            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            headers.append(&mut api_key);

            Ok(headers)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.volt.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.volt.base_url
        }

    }
);

// Implement access token support for Volt
impl<T, F: Sync, Req: Sync, Res: Sync> AccessTokenAuth<F, Req, Res> for Volt<T>
where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    async fn get_access_token(
        &self,
        router_data: &RouterDataV2<F, domain_types::connector_types::PaymentFlowData, Req, Res>,
    ) -> CustomResult<grpc_api_types::payments::AccessToken, errors::ConnectorError> {
        let auth = volt::VoltAuthType::try_from(&router_data.connector_auth_type)?;

        // Debug log credential mapping (without exposing secrets)
        tracing::debug!(
            "OAuth credential mapping - username_len: {}, password_len: {}, client_id_len: {}, client_secret_len: {}",
            auth.username.clone().expose().len(),
            auth.password.clone().expose().len(),
            auth.client_id.clone().expose().len(),
            auth.client_secret.clone().expose().len()
        );

        let request = VoltAccessTokenRequest {
            grant_type: "password".to_string(),
            username: auth.username,
            password: auth.password,
            client_id: auth.client_id,
            client_secret: auth.client_secret,
        };

        let _headers: Vec<(String, hyperswitch_masking::Maskable<String>)> = vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string().into(),
        )];

        let body = serde_urlencoded::to_string(&[
            ("grant_type", request.grant_type.as_str()),
            ("username", &request.username.expose()),
            ("password", &request.password.expose()),
            ("client_id", &request.client_id.expose()),
            ("client_secret", &request.client_secret.expose()),
        ])
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let url = format!(
            "{}oauth",
            router_data.resource_common_data.connectors.volt.base_url
        );

        // Make HTTP request to OAuth endpoint
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to send OAuth request to Volt: {}", e);
                errors::ConnectorError::RequestEncodingFailed
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!(
                "OAuth request failed with status {}: {}",
                status,
                error_text
            );
            return Err(errors::ConnectorError::RequestEncodingFailed.into());
        }

        let token_response: VoltAccessTokenResponse = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse OAuth response from Volt: {}", e);
            errors::ConnectorError::ResponseDeserializationFailed
        })?;

        // Convert to domain AccessToken
        let access_token = grpc_api_types::payments::AccessToken::from(token_response);

        tracing::info!("Successfully obtained access token from Volt");
        Ok(access_token)
    }
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorCommon for Volt<T>
{
    fn id(&self) -> &'static str {
        "volt"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // For Volt, use basic auth with client credentials for simplicity
        // In production, OAuth token management should be handled at infrastructure level
        let auth = volt::VoltAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;

        let basic_auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                auth.client_id.expose(),
                auth.client_secret.expose()
            ))
        );

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            basic_auth.into_masked(),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.volt.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: volt::VoltErrorResponse = res
            .response
            .parse_struct("VoltErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let reason = match &response.exception.error_list {
            Some(error_list) => error_list
                .iter()
                .map(|error| error.message.clone())
                .collect::<Vec<String>>()
                .join(" & "),
            None => response.exception.message.clone(),
        };

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.exception.message.clone(),
            message: response.exception.message.clone(),
            reason: Some(reason),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: Some(String::from_utf8_lossy(&res.response).to_string()),
        })
    }
}

const VOLT_API_VERSION: &str = "v2";

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Volt,
    curl_request: Json(VoltPaymentRequest),
    curl_response: VoltPaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {

        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}{}/payments", self.connector_base_url_payments(req), VOLT_API_VERSION))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Volt,
    curl_response: VoltPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [domain_types::payment_method_data::PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {


        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let payment_id = match req.request.connector_transaction_id {
                ResponseId::ConnectorTransactionId(ref id) => id,
                _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
            };
            Ok(format!("{}payments/{}", self.connector_base_url_payments(req), payment_id))
        }
    }
);

// Capture flow commented out for now
// macros::macro_connector_implementation!(
//     connector_default_implementations: [get_content_type, get_error_response_v2],
//     connector: Volt,
//     curl_request: Json(VoltCaptureRequest),
//     curl_response: VoltCaptureResponse,
//     flow_name: Capture,
//     resource_common_data: PaymentFlowData,
//     flow_request: PaymentsCaptureData,
//     flow_response: PaymentsResponseData,
//     http_method: Post,
//     other_functions: {
//         fn get_headers(
//             &self,
//             req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
//         ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
//             self.build_headers(req)
//         }
//         fn get_url(
//             &self,
//             req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
//         ) -> CustomResult<String, errors::ConnectorError> {
//             let payment_id = match &req.request.connector_transaction_id {
//                 ResponseId::ConnectorTransactionId(id) => id,
//                 _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into())
//             };
//             Ok(format!("{}/payments/{}/capture", self.connector_base_url_payments(req), payment_id))
//         }
//     }
// );

// Refund flow commented out for now
// macros::macro_connector_implementation!(
//     connector_default_implementations: [get_content_type, get_error_response_v2],
//     connector: Volt,
//     curl_request: Json(VoltRefundRequest),
//     curl_response: VoltRefundResponse,
//     flow_name: Refund,
//     resource_common_data: RefundFlowData,
//     flow_request: RefundsData,
//     flow_response: RefundsResponseData,
//     http_method: Post,
//     other_functions: {
//         fn get_headers(
//             &self,
//             req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
//         ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
//             self.build_headers_refund(req)
//         }
//         fn get_url(
//             &self,
//             req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
//         ) -> CustomResult<String, errors::ConnectorError> {
//             let payment_id = req.request.connector_transaction_id.clone();
//             Ok(format!("{}/payments/{}/request-refund", self.connector_base_url_refunds(req), payment_id))
//         }
//     }
// );

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > connector_types::ValidationTrait for Volt<T>
{
}

// impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Volt {}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateSessionToken,
        PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    > for Volt<T>
{
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Volt<T>
{
}

static VOLT_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let _volt_supported_capture_methods = vec![CaptureMethod::Automatic, CaptureMethod::Manual];

    let mut volt_supported_payment_methods = SupportedPaymentMethods::new();

    volt_supported_payment_methods.add(
        PaymentMethod::BankRedirect,
        PaymentMethodType::OpenBankingUk,
        PaymentMethodDetails {
            mandates: FeatureStatus::NotSupported,
            refunds: FeatureStatus::NotSupported,
            supported_capture_methods: vec![CaptureMethod::Automatic],
            specific_features: None,
        },
    );

    volt_supported_payment_methods
});

static VOLT_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Volt",
    description: "Volt is an Open Banking payment infrastructure provider that enables instant bank payments across multiple markets.",
    connector_type: types::PaymentConnectorCategory::PaymentGateway,
};

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > ConnectorSpecifications for Volt<T>
{
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&VOLT_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&VOLT_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        None
    }
}

impl ConnectorValidation for Volt<domain_types::payment_method_data::DefaultPCIHolder> {
    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>,
    ) -> CustomResult<(), errors::ConnectorError> {
        let mandate_supported_pmd = std::collections::HashSet::from([]);
        is_mandate_supported(pm_data, pm_type, mandate_supported_pmd, self.id())
    }

    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false
    }
}

// Empty webhook implementation - uses default "not supported" behavior from trait
impl<T> connector_types::IncomingWebhook for Volt<T> where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize
{
}
