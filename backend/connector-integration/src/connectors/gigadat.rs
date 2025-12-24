pub mod transformers;

use std::fmt::Debug;

use common_enums::{self, AttemptStatus};

use common_utils::{errors::CustomResult, events, ext_traits::XmlExt};
use domain_types::{
    connector_flow::{
        Authorize, PSync, Refund, RSync, Void,
    },
    connector_types::{
        ConnectorCustomerData, ConnectorCustomerResponse, DisputeFlowData, DisputeResponseData,
        PaymentFlowData, PaymentMethodTokenizationData, PaymentMethodTokenResponse, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SetupMandateRequestData, SessionTokenRequestData, SessionTokenResponseData,
        SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use hyperswitch_masking::Maskable;
use interfaces::{api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2};
use serde::Serialize;
use serde_json::Value;
use transformers::{
    GigadatAuthorizeRequest, GigadatAuthorizeResponse, GigadatPSyncRequest, GigadatPSyncResponse,
    GigadatRSyncRequest, GigadatRSyncResponse,
    GigadatRefundRequest, GigadatRefundResponse, GigadatErrorResponse,
};

use super::macros;
use crate::types::ResponseRouterData;
use interfaces::verification::SourceVerification;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}



// Create all prerequisites for the connector using macros
macros::create_all_prerequisites!(
    connector_name: Gigadat,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: GigadatAuthorizeRequest<T>,
            response_body: GigadatAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: GigadatPSyncRequest,
            response_body: GigadatPSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: GigadatRefundRequest,
            response_body: GigadatRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: GigadatRSyncRequest,
            response_body: GigadatRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let header = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
            ];
            Ok(header)
        }

        pub fn connector_base_url<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.gigadat.base_url
        }
    }
);

// Implement ConnectorCommon trait
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Gigadat<T>
{
    fn id(&self) -> &'static str {
        "gigadat"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Base
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.gigadat.base_url
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1: campaign_id,
                api_secret,
            } => {
                let auth = format!("{}:{}", api_key, api_secret);
                let encoded = base64::encode(auth);
                Ok(vec![(
                    "Authorization".to_string(),
                    format!("Basic {}", encoded).into(),
                )])
            }
            _ => Err(errors::ConnectorError::InvalidConnectorConfig {
                config: "Invalid auth configuration".to_string(),
            })?,
        }
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: GigadatErrorResponse = if res.response.is_empty() {
            GigadatErrorResponse::default()
        } else {
            String::from_utf8(res.response.to_vec())
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        };

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response
                .err
                .clone()
                .unwrap_or_else(|| "UNKNOWN".to_string()),
            message: response
                .err
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string()),
            reason: response.err,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Implement Authorize flow using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_headers, get_error_response_v2],
    connector: Gigadat,
    curl_request: Json(GigadatAuthorizeRequest<T>),
    curl_response: GigadatAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let campaign_id = req
                .router_data
                .metadata
                .clone()
                .and_then(|m| m.get("site"))
                .and_then(|v| Value::as_str(v))
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "metadata.site",
                })?
                .to_string();
            Ok(format!(
                "{}/api/payment-token/{}",
                self.connector_base_url(req),
                campaign_id
            ))
        }
    }
);

// Implement PSync flow using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_headers, get_error_response_v2],
    connector: Gigadat,
    curl_request: Json(GigadatPSyncRequest),
    curl_response: GigadatPSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let transaction_id = req.router_data.connector_transaction_id.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                },
            )?;
            Ok(format!(
                "{}/api/transactions/{}",
                self.connector_base_url(req),
                transaction_id
            ))
        }
    }
);

// Implement Refund flow using macros
macros::macro_connector_implementation!(
    connector_default_implementations: [get_headers, get_error_response_v2],
    connector: Gigadat,
    curl_request: Json(GigadatRefundRequest),
    curl_response: GigadatRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}/refunds", self.connector_base_url(req)))
        }
    }
);

// Implement the required traits for Gigadat
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentAuthorizeV2<T> for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentSyncV2 for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::RefundV2 for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::RefundSyncV2 for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentVoidV2 for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::ValidationTrait for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentOrderCreate for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentSessionToken for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentAccessToken for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::CreateConnectorCustomer for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentTokenV2<T> for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentVoidPostCaptureV2 for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::IncomingWebhook for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentCapture for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::SetupMandateV2<T> for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::RepeatPaymentV2 for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::AcceptDispute for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::DisputeDefend for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::SubmitEvidenceV2 for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentPreAuthenticateV2<T> for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentAuthenticateV2<T> for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::PaymentPostAuthenticateV2<T> for Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::SdkSessionTokenV2 for Gigadat<T>
{
}

// Implement ConnectorServiceTrait which combines all the required traits
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::connector_types::ConnectorServiceTrait<T> for Gigadat<T>
{
}

