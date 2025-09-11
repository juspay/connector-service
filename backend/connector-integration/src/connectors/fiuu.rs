pub mod transformers;

use std::collections::HashMap;

use bytes::Bytes;
use common_enums::CurrencyUnit;
use common_utils::{errors::CustomResult, ext_traits::BytesExt, types::StringMajorUnit};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync,
        PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SessionTokenRequestData, SessionTokenResponseData, SetupMandateRequestData,
        SubmitEvidenceData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, Secret};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, warn};
use transformers::{
    self as fiuu, FiuuPaymentCancelRequest, FiuuPaymentCancelResponse, FiuuPaymentResponse,
    FiuuPaymentSyncRequest, FiuuPaymentsRequest, FiuuPaymentsResponse, FiuuRefundRequest,
    FiuuRefundResponse, FiuuRefundSyncRequest, FiuuRefundSyncResponse, PaymentCaptureRequest,
    PaymentCaptureResponse,
};

use super::macros;
use crate::{
    types::ResponseRouterData, utils::xml_utils::flatten_json_structure, with_error_response_body,
    with_response_body,
};

// Trait implementations with generic type parameters
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ConnectorServiceTrait<T> for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthorizeV2<T> for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSessionToken for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentSyncV2 for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentVoidV2 for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundSyncV2 for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RefundV2 for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentCapture for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::ValidationTrait for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentOrderCreate for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SetupMandateV2<T> for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::AcceptDispute for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::SubmitEvidenceV2 for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::DisputeDefend for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::IncomingWebhook for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::RepeatPaymentV2 for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentTokenV2<T> for Fiuu<T>
{
}

// Authentication trait implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPreAuthenticateV2<T> for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentAuthenticateV2<T> for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::PaymentPostAuthenticateV2<T> for Fiuu<T>
{
}

macros::create_all_prerequisites!(
    connector_name: Fiuu,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: FiuuPaymentsRequest<T>,
            response_body: FiuuPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: FiuuPaymentSyncRequest,
            response_body: FiuuPaymentResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: PaymentCaptureRequest,
            response_body: PaymentCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: FiuuPaymentCancelRequest,
            response_body: FiuuPaymentCancelResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: FiuuRefundRequest,
            response_body: FiuuRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: FiuuRefundSyncRequest,
            response_body: FiuuRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn preprocess_response_bytes<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
            response_bytes: Bytes,
        ) -> Result<Bytes, errors::ConnectorError> {
                let response_str = String::from_utf8(response_bytes.to_vec()).map_err(|e| {
                error!("Error in Deserializing Response Data: {:?}", e);
                errors::ConnectorError::ResponseDeserializationFailed
            })?;

            let mut json = serde_json::Map::new();
            let mut miscellaneous: HashMap<String, Secret<String>> = HashMap::new();

            for line in response_str.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    if key.trim().is_empty() {
                        error!("Null or empty key encountered in response.");
                        continue;
                    }

                    if let Some(old_value) = json.insert(key.to_string(), Value::String(value.to_string()))
                    {
                        warn!("Repeated key encountered: {}", key);
                        miscellaneous.insert(key.to_string(), Secret::new(old_value.to_string()));
                    }
                }
            }
            if !miscellaneous.is_empty() {
                let misc_value = serde_json::to_value(miscellaneous).map_err(|e| {
                    error!("Error serializing miscellaneous data: {:?}", e);
                    errors::ConnectorError::ResponseDeserializationFailed
                })?;
                json.insert("miscellaneous".to_string(), misc_value);
            }
                // Extract and flatten the JSON structure
            let flattened_json = flatten_json_structure(Value::Object(json));

            // Convert JSON Value to string and then to bytes
            let json_string = serde_json::to_string(&flattened_json).map_err(|e| {
                tracing::error!(error=?e, "Failed to convert to JSON string");
                errors::ConnectorError::ResponseDeserializationFailed
            })?;

            tracing::info!(json=?json_string, "Flattened JSON structure");

            // Return JSON as bytes
            Ok(Bytes::from(json_string.into_bytes()))
        }

        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![])
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiuu.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.fiuu.base_url
        }
    }
);

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorCommon for Fiuu<T>
{
    fn id(&self) -> &'static str {
        "fiuu"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "multipart/form-data"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.fiuu.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: fiuu::FiuuErrorResponse = res
            .response
            .parse_struct("FiuuErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.clone(),
            message: response.error_desc.clone(),
            reason: Some(response.error_desc.clone()),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiuu,
    curl_request: FormData(FiuuPaymentsRequest<T>),
    curl_response: FiuuPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
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
            let optional_is_mit_flow = req.request.off_session;
            let optional_is_nti_flow = req
                .request
                .mandate_id
                .as_ref()
                .map(|mandate_id| mandate_id.is_network_transaction_id_flow());
            let url = match (optional_is_mit_flow, optional_is_nti_flow) {
                (Some(true), Some(false)) => format!(
                    "{}/RMS/API/Recurring/input_v7.php",
                    self.connector_base_url_payments(req)
                ),
                _ => {
                    format!(
                        "{}RMS/API/Direct/1.4.0/index.php",
                        self.connector_base_url_payments(req)
                    )
                }
            };
            Ok(url)
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiuu,
    curl_request: FormData(PaymentCaptureRequest),
    curl_response: PaymentCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}RMS/API/capstxn/index.php",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

// Add implementation for Void
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiuu,
    curl_request: FormData(FiuuPaymentCancelRequest),
    curl_response: FiuuPaymentCancelResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    preprocess_response: true,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}RMS/API/refundAPI/refund.php",
                self.connector_base_url_payments(req)
            ))
        }
    }
);

// Add implementation for Refund
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiuu,
    curl_request: FormData(FiuuRefundRequest),
    curl_response: FiuuRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}RMS/API/refundAPI/index.php",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Fiuu,
    curl_request: FormData(FiuuRefundSyncRequest),
    curl_response: FiuuRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!(
                "{}RMS/API/refundAPI/q_by_txn.php",
                self.connector_base_url_refunds(req)
            ))
        }
    }
);

// PSync is not implemented using the macro structure because the response is parsed differently according to the header
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for Fiuu<T>
{
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
        Ok(format!(
            "{}RMS/API/gate-query/index.php",
            self.connector_base_url_payments(req)
        ))
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<macro_types::RequestContent>, macro_types::ConnectorError> {
        let bridge = self.p_sync;
        let input_data = FiuuRouterData {
            connector: self.to_owned(),
            router_data: req.clone(),
        };
        let request = bridge.request_body(input_data)?;
        let form_data = <FiuuPaymentSyncRequest as GetFormData>::get_form_data(&request);
        Ok(Some(macro_types::RequestContent::FormData(form_data)))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        macro_types::ConnectorError,
    > {
        match res.headers {
            Some(headers) => {
                let content_header = utils::get_http_header("Content-type", &headers)
                    .attach_printable("Missing content type in headers")
                    .change_context(errors::ConnectorError::ResponseHandlingFailed)?;
                let response: fiuu::FiuuPaymentResponse = if content_header
                    == "text/plain;charset=UTF-8"
                {
                    parse_response(&res.response)
                } else {
                    Err(errors::ConnectorError::ResponseDeserializationFailed)
                        .attach_printable(format!("Expected content type to be text/plain;charset=UTF-8 , but received different content type as {content_header} in response"))?
                }?;
                with_response_body!(event_builder, response);

                RouterDataV2::try_from(ResponseRouterData {
                    response,
                    router_data: data.clone(),
                    http_code: res.status_code,
                })
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
            }
            None => {
                // We don't get headers for payment webhook response handling
                let response: fiuu::FiuuPaymentResponse = res
                    .response
                    .parse_struct("fiuu::FiuuPaymentResponse")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                with_response_body!(event_builder, response);

                RouterDataV2::try_from(ResponseRouterData {
                    response,
                    router_data: data.clone(),
                    http_code: res.status_code,
                })
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
            }
        }
    }
    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, macro_types::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// Implementation for empty stubs - these will need to be properly implemented later
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Fiuu<T>
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
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Fiuu<T>
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
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Fiuu<T>
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
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Fiuu<T>
{
}
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Fiuu<T>
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
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorSpecifications for Fiuu<T>
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
    > for Fiuu<T>
{
}

// SourceVerification implementations for all flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
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
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Fiuu<T>
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
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Fiuu<T>
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
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Fiuu<T>
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
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Fiuu<T>
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
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Fiuu<T>
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
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
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
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Fiuu<T>
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
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Fiuu<T>
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
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Fiuu<T>
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
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Fiuu<T>
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
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Fiuu<T>
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
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Fiuu<T>
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
    > for Fiuu<T>
{
}

// Authentication flow ConnectorIntegrationV2 implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
    for Fiuu<T>
{
}

// Authentication flow SourceVerification implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    interfaces::verification::SourceVerification<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
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
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
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
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Fiuu<T>
{
}

fn parse_response<T>(data: &[u8]) -> Result<T, errors::ConnectorError>
where
    T: for<'de> Deserialize<'de>,
{
    let response_str = String::from_utf8(data.to_vec()).map_err(|e| {
        error!("Error in Deserializing Response Data: {:?}", e);
        errors::ConnectorError::ResponseDeserializationFailed
    })?;

    let mut json = serde_json::Map::new();
    let mut miscellaneous: HashMap<String, Secret<String>> = HashMap::new();

    for line in response_str.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim().is_empty() {
                error!("Null or empty key encountered in response.");
                continue;
            }

            if let Some(old_value) = json.insert(key.to_string(), Value::String(value.to_string()))
            {
                warn!("Repeated key encountered: {}", key);
                miscellaneous.insert(key.to_string(), Secret::new(old_value.to_string()));
            }
        }
    }
    if !miscellaneous.is_empty() {
        let misc_value = serde_json::to_value(miscellaneous).map_err(|e| {
            error!("Error serializing miscellaneous data: {:?}", e);
            errors::ConnectorError::ResponseDeserializationFailed
        })?;
        json.insert("miscellaneous".to_string(), misc_value);
    }

    let response: T = serde_json::from_value(Value::Object(json)).map_err(|e| {
        error!("Error in Deserializing Response Data: {:?}", e);
        errors::ConnectorError::ResponseDeserializationFailed
    })?;

    Ok(response)
}
