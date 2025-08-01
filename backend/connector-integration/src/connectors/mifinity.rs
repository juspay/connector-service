pub mod transformers;

use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent, StringMajorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund,
        RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
    errors::{self, ConnectorError},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::{ExposeInterface, Mask, Maskable};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};

use super::macros;
use crate::{
    connectors::mifinity::transformers::{
        MifinityAuthType, MifinityErrorResponse, MifinityPaymentsRequest, MifinityPaymentsResponse,
        MifinityPsyncResponse,
    },
    types::ResponseRouterData,
};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
}

impl connector_types::ConnectorServiceTrait for Mifinity {}
impl connector_types::PaymentAuthorizeV2 for Mifinity {}
impl connector_types::PaymentSyncV2 for Mifinity {}
impl connector_types::PaymentVoidV2 for Mifinity {}
impl connector_types::RefundSyncV2 for Mifinity {}
impl connector_types::RefundV2 for Mifinity {}
impl connector_types::PaymentCapture for Mifinity {}
impl connector_types::ValidationTrait for Mifinity {}
impl connector_types::SetupMandateV2 for Mifinity {}
impl connector_types::RepeatPaymentV2 for Mifinity {}
impl connector_types::AcceptDispute for Mifinity {}
impl connector_types::SubmitEvidenceV2 for Mifinity {}
impl connector_types::DisputeDefend for Mifinity {}
impl connector_types::IncomingWebhook for Mifinity {}
impl connector_types::PaymentOrderCreate for Mifinity {}

const API_VERSION: &str = "1";

macros::create_all_prerequisites!(
    connector_name: Mifinity,
    api: [
        (
            flow: Authorize,
            request_body: MifinityPaymentsRequest,
            response_body: MifinityPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        (
            flow: PSync,
            response_body: MifinityPsyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                "api-version".to_string(),
                API_VERSION.to_string().into(),
            ),
            ];
            let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut auth_header);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.mifinity.base_url
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Mifinity,
    curl_request: Json(MifinityPaymentsRequest),
    curl_response: MifinityPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}pegasus-ci/api/gateway/init-iframe", self.connector_base_url_payments(req)))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Mifinity,
    curl_response: MifinityPsyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
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
            let merchant_id = &req.resource_common_data.merchant_id;
            let payment_id = &req.resource_common_data.connector_request_reference_id;
            Ok(format!(
                "{}api/gateway/payment-status/payment_validation_key_{}_{}",
                self.connector_base_url_payments(req),
                merchant_id.get_string_repr(),
                payment_id
            ))
        }
    }
);

impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for Mifinity
{
}

impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for Mifinity
{
}

impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Mifinity {}

impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Mifinity
{
}

impl
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Mifinity
{
}
impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Mifinity
{
}
impl
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Mifinity
{
}
impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Mifinity
{
}
impl
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Mifinity
{
}

// SourceVerification implementations for all flows
impl
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Mifinity
{
}

impl
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for Mifinity
{
}

impl ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for Mifinity
{
}

impl ConnectorCommon for Mifinity {
    fn id(&self) -> &'static str {
        "mifinity"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.mifinity.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = MifinityAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![("key".to_string(), auth.key.expose().into_masked())])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        if res.response.is_empty() {
            Ok(ErrorResponse {
                status_code: res.status_code,
                code: "No error code".to_string(),
                message: "No error message".to_string(),
                reason: Some("Authentication Error from the connector".to_string()),
                attempt_status: None,
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                raw_connector_response: None,
            })
        } else {
            let response: Result<
                MifinityErrorResponse,
                Report<common_utils::errors::ParsingError>,
            > = res.response.parse_struct("MifinityErrorResponse");

            match response {
                Ok(response) => {
                    if let Some(i) = event_builder {
                        i.set_response_body(&response);
                    }
                    Ok(ErrorResponse {
                        status_code: res.status_code,
                        code: response
                            .errors
                            .iter()
                            .map(|error| error.error_code.clone())
                            .collect::<Vec<String>>()
                            .join(" & "),
                        message: response
                            .errors
                            .iter()
                            .map(|error| error.message.clone())
                            .collect::<Vec<String>>()
                            .join(" & "),
                        reason: Some(
                            response
                                .errors
                                .iter()
                                .map(|error| error.message.clone())
                                .collect::<Vec<String>>()
                                .join(" & "),
                        ),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                        raw_connector_response: None,
                    })
                }

                Err(_error_msg) => {
                    if let Some(event) = event_builder {
                        event.set_error(serde_json::json!({"error": res.response.escape_ascii().to_string(), "status_code": res.status_code}));
                    }
                    crate::utils::handle_json_response_deserialization_failure(res, "mifinity")
                }
            }
        }
    }
}
