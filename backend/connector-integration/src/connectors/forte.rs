pub mod transformers;

use std::fmt::Debug;

use common_enums::enums;
use common_utils::{errors::CustomResult, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, RSync, Void},
    connector_types::*,
    errors::ConnectorError,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::*,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, Secret};
use serde::Serialize;

use crate::connectors::forte::transformers as forte;

#[derive(Clone)]
pub struct Forte<T: PaymentMethodDataTypes> {
    #[allow(dead_code)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes> Forte<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

// Service trait
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorServiceTrait<T> for Forte<T>
{
}

// Flow-specific traits (implement only what's actually supported)
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    PaymentAuthorizeV2<T> for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentSyncV2
    for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentCapture
    for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentVoidV2
    for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> RefundV2
    for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> RefundSyncV2
    for Forte<T>
{
}

// Validation trait
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ValidationTrait
    for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Forte<T>
{
    fn id(&self) -> &'static str {
        "forte"
    }

    fn get_currency_unit(&self) -> enums::CurrencyUnit {
        enums::CurrencyUnit::Major
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = forte::ForteAuthType::try_from(auth_type)
            .change_context(ConnectorError::FailedToObtainAuthType)?;
        
        let raw_basic_token = format!(
            "{}:{}",
            auth.api_access_id.peek(),
            auth.api_secret_key.peek()
        );
        let basic_token = format!("Basic {}", base64::encode(raw_basic_token));
        
        Ok(vec![
            (
                "Authorization".to_string(),
                basic_token.into_masked(),
            ),
            (
                "X-Forte-Auth-Organization-Id".to_string(),
                auth.organization_id.into_masked(),
            ),
        ])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.forte.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: forte::ForteErrorResponse = res
            .response
            .parse_struct("Forte ErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));

        let message = response.response.response_desc;
        let code = response
            .response
            .response_code
            .unwrap_or_else(|| "UNKNOWN_ERROR".to_string());

        Ok(ErrorResponse {
            status_code: res.status_code,
            code,
            message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// Macro implementations for each flow
macros::create_all_prerequisites!(
    connector_name: Forte,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: forte::FortePaymentRequest<T>,
            response_body: forte::FortePaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: forte::ForteCaptureRequest,
            response_body: forte::ForteCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: forte::ForteVoidRequest,
            response_body: forte::ForteVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: (),
            response_body: forte::FortePaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: forte::ForteRefundRequest,
            response_body: forte::ForteRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: (),
            response_body: forte::ForteRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
    ],
    amount_converters: [],
    member_functions: {}
);

// Authorize flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: Json(forte::FortePaymentRequest),
    curl_response: forte::FortePaymentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = forte::ForteAuthType::try_from(&req.resource_common_data.connector_auth_type)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek()
            ))
        }
    }
);

// Capture flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: Json(forte::ForteCaptureRequest),
    curl_response: forte::ForteCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Put,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = forte::ForteAuthType::try_from(&req.resource_common_data.connector_auth_type)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek()
            ))
        }
    }
);

// Void flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: Json(forte::ForteVoidRequest),
    curl_response: forte::ForteVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCancelData,
    flow_response: PaymentsResponseData,
    http_method: Put,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = forte::ForteAuthType::try_from(&req.resource_common_data.connector_auth_type)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions/{}",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek(),
                req.request.connector_transaction_id
            ))
        }
    }
);

// PSync flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: (),
    curl_response: forte::FortePaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = forte::ForteAuthType::try_from(&req.resource_common_data.connector_auth_type)?;
            let txn_id = req.request.connector_transaction_id
                .as_ref()
                .ok_or(ConnectorError::MissingConnectorTransactionID)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions/{}",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek(),
                txn_id
            ))
        }
    }
);

// Refund flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: Json(forte::ForteRefundRequest),
    curl_response: forte::ForteRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = forte::ForteAuthType::try_from(&req.resource_common_data.connector_auth_type)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek()
            ))
        }
    }
);

// RSync flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: (),
    curl_response: forte::ForteRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = forte::ForteAuthType::try_from(&req.resource_common_data.connector_auth_type)?;
            let refund_id = req.request.connector_refund_id
                .as_ref()
                .ok_or(ConnectorError::MissingConnectorRefundID)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions/{}",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek(),
                refund_id
            ))
        }
    }
);

// Connector specifications
impl ConnectorSpecifications for Forte<DefaultPCIHolder> {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&FORTE_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&FORTE_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        Some(&FORTE_SUPPORTED_WEBHOOK_FLOWS)
    }
}

// Connector info and supported methods
static FORTE_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Forte",
    description: "CSG Forte offers a unified payments platform, enabling businesses to securely process credit cards, debit cards, ACH/eCheck transactions, and more, with advanced fraud prevention and seamless integration.",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Sandbox,
};

static FORTE_SUPPORTED_PAYMENT_METHODS: SupportedPaymentMethods = SupportedPaymentMethods {
    payment_methods: &[
        (
            enums::PaymentMethod::Card,
            &[
                enums::PaymentMethodType::Credit,
                enums::PaymentMethodType::Debit,
            ],
        ),
    ],
};

static FORTE_SUPPORTED_WEBHOOK_FLOWS: [EventClass; 0] = [];