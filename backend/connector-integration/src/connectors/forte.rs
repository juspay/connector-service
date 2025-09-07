use std::fmt::Debug;

use common_enums::enums;
use common_utils::{errors::CustomResult, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::*,
    errors::ConnectorError,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    types::{PaymentFlowData, RefundFlowData},
};
use error_stack::ResultExt;
use hyperswitch_interfaces::{
    api::{ConnectorCommon, ConnectorSpecifications},
    configs::Connectors,
    consts::NO_ERROR_CODE,
    events::connector_api_logs::ConnectorEvent,
    types::{ErrorResponse, Response},
};
use hyperswitch_masking::{Maskable, Secret};
use serde::Serialize;

use crate::connectors::forte::transformers;

#[derive(Clone)]
pub struct Forte<T: PaymentMethodDataTypes> {
    #[allow(dead_code)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Forte<T> {
    pub const fn new() -> &'static Self {
        &Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

// Service trait implementation
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorServiceTrait<T> for Forte<T>
{
}

// Flow-specific trait implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    PaymentAuthorizeV2<T> for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    PaymentSyncV2 for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    PaymentCapture for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    PaymentVoidV2 for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    RefundV2 for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    RefundSyncV2 for Forte<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ValidationTrait for Forte<T>
{
}

// ConnectorCommon implementation
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorCommon for Forte<T>
{
    fn id(&self) -> &'static str {
        "forte"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = transformers::ForteAuthType::try_from(auth_type)
            .change_context(ConnectorError::FailedToObtainAuthType)?;

        let raw_basic_token = format!(
            "{}:{}",
            auth.api_access_id.peek(),
            auth.api_secret_key.peek()
        );
        let basic_token = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw_basic_token));

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
        let response: transformers::ForteErrorResponse = res
            .response
            .parse_struct("Forte ErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));

        let message = response.response.response_desc.clone();
        let code = response
            .response
            .response_code
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        Ok(ErrorResponse {
            status_code: res.status_code,
            code,
            message,
            reason: Some(response.response.response_desc),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// Macro implementations for all flows
macros::create_all_prerequisites!(
    connector_name: Forte,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: transformers::FortePaymentsRequest<T>,
            response_body: transformers::FortePaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: transformers::ForteCaptureRequest,
            response_body: transformers::ForteCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: (),
            response_body: transformers::FortePaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: transformers::ForteCancelRequest,
            response_body: transformers::ForteCancelResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: transformers::ForteRefundRequest,
            response_body: transformers::RefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: (),
            response_body: transformers::RefundSyncResponse,
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
    curl_request: Json(transformers::FortePaymentsRequest),
    curl_response: transformers::FortePaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = transformers::ForteAuthType::try_from(&req.connector_auth_type)?;
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
    curl_request: Json(transformers::ForteCaptureRequest),
    curl_response: transformers::ForteCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Put,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = transformers::ForteAuthType::try_from(&req.connector_auth_type)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek()
            ))
        }
    }
);

// Payment Sync flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: (),
    curl_response: transformers::FortePaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = transformers::ForteAuthType::try_from(&req.connector_auth_type)?;
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

// Void flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: Json(transformers::ForteCancelRequest),
    curl_response: transformers::ForteCancelResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCancelData,
    flow_response: PaymentsResponseData,
    http_method: Put,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Void, PaymentFlowData, PaymentsCancelData, PaymentsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = transformers::ForteAuthType::try_from(&req.connector_auth_type)?;
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

// Refund flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: Json(transformers::ForteRefundRequest),
    curl_response: transformers::RefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = transformers::ForteAuthType::try_from(&req.connector_auth_type)?;
            Ok(format!(
                "{}/organizations/{}/locations/{}/transactions",
                self.base_url(&req.resource_common_data.connectors),
                auth.organization_id.peek(),
                auth.location_id.peek()
            ))
        }
    }
);

// Refund Sync flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Forte,
    curl_request: (),
    curl_response: transformers::RefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<RSync, RefundFlowData, RefundsData, RefundsResponseData>) -> CustomResult<String, ConnectorError> {
            let auth = transformers::ForteAuthType::try_from(&req.connector_auth_type)?;
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
use api_models::feature_matrix::{CardSpecificFeatures, PaymentMethodSpecificFeatures};
use common_enums::FeatureStatus;
use domain_types::router_response_types::{ConnectorInfo, PaymentMethodDetails, SupportedPaymentMethods};

static FORTE_SUPPORTED_PAYMENT_METHODS: std::sync::LazyLock<SupportedPaymentMethods> = 
    std::sync::LazyLock::new(|| {
        let supported_capture_methods = vec![
            enums::CaptureMethod::Automatic,
            enums::CaptureMethod::Manual,
            enums::CaptureMethod::SequentialAutomatic,
        ];

        let supported_card_network = vec![
            common_enums::CardNetwork::AmericanExpress,
            common_enums::CardNetwork::Discover,
            common_enums::CardNetwork::DinersClub,
            common_enums::CardNetwork::JCB,
            common_enums::CardNetwork::Mastercard,
            common_enums::CardNetwork::Visa,
        ];

        let mut forte_supported_payment_methods = SupportedPaymentMethods::new();

        forte_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Credit,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: Some(
                    PaymentMethodSpecificFeatures::Card(CardSpecificFeatures {
                        three_ds: FeatureStatus::NotSupported,
                        no_three_ds: FeatureStatus::Supported,
                        supported_card_networks: supported_card_network.clone(),
                    }),
                ),
            },
        );

        forte_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Debit,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: Some(
                    PaymentMethodSpecificFeatures::Card(CardSpecificFeatures {
                        three_ds: FeatureStatus::NotSupported,
                        no_three_ds: FeatureStatus::Supported,
                        supported_card_networks: supported_card_network.clone(),
                    }),
                ),
            },
        );

        forte_supported_payment_methods
    });

static FORTE_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Forte",
    description: "CSG Forte offers a unified payments platform, enabling businesses to securely process credit cards, debit cards, ACH/eCheck transactions, and more, with advanced fraud prevention and seamless integration.",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Sandbox,
};

static FORTE_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 0] = [];

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorSpecifications for Forte<T>
{
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&FORTE_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*FORTE_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&FORTE_SUPPORTED_WEBHOOK_FLOWS)
    }
}