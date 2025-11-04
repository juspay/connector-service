pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethod, PaymentMethodType};
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        ConnectorSpecifications, ConnectorWebhookSecrets, EventType, PaymentFlowData,
        PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundsData, RefundsResponseData, RefundSyncData, RequestDetails, ResponseId,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::{
        PaymentsAuthorizeRouterData, PaymentsSyncRouterData, RefundSyncRouterData,
        RefundsRouterData,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    constants::headers,
    macros,
    types::{self, ConnectorCommon},
    utils,
};

pub use transformers::{
    TPSLAuthType, TPSLPaymentsRequest, TPSLPaymentsResponse, TPSLPaymentsSyncRequest,
    TPSLRefundRequest, TPSLRefundResponse, TPSLRefundSyncRequest, TPSLRefundSyncResponse,
};

// CRITICAL: Use UCS v2 macro framework - NO manual implementations
macros::create_all_prerequisites!(
    connector_name: TPSL,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: TPSLPaymentsRequest,
            response_body: TPSLPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: TPSLPaymentsSyncRequest,
            response_body: TPSLPaymentsResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: TPSLRefundRequest,
            response_body: TPSLRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: TPSLRefundSyncRequest,
            response_body: TPSLRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self, flow: &str) -> String {
            match flow {
                "Authorize" => "upi_transaction".to_string(),
                "PSync" => "payment_sync".to_string(),
                "Refund" => "refund".to_string(),
                "RSync" => "refund_sync".to_string(),
                _ => flow.to_string(),
            }
        }
    }
);

// CRITICAL: Use macro_connector_implementation! for Authorize flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TPSLPaymentsRequest),
    curl_response: TPSLPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let auth: TPSLAuthType = TPSLAuthType::try_from(&req.connector_auth_type)?;
            let base_url = if req.resource_common_data.test_mode.unwrap_or(false) {
                "https://www.tekprocess.co.in/PaymentGateway"
            } else {
                "https://www.tpsl-india.in/PaymentGateway"
            };
            Ok(format!("{}/merchant2.pg/{}", base_url, auth.merchant_code.expose()))
        }

        fn get_request_body(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<RequestContent, errors::ConnectorError> {
            let connector_req = TPSLPaymentsRequest::try_from(req)?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        }
    }
);

// CRITICAL: Use macro_connector_implementation! for PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TPSLPaymentsSyncRequest),
    curl_response: TPSLPaymentsResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = if req.resource_common_data.test_mode.unwrap_or(false) {
                "https://www.tekprocess.co.in/PaymentGateway"
            } else {
                "https://www.tpsl-india.in/PaymentGateway"
            };
            Ok(format!("{}/services/TransactionDetailsNew", base_url))
        }

        fn get_request_body(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<RequestContent, errors::ConnectorError> {
            let connector_req = TPSLPaymentsSyncRequest::try_from(req)?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        }
    }
);

// CRITICAL: Use macro_connector_implementation! for Refund flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TPSLRefundRequest),
    curl_response: TPSLRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = if req.resource_common_data.test_mode.unwrap_or(false) {
                "https://www.tekprocess.co.in/PaymentGateway"
            } else {
                "https://www.tpsl-india.in/PaymentGateway"
            };
            Ok(format!("{}/services/RefundService", base_url))
        }

        fn get_request_body(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<RequestContent, errors::ConnectorError> {
            let connector_req = TPSLRefundRequest::try_from(req)?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        }
    }
);

// CRITICAL: Use macro_connector_implementation! for RSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: TPSL,
    curl_request: Json(TPSLRefundSyncRequest),
    curl_response: TPSLRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = if req.resource_common_data.test_mode.unwrap_or(false) {
                "https://www.tekprocess.co.in/PaymentGateway"
            } else {
                "https://www.tpsl-india.in/PaymentGateway"
            };
            Ok(format!("{}/services/RefundArnSync", base_url))
        }

        fn get_request_body(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<RequestContent, errors::ConnectorError> {
            let connector_req = TPSLRefundSyncRequest::try_from(req)?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        }
    }
);

// Implement ConnectorCommon for custom logic
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for TPSL<T>
{
    fn id(&self) -> &'static str {
        "tpsl"
    }

    fn get_auth_header(
        &self,
        _auth_type: &domain_types::ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        Ok(vec![])
    }

    fn base_url<'a>(&self, connectors: &'a domain_types::Connectors) -> &'a str {
        connectors.tpsl.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: common_utils::types::Response,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        let response: TPSLPaymentsResponse = res
            .response
            .parse_struct("TPSLPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(types::ErrorResponse {
            status_code: res.status_code,
            code: response.status_code.unwrap_or_default(),
            message: response.status_message.unwrap_or_default(),
            reason: response.error_message,
            attempt_status: None,
            connector_transaction_id: response.transaction_identifier,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::ConnectorValidation for TPSL<T>
{
    fn validate_capture_method(
        &self,
        capture_method: &Option<common_enums::CaptureMethod>,
    ) -> CustomResult<(), errors::ConnectorError> {
        let capture_method = capture_method.unwrap_or_default();
        match capture_method {
            common_enums::CaptureMethod::Automatic | common_enums::CaptureMethod::Manual => Ok(()),
            common_enums::CaptureMethod::Scheduled => Err(
                utils::construct_not_supported_error_report(capture_method, self.id()),
            ),
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    domain_types::ConnectorSpecifications for TPSL<T>
{
    fn get_connector_specifications(
        &self,
    ) -> CustomResult<ConnectorSpecifications, errors::ConnectorError> {
        Ok(ConnectorSpecifications {
            supported_payment_methods: vec![PaymentMethod::Upi],
            supported_payment_method_types: vec![PaymentMethodType::UpiIntent],
            supported_webhook_flows: vec![],
        })
    }
}
