pub mod transformers;

use std::fmt::Debug;

use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, SetupMandate, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::ConnectorInfo,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{
        ConnectorValidation, PaymentAuthorizeV2, PaymentCapture, PaymentSyncV2, PaymentTokenV2,
        PaymentVoidV2, RefundSyncV2, RefundV2,
    },
    events::connector_api_logs::ConnectorEvent,
};
use serde::Serialize;

use crate::{
    connectors::datatrans::transformers as datatrans,
    types::ResponseRouterData,
    utils,
};

#[derive(Debug, Clone)]
pub struct Datatrans<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    amount_converter: &'static (dyn common_utils::types::AmountConvertor<Output = common_utils::types::MinorUnit> + Sync),
    _phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> Datatrans<T> {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMinorUnit,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> Default for Datatrans<T> {
    fn default() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon for Datatrans<T> {
    fn id(&self) -> &'static str {
        "datatrans"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a domain_types::types::Connectors) -> &'a str {
        connectors.datatrans.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = datatrans::DatatransAuthType::try_from(auth_type)
            .change_context(ConnectorError::FailedToObtainAuthType)?;
        let credentials = format!("{}:{}", auth.merchant_id.expose(), auth.passcode.expose());
        let encoded_credentials = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials.as_bytes());
        Ok(vec![(
            "Authorization".to_string(),
            format!("Basic {}", encoded_credentials).into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut dyn ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: datatrans::DatatransErrorResponse = res
            .response
            .parse_struct("DatatransErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.code,
            message: response.error.message.clone(),
            reason: Some(response.error.message),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorValidation for Datatrans<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentAuthorizeV2<T> for Datatrans<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentSyncV2 for Datatrans<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentCapture for Datatrans<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentVoidV2 for Datatrans<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> RefundV2 for Datatrans<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> RefundSyncV2 for Datatrans<T> {}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> PaymentTokenV2<T> for Datatrans<T> {}

super::macros::create_all_prerequisites!(
    connector_name: Datatrans,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: DatatransPaymentsRequest<T>,
            response_body: DatatransResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: DatatransSyncRequest,
            response_body: DatatransSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: DataPaymentCaptureRequest,
            response_body: DataTransCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: DatatransVoidRequest,
            response_body: DataTransCancelResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: DatatransRefundRequest,
            response_body: DatatransRefundsResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: DatatransRSyncRequest,
            response_body: DatatransSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: DatatransPaymentsRequest<T>,
            response_body: DatatransResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: common_utils::types::MinorUnit
    ],
    member_functions: {
    }
);

super::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Datatrans,
    curl_request: Json(DatatransPaymentsRequest),
    curl_response: DatatransResponse,
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
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}/v1/transactions", self.base_url(&req.connector_info.connectors)))
        }
    }
);

super::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Datatrans,
    curl_request: Json(DatatransSyncRequest),
    curl_response: DatatransSyncResponse,
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
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}/v1/transactions/{}", 
                self.base_url(&req.connector_info.connectors),
                req.request.connector_transaction_id.get_connector_transaction_id()?
            ))
        }
    }
);

super::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Datatrans,
    curl_request: Json(DataPaymentCaptureRequest),
    curl_response: DataTransCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}/v1/transactions/{}/settle", 
                self.base_url(&req.connector_info.connectors),
                req.request.connector_transaction_id
            ))
        }
    }
);

super::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Datatrans,
    curl_request: Json(DatatransVoidRequest),
    curl_response: DataTransCancelResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}/v1/transactions/{}/cancel", 
                self.base_url(&req.connector_info.connectors),
                req.request.connector_transaction_id
            ))
        }
    }
);

super::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Datatrans,
    curl_request: Json(DatatransRefundRequest),
    curl_response: DatatransRefundsResponse,
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
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}/v1/transactions/{}/credit", 
                self.base_url(&req.connector_info.connectors),
                req.request.connector_transaction_id
            ))
        }
    }
);

super::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Datatrans,
    curl_request: Json(DatatransRSyncRequest),
    curl_response: DatatransSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}/v1/transactions/{}", 
                self.base_url(&req.connector_info.connectors),
                req.request.connector_transaction_id
            ))
        }
    }
);

super::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Datatrans,
    curl_request: Json(DatatransPaymentsRequest),
    curl_response: DatatransResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            req: &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, ConnectorError> {
            Ok(format!("{}/v1/transactions", self.base_url(&req.connector_info.connectors)))
        }
    }
);