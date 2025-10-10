pub mod constants;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::PaymentMethodType;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorSpecifications, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData,
        RefundsResponseData, RefundSyncData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;

use self::transformers::{
    EaseBuzzPaymentsRequest, EaseBuzzPaymentsResponse, EaseBuzzPaymentsSyncRequest,
    EaseBuzzPaymentsSyncResponse, EaseBuzzRefundRequest, EaseBuzzRefundResponse,
    EaseBuzzRefundSyncRequest, EaseBuzzRefundSyncResponse,
};
use crate::{
    impl_source_verification_stub,
    macros::{create_all_prerequisites, macro_connector_implementation},
    services::{api::ConnectorCommon, ConnectorIntegrationV2},
    types::{ConnectorAuthType, ConnectorRequestHeaders, ConnectorRequestParams},
};

// Create all prerequisites using the mandatory macro framework
create_all_prerequisites!(
    connector_name: EaseBuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: EaseBuzzPaymentsRequest,
            response_body: EaseBuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EaseBuzzPaymentsSyncRequest,
            response_body: EaseBuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EaseBuzzRefundSyncRequest,
            response_body: EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EaseBuzzRefundRequest,
            response_body: EaseBuzzRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self) -> &'static str {
            match self.flow_name {
                "Authorize" => "payment",
                "PSync" => "sync",
                "RSync" => "refund_sync",
                "Refund" => "refund",
                _ => "default",
            }
        }
    }
);

// Implement the connector using the mandatory macro framework
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzPaymentsRequest),
    curl_response: EaseBuzzPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }
    }
);

macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzPaymentsSyncRequest),
    curl_response: EaseBuzzPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }
    }
);

macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzRefundRequest),
    curl_response: EaseBuzzRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }
    }
);

macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzRefundSyncRequest),
    curl_response: EaseBuzzRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }
    }
);

// Implement source verification stubs for all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);

// Implement ConnectorCommon trait for custom logic
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn get_auth_header(&self, _auth_type: &ConnectorAuthType) -> CustomResult<ConnectorRequestHeaders, errors::ConnectorError> {
        Ok(ConnectorRequestHeaders::default())
    }

    fn get_base_url(&self) -> &'static str {
        if self.test_mode.unwrap_or(false) {
            "https://testpay.easebuzz.in"
        } else {
            "https://pay.easebuzz.in"
        }
    }

    fn build_request(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        connectors: &(),
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = self.build_request_v2(req)?;
        Ok(Some(request))
    }
}

// Implement connector types traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentAuthorizeV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSyncV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentRefundV2 for EaseBuzz<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentRefundSyncV2 for EaseBuzz<T>
{
}

// Connector specifications
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorSpecifications for EaseBuzz<T>
{
    fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        vec![PaymentMethodType::Upi, PaymentMethodType::UpiCollect, PaymentMethodType::UpiIntent]
    }

    fn get_webhook_secret(&self) -> Option<&ConnectorWebhookSecrets> {
        None
    }
}