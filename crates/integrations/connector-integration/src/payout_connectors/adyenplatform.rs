use crate::{
    connectors::{
        adyenplatform::transformers::{AdyenTransferRequest, AdyenTransferResponse},
        macros,
    },
    types::ResponseRouterData,
};
use common_utils::{errors::CustomResult, events};
use domain_types::{
    connector_flow::PayoutTransfer,
    errors::IntegrationError,
    payment_method_data::PaymentMethodDataTypes,
    payouts::payouts_types::{PayoutFlowData, PayoutTransferRequest, PayoutTransferResponse},
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{PayoutServiceTrait, PayoutTransferV2},
};
use serde::Serialize;
use std::fmt::Debug;

macros::create_all_prerequisites!(
    connector_name: AdyenplatformPayouts,
    generic_type: T,
    api: [
        (
            flow: PayoutTransfer,
            request_body: AdyenTransferRequest,
            response_body: AdyenTransferResponse,
            router_data: RouterDataV2<PayoutTransfer, PayoutFlowData, PayoutTransferRequest<T>, PayoutTransferResponse>,
        )
    ],
    amount_converters: [],
    member_functions: {}
);

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize> PayoutServiceTrait<T>
    for AdyenplatformPayouts<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static + Serialize> PayoutTransferV2<T>
    for AdyenplatformPayouts<T>
{
}
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: AdyenplatformPayouts,
    curl_request: Json(AdyenTransferRequest),
    curl_response: AdyenTransferResponse,
    flow_name: PayoutTransfer,
    resource_common_data: PayoutFlowData,
    flow_request: PayoutTransferRequest<T>,
    flow_response: PayoutTransferResponse,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(&self, req: &RouterDataV2<PayoutTransfer, PayoutFlowData, PayoutTransferRequest<T>, PayoutTransferResponse>) -> CustomResult<String, IntegrationError> {
            Ok(format!("{}/btl/v4/transfers", self.base_url(&req.resource_common_data.connectors).trim_end_matches('/')))
        }
        fn get_headers(&self, req: &RouterDataV2<PayoutTransfer, PayoutFlowData, PayoutTransferRequest<T>, PayoutTransferResponse>) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            let mut headers = self.get_auth_header(&req.connector_config)?;
            headers.push(("Content-Type".into(), self.common_get_content_type().to_owned().into()));
            Ok(headers)
        }
    }
);
macros::macro_connector_payout_implementation!(
    connector: AdyenplatformPayouts, generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    payout_flows: [PayoutCreate,PayoutVoid,PayoutStage,PayoutCreateLink,PayoutCreateRecipient,PayoutEnrollDisburseAccount,PayoutEligibility,PayoutGet]
);
