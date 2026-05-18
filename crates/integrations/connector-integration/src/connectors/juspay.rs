pub mod transformers;

use std::fmt::Debug;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
};
use domain_types::{
    connector_flow::{Authorize, Capture, CreateOrder, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
    },
    errors::{self, IntegrationError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding, verification::SourceVerification,
};
use serde::Serialize;
use transformers::{
    self as juspay, JuspayAuthorizeRequest, JuspayAuthorizeResponse, JuspayCaptureRequest,
    JuspayCaptureResponse, JuspayCreateOrderRequest, JuspayCreateOrderResponse,
    JuspayOrderStatusResponse, JuspayRefundRequest, JuspayRefundResponse,
    JuspayRefundSyncResponse, JuspayVoidRequest, JuspayVoidResponse,
};

use crate::{types::ResponseRouterData, with_error_response_body};

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub(crate) mod headers {
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const X_MERCHANT_ID: &str = "x-merchantid";
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const VERSION: &str = "version";
}

/// Juspay EC API version header. Pins the response schema so the connector
/// keeps a stable contract independent of any future Juspay-side changes.
const JUSPAY_API_VERSION: &str = "2023-06-30";

use super::macros;

macros::create_amount_converter_wrapper!(connector_name: Juspay, amount_type: StringMajorUnit);

// =============================================================================
// CONNECTOR STRUCT + FLOW BRIDGES
// =============================================================================
// `create_all_prerequisites!` defines the `Juspay<T>` struct, the
// `JuspayRouterData<RD, T>` input-wrapper, and the per-flow `Bridge`
// implementations. Every flow listed here MUST also be removed from the
// `macro_connector_flow_status_impls!` `not_implemented` list at the bottom of
// the file and have a matching `macro_connector_implementation!` block below.
macros::create_all_prerequisites!(
    connector_name: Juspay,
    generic_type: T,
    api: [
        (
            flow: CreateOrder,
            request_body: JuspayCreateOrderRequest,
            response_body: JuspayCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: Authorize,
            request_body: JuspayAuthorizeRequest,
            response_body: JuspayAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: JuspayOrderStatusResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: JuspayCaptureRequest,
            response_body: JuspayCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: JuspayRefundRequest,
            response_body: JuspayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: JuspayRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: Void,
            request_body: JuspayVoidRequest,
            response_body: JuspayVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        /// Compose the headers every Juspay EC API call expects:
        ///   * `Authorization: Basic base64(api_key:)` and `x-merchantid`
        ///     come from `ConnectorCommon::get_auth_header`.
        ///   * `Content-Type: application/x-www-form-urlencoded` because every
        ///     EC write endpoint is form-encoded.
        ///   * `version: 2023-06-30` to pin the response schema (the tech spec
        ///     strongly recommends sending this on every call).
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut headers = vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    self.common_get_content_type().to_string().into(),
                ),
                (
                    headers::VERSION.to_string(),
                    JUSPAY_API_VERSION.to_string().into(),
                ),
            ];
            let mut auth_headers = self.get_auth_header(&req.connector_config)?;
            headers.append(&mut auth_headers);
            Ok(headers)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.juspay.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.juspay.base_url
        }
    }
);

// =============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for Juspay<T>
{
    fn id(&self) -> &'static str {
        "juspay"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.juspay.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
        let auth = juspay::JuspayAuthType::try_from(auth_type).change_context(
            IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            },
        )?;
        let encoded_api_key = BASE64_ENGINE.encode(format!("{}:", auth.api_key.peek()));
        Ok(vec![
            (
                headers::AUTHORIZATION.to_string(),
                format!("Basic {encoded_api_key}").into_masked(),
            ),
            (
                headers::X_MERCHANT_ID.to_string(),
                auth.merchant_id.peek().to_string().into_masked(),
            ),
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
        _connector_config: &ConnectorSpecificConfig,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Juspay returns at least two error envelope shapes. Parse defensively
        // by deserializing into a single struct where every field is optional
        // so we never fail to surface upstream errors back to the caller.
        let response: juspay::JuspayErrorResponse = res
            .response
            .parse_struct("JuspayErrorResponse")
            .change_context(crate::utils::response_deserialization_fail(
                res.status_code,
                "juspay: response body did not match the expected error format; \
                 confirm API version and connector documentation.",
            ))?;

        with_error_response_body!(event_builder, response);

        let code = response
            .error_code
            .clone()
            .or_else(|| response.status.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let message = response
            .error_message
            .clone()
            .or_else(|| response.status.clone())
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());

        let reason = response
            .error_info
            .as_ref()
            .and_then(|info| {
                info.user_message
                    .clone()
                    .or_else(|| info.developer_message.clone())
            })
            .or_else(|| response.error_message.clone());

        Ok(ErrorResponse {
            status_code: res.status_code,
            code,
            message,
            reason,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// =============================================================================
// CREATE ORDER FLOW IMPLEMENTATION
// =============================================================================
// `POST /orders` -- creates a Juspay order so that subsequent /txns,
// /v2/txns/{txn_uuid}/capture, /v2/txns/{txn_uuid}/void and
// /orders/{order_id}/refunds calls have an order to attach to. The request
// body is `application/x-www-form-urlencoded`; nested fields use the
// dot-flat convention (e.g. `metadata.txns.auto_capture=false`).
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Juspay,
    curl_request: FormUrlEncoded(JuspayCreateOrderRequest),
    curl_response: JuspayCreateOrderResponse,
    flow_name: CreateOrder,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentCreateOrderData,
    flow_response: PaymentCreateOrderResponse,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ) -> CustomResult<String, IntegrationError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}orders"))
        }
    }
);

// =============================================================================
// AUTHORIZE FLOW IMPLEMENTATION
// =============================================================================
// `POST /txns` -- charges the card against the order that CreateOrder built.
// Body is `application/x-www-form-urlencoded`. The response is JSON and
// branches on `status`: a 3DS card returns `PENDING_VBV` with a redirect URL
// inside `payment.authentication`; a non-3DS pre-auth card lands directly on
// `AUTHORIZED`. Because we always create orders with
// `metadata.txns.auto_capture=false`, frictionless flows still need a separate
// Capture before funds move.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Juspay,
    curl_request: FormUrlEncoded(JuspayAuthorizeRequest),
    curl_response: JuspayAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}txns"))
        }
    }
);

// =============================================================================
// PSYNC FLOW IMPLEMENTATION
// =============================================================================
// `GET /orders/{order_id}` -- pulls the authoritative order envelope (status,
// txn_uuid, refunds[], etc.) from Juspay. Juspay collapses every txn under an
// order into a single envelope status, so we read `status` here and refresh
// `txn_uuid` so downstream Capture / Void / RSync calls still have it.
//
// No request body. Path parameter is the merchant `order_id`, which is sourced
// from `PaymentFlowData::connector_order_id` (mirrored there by CreateOrder),
// with a fallback to `connector_request_reference_id` (the same value before
// CreateOrder ran). Juspay merchant order ids are URL-safe so we do not
// percent-encode them.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Juspay,
    curl_response: JuspayOrderStatusResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            // Prefer `connector_order_id` (populated by CreateOrder) and fall
            // back to `connector_request_reference_id` (the source value) so a
            // sync remains well-formed even before CreateOrder persists.
            let order_id = req
                .resource_common_data
                .connector_order_id
                .clone()
                .unwrap_or_else(|| {
                    req.resource_common_data
                        .connector_request_reference_id
                        .clone()
                });
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}orders/{order_id}"))
        }
    }
);

// =============================================================================
// CAPTURE FLOW IMPLEMENTATION
// =============================================================================
// `POST /v2/txns/{txn_uuid}/capture` -- captures funds on a previously
// AUTHORIZED transaction. Body shape:
//   * full capture  -> empty body (the `amount` field is skipped via
//                       `skip_serializing_if = Option::is_none`).
//   * partial       -> single form field `amount=<major-unit decimal>`.
// `txn_uuid` is the *opaque* Juspay txn identifier that Authorize persisted
// into `PaymentsResponseData::resource_id` as `ConnectorTransactionId`. The
// orchestrator copies that value into
// `PaymentsCaptureData::connector_transaction_id` for this flow.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Juspay,
    curl_request: FormUrlEncoded(JuspayCaptureRequest),
    curl_response: JuspayCaptureResponse,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            // Capture takes the Juspay `txn_uuid` in the URL. Authorize stored
            // it in `PaymentsResponseData::resource_id` as
            // `ConnectorTransactionId`, which the orchestrator surfaces here as
            // `PaymentsCaptureData::connector_transaction_id`. Reject anything
            // else with a clear error rather than papering over it.
            let txn_uuid = req
                .request
                .get_connector_transaction_id()
                .change_context(IntegrationError::MissingConnectorTransactionID {
                    context: Default::default(),
                })?;
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}v2/txns/{txn_uuid}/capture"))
        }
    }
);

// =============================================================================
// REFUND FLOW IMPLEMENTATION
// =============================================================================
// `POST /orders/{order_id}/refunds` -- enqueues a refund against a CHARGED
// order. Body is `application/x-www-form-urlencoded` with two fields:
//   * `unique_request_id` -- idempotency key, sourced from the UCS
//                             `RefundsData::refund_id`.
//   * `amount`             -- refund amount in major units (StringMajorUnit).
//
// The URL path parameter is the merchant `order_id`. Juspay does not expose a
// way to derive an order_id from the txn_uuid we returned on Authorize, so the
// caller is expected to pass the merchant order_id as
// `RefundsData::connector_transaction_id` (the same convention as other
// order-anchored connectors such as Cashfree -- see `pg/orders/{order_id}/
// refunds` there). The initial refund response is always `PENDING`; RSync
// re-queries Order Status to pick up the eventual SUCCESS/FAILURE state.
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Juspay,
    curl_request: FormUrlEncoded(JuspayRefundRequest),
    curl_response: JuspayRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            // The refund endpoint is keyed on the merchant `order_id`. The
            // orchestrator surfaces the value the caller passed for the
            // underlying payment as `RefundsData::connector_transaction_id`;
            // for Juspay the caller must pass the merchant order_id there
            // (mirroring the field-mapping suggestion in the tech spec, since
            // the Juspay `txn_uuid` cannot be reversed to an order_id).
            let order_id = &req.request.connector_transaction_id;
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{base_url}orders/{order_id}/refunds"))
        }
    }
);

// =============================================================================
// RSYNC FLOW IMPLEMENTATION
// =============================================================================
// `GET /orders/{order_id}` -- Juspay does not expose a dedicated refund-status
// endpoint, so RSync reuses the Order Status response and locates the refund
// by `unique_request_id` inside the `refunds[]` array (see the RSync section
// of the tech spec). The URL shape is identical to PSync. The order_id source
// is `RefundFlowData::connector_transaction_id`, mirroring the Refund flow's
// URL builder (the caller passes the merchant order_id there because Juspay
// has no way to derive an order_id from a txn_uuid).
//
// No request body (GET).
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Juspay,
    curl_response: JuspayRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            // Same convention as the Refund flow: the merchant order_id arrives
            // on `RefundFlowData::connector_transaction_id` (because Juspay's
            // txn_uuid cannot be reversed to an order_id).
            let order_id = &req.request.connector_transaction_id;
            let base_url = self.connector_base_url_refunds(req);
            Ok(format!("{base_url}orders/{order_id}"))
        }
    }
);

// =============================================================================
// VOID FLOW IMPLEMENTATION
// =============================================================================
// `POST /v2/txns/{txn_uuid}/void` -- cancels a previously AUTHORIZED transaction
// and releases the hold on the cardholder's funds. The body is empty (the void
// is fully described by the URL); we model it as `JuspayVoidRequest {}` so the
// macro path stays uniform with the other write flows (always
// `FormUrlEncoded(<Request>)`). `serde_urlencoded` serialises a unit-shaped
// struct to an empty string, which matches Juspay's "empty body" requirement.
//
// `txn_uuid` is the opaque Juspay txn identifier Authorize / Capture persist
// into `PaymentsResponseData::resource_id` as `ConnectorTransactionId`. The
// orchestrator surfaces it here as `PaymentVoidData::connector_transaction_id`
// (a `String`, not `Option`, so a missing value is impossible by construction).
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Juspay,
    curl_request: FormUrlEncoded(JuspayVoidRequest),
    curl_response: JuspayVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, IntegrationError> {
            self.build_headers(req)
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, IntegrationError> {
            // Void takes the Juspay `txn_uuid` in the URL. Authorize / Capture
            // store it in `PaymentsResponseData::resource_id` as
            // `ConnectorTransactionId`, which the orchestrator surfaces here as
            // `PaymentVoidData::connector_transaction_id` (a `String`, so the
            // field is always populated; we reject an empty value with a clear
            // error rather than letting Juspay produce a confusing 400).
            let txn_uuid = req.request.connector_transaction_id.as_str();
            if txn_uuid.is_empty() {
                return Err(error_stack::report!(
                    IntegrationError::MissingConnectorTransactionID {
                        context: Default::default(),
                    }
                ));
            }
            let base_url = self.connector_base_url_payments(req);
            Ok(format!("{base_url}v2/txns/{txn_uuid}/void"))
        }
    }
);

// =============================================================================
// BODY DECODING IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> BodyDecoding
    for Juspay<T>
{
}

// =============================================================================
// SOURCE VERIFICATION IMPLEMENTATION
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> SourceVerification
    for Juspay<T>
{
}

// =============================================================================
// DYNAMICALLY GENERATED IMPLEMENTATIONS
// =============================================================================
// Auto-generated by add_connector.sh using the macro-based pattern. All flow
// traits are stubbed via `macros::macro_connector_flow_status_impls!` with
// `not_implemented` status, which emits both the marker-trait impl and a stub
// `ConnectorIntegrationV2` impl per flow.
//
// To implement a flow:
//   1. Remove that flow's name from the `not_implemented` list below.
//   2. Add the flow to `create_all_prerequisites!` above.
//   3. Add a `macros::macro_connector_implementation!(...)` block with the
//      flow's request/response types, HTTP method, and `get_url`/`get_headers`.
//   4. Add a manual marker-trait impl iff the auto-generated one collides;
//      `expand_flow_status_impl!` emits the marker for the flow only when the
//      flow stays in the `not_implemented` list, so manual impls are required
//      for flows that have been removed from that list (see PaymentOrderCreate
//      below for the CreateOrder example).
// =============================================================================

// ===== CONNECTOR SERVICE TRAIT IMPLEMENTATION =====
// Aggregate trait - composes all other connector traits.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Juspay<T>
{
}

// ===== BASE (NON-FLOW) TRAIT IMPLEMENTATIONS =====
// These are simple marker traits that are NOT flows and therefore have no arm
// in expand_flow_status_impl!. They must be impl'd manually.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Juspay<T>
{
    /// Juspay's EC API requires an Order to exist before the Authorize / `/txns`
    /// call. Tell the orchestrator to run CreateOrder ahead of Authorize.
    fn should_do_order_create(&self) -> bool {
        true
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Juspay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Juspay<T>
{
}

// ===== MARKER TRAITS FOR FLOWS REMOVED FROM `not_implemented` =====
// `expand_flow_status_impl!` emits the marker-trait impl together with its
// stub `ConnectorIntegrationV2` impl. Since CreateOrder has been removed from
// the `not_implemented` list (its real impl lives in the
// `macro_connector_implementation!` block above), we have to hand-write the
// marker impl that the orchestrator looks for.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Juspay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Juspay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Juspay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Juspay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Juspay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Juspay<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Juspay<T>
{
}

// ===== PAYOUT TRAIT IMPLEMENTATIONS =====
// Emits payout marker-trait impls and default no-op ConnectorIntegrationV2
// impls for all PayoutXxxV2 flows.
crate::connectors::macros::macro_connector_payout_implementation!(
    connector: Juspay,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize]
);

// ===== FLOW STATUS IMPLEMENTATIONS =====
// Emits marker-trait impls AND stub ConnectorIntegrationV2 impls for every
// flow listed. Each stub's get_url returns
// IntegrationError::connector_flow_not_implemented(...).
crate::connectors::macros::macro_connector_flow_status_impls!(
    connector: Juspay,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    not_implemented: [
        Accept,
        ClientAuthenticationToken,
        CreateConnectorCustomer,
        DefendDispute,
        MandateRevoke,
        Authenticate,
        IncrementalAuthorization,
        PostAuthenticate,
        PreAuthenticate,
        PaymentMethodToken,
        VoidPC,
        RepeatPayment,
        ServerAuthenticationToken,
        ServerSessionAuthenticationToken,
        SetupMandate,
        SubmitEvidence
    ],
);
