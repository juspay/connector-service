pub mod constants;
pub mod types;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{
    AttemptStatus, AuthorizationType, CaptureMethod, Currency, PaymentMethodType,
};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    pii::SecretSerdeValue,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
        VoidData, WebhookDetailsData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;

use self::transformers::{
    EaseBuzzAccessKeyRequest, EaseBuzzAccessKeyResponse, EaseBuzzAuthZRequest,
    EaseBuzzAuthZResponse, EaseBuzzCreateMandateRequest, EaseBuzzCreateMandateResponse,
    EaseBuzzCreateSettlementRequest, EaseBuzzCreateSettlementResponse, EaseBuzzDebitRequestRetrieve,
    EaseBuzzDebitRequestRetrieveResponse, EaseBuzzDelayedSettlementStatusCheckRequest,
    EaseBuzzDelayedSettlementStatusCheckResponse, EaseBuzzEMIOptionRequest,
    EaseBuzzEMIOptionResponse, EaseBuzzExecuteMandateRequest, EaseBuzzExecuteMandateResponse,
    EaseBuzzGetEMIOptionsRequest, EaseBuzzGetEMIOptionsResponse, EaseBuzzInitiatePaymentRequest,
    EaseBuzzInitiatePaymentResponse, EaseBuzzMandateNotificationSyncRequest,
    EaseBuzzMandateNotificationSyncResponse, EaseBuzzMandateRetrieveRequest,
    EaseBuzzMandateRetrieveResponse, EaseBuzzNotificationRequest, EaseBuzzNotificationResponse,
    EaseBuzzPlansRequest, EaseBuzzPlansResponse, EaseBuzzRefundRequest, EaseBuzzRefundResponse,
    EaseBuzzRefundSyncRequest, EaseBuzzRefundSyncResponse, EaseBuzzRevokeMandateRequest,
    EaseBuzzRevokeMandateResponse, EaseBuzzSeamlessTxnRequest, EaseBuzzSeamlessTxnResponse,
    EaseBuzzTxnSyncRequest, EaseBuzzTxnSyncResponse, EaseBuzzUpiAutoPayCollectRequest,
    EaseBuzzUpiAutoPayCollectResponse, EaseBuzzUpiAutoPayIntentRequest,
    EaseBuzzUpiAutoPayIntentResponse, EaseBuzzUpiExecuteMandateRequest,
    EaseBuzzUpiExecuteMandateResponse, EaseBuzzUpiIntentResponse,
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
        // Payment flows
        (
            flow: Authorize,
            request_body: EaseBuzzInitiatePaymentRequest,
            response_body: EaseBuzzInitiatePaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzSeamlessTxnRequest,
            response_body: EaseBuzzUpiIntentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EaseBuzzTxnSyncRequest,
            response_body: EaseBuzzTxnSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EaseBuzzRefundRequest,
            response_body: EaseBuzzRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EaseBuzzRefundSyncRequest,
            response_body: EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        // EMI flows
        (
            flow: Authorize,
            request_body: EaseBuzzGetEMIOptionsRequest,
            response_body: EaseBuzzGetEMIOptionsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzEMIOptionRequest,
            response_body: EaseBuzzEMIOptionResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzPlansRequest,
            response_body: EaseBuzzPlansResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        // Mandate flows
        (
            flow: SetupMandate,
            request_body: EaseBuzzCreateMandateRequest,
            response_body: EaseBuzzCreateMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzMandateRetrieveRequest,
            response_body: EaseBuzzMandateRetrieveResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzExecuteMandateRequest,
            response_body: EaseBuzzExecuteMandateResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzDebitRequestRetrieve,
            response_body: EaseBuzzDebitRequestRetrieveResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzRevokeMandateRequest,
            response_body: EaseBuzzRevokeMandateResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        // UPI Autopay flows
        (
            flow: Authorize,
            request_body: EaseBuzzUpiAutoPayIntentRequest,
            response_body: EaseBuzzUpiAutoPayIntentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzUpiAutoPayCollectRequest,
            response_body: EaseBuzzUpiAutoPayCollectResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzUpiExecuteMandateRequest,
            response_body: EaseBuzzUpiExecuteMandateResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        // Notification flows
        (
            flow: Authorize,
            request_body: EaseBuzzNotificationRequest,
            response_body: EaseBuzzNotificationResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzMandateNotificationSyncRequest,
            response_body: EaseBuzzMandateNotificationSyncResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        // Settlement flows
        (
            flow: Authorize,
            request_body: EaseBuzzCreateSettlementRequest,
            response_body: EaseBuzzCreateSettlementResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzDelayedSettlementStatusCheckRequest,
            response_body: EaseBuzzDelayedSettlementStatusCheckResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        // Authentication flows
        (
            flow: Authorize,
            request_body: EaseBuzzAuthZRequest,
            response_body: EaseBuzzAuthZResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: Authorize,
            request_body: EaseBuzzAccessKeyRequest,
            response_body: EaseBuzzAccessKeyResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self) -> &'static str {
            match self.flow_name {
                "Authorize" => match self.request_type {
                    "EaseBuzzInitiatePaymentRequest" => "initiate_payment",
                    "EaseBuzzSeamlessTxnRequest" => "seamless_transaction",
                    "EaseBuzzGetEMIOptionsRequest" => "get_emi_options",
                    "EaseBuzzEMIOptionRequest" => "emi_option",
                    "EaseBuzzPlansRequest" => "plans",
                    "EaseBuzzCreateMandateRequest" => "create_mandate",
                    "EaseBuzzMandateRetrieveRequest" => "mandate_retrieve",
                    "EaseBuzzExecuteMandateRequest" => "execute_mandate",
                    "EaseBuzzDebitRequestRetrieve" => "debit_request_retrieve",
                    "EaseBuzzRevokeMandateRequest" => "revoke_mandate",
                    "EaseBuzzUpiAutoPayIntentRequest" => "upi_autopay_intent",
                    "EaseBuzzUpiAutoPayCollectRequest" => "upi_autopay_collect",
                    "EaseBuzzUpiExecuteMandateRequest" => "upi_execute_mandate",
                    "EaseBuzzNotificationRequest" => "notification",
                    "EaseBuzzMandateNotificationSyncRequest" => "mandate_notification_sync",
                    "EaseBuzzCreateSettlementRequest" => "create_settlement",
                    "EaseBuzzDelayedSettlementStatusCheckRequest" => "settlement_status_check",
                    "EaseBuzzAuthZRequest" => "authz",
                    "EaseBuzzAccessKeyRequest" => "access_key",
                    _ => "payment",
                },
                "PSync" => "sync",
                "RSync" => "refund_sync",
                "Refund" => "refund",
                "SetupMandate" => "setup_mandate",
                _ => "default",
            }
        }
    }
);

// Implement the connector using the mandatory macro framework for all flows

// Payment Initiate Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzInitiatePaymentRequest),
    curl_response: EaseBuzzInitiatePaymentResponse,
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

// Seamless Transaction Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzSeamlessTxnRequest),
    curl_response: EaseBuzzUpiIntentResponse,
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

// Payment Sync Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzTxnSyncRequest),
    curl_response: EaseBuzzTxnSyncResponse,
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

// Refund Flow
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

// Refund Sync Flow
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

// EMI Options Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzGetEMIOptionsRequest),
    curl_response: EaseBuzzGetEMIOptionsResponse,
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

// EMI Option Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzEMIOptionRequest),
    curl_response: EaseBuzzEMIOptionResponse,
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

// Plans Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzPlansRequest),
    curl_response: EaseBuzzPlansResponse,
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

// Create Mandate Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzCreateMandateRequest),
    curl_response: EaseBuzzCreateMandateResponse,
    flow_name: SetupMandate,
    resource_common_data: PaymentFlowData,
    flow_request: SetupMandateRequestData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Mandate Retrieve Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzMandateRetrieveRequest),
    curl_response: EaseBuzzMandateRetrieveResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Execute Mandate Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzExecuteMandateRequest),
    curl_response: EaseBuzzExecuteMandateResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Debit Request Retrieve Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzDebitRequestRetrieve),
    curl_response: EaseBuzzDebitRequestRetrieveResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Revoke Mandate Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzRevokeMandateRequest),
    curl_response: EaseBuzzRevokeMandateResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// UPI Autopay Intent Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzUpiAutoPayIntentRequest),
    curl_response: EaseBuzzUpiAutoPayIntentResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// UPI Autopay Collect Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzUpiAutoPayCollectRequest),
    curl_response: EaseBuzzUpiAutoPayCollectResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// UPI Execute Mandate Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzUpiExecuteMandateRequest),
    curl_response: EaseBuzzUpiExecuteMandateResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Notification Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzNotificationRequest),
    curl_response: EaseBuzzNotificationResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Mandate Notification Sync Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzMandateNotificationSyncRequest),
    curl_response: EaseBuzzMandateNotificationSyncResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Create Settlement Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzCreateSettlementRequest),
    curl_response: EaseBuzzCreateSettlementResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Settlement Status Check Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzDelayedSettlementStatusCheckRequest),
    curl_response: EaseBuzzDelayedSettlementStatusCheckResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// AuthZ Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzAuthZRequest),
    curl_response: EaseBuzzAuthZResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Access Key Flow
macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzAccessKeyRequest),
    curl_response: EaseBuzzAccessKeyResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn get_content_type(&self) -> &'static str {
            "application/json"
        }
    }
);

// Implement source verification stubs for all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData);

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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSetupMandateV2 for EaseBuzz<T>
{
}

// Connector specifications
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorSpecifications for EaseBuzz<T>
{
    fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        vec![
            PaymentMethodType::Upi,
            PaymentMethodType::UpiCollect,
            PaymentMethodType::UpiIntent,
            PaymentMethodType::Card,
            PaymentMethodType::NetBanking,
            PaymentMethodType::Wallet,
        ]
    }

    fn get_webhook_secret(&self) -> Option<&ConnectorWebhookSecrets> {
        None
    }
}