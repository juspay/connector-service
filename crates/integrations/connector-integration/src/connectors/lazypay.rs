pub mod transformers;

use std::sync::LazyLock;

use base64::{engine::general_purpose, Engine};
use common_enums::{CaptureMethod, EventClass, PaymentMethod, PaymentMethodType};
use common_utils::{
    crypto::RsaOaepSha256,
    errors::CustomResult,
    events,
    ext_traits::ByteSliceExt,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, IncrementalAuthorization, MandateRevoke,
        PSync, PaymentMethodToken, PostAuthenticate, PreAuthenticate, RSync, Refund, RepeatPayment,
        SdkSessionToken, SetupMandate, SubmitEvidence, VerifyWebhookSource, Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorSpecifications, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, MandateRevokeRequestData, MandateRevokeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsPostAuthenticateData,
        PaymentsPreAuthenticateData, PaymentsResponseData, PaymentsSdkSessionTokenData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData, SupportedPaymentMethodsExt,
        VerifyWebhookSourceFlowData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::VerifyWebhookSourceRequestData,
    router_response_types::{Response, VerifyWebhookSourceResponseData},
    types::{
        ConnectorInfo, Connectors, FeatureStatus, PaymentConnectorCategory, PaymentMethodDetails,
        SupportedPaymentMethods,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    decode::BodyDecoding,
};
use serde::Serialize;
use transformers as lazypay;
use transformers::{
    LazypayAuthorizeRequest, LazypayAuthorizeResponse, LazypayRSyncResponse, LazypayRefundRequest,
    LazypayRefundResponse, LazypaySyncResponse, LazypayVoidRequest, LazypayVoidResponse,
};

use super::macros;
use crate::types::ResponseRouterData;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const ACCESS_KEY: &str = "accessKey";
    pub(crate) const SIGNATURE: &str = "signature";
}

// ============================================================================
// PREREQUISITES AND AUTHORIZE FLOW IMPLEMENTATION
// (The create_all_prerequisites! macro generates the Lazypay<T> struct,
//  Clone impl, and new() fn.)
// ============================================================================

macros::create_all_prerequisites!(
    connector_name: Lazypay,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: LazypayAuthorizeRequest,
            response_body: LazypayAuthorizeResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            response_body: LazypaySyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: LazypayVoidRequest,
            response_body: LazypayVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: LazypayRefundRequest,
            response_body: LazypayRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            response_body: LazypayRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: MinorUnit
    ],
    member_functions: {
        pub fn connector_base_url<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.lazypay.base_url.to_string()
        }

        pub fn generate_signature(
            &self,
            access_key: &str,
            merchant_txn_id: &str,
            amount: &str,
            secret_key_pem: &str,
        ) -> CustomResult<String, errors::ConnectorError> {
            let signature_data = format!(
                "merchantAccessKey={access_key}&transactionId={merchant_txn_id}&amount={amount}"
            );

            // Parse PEM public key and convert to DER
            let rsa_key = openssl::rsa::Rsa::public_key_from_pem(secret_key_pem.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to parse LazyPay RSA public key from PEM")?;

            let pkey = openssl::pkey::PKey::from_rsa(rsa_key)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to create PKey from RSA key")?;

            let public_key_der = pkey
                .public_key_to_der()
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to convert RSA public key to DER")?;

            let encrypted_bytes = RsaOaepSha256::encrypt(&public_key_der, signature_data.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("RSA OAEP-SHA256 encryption of LazyPay signature failed")?;

            Ok(general_purpose::STANDARD.encode(&encrypted_bytes))
        }

        pub fn generate_psync_signature(
            &self,
            access_key: &str,
            merchant_txn_id: &str,
            secret_key_pem: &str,
        ) -> CustomResult<String, errors::ConnectorError> {
            let signature_data = format!(
                "merchantAccessKey={access_key}&merchantTxnId={merchant_txn_id}"
            );

            // Parse PEM public key and convert to DER
            let rsa_key = openssl::rsa::Rsa::public_key_from_pem(secret_key_pem.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to parse LazyPay RSA public key from PEM")?;

            let pkey = openssl::pkey::PKey::from_rsa(rsa_key)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to create PKey from RSA key")?;

            let public_key_der = pkey
                .public_key_to_der()
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to convert RSA public key to DER")?;

            let encrypted_bytes = RsaOaepSha256::encrypt(&public_key_der, signature_data.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("RSA OAEP-SHA256 encryption of LazyPay PSync signature failed")?;

            Ok(general_purpose::STANDARD.encode(&encrypted_bytes))
        }

        pub fn generate_void_signature(
            &self,
            access_key: &str,
            txn_ref_no: &str,
            secret_key_pem: &str,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Cancel Payment uses the same signature pattern as PSync:
            // merchantAccessKey={key}&merchantTxnId={txnRefNo}
            let signature_data = format!(
                "merchantAccessKey={access_key}&merchantTxnId={txn_ref_no}"
            );

            let rsa_key = openssl::rsa::Rsa::public_key_from_pem(secret_key_pem.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to parse LazyPay RSA public key from PEM")?;

            let pkey = openssl::pkey::PKey::from_rsa(rsa_key)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to create PKey from RSA key")?;

            let public_key_der = pkey
                .public_key_to_der()
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to convert RSA public key to DER")?;

            let encrypted_bytes = RsaOaepSha256::encrypt(&public_key_der, signature_data.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("RSA OAEP-SHA256 encryption of LazyPay Void signature failed")?;

            Ok(general_purpose::STANDARD.encode(&encrypted_bytes))
        }

        pub fn connector_base_url_refund<F, Req, Res>(
            &self,
            req: &RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> String {
            req.resource_common_data.connectors.lazypay.base_url.to_string()
        }

        pub fn generate_refund_signature(
            &self,
            access_key: &str,
            merchant_txn_id: &str,
            amount: &str,
            secret_key_pem: &str,
        ) -> CustomResult<String, errors::ConnectorError> {
            // Refund signature: merchantAccessKey={key}&merchantTxnId={txnId}&amount={amount}
            let signature_data = format!(
                "merchantAccessKey={access_key}&merchantTxnId={merchant_txn_id}&amount={amount}"
            );

            let rsa_key = openssl::rsa::Rsa::public_key_from_pem(secret_key_pem.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to parse LazyPay RSA public key from PEM")?;

            let pkey = openssl::pkey::PKey::from_rsa(rsa_key)
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to create PKey from RSA key")?;

            let public_key_der = pkey
                .public_key_to_der()
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to convert RSA public key to DER")?;

            let encrypted_bytes = RsaOaepSha256::encrypt(&public_key_der, signature_data.as_bytes())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("RSA OAEP-SHA256 encryption of LazyPay Refund signature failed")?;

            Ok(general_purpose::STANDARD.encode(&encrypted_bytes))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Lazypay,
    curl_request: Json(LazypayAuthorizeRequest),
    curl_response: LazypayAuthorizeResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = lazypay::LazypayAuthType::try_from(&req.connector_config)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let access_key = auth.access_key.expose();
            let secret_key_pem = auth.secret_key.expose();

            let merchant_txn_id = req
                .resource_common_data
                .connector_request_reference_id
                .clone();

            let amount = req.request.minor_amount.get_amount_as_i64().to_string();

            let signature = self.generate_signature(
                &access_key,
                &merchant_txn_id,
                &amount,
                &secret_key_pem,
            )?;

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::ACCESS_KEY.to_string(),
                    access_key.into(),
                ),
                (
                    headers::SIGNATURE.to_string(),
                    signature.into(),
                ),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{base_url}/v2/payment/initiate"))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Lazypay,
    curl_response: LazypaySyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = lazypay::LazypayAuthType::try_from(&req.connector_config)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let access_key = auth.access_key.expose();
            let secret_key_pem = auth.secret_key.expose();

            let merchant_txn_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

            let signature = self.generate_psync_signature(
                &access_key,
                &merchant_txn_id,
                &secret_key_pem,
            )?;

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::ACCESS_KEY.to_string(),
                    access_key.into(),
                ),
                (
                    headers::SIGNATURE.to_string(),
                    signature.into(),
                ),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let merchant_txn_id = req
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

            let base_url = self.connector_base_url(req);
            Ok(format!(
                "{base_url}/v0/enquiry?merchantTxnId={merchant_txn_id}&isSale=true"
            ))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Lazypay,
    curl_request: Json(LazypayVoidRequest),
    curl_response: LazypayVoidResponse,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = lazypay::LazypayAuthType::try_from(&req.connector_config)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let access_key = auth.access_key.expose();
            let secret_key_pem = auth.secret_key.expose();

            // Extract txnRefNo from connector_feature_data to build the signature
            let connector_meta = req
                .resource_common_data
                .connector_feature_data
                .as_ref()
                .ok_or_else(|| {
                    error_stack::report!(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_feature_data for void signature",
                    })
                })?;

            let meta: lazypay::LazypayConnectorMetadata =
                serde_json::from_value(connector_meta.peek().clone())
                    .change_context(errors::ConnectorError::RequestEncodingFailed)
                    .attach_printable("Failed to deserialize metadata for void signature")?;

            let signature = self.generate_void_signature(
                &access_key,
                &meta.txn_ref_no,
                &secret_key_pem,
            )?;

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::SIGNATURE.to_string(),
                    signature.into(),
                ),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url(req);
            Ok(format!("{base_url}/v0/payment/pay"))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Lazypay,
    curl_request: Json(LazypayRefundRequest),
    curl_response: LazypayRefundResponse,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = lazypay::LazypayAuthType::try_from(&req.connector_config)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let access_key = auth.access_key.expose();
            let secret_key_pem = auth.secret_key.expose();

            let merchant_txn_id = req.request.connector_transaction_id.clone();

            let amount = req.request.minor_refund_amount.get_amount_as_i64().to_string();

            let signature = self.generate_refund_signature(
                &access_key,
                &merchant_txn_id,
                &amount,
                &secret_key_pem,
            )?;

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::ACCESS_KEY.to_string(),
                    access_key.into(),
                ),
                (
                    headers::SIGNATURE.to_string(),
                    signature.into(),
                ),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let base_url = self.connector_base_url_refund(req);
            Ok(format!("{base_url}/v0/refund"))
        }
    }
);

macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: Lazypay,
    curl_response: LazypayRSyncResponse,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            let auth = lazypay::LazypayAuthType::try_from(&req.connector_config)
                .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

            let access_key = auth.access_key.expose();
            let secret_key_pem = auth.secret_key.expose();

            // RSync uses the same signature pattern as PSync:
            // merchantAccessKey={key}&merchantTxnId={txnId}
            // where txnId is the original connector_transaction_id
            let merchant_txn_id = req.request.connector_transaction_id.clone();

            let signature = self.generate_psync_signature(
                &access_key,
                &merchant_txn_id,
                &secret_key_pem,
            )?;

            Ok(vec![
                (
                    headers::CONTENT_TYPE.to_string(),
                    "application/json".to_string().into(),
                ),
                (
                    headers::ACCESS_KEY.to_string(),
                    access_key.into(),
                ),
                (
                    headers::SIGNATURE.to_string(),
                    signature.into(),
                ),
            ])
        }

        fn get_url(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            let merchant_txn_id = req.request.connector_transaction_id.clone();
            let base_url = self.connector_base_url_refund(req);
            Ok(format!(
                "{base_url}/v0/enquiry?merchantTxnId={merchant_txn_id}&isSale=false"
            ))
        }
    }
);

// ============================================================================
// CONNECTOR COMMON IMPLEMENTATION
// ============================================================================
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorCommon for Lazypay<T>
{
    fn id(&self) -> &'static str {
        "lazypay"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.lazypay.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorSpecificConfig,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = lazypay::LazypayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::ACCESS_KEY.to_string(),
            auth.access_key.expose().into(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut events::Event>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: lazypay::LazypayErrorResponse = res
            .response
            .parse_struct("LazypayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        crate::with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code,
            message: response.message,
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// ============================================================================
// BODY DECODING IMPLEMENTATION
// ============================================================================
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    BodyDecoding for Lazypay<T>
{
}

// ============================================================================
// CONNECTOR SPECIFICATIONS
// ============================================================================

static LAZYPAY_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "LazyPay",
    description: "LazyPay is an Indian BNPL (Buy Now Pay Later) wallet payment method.",
    connector_type: PaymentConnectorCategory::PaymentGateway,
};

static LAZYPAY_SUPPORTED_WEBHOOK_FLOWS: &[EventClass] = &[EventClass::Payments];

static LAZYPAY_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let mut supported_payment_methods = SupportedPaymentMethods::new();

        let lazypay_supported_capture_methods = vec![CaptureMethod::Automatic];

        supported_payment_methods.add(
            PaymentMethod::Wallet,
            PaymentMethodType::LazyPay,
            PaymentMethodDetails {
                mandates: FeatureStatus::NotSupported,
                refunds: FeatureStatus::NotSupported,
                supported_capture_methods: lazypay_supported_capture_methods,
                specific_features: None,
            },
        );

        supported_payment_methods
    });

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorSpecifications for Lazypay<T>
{
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&LAZYPAY_CONNECTOR_INFO)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        Some(LAZYPAY_SUPPORTED_WEBHOOK_FLOWS)
    }

    fn get_supported_payment_methods(
        &self,
    ) -> Option<&'static SupportedPaymentMethods> {
        Some(&LAZYPAY_SUPPORTED_PAYMENT_METHODS)
    }
}

// ============================================================================
// CONNECTOR SERVICE TRAIT IMPLEMENTATIONS
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::CreateConnectorCustomer for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::MandateRevokeV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAccessToken for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthenticateV2<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentIncrementalAuthorization for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPostAuthenticateV2<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentPreAuthenticateV2<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentTokenV2<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidPostCaptureV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::SdkSessionTokenV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyRedirectResponse for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    connector_types::VerifyWebhookSourceV2 for Lazypay<T>
{
}

// ============================================================================
// CONNECTOR INTEGRATION V2 IMPLEMENTATIONS (empty — unsupported flows)
// ============================================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        MandateRevoke,
        PaymentFlowData,
        MandateRevokeRequestData,
        MandateRevokeResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateAccessToken,
        PaymentFlowData,
        AccessTokenRequestData,
        AccessTokenResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        IncrementalAuthorization,
        PaymentFlowData,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VoidPC,
        PaymentFlowData,
        PaymentsCancelPostCaptureData,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData<T>,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SdkSessionToken,
        PaymentFlowData,
        PaymentsSdkSessionTokenData,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<
        VerifyWebhookSource,
        VerifyWebhookSourceFlowData,
        VerifyWebhookSourceRequestData,
        VerifyWebhookSourceResponseData,
    > for Lazypay<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification for Lazypay<T>
{
}
