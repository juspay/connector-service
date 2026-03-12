#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use domain_types::{
        connector_types::{EventType, HttpMethod, RequestDetails},
        payment_method_data::DefaultPCIHolder,
    };
    use interfaces::{api::ConnectorCommon, connector_types::IncomingWebhook};

    use crate::connectors;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make_request(body: &[u8]) -> RequestDetails {
        RequestDetails {
            method: HttpMethod::Post,
            uri: None,
            headers: HashMap::new(),
            body: body.to_vec(),
            query_params: None,
        }
    }

    fn charge_webhook(event_type: &str, status: &str) -> Vec<u8> {
        format!(
            r#"{{
                "specversion": "1.0",
                "type": "{event_type}",
                "source": "https://api.sandbox.eu.ppro.com",
                "id": "evt_test_001",
                "time": "2024-01-01T00:00:00Z",
                "data": {{
                    "charge": {{
                        "id": "pc_test_123",
                        "status": "{status}"
                    }}
                }}
            }}"#
        )
        .into_bytes()
    }

    fn agreement_webhook(event_type: &str, status: &str) -> Vec<u8> {
        format!(
            r#"{{
                "specversion": "1.0",
                "type": "{event_type}",
                "source": "https://api.sandbox.eu.ppro.com",
                "id": "evt_test_001",
                "time": "2024-01-01T00:00:00Z",
                "data": {{
                    "agreement": {{
                        "id": "agr_test_123",
                        "status": "{status}"
                    }}
                }}
            }}"#
        )
        .into_bytes()
    }

    macro_rules! ensure_eq {
        ($left:expr, $right:expr $(,)?) => {{
            let left = &$left;
            let right = &$right;
            if left != right {
                return Err(format!("assertion failed: {left:?} != {right:?}").into());
            }
        }};
        ($left:expr, $right:expr, $($msg:tt)+) => {{
            let left = &$left;
            let right = &$right;
            if left != right {
                return Err(
                    format!("{}: {left:?} != {right:?}", format_args!($($msg)+)).into(),
                );
            }
        }};
    }

    macro_rules! ensure {
        ($cond:expr $(,)?) => {{
            if !($cond) {
                return Err(concat!("assertion failed: ", stringify!($cond)).into());
            }
        }};
        ($cond:expr, $($msg:tt)+) => {{
            if !($cond) {
                return Err(format!($($msg)+).into());
            }
        }};
    }

    // ── Connector Setup ───────────────────────────────────────────────────────

    #[test]
    fn test_ppro_connector_creation() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        assert_eq!(connector.id(), "ppro");
    }

    #[test]
    fn test_ppro_currency_unit() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        assert!(matches!(
            connector.get_currency_unit(),
            common_enums::CurrencyUnit::Minor
        ));
    }

    #[test]
    fn test_ppro_content_type() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        assert_eq!(connector.common_get_content_type(), "application/json");
    }

    // ── Webhook: get_event_type ───────────────────────────────────────────────

    #[test]
    fn test_webhook_event_type_capture_succeeded() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_CAPTURE_SUCCEEDED", "CAPTURED");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::PaymentIntentCaptureSuccess);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_charge_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        for event in &[
            "PAYMENT_CHARGE_FAILED",
            "PAYMENT_CHARGE_AUTHORIZATION_FAILED",
            "PAYMENT_CHARGE_DISCARDED",
        ] {
            let body = charge_webhook(event, "FAILED");
            let event_type = connector.get_event_type(make_request(&body), None, None)?;
            ensure_eq!(
                event_type,
                EventType::PaymentIntentFailure,
                "expected PaymentIntentFailure for {event}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_authorization_succeeded() -> Result<(), Box<dyn std::error::Error>>
    {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        for event in &[
            "PAYMENT_CHARGE_AUTHORIZATION_SUCCEEDED",
            "PAYMENT_CHARGE_SUCCESS",
        ] {
            let body = charge_webhook(event, "SUCCESS");
            let event_type = connector.get_event_type(make_request(&body), None, None)?;
            ensure_eq!(
                event_type,
                EventType::PaymentIntentAuthorizationSuccess,
                "expected PaymentIntentAuthorizationSuccess for {event}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_refund_succeeded() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_SUCCEEDED", "REFUNDED");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::RefundSuccess);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_refund_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_FAILED", "FAILED");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::RefundFailure);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_void_succeeded() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_VOID_SUCCEEDED", "VOIDED");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::PaymentIntentCancelled);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_void_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_VOID_FAILED", "FAILED");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::PaymentIntentCancelFailure);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_capture_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_CAPTURE_FAILED", "FAILED");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::PaymentIntentCaptureFailure);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_mandate_active() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = agreement_webhook("PAYMENT_AGREEMENT_ACTIVE", "ACTIVE");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::MandateActive);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_mandate_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = agreement_webhook("PAYMENT_AGREEMENT_FAILED", "FAILED");
        let event_type = connector.get_event_type(make_request(&body), None, None)?;
        ensure_eq!(event_type, EventType::MandateFailed);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_mandate_revoked() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        for event in &[
            "PAYMENT_AGREEMENT_REVOKED_BY_CONSUMER",
            "PAYMENT_AGREEMENT_REVOKED_BY_MERCHANT",
            "PAYMENT_AGREEMENT_REVOKED_BY_PROVIDER",
        ] {
            let body = agreement_webhook(event, "REVOKED");
            let event_type = connector.get_event_type(make_request(&body), None, None)?;
            ensure_eq!(
                event_type,
                EventType::MandateRevoked,
                "expected MandateRevoked for {event}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_invalid_body() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let result = connector.get_event_type(make_request(b"not-valid-json"), None, None);
        assert!(result.is_err(), "invalid JSON should return an error");
    }

    // ── Webhook: process_payment_webhook ─────────────────────────────────────

    #[test]
    fn test_process_payment_webhook_captured() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_CAPTURE_SUCCEEDED", "CAPTURED");
        let details = connector.process_payment_webhook(make_request(&body), None, None)?;
        ensure_eq!(
            details.status,
            common_enums::AttemptStatus::Charged,
            "CAPTURED charge should map to Charged"
        );
        ensure!(
            details.resource_id.is_some(),
            "resource_id should be set from charge.id"
        );
        ensure!(
            details.raw_connector_response.is_some(),
            "raw_connector_response should be populated"
        );
        Ok(())
    }

    #[test]
    fn test_process_payment_webhook_failed_with_failure_details()
    -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = r#"{
            "specversion": "1.0",
            "type": "PAYMENT_CHARGE_FAILED",
            "source": "https://api.sandbox.eu.ppro.com",
            "id": "evt_test_002",
            "time": "2024-01-01T00:00:00Z",
            "data": {
                "charge": {
                    "id": "pc_test_456",
                    "status": "FAILED",
                    "failure": {
                        "failureType": "AUTHORIZATION",
                        "failureCode": "CARD_DECLINED",
                        "failureMessage": "Card was declined"
                    }
                }
            }
        }"#
        .as_bytes();
        let details = connector.process_payment_webhook(make_request(body), None, None)?;
        ensure_eq!(details.status, common_enums::AttemptStatus::Failure);
        ensure_eq!(
            details.error_code.as_deref(),
            Some("CARD_DECLINED"),
            "error_code should be populated from failure"
        );
        ensure!(
            details.error_message.is_some(),
            "error_message should be populated"
        );
        Ok(())
    }

    #[test]
    fn test_process_payment_webhook_agreement_returns_error() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = r#"{
            "specversion": "1.0",
            "type": "PAYMENT_AGREEMENT_ACTIVE",
            "source": "https://api.sandbox.eu.ppro.com",
            "id": "evt_test_003",
            "time": "2024-01-01T00:00:00Z",
            "data": {
                "agreement": {
                    "id": "pa_test_789",
                    "status": "ACTIVE"
                }
            }
        }"#
        .as_bytes();
        let result = connector.process_payment_webhook(make_request(body), None, None);
        assert!(
            result.is_err(),
            "Agreement webhook data should return an error for process_payment_webhook"
        );
    }

    // ── Webhook: process_refund_webhook ──────────────────────────────────────

    #[test]
    fn test_process_refund_webhook_success() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_SUCCEEDED", "REFUNDED");
        let details = connector.process_refund_webhook(make_request(&body), None, None)?;
        ensure_eq!(
            details.status,
            common_enums::RefundStatus::Success,
            "REFUNDED status should map to RefundStatus::Success"
        );
        ensure!(
            details.connector_refund_id.is_some(),
            "connector_refund_id should be set from charge.id"
        );
        Ok(())
    }

    #[test]
    fn test_process_refund_webhook_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_FAILED", "FAILED");
        let details = connector.process_refund_webhook(make_request(&body), None, None)?;
        ensure_eq!(
            details.status,
            common_enums::RefundStatus::Failure,
            "FAILED status should map to RefundStatus::Failure"
        );
        Ok(())
    }
}

// ── Transformer unit tests ────────────────────────────────────────────────────
//
// These tests validate the serde round-trips and status mappings for each flow's
// request / response structs without requiring a full RouterDataV2 setup.
#[cfg(test)]
mod transformer_tests {
    use super::super::transformers::*;
    use common_utils::MinorUnit;

    macro_rules! ensure_eq {
        ($left:expr, $right:expr $(,)?) => {{
            let left = &$left;
            let right = &$right;
            if left != right {
                return Err(format!("assertion failed: {left:?} != {right:?}").into());
            }
        }};
        ($left:expr, $right:expr, $($msg:tt)+) => {{
            let left = &$left;
            let right = &$right;
            if left != right {
                return Err(
                    format!("{}: {left:?} != {right:?}", format_args!($($msg)+)).into(),
                );
            }
        }};
    }

    macro_rules! ensure {
        ($cond:expr $(,)?) => {{
            if !($cond) {
                return Err(concat!("assertion failed: ", stringify!($cond)).into());
            }
        }};
        ($cond:expr, $($msg:tt)+) => {{
            if !($cond) {
                return Err(format!($($msg)+).into());
            }
        }};
    }

    // ── Authorize / PSync response deserialization ────────────────────────────

    /// All PproPaymentStatus values round-trip through serde correctly.
    #[test]
    fn test_payment_status_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                "\"AUTHORIZATION_PROCESSING\"",
                PproPaymentStatus::AuthorizationProcessing,
            ),
            (
                "\"CAPTURE_PROCESSING\"",
                PproPaymentStatus::CaptureProcessing,
            ),
            (
                "\"AUTHENTICATION_PENDING\"",
                PproPaymentStatus::AuthenticationPending,
            ),
            (
                "\"AUTHORIZATION_ASYNC\"",
                PproPaymentStatus::AuthorizationAsync,
            ),
            ("\"CAPTURE_PENDING\"", PproPaymentStatus::CapturePending),
            ("\"CAPTURED\"", PproPaymentStatus::Captured),
            ("\"FAILED\"", PproPaymentStatus::Failed),
            ("\"DISCARDED\"", PproPaymentStatus::Discarded),
            ("\"VOIDED\"", PproPaymentStatus::Voided),
            ("\"REFUND_SETTLED\"", PproPaymentStatus::RefundSettled),
            ("\"SUCCESS\"", PproPaymentStatus::Success),
            ("\"REFUNDED\"", PproPaymentStatus::Refunded),
            ("\"REJECTED\"", PproPaymentStatus::Rejected),
            ("\"DECLINED\"", PproPaymentStatus::Declined),
        ];
        for (json, expected) in cases {
            let parsed: PproPaymentStatus = serde_json::from_str(json)?;
            ensure_eq!(parsed, expected, "mismatch for {json}");
        }
        Ok(())
    }

    /// A minimal authorize response with `AUTHENTICATION_PENDING` and a redirect URL.
    #[test]
    fn test_authorize_response_with_redirect() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "id": "charge_abc123",
            "status": "AUTHENTICATION_PENDING",
            "authenticationMethods": [
                {
                    "type": "REDIRECT",
                    "details": {
                        "requestUrl": "https://redirect.ppro.com/auth",
                        "requestMethod": "GET"
                    }
                }
            ]
        }"#;
        let resp: PproPaymentsResponse = serde_json::from_str(json)?;
        ensure_eq!(resp.id, "charge_abc123");
        ensure_eq!(resp.status, PproPaymentStatus::AuthenticationPending);
        let methods = resp
            .authentication_methods
            .ok_or("should have auth methods")?;
        ensure_eq!(methods.len(), 1);
        let method = methods.first().ok_or("methods should be non-empty")?;
        ensure_eq!(method.r#type, PproAuthenticationType::Redirect);
        let details = method.details.as_ref().ok_or("should have details")?;
        ensure_eq!(
            details.request_url.as_deref(),
            Some("https://redirect.ppro.com/auth")
        );
        ensure_eq!(details.request_method, Some(PproHttpMethod::Get));
        Ok(())
    }

    /// A captured response carries the instrument_id for mandate storage.
    #[test]
    fn test_authorize_response_captured_with_instrument_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "id": "charge_xyz789",
            "status": "CAPTURED",
            "instrumentId": "instr_abc123"
        }"#;
        let resp: PproPaymentsResponse = serde_json::from_str(json)?;
        ensure_eq!(resp.status, PproPaymentStatus::Captured);
        ensure_eq!(
            resp.instrument_id.as_deref(),
            Some("instr_abc123"),
            "instrumentId should be captured"
        );
        Ok(())
    }

    /// A failed response carries failure details.
    #[test]
    fn test_authorize_response_failed_with_failure() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "id": "charge_fail",
            "status": "FAILED",
            "failure": {
                "failureType": "AUTHORIZATION",
                "failureCode": "INSUFFICIENT_FUNDS",
                "failureMessage": "Insufficient funds"
            }
        }"#;
        let resp: PproPaymentsResponse = serde_json::from_str(json)?;
        ensure_eq!(resp.status, PproPaymentStatus::Failed);
        let failure = resp.failure.ok_or("should have failure")?;
        ensure_eq!(failure.failure_type, "AUTHORIZATION");
        ensure_eq!(failure.failure_code.as_deref(), Some("INSUFFICIENT_FUNDS"));
        ensure_eq!(failure.failure_message, "Insufficient funds");
        Ok(())
    }

    // ── Capture request serialization ────────────────────────────────────────

    #[test]
    fn test_capture_request_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let req = PproCaptureRequest {
            amount: MinorUnit::new(2500),
        };
        let json: serde_json::Value = serde_json::to_value(&req)?;
        ensure_eq!(
            json.get("amount"),
            Some(&serde_json::json!(2500)),
            "amount should be serialized as integer"
        );
        Ok(())
    }

    // ── Void request serialization ────────────────────────────────────────────

    #[test]
    fn test_void_request_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let req = PproVoidRequest {
            amount: MinorUnit::new(1000),
        };
        let json: serde_json::Value = serde_json::to_value(&req)?;
        ensure_eq!(json.get("amount"), Some(&serde_json::json!(1000)));
        Ok(())
    }

    // ── Refund request serialization ─────────────────────────────────────────

    #[test]
    fn test_refund_request_serialization_with_reason() -> Result<(), Box<dyn std::error::Error>> {
        let req = PproRefundRequest {
            amount: MinorUnit::new(500),
            refund_reason: Some(PproRefundReason::Fraud),
        };
        let json: serde_json::Value = serde_json::to_value(&req)?;
        ensure_eq!(json.get("amount"), Some(&serde_json::json!(500)));
        ensure!(
            json.get("refundReason").is_some_and(|v| !v.is_null()),
            "refundReason should be present"
        );
        Ok(())
    }

    #[test]
    fn test_refund_request_serialization_no_reason() -> Result<(), Box<dyn std::error::Error>> {
        let req = PproRefundRequest {
            amount: MinorUnit::new(300),
            refund_reason: None,
        };
        let json: serde_json::Value = serde_json::to_value(&req)?;
        ensure_eq!(json.get("amount"), Some(&serde_json::json!(300)));
        ensure!(
            json.get("refundReason").is_none(),
            "refundReason should be omitted when None"
        );
        Ok(())
    }

    // ── RSync response (refund sync) ─────────────────────────────────────────

    /// REFUND_SETTLED and REFUNDED indicate a successful refund.
    #[test]
    fn test_rsync_response_refunded_statuses() -> Result<(), Box<dyn std::error::Error>> {
        for status in &["REFUND_SETTLED", "REFUNDED"] {
            let json = format!(r#"{{"id":"ref_001","status":"{status}"}}"#);
            let resp: PproPaymentsResponse = serde_json::from_str(&json)?;
            ensure!(
                matches!(
                    resp.status,
                    PproPaymentStatus::RefundSettled | PproPaymentStatus::Refunded
                ),
                "status {status} should deserialize to a refund-success variant"
            );
        }
        Ok(())
    }

    // ── SetupMandate (agreement) response deserialization ────────────────────

    #[test]
    fn test_agreement_response_authentication_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "id": "agr_abc123",
            "status": "AUTHENTICATION_PENDING",
            "authenticationMethods": [
                {
                    "type": "REDIRECT",
                    "details": {
                        "requestUrl": "https://auth.ppro.com/agr",
                        "requestMethod": "GET"
                    }
                }
            ]
        }"#;
        let resp: PproAgreementResponse = serde_json::from_str(json)?;
        ensure_eq!(resp.id, "agr_abc123");
        ensure_eq!(resp.status, PproAgreementStatus::AuthenticationPending);
        let methods = resp
            .authentication_methods
            .ok_or("should have auth methods")?;
        let method = methods.first().ok_or("methods should be non-empty")?;
        ensure_eq!(method.r#type, PproAuthenticationType::Redirect);
        ensure_eq!(
            method
                .details
                .as_ref()
                .and_then(|d| d.request_url.as_deref()),
            Some("https://auth.ppro.com/agr")
        );
        Ok(())
    }

    #[test]
    fn test_agreement_response_active_with_instrument_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "id": "agr_xyz456",
            "status": "ACTIVE",
            "instrumentId": "instr_mandate_001"
        }"#;
        let resp: PproAgreementResponse = serde_json::from_str(json)?;
        ensure_eq!(resp.status, PproAgreementStatus::Active);
        ensure_eq!(
            resp.instrument_id.as_deref(),
            Some("instr_mandate_001"),
            "instrumentId should be stored as mandate reference"
        );
        Ok(())
    }

    #[test]
    fn test_agreement_response_failed() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "id": "agr_fail",
            "status": "FAILED",
            "failure": {
                "failureType": "AUTHENTICATION",
                "failureMessage": "Consumer rejected the mandate"
            }
        }"#;
        let resp: PproAgreementResponse = serde_json::from_str(json)?;
        ensure_eq!(resp.status, PproAgreementStatus::Failed);
        let failure = resp.failure.ok_or("should have failure")?;
        ensure_eq!(failure.failure_type, "AUTHENTICATION");
        Ok(())
    }

    // ── Error response deserialization ───────────────────────────────────────

    #[test]
    fn test_error_response_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"status": 422, "failureMessage": "Validation failed"}"#;
        let resp: PproErrorResponse = serde_json::from_str(json)?;
        ensure_eq!(resp.status, 422);
        ensure_eq!(resp.failure_message, "Validation failed");
        Ok(())
    }
}
