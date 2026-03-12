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
    fn test_webhook_event_type_capture_succeeded() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_CAPTURE_SUCCEEDED", "CAPTURED");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::PaymentIntentCaptureSuccess);
    }

    #[test]
    fn test_webhook_event_type_charge_failed() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        for event in &[
            "PAYMENT_CHARGE_FAILED",
            "PAYMENT_CHARGE_AUTHORIZATION_FAILED",
            "PAYMENT_CHARGE_DISCARDED",
        ] {
            let body = charge_webhook(event, "FAILED");
            let event_type = connector
                .get_event_type(make_request(&body), None, None)
                .expect("should parse event type");
            assert_eq!(
                event_type,
                EventType::PaymentIntentFailure,
                "expected PaymentIntentFailure for {event}"
            );
        }
    }

    #[test]
    fn test_webhook_event_type_authorization_succeeded() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        for event in &[
            "PAYMENT_CHARGE_AUTHORIZATION_SUCCEEDED",
            "PAYMENT_CHARGE_SUCCESS",
        ] {
            let body = charge_webhook(event, "SUCCESS");
            let event_type = connector
                .get_event_type(make_request(&body), None, None)
                .expect("should parse event type");
            assert_eq!(
                event_type,
                EventType::PaymentIntentAuthorizationSuccess,
                "expected PaymentIntentAuthorizationSuccess for {event}"
            );
        }
    }

    #[test]
    fn test_webhook_event_type_refund_succeeded() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_SUCCEEDED", "REFUNDED");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::RefundSuccess);
    }

    #[test]
    fn test_webhook_event_type_refund_failed() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_FAILED", "FAILED");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::RefundFailure);
    }

    #[test]
    fn test_webhook_event_type_void_succeeded() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_VOID_SUCCEEDED", "VOIDED");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::PaymentIntentCancelled);
    }

    #[test]
    fn test_webhook_event_type_void_failed() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_VOID_FAILED", "FAILED");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::PaymentIntentCancelFailure);
    }

    #[test]
    fn test_webhook_event_type_capture_failed() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_CAPTURE_FAILED", "FAILED");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::PaymentIntentCaptureFailure);
    }

    #[test]
    fn test_webhook_event_type_mandate_active() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_AGREEMENT_ACTIVE", "SUCCESS");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::MandateActive);
    }

    #[test]
    fn test_webhook_event_type_mandate_failed() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_AGREEMENT_FAILED", "FAILED");
        let event_type = connector
            .get_event_type(make_request(&body), None, None)
            .expect("should parse event type");
        assert_eq!(event_type, EventType::MandateFailed);
    }

    #[test]
    fn test_webhook_event_type_mandate_revoked() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        for event in &[
            "PAYMENT_AGREEMENT_REVOKED_BY_CONSUMER",
            "PAYMENT_AGREEMENT_REVOKED_BY_MERCHANT",
            "PAYMENT_AGREEMENT_REVOKED_BY_PROVIDER",
        ] {
            let body = charge_webhook(event, "REVOKED");
            let event_type = connector
                .get_event_type(make_request(&body), None, None)
                .expect("should parse event type");
            assert_eq!(
                event_type,
                EventType::MandateRevoked,
                "expected MandateRevoked for {event}"
            );
        }
    }

    #[test]
    fn test_webhook_event_type_invalid_body() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let result = connector.get_event_type(make_request(b"not-valid-json"), None, None);
        assert!(result.is_err(), "invalid JSON should return an error");
    }

    // ── Webhook: process_payment_webhook ─────────────────────────────────────

    #[test]
    fn test_process_payment_webhook_captured() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_CAPTURE_SUCCEEDED", "CAPTURED");
        let details = connector
            .process_payment_webhook(make_request(&body), None, None)
            .expect("should process webhook");
        assert_eq!(
            details.status,
            common_enums::AttemptStatus::Charged,
            "CAPTURED charge should map to Charged"
        );
        assert!(
            details.resource_id.is_some(),
            "resource_id should be set from charge.id"
        );
        assert!(
            details.raw_connector_response.is_some(),
            "raw_connector_response should be populated"
        );
    }

    #[test]
    fn test_process_payment_webhook_failed_with_failure_details() {
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
        let details = connector
            .process_payment_webhook(make_request(body), None, None)
            .expect("should process webhook");
        assert_eq!(details.status, common_enums::AttemptStatus::Failure);
        assert_eq!(
            details.error_code.as_deref(),
            Some("CARD_DECLINED"),
            "error_code should be populated from failure"
        );
        assert!(
            details.error_message.is_some(),
            "error_message should be populated"
        );
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
    fn test_process_refund_webhook_success() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_SUCCEEDED", "REFUNDED");
        let details = connector
            .process_refund_webhook(make_request(&body), None, None)
            .expect("should process refund webhook");
        assert_eq!(
            details.status,
            common_enums::RefundStatus::Success,
            "REFUNDED status should map to RefundStatus::Success"
        );
        assert!(
            details.connector_refund_id.is_some(),
            "connector_refund_id should be set from charge.id"
        );
    }

    #[test]
    fn test_process_refund_webhook_failed() {
        let connector = connectors::ppro::Ppro::<DefaultPCIHolder>::new();
        let body = charge_webhook("PAYMENT_CHARGE_REFUND_FAILED", "FAILED");
        let details = connector
            .process_refund_webhook(make_request(&body), None, None)
            .expect("should process refund webhook");
        assert_eq!(
            details.status,
            common_enums::RefundStatus::Failure,
            "FAILED status should map to RefundStatus::Failure"
        );
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

    // ── Authorize / PSync response deserialization ────────────────────────────

    /// All PproPaymentStatus values round-trip through serde correctly.
    #[test]
    fn test_payment_status_deserialization() {
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
            let parsed: PproPaymentStatus =
                serde_json::from_str(json).unwrap_or_else(|_| panic!("failed to parse {json}"));
            assert_eq!(parsed, expected, "mismatch for {json}");
        }
    }

    /// A minimal authorize response with `AUTHENTICATION_PENDING` and a redirect URL.
    #[test]
    fn test_authorize_response_with_redirect() {
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
        let resp: PproPaymentsResponse = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(resp.id, "charge_abc123");
        assert_eq!(resp.status, PproPaymentStatus::AuthenticationPending);
        let methods = resp
            .authentication_methods
            .expect("should have auth methods");
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].r#type, PproAuthenticationType::Redirect);
        let details = methods[0].details.as_ref().expect("should have details");
        assert_eq!(
            details.request_url.as_deref(),
            Some("https://redirect.ppro.com/auth")
        );
        assert_eq!(details.request_method.as_deref(), Some("GET"));
    }

    /// A captured response carries the instrument_id for mandate storage.
    #[test]
    fn test_authorize_response_captured_with_instrument_id() {
        let json = r#"{
            "id": "charge_xyz789",
            "status": "CAPTURED",
            "instrumentId": "instr_abc123"
        }"#;
        let resp: PproPaymentsResponse = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(resp.status, PproPaymentStatus::Captured);
        assert_eq!(
            resp.instrument_id.as_deref(),
            Some("instr_abc123"),
            "instrumentId should be captured"
        );
    }

    /// A failed response carries failure details.
    #[test]
    fn test_authorize_response_failed_with_failure() {
        let json = r#"{
            "id": "charge_fail",
            "status": "FAILED",
            "failure": {
                "failureType": "AUTHORIZATION",
                "failureCode": "INSUFFICIENT_FUNDS",
                "failureMessage": "Insufficient funds"
            }
        }"#;
        let resp: PproPaymentsResponse = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(resp.status, PproPaymentStatus::Failed);
        let failure = resp.failure.expect("should have failure");
        assert_eq!(failure.failure_type, "AUTHORIZATION");
        assert_eq!(failure.failure_code.as_deref(), Some("INSUFFICIENT_FUNDS"));
        assert_eq!(failure.failure_message, "Insufficient funds");
    }

    // ── Capture request serialization ────────────────────────────────────────

    #[test]
    fn test_capture_request_serialization() {
        let req = PproCaptureRequest {
            amount: MinorUnit::new(2500),
        };
        let json: serde_json::Value = serde_json::to_value(&req).expect("should serialize");
        assert_eq!(
            json["amount"], 2500,
            "amount should be serialized as integer"
        );
    }

    // ── Void request serialization ────────────────────────────────────────────

    #[test]
    fn test_void_request_serialization() {
        let req = PproVoidRequest {
            amount: MinorUnit::new(1000),
        };
        let json: serde_json::Value = serde_json::to_value(&req).expect("should serialize");
        assert_eq!(json["amount"], 1000);
    }

    // ── Refund request serialization ─────────────────────────────────────────

    #[test]
    fn test_refund_request_serialization_with_reason() {
        let req = PproRefundRequest {
            amount: MinorUnit::new(500),
            refund_reason: Some(PproRefundReason::Fraud),
        };
        let json: serde_json::Value = serde_json::to_value(&req).expect("should serialize");
        assert_eq!(json["amount"], 500);
        assert!(
            !json["refundReason"].is_null(),
            "refundReason should be present"
        );
    }

    #[test]
    fn test_refund_request_serialization_no_reason() {
        let req = PproRefundRequest {
            amount: MinorUnit::new(300),
            refund_reason: None,
        };
        let json: serde_json::Value = serde_json::to_value(&req).expect("should serialize");
        assert_eq!(json["amount"], 300);
        assert!(
            json.get("refundReason").is_none(),
            "refundReason should be omitted when None"
        );
    }

    // ── RSync response (refund sync) ─────────────────────────────────────────

    /// REFUND_SETTLED and REFUNDED indicate a successful refund.
    #[test]
    fn test_rsync_response_refunded_statuses() {
        for status in &["REFUND_SETTLED", "REFUNDED"] {
            let json = format!(r#"{{"id":"ref_001","status":"{status}"}}"#);
            let resp: PproPaymentsResponse =
                serde_json::from_str(&json).expect("should deserialize");
            assert!(
                matches!(
                    resp.status,
                    PproPaymentStatus::RefundSettled | PproPaymentStatus::Refunded
                ),
                "status {status} should deserialize to a refund-success variant"
            );
        }
    }

    // ── SetupMandate (agreement) response deserialization ────────────────────

    #[test]
    fn test_agreement_response_authentication_pending() {
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
        let resp: PproAgreementResponse = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(resp.id, "agr_abc123");
        assert_eq!(resp.status, PproAgreementStatus::AuthenticationPending);
        let methods = resp
            .authentication_methods
            .expect("should have auth methods");
        assert_eq!(methods[0].r#type, PproAuthenticationType::Redirect);
        assert_eq!(
            methods[0]
                .details
                .as_ref()
                .and_then(|d| d.request_url.as_deref()),
            Some("https://auth.ppro.com/agr")
        );
    }

    #[test]
    fn test_agreement_response_active_with_instrument_id() {
        let json = r#"{
            "id": "agr_xyz456",
            "status": "ACTIVE",
            "instrumentId": "instr_mandate_001"
        }"#;
        let resp: PproAgreementResponse = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(resp.status, PproAgreementStatus::Active);
        assert_eq!(
            resp.instrument_id.as_deref(),
            Some("instr_mandate_001"),
            "instrumentId should be stored as mandate reference"
        );
    }

    #[test]
    fn test_agreement_response_failed() {
        let json = r#"{
            "id": "agr_fail",
            "status": "FAILED",
            "failure": {
                "failureType": "AUTHENTICATION",
                "failureMessage": "Consumer rejected the mandate"
            }
        }"#;
        let resp: PproAgreementResponse = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(resp.status, PproAgreementStatus::Failed);
        let failure = resp.failure.expect("should have failure");
        assert_eq!(failure.failure_type, "AUTHENTICATION");
    }

    // ── Error response deserialization ───────────────────────────────────────

    #[test]
    fn test_error_response_deserialization() {
        let json = r#"{"status": 422, "failureMessage": "Validation failed"}"#;
        let resp: PproErrorResponse = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(resp.status, 422);
        assert_eq!(resp.failure_message, "Validation failed");
    }
}
