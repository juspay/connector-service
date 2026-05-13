#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use domain_types::{
        connector_types::{EventType, HttpMethod, RequestDetails, WebhookResourceReference},
        payment_method_data::DefaultPCIHolder,
    };
    use interfaces::{api::ConnectorCommon, connector_types::IncomingWebhook};

    use crate::connectors::{
        self,
        dummy::transformers::{parse_dummy_redirect_query, DummyRedirectStatus},
    };

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

    fn payment_webhook(event: &str, payment_id: &str) -> Vec<u8> {
        format!(
            r#"{{"event":"{event}","payment_id":"{payment_id}","merchant_reference_id":"dummy_ref_001"}}"#
        )
        .into_bytes()
    }

    fn refund_webhook(event: &str, refund_id: &str, payment_id: &str) -> Vec<u8> {
        format!(
            r#"{{"event":"{event}","payment_id":"{payment_id}","refund_id":"{refund_id}","merchant_reference_id":"dummy_ref_001"}}"#
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
                return Err(format!("{}: {left:?} != {right:?}", format_args!($($msg)+)).into());
            }
        }};
    }

    // ── Connector setup ──────────────────────────────────────────────────────

    #[test]
    fn test_dummy_connector_creation() {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        assert_eq!(connector.id(), "dummy");
    }

    #[test]
    fn test_dummy_currency_unit() {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        assert!(matches!(
            connector.get_currency_unit(),
            common_enums::CurrencyUnit::Minor
        ));
    }

    #[test]
    fn test_dummy_content_type() {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        assert_eq!(
            connector.common_get_content_type(),
            "application/x-www-form-urlencoded"
        );
    }

    // ── Webhook event-type parsing ───────────────────────────────────────────

    #[test]
    fn test_webhook_event_type_payment_succeeded() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = payment_webhook("payment_succeeded", "DUMMY-pi_001");
        let event_type = connector.get_event_type(make_request(&body))?;
        ensure_eq!(event_type, EventType::PaymentIntentSuccess);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_payment_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = payment_webhook("payment_failed", "DUMMY-pi_002");
        let event_type = connector.get_event_type(make_request(&body))?;
        ensure_eq!(event_type, EventType::PaymentIntentFailure);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_payment_processing() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = payment_webhook("payment_processing", "DUMMY-pi_003");
        let event_type = connector.get_event_type(make_request(&body))?;
        ensure_eq!(event_type, EventType::PaymentIntentProcessing);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_payment_cancelled() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = payment_webhook("payment_cancelled", "DUMMY-pi_004");
        let event_type = connector.get_event_type(make_request(&body))?;
        ensure_eq!(event_type, EventType::PaymentIntentCancelled);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_refund_succeeded() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = refund_webhook("refund_succeeded", "DUMMY-re_001", "DUMMY-pi_005");
        let event_type = connector.get_event_type(make_request(&body))?;
        ensure_eq!(event_type, EventType::RefundSuccess);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_refund_failed() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = refund_webhook("refund_failed", "DUMMY-re_002", "DUMMY-pi_006");
        let event_type = connector.get_event_type(make_request(&body))?;
        ensure_eq!(event_type, EventType::RefundFailure);
        Ok(())
    }

    #[test]
    fn test_webhook_event_type_invalid_body() {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = br#"{"event":"unknown_event_xyz"}"#;
        let result = connector.get_event_type(make_request(body));
        assert!(result.is_err());
    }

    // ── Webhook reference routing ────────────────────────────────────────────

    #[test]
    fn test_webhook_reference_for_payment_event() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = payment_webhook("payment_succeeded", "DUMMY-pi_007");
        let reference = connector
            .get_webhook_event_reference(make_request(&body))?
            .expect("payment reference");
        match reference {
            WebhookResourceReference::Payment(p) => {
                ensure_eq!(p.connector_transaction_id, Some("DUMMY-pi_007".to_string()));
            }
            other => return Err(format!("expected Payment ref, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn test_webhook_reference_for_refund_event() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = refund_webhook("refund_succeeded", "DUMMY-re_008", "DUMMY-pi_008");
        let reference = connector
            .get_webhook_event_reference(make_request(&body))?
            .expect("refund reference");
        match reference {
            WebhookResourceReference::Refund(r) => {
                ensure_eq!(r.connector_refund_id, Some("DUMMY-re_008".to_string()));
                ensure_eq!(r.connector_transaction_id, Some("DUMMY-pi_008".to_string()));
            }
            other => return Err(format!("expected Refund ref, got {other:?}").into()),
        }
        Ok(())
    }

    // ── verify_webhook_source ────────────────────────────────────────────────

    #[test]
    fn test_verify_webhook_source_always_true() -> Result<(), Box<dyn std::error::Error>> {
        let connector = connectors::dummy::Dummy::<DefaultPCIHolder>::new();
        let body = payment_webhook("payment_succeeded", "DUMMY-pi_009");
        let verified = connector.verify_webhook_source(make_request(&body), None, None)?;
        ensure_eq!(verified, true);
        Ok(())
    }

    // ── Redirect-query parser ────────────────────────────────────────────────

    #[test]
    fn test_redirect_query_parser_success() {
        let (status, id) =
            parse_dummy_redirect_query("dummy_status=success&dummy_id=DUMMY-pi_010");
        assert_eq!(status, Some(DummyRedirectStatus::Success));
        assert_eq!(id.as_deref(), Some("DUMMY-pi_010"));
    }

    #[test]
    fn test_redirect_query_parser_failure() {
        let (status, id) = parse_dummy_redirect_query("dummy_status=failure&dummy_id=DUMMY-pi_011");
        assert_eq!(status, Some(DummyRedirectStatus::Failure));
        assert_eq!(id.as_deref(), Some("DUMMY-pi_011"));
    }

    #[test]
    fn test_redirect_query_parser_pending() {
        let (status, _) = parse_dummy_redirect_query("dummy_status=pending");
        assert_eq!(status, Some(DummyRedirectStatus::Pending));
    }

    #[test]
    fn test_redirect_query_parser_missing_status() {
        let (status, id) = parse_dummy_redirect_query("dummy_id=only_id");
        assert!(status.is_none());
        assert_eq!(id.as_deref(), Some("only_id"));
    }

    #[test]
    fn test_redirect_query_parser_unknown_status() {
        let (status, _) = parse_dummy_redirect_query("dummy_status=gibberish&dummy_id=x");
        assert!(status.is_none());
    }

    #[test]
    fn test_redirect_query_parser_ignores_unrelated_params() {
        let (status, id) = parse_dummy_redirect_query(
            "status=success&payment_id=tampered&dummy_status=success&dummy_id=real_id",
        );
        assert_eq!(status, Some(DummyRedirectStatus::Success));
        assert_eq!(id.as_deref(), Some("real_id"));
    }
}
