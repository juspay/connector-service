#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use common_enums::AttemptStatus;
    use domain_types::{
        connector_types::{EventType, HttpMethod, RequestDetails, WebhookResourceReference},
        payment_method_data::DefaultPCIHolder,
    };
    use interfaces::connector_types::IncomingWebhook;

    use crate::connectors::noon::{
        transformers::{get_payment_status, normalize_noon_order_name, NoonPaymentStatus},
        Noon,
    };

    macro_rules! ensure_eq {
        ($left:expr, $right:expr $(,)?) => {{
            let left = &$left;
            let right = &$right;
            if left != right {
                return Err(format!("assertion failed: {left:?} != {right:?}").into());
            }
        }};
    }

    fn make_request(body: &[u8]) -> RequestDetails {
        RequestDetails {
            method: HttpMethod::Post,
            uri: None,
            headers: HashMap::new(),
            body: body.to_vec(),
            query_params: None,
        }
    }

    fn webhook(event_type: &str, order_status: &str, merchant_txn_ref: Option<&str>) -> Vec<u8> {
        let txn_ref = merchant_txn_ref
            .map(|reference| format!(r#","merchantTxnRef":"{reference}""#))
            .unwrap_or_default();
        format!(
            r#"{{"orderId":12345,"orderStatus":"{order_status}","eventType":"{event_type}","eventId":"evt-1","timeStamp":"2024-01-01T00:00:00Z"{txn_ref}}}"#
        )
        .into_bytes()
    }

    fn event_type(
        event_type: &str,
        order_status: &str,
    ) -> Result<EventType, Box<dyn std::error::Error>> {
        let connector = Noon::<DefaultPCIHolder>::new();
        connector
            .get_event_type(make_request(&webhook(event_type, order_status, None)))
            .map_err(|err| format!("{err:?}").into())
    }

    #[test]
    fn empty_body_is_endpoint_verification() -> Result<(), Box<dyn std::error::Error>> {
        let connector = Noon::<DefaultPCIHolder>::new();
        let event = connector
            .get_event_type(make_request(b""))
            .map_err(|err| format!("{err:?}"))?;
        ensure_eq!(event, EventType::EndpointVerification);
        Ok(())
    }

    #[test]
    fn payment_event_matrix() -> Result<(), Box<dyn std::error::Error>> {
        ensure_eq!(
            event_type("Sale", "CAPTURED")?,
            EventType::PaymentIntentSuccess
        );
        ensure_eq!(
            event_type("Capture", "PARTIALLY_CAPTURED")?,
            EventType::PaymentIntentCaptureSuccess
        );
        ensure_eq!(
            event_type("Authorize", "AUTHORIZED")?,
            EventType::PaymentIntentAuthorizationSuccess
        );
        ensure_eq!(
            event_type("Fail", "FAILED")?,
            EventType::PaymentIntentFailure
        );
        ensure_eq!(
            event_type("Reject", "REJECTED")?,
            EventType::PaymentIntentFailure
        );
        ensure_eq!(
            event_type("Reverse", "REVERSED")?,
            EventType::PaymentIntentCancelled
        );
        Ok(())
    }

    #[test]
    fn reverse_with_authorized_is_a_failed_void() -> Result<(), Box<dyn std::error::Error>> {
        ensure_eq!(
            event_type("Reverse", "AUTHORIZED")?,
            EventType::PaymentIntentCancelFailure
        );
        Ok(())
    }

    #[test]
    fn failed_later_operation_is_not_a_payment_failure() -> Result<(), Box<dyn std::error::Error>> {
        ensure_eq!(
            event_type("Fail", "CAPTURED")?,
            EventType::IncomingWebhookEventUnspecified
        );
        Ok(())
    }

    #[test]
    fn refund_event_matrix() -> Result<(), Box<dyn std::error::Error>> {
        ensure_eq!(event_type("Refund", "REFUNDED")?, EventType::RefundSuccess);
        ensure_eq!(
            event_type("Refund", "PARTIALLY_REFUNDED")?,
            EventType::RefundSuccess
        );
        ensure_eq!(
            event_type("Refund", "PENDING")?,
            EventType::RefundProcessing
        );
        ensure_eq!(
            event_type("Refund", "CAPTURED")?,
            EventType::IncomingWebhookEventUnspecified
        );
        Ok(())
    }

    #[test]
    fn undocumented_pairs_are_unspecified() -> Result<(), Box<dyn std::error::Error>> {
        ensure_eq!(
            event_type("Sale", "AUTHORIZED")?,
            EventType::IncomingWebhookEventUnspecified
        );
        ensure_eq!(
            event_type("Cancel", "CANCELLED")?,
            EventType::IncomingWebhookEventUnspecified
        );
        Ok(())
    }

    #[test]
    fn refund_reference_carries_order_id_and_merchant_ref() -> Result<(), Box<dyn std::error::Error>>
    {
        let connector = Noon::<DefaultPCIHolder>::new();
        let reference = connector
            .get_webhook_event_reference(make_request(&webhook(
                "Refund",
                "REFUNDED",
                Some("refund_1"),
            )))
            .map_err(|err| format!("{err:?}"))?;
        match reference {
            Some(WebhookResourceReference::Refund(refund)) => {
                ensure_eq!(refund.connector_transaction_id, Some("12345".to_string()));
                ensure_eq!(refund.merchant_refund_id, Some("refund_1".to_string()));
            }
            other => return Err(format!("expected a refund reference, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn refund_webhook_status_comes_from_signed_fields() -> Result<(), Box<dyn std::error::Error>> {
        let connector = Noon::<DefaultPCIHolder>::new();
        let success = connector
            .process_refund_webhook(
                make_request(&webhook("Refund", "PARTIALLY_REFUNDED", Some("r1"))),
                None,
                None,
            )
            .map_err(|err| format!("{err:?}"))?;
        ensure_eq!(success.status, common_enums::RefundStatus::Success);
        let pending = connector
            .process_refund_webhook(
                make_request(&webhook("Refund", "PENDING", Some("r1"))),
                None,
                None,
            )
            .map_err(|err| format!("{err:?}"))?;
        ensure_eq!(pending.status, common_enums::RefundStatus::Pending);
        let not_a_refund = connector.process_refund_webhook(
            make_request(&webhook("Sale", "CAPTURED", None)),
            None,
            None,
        );
        ensure_eq!(not_a_refund.is_err(), true);
        Ok(())
    }

    #[test]
    fn payment_status_mapping() -> Result<(), Box<dyn std::error::Error>> {
        ensure_eq!(
            get_payment_status(NoonPaymentStatus::Captured, AttemptStatus::Pending),
            AttemptStatus::Charged
        );
        ensure_eq!(
            get_payment_status(NoonPaymentStatus::Reversed, AttemptStatus::Pending),
            AttemptStatus::Voided
        );
        ensure_eq!(
            get_payment_status(NoonPaymentStatus::Rejected, AttemptStatus::Pending),
            AttemptStatus::Failure
        );
        // LOCKED and unknown statuses never move the attempt.
        ensure_eq!(
            get_payment_status(NoonPaymentStatus::Locked, AttemptStatus::Authorized),
            AttemptStatus::Authorized
        );
        Ok(())
    }

    #[test]
    fn order_name_is_collapsed_trimmed_and_capped() -> Result<(), Box<dyn std::error::Error>> {
        ensure_eq!(
            normalize_noon_order_name("  two   words \n"),
            Some("two words".to_string())
        );
        ensure_eq!(normalize_noon_order_name("   "), None);
        ensure_eq!(
            normalize_noon_order_name(&"a".repeat(80)).map(|name| name.len()),
            Some(50)
        );
        Ok(())
    }
}
