#[cfg(test)]
mod test {
    use super::constants;
    use serde_json::json;

    #[test]
    fn test_constants() {
        assert_eq!(constants::API_VERSION, "2.0");
        assert_eq!(constants::DEVICE_INFO, "web");
        assert_eq!(constants::PRODUCT_INFO, "Payment");
        assert_eq!(constants::UPI_PG, "UPI");
        assert_eq!(constants::UPI_COLLECT_BANKCODE, "UPI");
        assert_eq!(constants::UPI_INTENT_BANKCODE, "INTENT");
        assert_eq!(constants::UPI_S2S_FLOW, "2");
        assert_eq!(constants::COMMAND, "verify_payment");
    }

    #[test]
    fn test_payu_status_deserialization() {
        use super::transformers::PayuPaymentResponse;

        // Test integer status
        let json_int = json!({"status": 1, "reference_id": "test_ref"});
        let response: PayuPaymentResponse = serde_json::from_value(json_int).unwrap();
        match response.status {
            Some(super::transformers::PayuStatusValue::IntStatus(1)) => assert!(true),
            _ => assert!(false, "Expected IntStatus(1)"),
        }

        // Test string status
        let json_str = json!({"status": "success", "reference_id": "test_ref"});
        let response: PayuPaymentResponse = serde_json::from_value(json_str).unwrap();
        match response.status {
            Some(super::transformers::PayuStatusValue::StringStatus(s)) => assert_eq!(s, "success"),
            _ => assert!(false, "Expected StringStatus('success')"),
        }
    }
}