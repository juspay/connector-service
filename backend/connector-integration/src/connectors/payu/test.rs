#[cfg(test)]
mod test {
    use super::transformers::*;
    use super::constants;
    use common_utils::{types::StringMajorUnit, pii::Email};
    use common_enums::Currency;
    use hyperswitch_masking::Secret;
    use serde_json::json;

    #[test]
    fn test_payu_payment_request_serialization() {
        let request = PayuPaymentRequest {
            key: "test_key".to_string(),
            txnid: "test_txn_123".to_string(),
            amount: StringMajorUnit::new("10.00".to_string()),
            currency: Currency::INR,
            productinfo: "Test Product".to_string(),
            firstname: Secret::new("John".to_string()),
            lastname: Some(Secret::new("Doe".to_string())),
            email: Email::from("test@example.com"),
            phone: Secret::new("9876543210".to_string()),
            surl: "https://example.com/success".to_string(),
            furl: "https://example.com/failure".to_string(),
            pg: Some("UPI".to_string()),
            bankcode: Some("UPI".to_string()),
            vpa: Some("test@upi".to_string()),
            txn_s2s_flow: "2".to_string(),
            s2s_client_ip: Secret::new("127.0.0.1".to_string()),
            s2s_device_info: "web".to_string(),
            api_version: Some("2.0".to_string()),
            hash: "test_hash".to_string(),
            udf1: Some("udf1_value".to_string()),
            udf2: Some("udf2_value".to_string()),
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
            offer_key: None,
            si: None,
            si_details: None,
            beneficiarydetail: None,
            user_token: None,
            offer_auto_apply: None,
            additional_charges: None,
            additional_gst_charges: None,
            upi_app_name: None,
        };

        let json = serde_json::to_value(&request).unwrap();
        
        // Verify key fields are present
        assert_eq!(json["key"], "test_key");
        assert_eq!(json["txnid"], "test_txn_123");
        assert_eq!(json["amount"], "10.00");
        assert_eq!(json["currency"], "INR");
        assert_eq!(json["pg"], "UPI");
        assert_eq!(json["bankcode"], "UPI");
        assert_eq!(json["vpa"], "test@upi");
        assert_eq!(json["txn_s2s_flow"], "2");
    }

    #[test]
    fn test_payu_sync_request_serialization() {
        let request = PayuSyncRequest {
            key: "test_key".to_string(),
            command: "verify_payment".to_string(),
            var1: "test_txn_123".to_string(),
            hash: "test_hash".to_string(),
        };

        let json = serde_json::to_value(&request).unwrap();
        
        assert_eq!(json["key"], "test_key");
        assert_eq!(json["command"], "verify_payment");
        assert_eq!(json["var1"], "test_txn_123");
        assert_eq!(json["hash"], "test_hash");
    }

    #[test]
    fn test_payu_status_deserialization() {
        // Test integer status
        let json_int = json!({"status": 1, "reference_id": "test_ref"});
        let response: PayuPaymentResponse = serde_json::from_value(json_int).unwrap();
        match response.status {
            Some(PayuStatusValue::IntStatus(1)) => assert!(true),
            _ => assert!(false, "Expected IntStatus(1)"),
        }

        // Test string status
        let json_str = json!({"status": "success", "reference_id": "test_ref"});
        let response: PayuPaymentResponse = serde_json::from_value(json_str).unwrap();
        match response.status {
            Some(PayuStatusValue::StringStatus(s)) => assert_eq!(s, "success"),
            _ => assert!(false, "Expected StringStatus('success')"),
        }
    }

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
}