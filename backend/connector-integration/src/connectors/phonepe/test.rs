//! Tests for PhonePe connector
//!
//! This module contains unit tests for the PhonePe connector implementation,
//! covering UPI Intent, UPI QR, and UPI Collect flows.

#[cfg(test)]
mod tests {
    use super::super::transformers::{
        PhonePeAuthType, PhonePeInnerPayload, PhonePePaymentInstrument, PhonePePaymentRequest,
        PhonePeDeviceContext, PhonePeSuccessResponse, PhonePeErrorResponse,
    };
    use hyperswitch_domain_models::router_data::ConnectorAuthType;
    use masking::Secret;
    use serde_json;
    use base64::Engine;

    #[test]
    fn test_phonepe_auth_type_conversion() {
        let auth_type = ConnectorAuthType::SignatureKey {
            api_key: Secret::new("MERCHANT123".to_string()),
            key1: Secret::new("salt_key_123".to_string()),
            api_secret: Secret::new("1".to_string()),
        };

        let phonepe_auth = PhonePeAuthType::try_from(&auth_type).unwrap();
        
        assert_eq!(phonepe_auth.merchant_id.expose(), "MERCHANT123");
        assert_eq!(phonepe_auth.salt_key.expose(), "salt_key_123");
        assert_eq!(phonepe_auth.salt_index.expose(), "1");
    }

    #[test]
    fn test_phonepe_upi_intent_payload() {
        let inner_payload = PhonePeInnerPayload {
            merchant_id: "MERCHANT123".to_string(),
            merchant_transaction_id: "TXN123456".to_string(),
            merchant_user_id: Some("USER123".to_string()),
            amount: 10000, // 100 INR in paise
            callback_url: "https://webhook.example.com/phonepe".to_string(),
            mobile_number: Some("9876543210".to_string()),
            device_context: Some(PhonePeDeviceContext {
                device_os: "ANDROID".to_string(),
            }),
            payment_instrument: PhonePePaymentInstrument {
                instrument_type: "UPI_INTENT".to_string(),
                target_app: Some("GPAY".to_string()),
                vpa: None,
            },
        };

        let request = PhonePePaymentRequest::new(inner_payload).unwrap();
        
        // Verify that the request contains base64 encoded data
        assert!(!request.request.is_empty());
        
        // Decode and verify the base64 content
        let decoded = base64::engine::general_purpose::STANDARD.decode(&request.request).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        let decoded_json: serde_json::Value = serde_json::from_str(&decoded_str).unwrap();
        
        assert_eq!(decoded_json["merchantId"], "MERCHANT123");
        assert_eq!(decoded_json["merchantTransactionId"], "TXN123456");
        assert_eq!(decoded_json["amount"], 10000);
        assert_eq!(decoded_json["paymentInstrument"]["type"], "UPI_INTENT");
        assert_eq!(decoded_json["deviceContext"]["deviceOS"], "ANDROID");
    }

    #[test]
    fn test_phonepe_upi_qr_payload() {
        let inner_payload = PhonePeInnerPayload {
            merchant_id: "MERCHANT123".to_string(),
            merchant_transaction_id: "TXN123456".to_string(),
            merchant_user_id: None,
            amount: 5000, // 50 INR in paise
            callback_url: "https://webhook.example.com/phonepe".to_string(),
            mobile_number: Some("9876543210".to_string()),
            device_context: None, // No device context for QR
            payment_instrument: PhonePePaymentInstrument {
                instrument_type: "UPI_QR".to_string(),
                target_app: None,
                vpa: None,
            },
        };

        let request = PhonePePaymentRequest::new(inner_payload).unwrap();
        
        // Decode and verify the base64 content
        let decoded = base64::engine::general_purpose::STANDARD.decode(&request.request).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        let decoded_json: serde_json::Value = serde_json::from_str(&decoded_str).unwrap();
        
        assert_eq!(decoded_json["merchantId"], "MERCHANT123");
        assert_eq!(decoded_json["amount"], 5000);
        assert_eq!(decoded_json["paymentInstrument"]["type"], "UPI_QR");
        assert!(decoded_json["deviceContext"].is_null());
    }

    #[test]
    fn test_phonepe_upi_collect_payload() {
        let inner_payload = PhonePeInnerPayload {
            merchant_id: "MERCHANT123".to_string(),
            merchant_transaction_id: "TXN123456".to_string(),
            merchant_user_id: Some("USER123".to_string()),
            amount: 15000, // 150 INR in paise
            callback_url: "https://webhook.example.com/phonepe".to_string(),
            mobile_number: Some("9876543210".to_string()),
            device_context: None, // No device context for Collect
            payment_instrument: PhonePePaymentInstrument {
                instrument_type: "UPI_COLLECT".to_string(),
                target_app: None,
                vpa: Some("customer@paytm".to_string()),
            },
        };

        let request = PhonePePaymentRequest::new(inner_payload).unwrap();
        
        // Decode and verify the base64 content
        let decoded = base64::decode(&request.request).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        let decoded_json: serde_json::Value = serde_json::from_str(&decoded_str).unwrap();
        
        assert_eq!(decoded_json["merchantId"], "MERCHANT123");
        assert_eq!(decoded_json["amount"], 15000);
        assert_eq!(decoded_json["paymentInstrument"]["type"], "UPI_COLLECT");
        assert_eq!(decoded_json["paymentInstrument"]["vpa"], "customer@paytm");
        assert!(decoded_json["deviceContext"].is_null());
    }

    #[test]
    fn test_vpa_validation() {
        // Valid VPAs
        assert!(PhonePePaymentRequest::validate_vpa("user@paytm"));
        assert!(PhonePePaymentRequest::validate_vpa("user.name@phonepe"));
        assert!(PhonePePaymentRequest::validate_vpa("user-123@gpay"));
        assert!(PhonePePaymentRequest::validate_vpa("user_test@upi"));
        
        // Invalid VPAs
        assert!(!PhonePePaymentRequest::validate_vpa("invalid"));
        assert!(!PhonePePaymentRequest::validate_vpa("@paytm"));
        assert!(!PhonePePaymentRequest::validate_vpa("user@"));
        assert!(!PhonePePaymentRequest::validate_vpa("user@@paytm"));
        assert!(!PhonePePaymentRequest::validate_vpa(""));
    }

    #[test]
    fn test_phonepe_success_response_deserialization() {
        let json_response = r#"
        {
            "success": true,
            "code": "PAYMENT_SUCCESS",
            "message": "Payment successful",
            "data": {
                "merchantId": "MERCHANT123",
                "merchantTransactionId": "TXN123456",
                "instrumentResponse": {
                    "type": "UPI_INTENT",
                    "intentUrl": "upi://pay?pa=merchant@upi&pn=MerchantName&tid=TXN123456&am=100.00&cu=INR"
                },
                "responseCode": "SUCCESS",
                "responseCodeDescription": "Transaction successful"
            }
        }
        "#;

        let response: PhonePeSuccessResponse = serde_json::from_str(json_response).unwrap();
        
        assert!(response.success);
        assert_eq!(response.code, "PAYMENT_SUCCESS");
        assert_eq!(response.data.merchant_id, "MERCHANT123");
        assert_eq!(response.data.instrument_response.instrument_type, "UPI_INTENT");
        assert!(response.data.instrument_response.intent_url.is_some());
    }

    #[test]
    fn test_phonepe_error_response_deserialization() {
        let json_response = r#"
        {
            "success": false,
            "code": "PAYMENT_ERROR",
            "message": "Invalid VPA"
        }
        "#;

        let response: PhonePeErrorResponse = serde_json::from_str(json_response).unwrap();
        
        assert!(!response.success);
        assert_eq!(response.code, "PAYMENT_ERROR");
        assert_eq!(response.message.unwrap(), "Invalid VPA");
    }

    #[test]
    fn test_phonepe_qr_response_deserialization() {
        let json_response = r#"
        {
            "success": true,
            "code": "PAYMENT_SUCCESS",
            "message": "QR generated successfully",
            "data": {
                "merchantId": "MERCHANT123",
                "merchantTransactionId": "TXN123456",
                "instrumentResponse": {
                    "type": "UPI_QR",
                    "qrData": "upi://pay?pa=merchant@upi&pn=MerchantName&tid=TXN123456&am=100.00&cu=INR"
                }
            }
        }
        "#;

        let response: PhonePeSuccessResponse = serde_json::from_str(json_response).unwrap();
        
        assert!(response.success);
        assert_eq!(response.data.instrument_response.instrument_type, "UPI_QR");
        assert!(response.data.instrument_response.qr_data.is_some());
        assert!(response.data.instrument_response.intent_url.is_none());
    }

    #[test]
    fn test_base64_encoding_decoding() {
        let test_payload = PhonePeInnerPayload {
            merchant_id: "TEST123".to_string(),
            merchant_transaction_id: "TXN789".to_string(),
            merchant_user_id: None,
            amount: 1000,
            callback_url: "https://test.com/callback".to_string(),
            mobile_number: None,
            device_context: None,
            payment_instrument: PhonePePaymentInstrument {
                instrument_type: "UPI_INTENT".to_string(),
                target_app: None,
                vpa: None,
            },
        };

        let request = PhonePePaymentRequest::new(test_payload.clone()).unwrap();
        
        // Decode the base64 and verify it matches original payload
        let decoded = base64::decode(&request.request).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        let decoded_payload: PhonePeInnerPayload = serde_json::from_str(&decoded_str).unwrap();
        
        assert_eq!(decoded_payload.merchant_id, test_payload.merchant_id);
        assert_eq!(decoded_payload.merchant_transaction_id, test_payload.merchant_transaction_id);
        assert_eq!(decoded_payload.amount, test_payload.amount);
        assert_eq!(decoded_payload.payment_instrument.instrument_type, test_payload.payment_instrument.instrument_type);
    }
}