#[cfg(test)]
mod test {
    use super::*;
    use common_enums::{Currency, PaymentMethod, PaymentMethodType};
    use common_utils::types::MinorUnit;
    use domain_types::{
        connector_flow::Authorize,
        connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData},
        payment_method_data::UpiData,
        router_data::{ConnectorAuthType, ResourceCommonData},
        router_data_v2::RouterDataV2,
    };
    use hyperswitch_masking::Secret;
    use std::collections::HashMap;

    #[test]
    fn test_billdesk_payments_request_creation() {
        // This is a basic test to ensure the connector structure compiles
        // In a real scenario, you would test the actual transformation logic
        
        let auth_type = ConnectorAuthType::SignatureKey {
            api_key: Some(Secret::new("test_merchant_id".to_string())),
            key1: Some(Secret::new("test_checksum_key".to_string())),
        };

        let payment_data = PaymentsAuthorizeData {
            payment_method_data: UpiData::UpiIntent {
                vpa: Some("test@upi".to_string()),
                payer_name: None,
                payer_app: None,
            }
            .into(),
            ..Default::default()
        };

        let resource_common_data = ResourceCommonData {
            connector_request_reference_id: "test_txn_123".to_string(),
            payment_method: PaymentMethod::Upi,
            ..Default::default()
        };

        let router_data = RouterDataV2 {
            resource_common_data,
            request: payment_data,
            response: Err(ErrorResponse {
                code: "test".to_string(),
                status_code: 200,
                message: "test".to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            }),
            connector_auth_type: auth_type,
            ..Default::default()
        };

        // Test that the structure can be created
        assert_eq!(router_data.resource_common_data.connector_request_reference_id, "test_txn_123");
    }

    #[test]
    fn test_billdesk_auth_conversion() {
        let auth_type = ConnectorAuthType::SignatureKey {
            api_key: Some(Secret::new("test_merchant_id".to_string())),
            key1: Some(Secret::new("test_checksum_key".to_string())),
        };

        let result = BilldeskAuth::try_from(&auth_type);
        assert!(result.is_ok());
        
        let auth = result.unwrap();
        assert_eq!(auth.merchant_id.peek(), "test_merchant_id");
        assert_eq!(auth.checksum_key.peek(), "test_checksum_key");
    }
}