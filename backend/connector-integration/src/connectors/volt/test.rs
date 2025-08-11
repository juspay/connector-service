#[cfg(test)]
mod tests {
    use common_enums::AttemptStatus;
    use domain_types::{connector_types::EventType, router_data::ConnectorAuthType};
    use hyperswitch_masking::Secret;

    use crate::connectors::volt::transformers::{
        get_volt_payment_status, get_volt_webhook_event_type, VoltAuthType, VoltEventType, VoltPaymentStatus,
    };

    #[test]
    fn test_volt_payment_status_mapping() {
        assert_eq!(
            get_volt_payment_status(VoltPaymentStatus::Completed),
            AttemptStatus::Charged
        );
        assert_eq!(
            get_volt_payment_status(VoltPaymentStatus::Failed),
            AttemptStatus::Failure
        );
        assert_eq!(
            get_volt_payment_status(VoltPaymentStatus::BankRedirect),
            AttemptStatus::AuthenticationPending
        );
        assert_eq!(
            get_volt_payment_status(VoltPaymentStatus::NewPayment),
            AttemptStatus::Started
        );
    }

    #[test]
    fn test_volt_webhook_event_mapping() {
        use domain_types::connector_types::EventType;
        
        assert_eq!(
            get_volt_webhook_event_type(VoltEventType::PaymentCompleted),
            EventType::Payment
        );
        assert_eq!(
            get_volt_webhook_event_type(VoltEventType::PaymentFailed),
            EventType::Payment
        );
        assert_eq!(
            get_volt_webhook_event_type(VoltEventType::RefundCompleted),
            EventType::Refund
        );
    }

    #[test]
    fn test_volt_auth_type_conversion() {
        let auth_type = ConnectorAuthType::MultiAuthKey {
            api_key: Secret::new("test_username".to_string()),
            key1: Secret::new("test_client_id".to_string()),
            api_secret: Secret::new("test_password".to_string()),
            key2: Secret::new("test_client_secret".to_string()),
        };

        let volt_auth = VoltAuthType::try_from(&auth_type);
        assert!(volt_auth.is_ok());
    }

    #[test]
    fn test_volt_auth_type_invalid_conversion() {
        let auth_type = ConnectorAuthType::HeaderKey {
            api_key: Secret::new("test_key".to_string()),
        };

        let volt_auth = VoltAuthType::try_from(&auth_type);
        assert!(volt_auth.is_err());
    }
}