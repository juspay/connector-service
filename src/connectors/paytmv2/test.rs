#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paytmv2_connector_creation() {
        let connector: PayTMv2<domain_types::payment_method_data::UpiData> = PayTMv2::default();
        assert_eq!(connector.get_id(), "paytmv2");
    }

    #[test]
    fn test_signature_generation() {
        let signature = generate_signature("test_client_id", "test_merchant_id").unwrap();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64); // SHA256 hex length
    }
}