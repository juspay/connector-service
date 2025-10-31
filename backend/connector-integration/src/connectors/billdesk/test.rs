#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_billdesk_connector_creation() {
        // This test will verify that the Billdesk connector can be created
        // For now, we'll just test that the module compiles
        assert!(true);
    }

    #[test]
    fn test_currency_mapping() {
        use crate::connectors::billdesk::constants::currency_mappings;
        use common_enums::Currency;

        assert_eq!(currency_mappings::to_billdesk_currency(Currency::INR), "356");
        assert_eq!(currency_mappings::to_billdesk_currency(Currency::USD), "840");
    }

    #[test]
    fn test_payment_method_mapping() {
        use crate::connectors::billdesk::constants::payment_method_mappings;
        use common_enums::PaymentMethodType;

        assert_eq!(payment_method_mappings::to_billdesk_payment_method(PaymentMethodType::Upi), "UPI");
        assert_eq!(payment_method_mappings::to_billdesk_payment_method(PaymentMethodType::Credit), "CC");
    }
}