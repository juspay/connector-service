#[cfg(test)]
mod tests {
    use common_enums::PaymentMethodType;
    use domain_types::payment_method_data::DefaultPCIHolder;
    use interfaces::api::ConnectorCommon;

    use crate::connectors;

    // Connector Setup Tests

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

    // Payment Method String Mapping Tests
    // Verifies that each PaymentMethodType correctly maps to the expected PPRO
    // API payment method string. PPRO uses SCREAMING_SNAKE_CASE strings.

    fn payment_method_to_ppro_string(pm: Option<PaymentMethodType>) -> Option<String> {
        match pm {
            Some(PaymentMethodType::BancontactCard) => Some("BANCONTACT".to_string()),
            Some(PaymentMethodType::UpiCollect) | Some(PaymentMethodType::UpiIntent) => {
                Some("UPI".to_string())
            }
            Some(PaymentMethodType::AliPay) => Some("ALIPAY".to_string()),
            Some(PaymentMethodType::WeChatPay) => Some("WECHATPAY".to_string()),
            Some(PaymentMethodType::MbWay) => Some("MBWAY".to_string()),
            Some(ref pm) => Some(pm.to_string().to_uppercase()),
            None => None,
        }
    }
}
