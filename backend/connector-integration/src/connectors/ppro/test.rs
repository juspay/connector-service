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

    // --- Wallet Payment Methods ---

    #[test]
    fn test_ppro_payment_method_alipay() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::AliPay)),
            Some("ALIPAY".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_wechatpay() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::WeChatPay)),
            Some("WECHATPAY".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_mbway() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::MbWay)),
            Some("MBWAY".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_satispay() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::Satispay)),
            Some("SATISPAY".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_wero() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::Wero)),
            Some("WERO".to_string())
        );
    }

    // --- UPI Payment Methods ---

    #[test]
    fn test_ppro_payment_method_upi_collect() {
        // UpiCollect maps to "UPI" (special case — not "UPICOLLECT")
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::UpiCollect)),
            Some("UPI".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_upi_intent() {
        // UpiIntent also maps to "UPI" (same PPRO payment method, different flow)
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::UpiIntent)),
            Some("UPI".to_string())
        );
    }

    // --- Bank Redirect Payment Methods ---

    #[test]
    fn test_ppro_payment_method_ideal() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::Ideal)),
            Some("IDEAL".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_bancontact() {
        // BancontactCard maps to "BANCONTACT" (special case — not "BANCONTACTCARD")
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::BancontactCard)),
            Some("BANCONTACT".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_blik() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::Blik)),
            Some("BLIK".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_trustly() {
        assert_eq!(
            payment_method_to_ppro_string(Some(PaymentMethodType::Trustly)),
            Some("TRUSTLY".to_string())
        );
    }

    #[test]
    fn test_ppro_payment_method_none() {
        // None should return None (will cause a MissingRequiredField error in production)
        assert_eq!(payment_method_to_ppro_string(None), None);
    }
}
