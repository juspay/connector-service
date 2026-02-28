#[cfg(test)]
mod tests {
    use domain_types::payment_method_data::DefaultPCIHolder;
    use interfaces::api::ConnectorCommon;

    use crate::connectors;

    #[test]
    fn test_ppro_connector_creation() {
        // Basic test to ensure connector can be created
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
}
