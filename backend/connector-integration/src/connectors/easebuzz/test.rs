#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_endpoint() {
        assert_eq!(
            get_endpoint(EaseBuzzEndpoints::EaseBuzInitiatePayment, true),
            "/payment/initiateLink"
        );
        assert_eq!(
            get_endpoint(EaseBuzzEndpoints::EasebuzSeamlessTransaction, false),
            "/pay/initiate"
        );
        assert_eq!(
            get_endpoint(EaseBuzzEndpoints::EasebuzTxnSync, true),
            "/transaction/status"
        );
    }

    #[test]
    fn test_get_base_url() {
        assert_eq!(get_base_url(), "https://pay.easebuzz.in");
    }

    #[test]
    fn test_supported_currencies() {
        assert!(SUPPORTED_CURRENCIES.contains(&Currency::INR));
    }

    #[test]
    fn test_supported_countries() {
        assert!(SUPPORTED_COUNTRIES.contains(&CountryAlpha2::IN));
    }
}