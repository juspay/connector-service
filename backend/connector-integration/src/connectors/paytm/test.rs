//! Tests for Paytm connector integration

#[cfg(test)]
mod tests {
    use super::super::transformers::*;
    use common_utils::types::MinorUnit;

    #[test]
    fn test_paytm_amount_creation() {
        let amount = MinorUnit::new(10000); // ₹100.00
        let paytm_amount = PaytmAmount::new(amount, "INR");

        assert_eq!(paytm_amount.value, "100.00");
        assert_eq!(paytm_amount.currency, "INR");
    }

    #[test]
    fn test_paytm_user_info_creation() {
        let user_info = PaytmUserInfo::new(
            "CUSTOMER123".to_string(),
            Some("9876543210".to_string()),
            Some("customer@example.com".to_string()),
            Some("John".to_string()),
            Some("Doe".to_string()),
        );

        assert_eq!(user_info.cust_id, "CUSTOMER123");
        assert_eq!(user_info.mobile.unwrap(), "9876543210");
        assert_eq!(user_info.email.unwrap(), "customer@example.com");
        assert_eq!(user_info.first_name.unwrap(), "John");
        assert_eq!(user_info.last_name.unwrap(), "Doe");
        assert!(user_info.middle_name.is_none());
    }

    #[test]
    fn test_paytm_payment_mode_upi() {
        let payment_mode = PaytmPaymentMode::upi();

        assert_eq!(payment_mode.mode, "UPI");
        assert_eq!(payment_mode.channels, vec!["UPI"]);
    }

    #[test]
    fn test_paytm_extend_info_creation() {
        let extend_info = PaytmExtendInfo::new(
            "INR".to_string(),
            Some("metadata1".to_string()),
            Some("https://example.com/return".to_string()),
            Some("MERCHANT_REF_123".to_string()),
        );

        assert_eq!(extend_info.currency, "INR");
        assert_eq!(extend_info.udf1.unwrap(), "metadata1");
        assert_eq!(
            extend_info.return_url.unwrap(),
            "https://example.com/return"
        );
        assert_eq!(extend_info.merc_unq_ref.unwrap(), "MERCHANT_REF_123");
        assert!(extend_info.udf2.is_none());
        assert!(extend_info.udf3.is_none());
    }
}
