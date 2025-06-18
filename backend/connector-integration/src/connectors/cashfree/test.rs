//! Tests for Cashfree UPI connector
//!
//! This module contains unit tests for the Cashfree UPI payment flows.

#[cfg(test)]
mod tests {
    use super::super::transformers::*;

    #[test]
    fn test_upi_flow_type_from_source_object() {
        // Test UPI Intent flow
        let intent_flow = UpiFlowType::from_source_object("UPI_PAY");
        assert!(matches!(intent_flow, UpiFlowType::Intent));
        assert_eq!(intent_flow.get_upi_mode(), Some("link".to_string()));
        assert!(intent_flow.should_include_secret_key());
        assert!(intent_flow.should_use_json_response());

        // Test UPI QR flow
        let qr_flow = UpiFlowType::from_source_object("UPI_QR");
        assert!(matches!(qr_flow, UpiFlowType::QR));
        assert_eq!(qr_flow.get_upi_mode(), Some("link".to_string()));
        assert!(qr_flow.should_include_secret_key());
        assert!(qr_flow.should_use_json_response());

        // Test UPI Collect flow
        let collect_flow = UpiFlowType::from_source_object("OTHER");
        assert!(matches!(collect_flow, UpiFlowType::Collect));
        assert_eq!(collect_flow.get_upi_mode(), None);
        assert!(!collect_flow.should_include_secret_key());
        assert!(!collect_flow.should_use_json_response());
    }
}
