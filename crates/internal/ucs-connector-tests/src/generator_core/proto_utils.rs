//! Proto utilities for checking field properties from proto descriptor

/// Returns the proto message name for a given suite name.
pub fn message_name_for_suite(suite: &str) -> &'static str {
    match suite {
        "authorize" => "PaymentServiceAuthorizeRequest",
        "capture" => "PaymentServiceCaptureRequest",
        "void" => "PaymentServiceVoidRequest",
        "refund" => "PaymentServiceRefundRequest",
        "refund_sync" => "RefundServiceGetRequest",
        "get" => "PaymentServiceGetRequest",
        "setup_recurring" => "PaymentServiceSetupRecurringRequest",
        "recurring_charge" => "RecurringPaymentServiceChargeRequest",
        "create_customer" => "CustomerServiceCreateRequest",
        "create_access_token" => "MerchantAuthenticationServiceCreateAccessTokenRequest",
        _ => "Unknown",
    }
}

/// Check if a field is optional in the proto definition for a given message.
/// Returns true if the proto3_optional flag is set for that field.
///
/// Uses hardcoded lists of known optional fields per request type.
pub fn is_field_optional(message_name: &str, field_path: &str) -> bool {
    let field_base = field_path.split('.').next().unwrap_or(field_path);

    let optional_fields: &[&str] = match message_name {
        "PaymentServiceAuthorizeRequest" => &[
            "merchant_transaction_id",
            "order_tax_amount",
            "shipping_cost",
            "capture_method",
            "customer",
            "enrolled_for_3ds",
            "authentication_data",
            "return_url",
            "webhook_url",
            "complete_authorize_url",
            "session_token",
            "order_category",
            "merchant_order_id",
            "setup_future_usage",
            "off_session",
            "request_incremental_authorization",
            "request_extended_authorization",
            "enable_partial_authorization",
            "customer_acceptance",
            "browser_info",
            "payment_experience",
            "description",
            "payment_channel",
            "test_mode",
            "setup_mandate_details",
            "statement_descriptor_name",
            "statement_descriptor_suffix",
            "billing_descriptor",
            "state",
            "order_details",
            "locale",
            "tokenization_strategy",
            "threeds_completion_indicator",
            "redirection_response",
            "continue_redirection_url",
            "payment_method_token",
            "l2_l3_data",
        ],
        "PaymentServiceCaptureRequest" => &[
            "merchant_capture_id",
            "metadata",
            "connector_feature_data",
            "multiple_capture_data",
            "browser_info",
            "capture_method",
            "state",
            "test_mode",
            "merchant_order_id",
        ],
        "PaymentServiceVoidRequest" => &[
            "merchant_void_id",
            "cancellation_reason",
            "all_keys_required",
            "browser_info",
            "amount",
            "metadata",
            "connector_feature_data",
            "state",
            "test_mode",
            "merchant_order_id",
        ],
        "PaymentServiceRefundRequest" => &[
            "merchant_refund_id",
            "reason",
            "webhook_url",
            "merchant_account_id",
            "capture_method",
            "metadata",
            "refund_metadata",
            "connector_feature_data",
            "browser_info",
            "state",
            "test_mode",
            "payment_method_type",
            "customer_id",
        ],
        "RefundServiceGetRequest" => &[
            "merchant_refund_id",
            "refund_reason",
            "browser_info",
            "refund_metadata",
            "state",
            "test_mode",
            "payment_method_type",
            "connector_feature_data",
        ],
        "PaymentServiceGetRequest" => &[
            "merchant_transaction_id",
            "encoded_data",
            "capture_method",
            "handle_response",
            "amount",
            "setup_future_usage",
            "state",
            "metadata",
            "connector_feature_data",
            "sync_type",
            "connector_order_reference_id",
            "test_mode",
            "payment_experience",
        ],
        "PaymentServiceSetupRecurringRequest" => &[
            "customer",
            "authentication_data",
            "metadata",
            "connector_feature_data",
            "return_url",
            "webhook_url",
            "complete_authorize_url",
            "session_token",
            "order_tax_amount",
            "order_category",
            "merchant_order_id",
            "shipping_cost",
            "setup_future_usage",
            "off_session",
            "request_extended_authorization",
            "enable_partial_authorization",
            "customer_acceptance",
            "browser_info",
            "payment_experience",
            "payment_channel",
            "billing_descriptor",
            "state",
            "payment_method_token",
            "order_id",
            "locale",
            "connector_testing_data",
            "l2_l3_data",
        ],
        "RecurringPaymentServiceChargeRequest" => &[
            "merchant_charge_id",
            "connector_recurring_payment_id",
            "payment_method",
            "merchant_order_id",
            "metadata",
            "connector_feature_data",
            "webhook_url",
            "return_url",
            "description",
            "address",
            "capture_method",
            "email",
            "connector_customer_id",
            "browser_info",
            "test_mode",
            "payment_method_type",
            "merchant_account_id",
            "merchant_configured_currency",
            "off_session",
            "enable_partial_authorization",
            "state",
            "original_payment_authorized_amount",
            "shipping_cost",
            "billing_descriptor",
            "mit_category",
            "authentication_data",
            "locale",
            "connector_testing_data",
            "customer",
            "l2_l3_data",
        ],
        "CustomerServiceCreateRequest" => &[
            "merchant_customer_id",
            "customer_name",
            "email",
            "phone_number",
            "address",
            "metadata",
            "connector_feature_data",
            "test_mode",
        ],
        "MerchantAuthenticationServiceCreateAccessTokenRequest" => &[
            "merchant_access_token_id",
            "metadata",
            "connector_feature_data",
            "test_mode",
        ],
        _ => &[],
    };

    optional_fields.contains(&field_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_fields() {
        assert!(is_field_optional(
            "PaymentServiceAuthorizeRequest",
            "merchant_transaction_id"
        ));
        assert!(is_field_optional(
            "PaymentServiceAuthorizeRequest",
            "capture_method"
        ));
        assert!(is_field_optional(
            "PaymentServiceAuthorizeRequest",
            "customer"
        ));
        assert!(is_field_optional(
            "PaymentServiceAuthorizeRequest",
            "customer.name"
        ));

        // Required fields (not optional)
        assert!(!is_field_optional(
            "PaymentServiceAuthorizeRequest",
            "amount"
        ));
        assert!(!is_field_optional(
            "PaymentServiceAuthorizeRequest",
            "payment_method"
        ));
        assert!(!is_field_optional(
            "PaymentServiceAuthorizeRequest",
            "auth_type"
        ));
    }

    #[test]
    fn test_capture_optional_fields() {
        assert!(is_field_optional(
            "PaymentServiceCaptureRequest",
            "merchant_capture_id"
        ));
        assert!(is_field_optional("PaymentServiceCaptureRequest", "state"));
        assert!(is_field_optional(
            "PaymentServiceCaptureRequest",
            "test_mode"
        ));
        assert!(is_field_optional(
            "PaymentServiceCaptureRequest",
            "merchant_order_id"
        ));

        // Required fields
        assert!(!is_field_optional(
            "PaymentServiceCaptureRequest",
            "connector_transaction_id"
        ));
        assert!(!is_field_optional(
            "PaymentServiceCaptureRequest",
            "amount_to_capture"
        ));
    }

    #[test]
    fn test_void_optional_fields() {
        assert!(is_field_optional(
            "PaymentServiceVoidRequest",
            "cancellation_reason"
        ));
        assert!(is_field_optional("PaymentServiceVoidRequest", "amount"));
        assert!(is_field_optional(
            "PaymentServiceVoidRequest",
            "merchant_order_id"
        ));
        assert!(!is_field_optional(
            "PaymentServiceVoidRequest",
            "connector_transaction_id"
        ));
    }

    #[test]
    fn test_refund_optional_fields() {
        assert!(is_field_optional("PaymentServiceRefundRequest", "reason"));
        assert!(is_field_optional("PaymentServiceRefundRequest", "state"));
        assert!(!is_field_optional(
            "PaymentServiceRefundRequest",
            "connector_transaction_id"
        ));
        assert!(!is_field_optional(
            "PaymentServiceRefundRequest",
            "refund_amount"
        ));
    }

    #[test]
    fn test_message_name_for_suite() {
        assert_eq!(
            message_name_for_suite("authorize"),
            "PaymentServiceAuthorizeRequest"
        );
        assert_eq!(
            message_name_for_suite("capture"),
            "PaymentServiceCaptureRequest"
        );
        assert_eq!(message_name_for_suite("void"), "PaymentServiceVoidRequest");
        assert_eq!(
            message_name_for_suite("refund"),
            "PaymentServiceRefundRequest"
        );
        assert_eq!(
            message_name_for_suite("refund_sync"),
            "RefundServiceGetRequest"
        );
    }
}
