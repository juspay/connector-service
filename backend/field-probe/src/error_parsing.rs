pub(crate) fn parse_missing_field(msg: &str) -> Option<String> {
    // Plural form: `MissingRequiredFields` formats as
    // `Missing required fields: ["billing_address.city", "billing_address.country"]`
    // Extract only the first name — the loop will pick up the rest on subsequent iterations.
    if let Some(pos) = msg.find("Missing required fields: [") {
        let rest = &msg[pos + "Missing required fields: [".len()..];
        // Names are double-quoted inside the list
        if let Some(first) = rest.split('"').nth(1) {
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }

    // Singular form: "Missing required param: X" or "Missing required field: X"
    for needle in &["Missing required param: ", "Missing required field: "] {
        if let Some(pos) = msg.find(needle) {
            let rest = &msg[pos + needle.len()..];
            // Field name ends at " (" (parenthetical note) or newline
            let field = rest
                .split(" (")
                .next()
                .unwrap_or(rest)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !field.is_empty() {
                return Some(field);
            }
        }
    }
    None
}

pub(crate) fn parse_missing_field_alt(msg: &str) -> Option<String> {
    if msg.contains("Amount is required") || msg.contains("MISSING_AMOUNT") {
        return Some("amount".to_string());
    }
    if msg.contains("Payment method data is required")
        || msg.contains("INVALID_PAYMENT_METHOD_DATA")
    {
        return Some("payment_method".to_string());
    }
    // Wallet token is missing — connectors that require a prior PaymentMethodToken flow
    // (e.g. Stripe Apple Pay) report this as InvalidWalletToken rather than a missing field.
    // Patching payment_method_token lets the probe proceed and produce a wire sample.
    if msg.contains("Failed to parse") && msg.contains("wallet token") {
        return Some("payment_method_token".to_string());
    }
    // Cybersource and similar connectors fail with "Invalid Configuration" when
    // connector_feature_data (metadata) is missing or cannot be parsed.
    if msg.contains("Invalid Configuration") && msg.contains("metadata") {
        return Some("connector_feature_data".to_string());
    }
    None
}

/// Returns true when the connector explicitly says this flow/PM has not been
/// implemented yet (development work still pending).  These are recorded as
/// `not_implemented` and rendered as ⚠ in the docs.
pub(crate) fn is_not_implemented(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("not been implemented")
        || lower.contains("notimplemented")
        || lower.contains("not implemented")
}

/// Returns true when the connector definitively does not support this payment
/// method / flow combination (by design, not a missing implementation).
/// These are recorded as `not_supported` and rendered as `x` in the docs.
pub(crate) fn is_not_supported(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("not supported")
        || lower.contains("not configured with the given connector")
        || lower.contains("only card payment")
        || lower.contains("only interac")
        || lower.contains("only upi")
        || lower.contains("payment method not supported")
        || lower.contains("does not support this payment")
        || lower.contains("notsupported")
        || lower.contains("flownotsupported")
        // Generic BadRequest with no missing-field information means the connector
        // rejected the PM type entirely (e.g. SamsungPay returned BadRequest on all connectors).
        || lower == "integration error: badrequest"
}

/// Returns true when the error signals not_implemented OR not_supported.
/// Convenience wrapper used where the probe only needs to know "stop patching".
#[allow(dead_code)]
pub(crate) fn is_pm_not_supported(msg: &str) -> bool {
    is_not_implemented(msg) || is_not_supported(msg)
}

/// Returns true when this connector requires an OAuth access token (prior CreateAccessToken step).
pub(crate) fn is_oauth_connector(connector: &domain_types::connector_types::ConnectorEnum) -> bool {
    let config = crate::config::get_config();
    let name = format!("{connector:?}").to_lowercase();
    config.oauth_connectors.iter().any(|c| c.name == name)
}
