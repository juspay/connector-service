use serde_json::Value;

use super::ConnectorOverride;

/// Override for connectors that use a tokenized payment method flow via the
/// `authorize` suite (e.g. Stax, Braintree).
///
/// The `authorize_suite/suite_spec.json` context_map injects the tokenize
/// response token into `payment_method.token.token.value`.  After the JSON
/// merge patch this creates a `payment_method` object with *both* the original
/// payment-method variant (card, google_pay, …) *and* the `token` variant,
/// which is invalid for a protobuf oneof.
///
/// `normalize_tonic_request` removes all non-`token` variants from
/// `payment_method` when a `token` key is present, so the final request
/// contains only the token variant and passes schema validation.
#[derive(Debug, Clone)]
pub struct TokenPaymentMethodOverride {
    connector: String,
}

impl TokenPaymentMethodOverride {
    #[must_use]
    pub fn new(connector: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
        }
    }
}

impl ConnectorOverride for TokenPaymentMethodOverride {
    fn connector_name(&self) -> &str {
        &self.connector
    }

    fn extra_context_deferred_paths(&self) -> Vec<String> {
        vec!["payment_method.token.token.value".to_string()]
    }

    fn normalize_tonic_request(&self, suite: &str, _scenario: &str, req: &mut Value) {
        if suite != "authorize" {
            return;
        }

        let Some(pm) = req
            .get_mut("payment_method")
            .and_then(Value::as_object_mut)
        else {
            return;
        };

        // Only act when a token variant is present alongside other variants.
        if !pm.contains_key("token") || pm.len() <= 1 {
            return;
        }

        let token_value = pm.remove("token").expect("key confirmed present above");
        pm.retain(|_, _| false);
        pm.insert("token".to_string(), token_value);
    }
}
