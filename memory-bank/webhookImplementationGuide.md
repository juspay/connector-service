# Connector Implementation Guide

This guide provides step-by-step instructions for adding support for webhooks in a connector.

### Steps
1. Fetch the connector file from Hyperswitch using the following curl dont remove it until last step is completed
```sh
curl -L -o temp_connector_file.rs https://raw.githubusercontent.com/juspay/hyperswitch/main/crates/hyperswitch_connectors/src/connectors/connectorname.rs
```

### File: backend/connector-integration/src/connectors/new_connector.rs

2. Locate the empty impl of IncomingWebhook
e.g:
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > connector_types::IncomingWebhook for Connectorname<T>
{
}
```

3. Add the required imports for RequestDetails and ConnectorWebhookSecrets from domain_types::connector_types:
```rust
use domain_types::{
    connector_types::{
        // ... existing imports ...
        ConnectorWebhookSecrets, RequestDetails,
        // ... other imports ...
    },
    // ... other imports ...
};
```

4. Add this function in the impl
```rust
fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<domain_types::errors::ConnectorError>> {
        Ok(false)
    }
```

5. Copy the code inside the verify_webhook_source function in temp_connector_file as it is, dont do anything else
```rust
fn verify_webhook_source(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        merchant_id: &common_utils::id_type::MerchantId,
        connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        _connector_account_details: common_utils::crypto::Encryptable<Secret<serde_json::Value>>,
        connector_label: &str,
    ) -> CustomResult<bool, errors::ConnectorError> {
        //Copy the code from here
    }
```

6. Extract the connector webhook secrets from the parameter:
```rust
let connector_webhook_secrets = match connector_webhook_secret {
    Some(secrets) => secrets,
    None => return Ok(false),
};
```

7. Add this function in the impl, the code inside should come from temp_connector_file get_webhook_source_verification_signature function
```rust
fn get_webhook_source_verification_signature(
        &self,
        _request: RequestDetails,
        _connector_webhook_secrets: &Option<ConnectorWebhookSecrets>,
    ) -> Result<Vec<u8>, error_stack::Report<domain_types::errors::ConnectorError>> {
        Ok(Vec::new())
    }
```

8. Add this function in the impl, the code inside should come from temp_connector_file get_event_type function
```rust
fn get_event_type(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<domain_types::errors::ConnectorError>> {
        Err(
            domain_types::errors::ConnectorError::NotImplemented("get_event_type".to_string())
                .into(),
        )
    }
```

8. Add this function in the impl
```rust
    fn process_payment_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<domain_types::errors::ConnectorError>>
    {
        // write appropriate code taking reference from temp_connector_file
        Ok(WebhookDetailsResponse {
            resource_id: ,
            status: ,
            status_code: ,
            connector_response_reference_id: ,
            error_code: ,
            error_message: ,
            raw_connector_response: Some(String::from_utf8_lossy(&request.body).to_string()),
            response_headers: ,
        })
    }
```
    