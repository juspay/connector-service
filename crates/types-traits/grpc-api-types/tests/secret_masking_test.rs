//! Webhook and redirect-verification secrets are `SecretString`, so the request logger's
//! `masked_serialize` hides them without a per-field path list.

use grpc_api_types::payments::{RedirectResponseSecrets, WebhookSecrets};
use hyperswitch_masking::{masked_serialize, Secret};

#[test]
fn webhook_secrets_are_masked_in_logged_json() -> Result<(), Box<dyn std::error::Error>> {
    let logged = masked_serialize(&WebhookSecrets {
        secret: Some(Secret::new("whsec_primary".to_string())),
        additional_secret: Some(Secret::new("whsec_extra".to_string())),
    })?
    .to_string();
    assert!(!logged.contains("whsec_primary"), "{logged}");
    assert!(!logged.contains("whsec_extra"), "{logged}");
    Ok(())
}

#[test]
fn redirect_response_secrets_are_masked_in_logged_json() -> Result<(), Box<dyn std::error::Error>> {
    let logged = masked_serialize(&RedirectResponseSecrets {
        secret: Some(Secret::new("redirect_primary".to_string())),
        additional_secret: None,
    })?
    .to_string();
    assert!(!logged.contains("redirect_primary"), "{logged}");
    Ok(())
}
