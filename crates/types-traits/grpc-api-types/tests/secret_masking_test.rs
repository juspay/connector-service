//! Webhook and redirect-verification secrets are carried as `SecretString` (`*_v2` fields), so the
//! request logger's `masked_serialize` hides them without a per-field path list. The deprecated
//! plain-string fields keep their field numbers and wire type so existing clients still decode.

use grpc_api_types::payments::{RedirectResponseSecrets, WebhookSecrets};
use hyperswitch_masking::{masked_serialize, Secret};
use prost::Message;

#[test]
fn webhook_secrets_are_masked_in_logged_json() -> Result<(), Box<dyn std::error::Error>> {
    let logged = masked_serialize(&WebhookSecrets {
        secret_v2: Some(Secret::new("whsec_primary".to_string())),
        additional_secret_v2: Some(Secret::new("whsec_extra".to_string())),
        ..Default::default()
    })?
    .to_string();
    assert!(!logged.contains("whsec_primary"), "{logged}");
    assert!(!logged.contains("whsec_extra"), "{logged}");
    Ok(())
}

#[test]
fn redirect_response_secrets_are_masked_in_logged_json() -> Result<(), Box<dyn std::error::Error>> {
    let logged = masked_serialize(&RedirectResponseSecrets {
        secret_v2: Some(Secret::new("redirect_primary".to_string())),
        ..Default::default()
    })?
    .to_string();
    assert!(!logged.contains("redirect_primary"), "{logged}");
    Ok(())
}

/// Bytes an old client produces for `WebhookSecrets { secret: "whsec_old" }` (field 1, string).
#[test]
fn old_schema_webhook_secret_bytes_still_decode() -> Result<(), Box<dyn std::error::Error>> {
    let mut old_client_bytes = vec![0x0a, 9];
    old_client_bytes.extend_from_slice(b"whsec_old");
    let decoded = WebhookSecrets::decode(old_client_bytes.as_slice())?;
    #[allow(deprecated)]
    let legacy = decoded.secret;
    assert_eq!(legacy, "whsec_old");
    assert!(decoded.secret_v2.is_none());
    Ok(())
}
