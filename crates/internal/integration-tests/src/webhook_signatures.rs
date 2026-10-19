//! Webhook signature generation for testing
//!
//! This module provides signature generation functions for various connectors
//! to enable webhook testing via EventService.HandleEvent
//!
//! Note: This module intentionally uses simple error handling (String-based errors)
//! to avoid adding extra dependencies to the integration-tests crate.

use std::fmt::Write;

/// Connector-specific inputs a signature scheme needs beyond the payload and
/// secret. All fields are optional: a new scheme adds a field here and a match
/// arm below, rather than a branch in the caller.
#[derive(Debug, Default, Clone)]
pub struct SignatureContext<'a> {
    pub timestamp: Option<i64>,
    /// Request URI/path, for schemes that hash it in (e.g. phonepe).
    pub api_path: Option<&'a str>,
    /// Key/version index appended to the signature, for schemes that use one
    /// (e.g. phonepe's `###<key_index>` suffix). Defaults to "1" if the
    /// scheme requires one and none is supplied.
    pub key_index: Option<&'a str>,
}

/// Generate webhook signature for a given connector.
///
/// `payload` must be the exact bytes the connector's own verification code
/// hashes. For most connectors that is the raw request body; for phonepe it is
/// the inner base64 `response` string, which the caller must extract first.
///
/// Returns the signature string for the connector's signature header.
pub fn generate_signature(
    connector: &str,
    payload: &[u8],
    secret: &str,
    ctx: &SignatureContext<'_>,
) -> Result<String, String> {
    match connector {
        "stripe" => generate_stripe_signature(payload, secret, ctx.timestamp),
        "adyen" => generate_adyen_signature(payload, secret),
        "authorizedotnet" => generate_authorizedotnet_signature(payload, secret),
        "checkout" => generate_checkout_signature(payload, secret),
        "paypal" => generate_paypal_signature(payload, secret),
        "phonepe" => generate_phonepe_signature(payload, secret, ctx),
        _ => Err(format!("Unsupported connector: {}", connector)),
    }
}

/// Generate PhonePe webhook X-VERIFY signature.
///
/// PhonePe's checksum, matching connectors/phonepe/transformers.rs's
/// compute_phonepe_webhook_checksum exactly:
///   sha256(base64_body + api_path + salt_key) + "###" + key_index
fn generate_phonepe_signature(
    inner_base64_body: &[u8],
    salt_key: &str,
    ctx: &SignatureContext<'_>,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let base64_body = std::str::from_utf8(inner_base64_body)
        .map_err(|e| format!("phonepe signature payload must be UTF-8: {e}"))?;
    let api_path = ctx.api_path.unwrap_or("");
    let key_index = ctx.key_index.unwrap_or("1");

    let checksum_input = format!("{base64_body}{api_path}{salt_key}");
    let hash_bytes = Sha256::digest(checksum_input.as_bytes());

    let mut hex_hash = String::with_capacity(hash_bytes.len() * 2);
    for byte in hash_bytes {
        write!(&mut hex_hash, "{byte:02x}").map_err(|e| format!("Failed to write hex: {e}"))?;
    }

    Ok(format!("{hex_hash}###{key_index}"))
}

/// Generate Stripe webhook signature
///
/// Stripe uses: t=<timestamp>,v1=<hmac_sha256_hex>
/// Message format: {timestamp}.{payload}
fn generate_stripe_signature(
    payload: &[u8],
    secret: &str,
    timestamp: Option<i64>,
) -> Result<String, String> {
    // Use current timestamp if not provided
    let timestamp = timestamp.unwrap_or_else(|| {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap_or(0)
    });

    // Stripe's signed_payload = timestamp.body
    let payload_str = std::str::from_utf8(payload)
        .map_err(|e| format!("Failed to convert payload to UTF-8: {}", e))?;

    let signed_payload = format!("{}.{}", timestamp, payload_str);

    // Compute HMAC-SHA256 using hmac/sha2 crates (available via dependencies)
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;
    mac.update(signed_payload.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();

    // Convert to hex
    let mut hex_signature = String::with_capacity(signature_bytes.len() * 2);
    for byte in signature_bytes {
        write!(&mut hex_signature, "{:02x}", byte)
            .map_err(|e| format!("Failed to write hex: {}", e))?;
    }

    // Stripe format: t=timestamp,v1=signature
    Ok(format!("t={},v1={}", timestamp, hex_signature))
}

/// Generate Adyen webhook signature
///
/// Adyen Standard webhooks carry the signature in the body
/// (`additionalData.hmacSignature`): HMAC-SHA256 keyed by the hex-decoded HMAC
/// key over the colon-joined 8-field preimage (`payload`, built by the caller),
/// Base64 (standard) encoded.
/// Docs test vector: key `44782DEF547AAA06C910C43932B1EB0C71FC68D9D0C057550C48EC2ACF6BA056`,
/// preimage `7914073381342284::TestMerchant:TestPayment-1407325143704:1130:EUR:AUTHORISATION:true`
/// -> `coqCmt/IZ4E3CzPvMY8zTjQVL5hYJUiBRg8UU+iCWo0=`.
fn generate_adyen_signature(payload: &[u8], hex_secret: &str) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let key = decode_hex(hex_secret)?;
    let mut mac =
        HmacSha256::new_from_slice(&key).map_err(|e| format!("Failed to create HMAC: {}", e))?;
    mac.update(payload);

    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

/// Decodes a hex string (either case) into bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err("hex key has an odd number of digits".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "hex key contains a non-hex digit".to_string())
        })
        .collect()
}

/// Generate Authorize.Net webhook signature
///
/// Authorize.Net uses HMAC-SHA512 with lowercase hex encoding
/// Header: X-ANET-Signature: sha512=<signature>
fn generate_authorizedotnet_signature(payload: &[u8], secret: &str) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    let mut mac = HmacSha512::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;
    mac.update(payload);
    let signature_bytes = mac.finalize().into_bytes();

    // Convert to lowercase hex
    let mut hex_signature = String::with_capacity(signature_bytes.len() * 2);
    for byte in signature_bytes {
        write!(&mut hex_signature, "{:02x}", byte)
            .map_err(|e| format!("Failed to write hex: {}", e))?;
    }

    Ok(format!("sha512={}", hex_signature))
}

/// Generate Checkout.com webhook signature
///
/// Checkout.com uses HMAC-SHA256 with lowercase hex encoding on the raw body.
/// Header: cko-signature: <hex>
fn generate_checkout_signature(payload: &[u8], secret: &str) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;
    mac.update(payload);
    let signature_bytes = mac.finalize().into_bytes();

    let mut hex_signature = String::with_capacity(signature_bytes.len() * 2);
    for byte in signature_bytes {
        write!(&mut hex_signature, "{:02x}", byte)
            .map_err(|e| format!("Failed to write hex: {}", e))?;
    }

    Ok(hex_signature)
}

/// Generate PayPal webhook signature
///
/// PayPal uses HMAC-SHA256 with base64 encoding
fn generate_paypal_signature(payload: &[u8], secret: &str) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;
    mac.update(payload);
    let signature_bytes = mac.finalize().into_bytes();

    // Base64 encode
    use base64::{engine::general_purpose::STANDARD, Engine};
    let signature_b64 = STANDARD.encode(signature_bytes);

    Ok(signature_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_signature_generation() {
        let payload = b"{\"id\":\"evt_test\",\"type\":\"payment_intent.succeeded\"}";
        let secret = "whsec_test_secret";
        let timestamp = Some(1234567890i64);

        let signature = generate_stripe_signature(payload, secret, timestamp)
            .expect("Failed to generate Stripe signature");

        assert!(signature.starts_with("t=1234567890,v1="));
        assert!(signature.len() > 20);
    }

    #[test]
    fn test_authorizedotnet_signature_generation() {
        let payload = b"{\"eventType\":\"net.authorize.payment.authorization.created\"}";
        let secret = "test_secret";

        let signature = generate_authorizedotnet_signature(payload, secret)
            .expect("Failed to generate Authorize.Net signature");

        assert!(signature.starts_with("sha512="));
        assert!(signature.len() > 100); // SHA512 is 128 hex chars
    }
}
