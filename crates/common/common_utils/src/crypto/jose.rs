//! JOSE (JSON Object Signing and Encryption) helpers for connectors that
//! wrap requests in a PS256 JWS inside an RSA-OAEP / A128CBC-HS256 JWE.
//!
//! Used by 2C2P PACO and reusable for any future connector with the same
//! envelope shape. Two non-obvious facts are isolated here so they don't
//! leak into every consumer:
//!
//! 1. **josekit 0.8.7's `RsassaPssJwsAlgorithm::from_pem` rejects PKCS#8
//!    PEMs with the generic-RSA OID** (`1.2.840.113549.1.1.1`). Real
//!    RSA-4096 keys we receive from PACO carry that OID rather than the
//!    `id-RSASSA-PSS` OID josekit looks for, so we reach for `openssl`
//!    directly with explicit PSS padding parameters.
//!
//! 2. **PACO's published public PEMs ship without a newline before
//!    `-----END...-----`.** OpenSSL refuses to parse those. We fix it once
//!    at [`JoseConfig::new`] so callers don't have to think about it on
//!    every request.

use base64::Engine;
use hyperswitch_masking::{PeekInterface, Secret};
use josekit::jwe::{alg::rsaes::RsaesJweAlgorithm, JweHeader};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer, Verifier},
};
use serde::Serialize;

use crate::consts::BASE64_ENGINE_URL_SAFE_NO_PAD;

/// Errors raised by the JOSE pipeline.
#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    #[error("Invalid PEM key material for {context}")]
    InvalidKey { context: &'static str },
    #[error("Failed to sign JWS")]
    SigningFailed,
    #[error("Failed to verify JWS signature")]
    VerificationFailed,
    #[error("Failed to encrypt JWE")]
    EncryptionFailed,
    #[error("Failed to decrypt JWE")]
    DecryptionFailed,
    #[error("Failed to serialise claims to JSON")]
    SerdeSerializeFailed,
    #[error("Decrypted JWS payload is not valid JSON")]
    SerdeDeserializeFailed,
    #[error("Compact JWS does not have three dot-separated segments")]
    MalformedJws,
}

/// Bundle of credentials needed by [`sign_then_encrypt`] / [`decrypt_then_verify`].
///
/// Generic over connectors — naming is deliberately non-PACO-specific so
/// other JOSE-using connectors (e.g. Juspay UPI Stack, future Paymob /
/// Geidea) can adopt the same struct with their own `kid` + key set.
/// PEM normalisation runs once at [`JoseConfig::new`] time.
#[derive(Debug, Clone)]
pub struct JoseConfig {
    /// Environment-specific JWE key id placed in the JWE protected header.
    /// PACO uses this to pick which decryption key to apply on the gateway side.
    pub kid: String,
    /// Merchant-side RSA private key that signs the JWS.
    pub merchant_signing_private_key: Secret<String>,
    /// Merchant-side RSA private key that decrypts the response JWE.
    pub merchant_encryption_private_key: Secret<String>,
    /// Counterparty (PACO) public key that verifies the response JWS.
    pub paco_signing_public_key: Secret<String>,
    /// Counterparty (PACO) public key that the request JWE is sealed against.
    pub paco_encryption_public_key: Secret<String>,
}

impl JoseConfig {
    /// Construct a [`JoseConfig`], normalising the four PEMs and verifying
    /// every key parses with OpenSSL. Fails fast on bad credentials so the
    /// gRPC response is a precise validation error instead of a vague
    /// runtime "request encoding failed".
    pub fn new(
        kid: String,
        merchant_signing_private_key: Secret<String>,
        merchant_encryption_private_key: Secret<String>,
        paco_signing_public_key: Secret<String>,
        paco_encryption_public_key: Secret<String>,
    ) -> Result<Self, JoseError> {
        let cfg = Self {
            kid,
            merchant_signing_private_key: normalise_pem_secret(merchant_signing_private_key),
            merchant_encryption_private_key: normalise_pem_secret(merchant_encryption_private_key),
            paco_signing_public_key: normalise_pem_secret(paco_signing_public_key),
            paco_encryption_public_key: normalise_pem_secret(paco_encryption_public_key),
        };
        cfg.validate_keys()?;
        Ok(cfg)
    }

    fn validate_keys(&self) -> Result<(), JoseError> {
        PKey::private_key_from_pem(self.merchant_signing_private_key.peek().as_bytes())
            .map_err(|_| JoseError::InvalidKey {
                context: "merchant_signing_private_key",
            })?;
        PKey::private_key_from_pem(self.merchant_encryption_private_key.peek().as_bytes())
            .map_err(|_| JoseError::InvalidKey {
                context: "merchant_encryption_private_key",
            })?;
        PKey::public_key_from_pem(self.paco_signing_public_key.peek().as_bytes()).map_err(|_| {
            JoseError::InvalidKey {
                context: "paco_signing_public_key",
            }
        })?;
        PKey::public_key_from_pem(self.paco_encryption_public_key.peek().as_bytes()).map_err(
            |_| JoseError::InvalidKey {
                context: "paco_encryption_public_key",
            },
        )?;
        Ok(())
    }
}

/// Sign a serialisable claim set with PS256, then seal the resulting JWS
/// inside an RSA-OAEP / A128CBC-HS256 JWE bound to `cfg.kid`. Returns the
/// compact JWE — five dot-separated base64url segments.
pub fn sign_then_encrypt<T: Serialize>(claims: &T, cfg: &JoseConfig) -> Result<String, JoseError> {
    let payload = serde_json::to_vec(claims).map_err(|_| JoseError::SerdeSerializeFailed)?;
    let jws = sign_jws_ps256(&payload, cfg.merchant_signing_private_key.peek())?;
    encrypt_jwe_rsa_oaep(
        jws.as_bytes(),
        &cfg.kid,
        cfg.paco_encryption_public_key.peek(),
    )
}

/// Inverse of [`sign_then_encrypt`]: decrypt the compact JWE, verify the
/// inner JWS signature, and return the inner JSON payload.
pub fn decrypt_then_verify(
    jwe_compact: &str,
    cfg: &JoseConfig,
) -> Result<serde_json::Value, JoseError> {
    let jws_bytes = decrypt_jwe_rsa_oaep(jwe_compact, cfg.merchant_encryption_private_key.peek())?;
    let jws = std::str::from_utf8(&jws_bytes).map_err(|_| JoseError::DecryptionFailed)?;
    let payload = verify_jws_ps256(jws, cfg.paco_signing_public_key.peek())?;
    serde_json::from_slice(&payload).map_err(|_| JoseError::SerdeDeserializeFailed)
}

// ---------- PEM normalisation ----------

fn normalise_pem_secret(secret: Secret<String>) -> Secret<String> {
    let raw = secret.peek().clone();
    Secret::new(normalise_pem(&raw))
}

/// PACO's published public PEMs sometimes drop the newline before
/// `-----END-----`. OpenSSL rejects that. Fix it idempotently.
fn normalise_pem(pem: &str) -> String {
    let trimmed = pem.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(trimmed.len() + 2);
    let mut chars = trimmed.chars().peekable();
    while let Some(ch) = chars.next() {
        out.push(ch);
        // Insert a newline before any `-----END` that didn't already
        // start a new line.
        if ch != '\n' && chars.peek() == Some(&'-') {
            let lookahead: String = chars.clone().take(8).collect();
            if lookahead.starts_with("-----END") {
                out.push('\n');
            }
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

// ---------- PS256 JWS via OpenSSL ----------

fn sign_jws_ps256(payload: &[u8], private_key_pem: &str) -> Result<String, JoseError> {
    let header = serde_json::json!({ "alg": "PS256", "typ": "JWT" });
    let header_b64 = BASE64_ENGINE_URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = BASE64_ENGINE_URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).map_err(|_| {
        JoseError::InvalidKey {
            context: "merchant_signing_private_key",
        }
    })?;

    let mut signer =
        Signer::new(MessageDigest::sha256(), &pkey).map_err(|_| JoseError::SigningFailed)?;
    signer
        .set_rsa_padding(Padding::PKCS1_PSS)
        .map_err(|_| JoseError::SigningFailed)?;
    signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .map_err(|_| JoseError::SigningFailed)?;
    signer
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|_| JoseError::SigningFailed)?;
    signer
        .update(signing_input.as_bytes())
        .map_err(|_| JoseError::SigningFailed)?;
    let sig = signer.sign_to_vec().map_err(|_| JoseError::SigningFailed)?;

    let sig_b64 = BASE64_ENGINE_URL_SAFE_NO_PAD.encode(sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

fn verify_jws_ps256(jws_compact: &str, public_key_pem: &str) -> Result<Vec<u8>, JoseError> {
    let parts: Vec<&str> = jws_compact.split('.').collect();
    if parts.len() != 3 {
        return Err(JoseError::MalformedJws);
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = BASE64_ENGINE_URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| JoseError::VerificationFailed)?;
    let payload = BASE64_ENGINE_URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| JoseError::VerificationFailed)?;

    let pkey =
        PKey::public_key_from_pem(public_key_pem.as_bytes()).map_err(|_| JoseError::InvalidKey {
            context: "paco_signing_public_key",
        })?;

    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &pkey).map_err(|_| JoseError::VerificationFailed)?;
    verifier
        .set_rsa_padding(Padding::PKCS1_PSS)
        .map_err(|_| JoseError::VerificationFailed)?;
    verifier
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .map_err(|_| JoseError::VerificationFailed)?;
    verifier
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|_| JoseError::VerificationFailed)?;
    verifier
        .update(signing_input.as_bytes())
        .map_err(|_| JoseError::VerificationFailed)?;

    if !verifier
        .verify(&sig)
        .map_err(|_| JoseError::VerificationFailed)?
    {
        return Err(JoseError::VerificationFailed);
    }
    Ok(payload)
}

// ---------- RSA-OAEP / A128CBC-HS256 JWE via josekit ----------

fn encrypt_jwe_rsa_oaep(
    plaintext: &[u8],
    kid: &str,
    public_key_pem: &str,
) -> Result<String, JoseError> {
    let mut header = JweHeader::new();
    header.set_content_encryption("A128CBC-HS256");
    header.set_key_id(kid);

    let encrypter = RsaesJweAlgorithm::RsaOaep
        .encrypter_from_pem(public_key_pem.as_bytes())
        .map_err(|_| JoseError::InvalidKey {
            context: "paco_encryption_public_key",
        })?;

    josekit::jwe::serialize_compact(plaintext, &header, &encrypter)
        .map_err(|_| JoseError::EncryptionFailed)
}

fn decrypt_jwe_rsa_oaep(
    jwe_compact: &str,
    private_key_pem: &str,
) -> Result<Vec<u8>, JoseError> {
    let decrypter = RsaesJweAlgorithm::RsaOaep
        .decrypter_from_pem(private_key_pem.as_bytes())
        .map_err(|_| JoseError::InvalidKey {
            context: "merchant_encryption_private_key",
        })?;

    let (plaintext, _header) = josekit::jwe::deserialize_compact(jwe_compact, &decrypter)
        .map_err(|_| JoseError::DecryptionFailed)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use hyperswitch_masking::Secret;
    use openssl::{pkey::PKey, rsa::Rsa};
    use serde::{Deserialize, Serialize};

    use super::{
        decrypt_then_verify, normalise_pem, sign_then_encrypt, JoseConfig, JoseError,
    };

    fn keypair_pems() -> (String, String) {
        let rsa = Rsa::generate(2048).expect("generate rsa");
        let pkey = PKey::from_rsa(rsa).expect("pkey");
        let priv_pem = pkey.private_key_to_pem_pkcs8().expect("priv pem");
        let pub_pem = pkey.public_key_to_pem().expect("pub pem");
        (
            String::from_utf8(priv_pem).expect("priv utf8"),
            String::from_utf8(pub_pem).expect("pub utf8"),
        )
    }

    fn config_from(
        merchant_priv: String,
        paco_pub_sign: String,
        paco_pub_enc: String,
        merchant_priv_dec: String,
    ) -> JoseConfig {
        JoseConfig::new(
            "test-kid-32-hex-chars-deadbeefcafe".to_string(),
            Secret::new(merchant_priv),
            Secret::new(merchant_priv_dec),
            Secret::new(paco_pub_sign),
            Secret::new(paco_pub_enc),
        )
        .expect("config")
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Claims {
        iss: String,
        n: u32,
    }

    #[test]
    fn round_trip_sign_encrypt_then_decrypt_verify() {
        // Two distinct keypairs, one for signing-side, one for encryption-side.
        let (merchant_sign_priv, merchant_sign_pub) = keypair_pems();
        let (counterparty_enc_priv, counterparty_enc_pub) = keypair_pems();

        // Sender encrypts with the receiver's encryption public key + signs
        // with its own signing private key.
        let sender_cfg = JoseConfig::new(
            "kid".into(),
            Secret::new(merchant_sign_priv.clone()),
            Secret::new(counterparty_enc_priv.clone()),
            Secret::new(merchant_sign_pub.clone()),
            Secret::new(counterparty_enc_pub.clone()),
        )
        .expect("sender cfg");

        let claims = Claims {
            iss: "test".into(),
            n: 7,
        };
        let jwe = sign_then_encrypt(&claims, &sender_cfg).expect("sign+encrypt");
        assert_eq!(jwe.split('.').count(), 5, "JWE compact has five segments");

        let decoded = decrypt_then_verify(&jwe, &sender_cfg).expect("decrypt+verify");
        let recovered: Claims = serde_json::from_value(decoded).expect("claims");
        assert_eq!(recovered, claims);
    }

    #[test]
    fn pem_without_trailing_end_newline_is_repaired() {
        let (_, pub_pem) = keypair_pems();
        // Strip the `\n` that comes right before `-----END`.
        let mut broken = pub_pem.replace("\n-----END", "-----END");
        // And drop the trailing newline so the only `\n` left is between
        // header line and body.
        if broken.ends_with('\n') {
            broken.pop();
        }
        assert!(!broken.contains("\n-----END"));
        let fixed = normalise_pem(&broken);
        assert!(fixed.contains("\n-----END"));
        // Re-parses cleanly with OpenSSL.
        PKey::public_key_from_pem(fixed.as_bytes()).expect("parse fixed pem");
    }

    #[test]
    fn invalid_pem_is_rejected_at_construction() {
        let result = JoseConfig::new(
            "kid".into(),
            Secret::new("not-a-pem".into()),
            Secret::new("not-a-pem".into()),
            Secret::new("not-a-pem".into()),
            Secret::new("not-a-pem".into()),
        );
        assert!(matches!(result, Err(JoseError::InvalidKey { .. })));
    }

    #[test]
    fn wrong_signing_key_fails_verify() {
        let (sign_priv_a, _sign_pub_a) = keypair_pems();
        let (_sign_priv_b, sign_pub_b) = keypair_pems();
        let (enc_priv, enc_pub) = keypair_pems();

        // Sender signs with key A, but the verifier expects key B.
        let cfg = JoseConfig::new(
            "kid".into(),
            Secret::new(sign_priv_a),
            Secret::new(enc_priv),
            Secret::new(sign_pub_b),
            Secret::new(enc_pub),
        )
        .expect("cfg");

        let jwe = sign_then_encrypt(&Claims { iss: "x".into(), n: 1 }, &cfg).expect("encrypt");
        let err = decrypt_then_verify(&jwe, &cfg).expect_err("must fail verification");
        assert!(matches!(err, JoseError::VerificationFailed));
    }

    // Suppress unused-import warning when this helper is not exercised.
    #[allow(dead_code)]
    fn _force_use_config_from() {
        let _ = config_from;
    }
}
