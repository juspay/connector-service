use std::collections::HashSet;

use bytes::Bytes;
use hyperswitch_masking::{Maskable, Secret};

/// Configuration for header masking in gRPC metadata.
#[derive(Debug, Clone)]
pub struct HeaderMaskingConfig {
    unmasked_keys: HashSet<String>,
}

impl HeaderMaskingConfig {
    pub fn new(unmasked_keys: HashSet<String>) -> Self {
        Self { unmasked_keys }
    }

    pub fn should_unmask(&self, key: &str) -> bool {
        self.unmasked_keys.contains(&key.to_lowercase())
    }
}

impl<'de> serde::Deserialize<'de> for HeaderMaskingConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Config {
            keys: Vec<String>,
        }

        Config::deserialize(deserializer).map(|config| Self {
            unmasked_keys: config
                .keys
                .into_iter()
                .map(|key| key.to_lowercase())
                .collect(),
        })
    }
}

impl Default for HeaderMaskingConfig {
    fn default() -> Self {
        Self {
            unmasked_keys: ["content-type", "content-length", "user-agent"]
                .iter()
                .map(|&key| key.to_string())
                .collect(),
        }
    }
}

/// Secure wrapper for gRPC metadata with configurable masking.
/// ASCII headers:
/// - get(key) -> Secret<String> - Forces explicit .expose() call
/// - get_raw(key) -> String - Raw access
/// - get_maskable(key) -> Maskable<String> - For logging/observability
/// Binary headers:
/// - get_bin(key) -> Secret<Bytes> - Forces explicit .expose() call
/// - get_bin_raw(key) -> Bytes - Raw access
/// - get_bin_maskable(key) -> Maskable<String> - Base64 encoded for logging
/// - get_all_masked() -> HashMap<String, String> - Safe for logging
#[derive(Clone)]
pub struct MaskedMetadata {
    raw_metadata: tonic::metadata::MetadataMap,
    masking_config: HeaderMaskingConfig,
}

impl std::fmt::Debug for MaskedMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaskedMetadata")
            .field("masked_headers", &self.get_all_masked())
            .field("masking_config", &self.masking_config)
            .finish()
    }
}

impl MaskedMetadata {
    pub fn new(
        raw_metadata: tonic::metadata::MetadataMap,
        masking_config: HeaderMaskingConfig,
    ) -> Self {
        Self {
            raw_metadata,
            masking_config,
        }
    }

    /// Always returns Secret - business logic must call .expose() explicitly
    pub fn get(&self, key: &str) -> Option<Secret<String>> {
        self.raw_metadata
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(|s| Secret::new(s.to_string()))
    }

    /// Returns raw string value regardless of config
    pub fn get_raw(&self, key: &str) -> Option<String> {
        self.raw_metadata
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Returns Maskable with enum variants for logging (masked/unmasked)
    pub fn get_maskable(&self, key: &str) -> Option<Maskable<String>> {
        self.raw_metadata
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(|s| {
                if self.masking_config.should_unmask(key) {
                    Maskable::new_normal(s.to_string())
                } else {
                    Maskable::new_masked(Secret::new(s.to_string()))
                }
            })
    }

    /// Always returns Secret<Bytes> - business logic must call .expose() explicitly
    pub fn get_bin(&self, key: &str) -> Option<Secret<Bytes>> {
        self.raw_metadata
            .get_bin(key)
            .and_then(|value| value.to_bytes().ok())
            .map(|bytes| Secret::new(bytes))
    }

    /// Returns raw Bytes value regardless of config
    pub fn get_bin_raw(&self, key: &str) -> Option<Bytes> {
        self.raw_metadata
            .get_bin(key)
            .and_then(|value| value.to_bytes().ok())
    }

    /// Returns Maskable<String> with base64 encoding for binary headers
    pub fn get_bin_maskable(&self, key: &str) -> Option<Maskable<String>> {
        self.raw_metadata.get_bin(key).map(|value| {
            let encoded = String::from_utf8_lossy(value.as_encoded_bytes()).to_string();
            if self.masking_config.should_unmask(key) {
                Maskable::new_normal(encoded)
            } else {
                Maskable::new_masked(Secret::new(encoded))
            }
        })
    }

    /// Get all metadata as HashMap with masking for logging
    pub fn get_all_masked(&self) -> std::collections::HashMap<String, String> {
        self.raw_metadata
            .iter()
            .filter_map(|entry| {
                let key_name = match entry {
                    tonic::metadata::KeyAndValueRef::Ascii(key, _) => key.as_str(),
                    tonic::metadata::KeyAndValueRef::Binary(key, _) => key.as_str(),
                };

                let masked_value = match entry {
                    tonic::metadata::KeyAndValueRef::Ascii(_, _) => self
                        .get_maskable(key_name)
                        .map(|maskable| format!("{:?}", maskable)),
                    tonic::metadata::KeyAndValueRef::Binary(_, _) => self
                        .get_bin_maskable(key_name)
                        .map(|maskable| format!("{:?}", maskable)),
                };

                masked_value.map(|value| (key_name.to_string(), value))
            })
            .collect()
    }
}
