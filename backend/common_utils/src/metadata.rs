use std::collections::HashSet;

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

    pub fn should_mask(&self, key: &str) -> bool {
        !self.unmasked_keys.contains(&key.to_lowercase())
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
/// - get(key) -> Secret<String> - Forces explicit .expose() call
/// - get_raw(key) -> String - Raw access
/// - get_maskable(key) -> Maskable<String> - For logging/observability
/// - get_all_masked() -> HashMap<String, String> - Safe for logging
#[derive(Debug, Clone)]
pub struct MaskedMetadata {
    raw_metadata: tonic::metadata::MetadataMap,
    masking_config: HeaderMaskingConfig,
}

impl MaskedMetadata {
    pub fn new(raw_metadata: tonic::metadata::MetadataMap, masking_config: HeaderMaskingConfig) -> Self {
        Self { raw_metadata, masking_config }
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
    
    /// Returns reference to the raw tonic metadata map
    pub fn raw_metadata(&self) -> &tonic::metadata::MetadataMap {
        &self.raw_metadata
    }
    
    /// Returns Maskable with enum variants for logging (masked/unmasked)
    pub fn get_maskable(&self, key: &str) -> Option<Maskable<String>> {
        self.raw_metadata
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(|s| {
                if self.masking_config.should_mask(key) {
                    Maskable::new_masked(Secret::new(s.to_string()))
                } else {
                    Maskable::new_normal(s.to_string())
                }
            })
    }
    
    /// Get all metadata as HashMap with masking for logging
    pub fn get_all_masked(&self) -> std::collections::HashMap<String, String> {
        self.raw_metadata
            .iter()
            .filter_map(|entry| {
                let key = match entry {
                    tonic::metadata::KeyAndValueRef::Ascii(k, _) => k.as_str(),
                    tonic::metadata::KeyAndValueRef::Binary(k, _) => k.as_str(),
                };
                
                let value = match entry {
                    tonic::metadata::KeyAndValueRef::Ascii(_, v) => v.to_str().ok().map(|s| s.to_string()),
                    tonic::metadata::KeyAndValueRef::Binary(_, v) => {
                        // For binary, encode as base64
                        use base64::Engine;
                        Some(base64::engine::general_purpose::STANDARD.encode(v.as_ref()))
                    }
                };
                
                value.map(|s| {
                    let masked_value = if self.masking_config.should_mask(key) {
                        "**MASKED**".to_string()
                    } else {
                        s.to_string()
                    };
                    (key.to_string(), masked_value)
                })
            })
            .collect()
    }
}