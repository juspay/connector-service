use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use tonic::metadata::{KeyAndValueRef, MetadataMap};

use common_utils::metadata::HeaderMaskingConfig;

pub trait MetadataMasking {
    fn mask_headers(&self, config: &HeaderMaskingConfig) -> HashMap<String, String>;
}

impl MetadataMasking for MetadataMap {
    fn mask_headers(&self, config: &HeaderMaskingConfig) -> HashMap<String, String> {
        self.iter()
            .filter_map(|entry| {
                let key = match entry {
                    KeyAndValueRef::Ascii(k, _) => k.as_str(),
                    KeyAndValueRef::Binary(k, _) => k.as_str(),
                };

                let value = match entry {
                    KeyAndValueRef::Ascii(_, v) => {
                        if config.should_mask(key) {
                            "**MASKED**".to_string()
                        } else {
                            match v.to_str() {
                                Ok(text) => text.to_string(),
                                Err(_) => {
                                    tracing::warn!("Invalid UTF-8 in header '{}'", key);
                                    "**INVALID-UTF8**".to_string()
                                }
                            }
                        }
                    }
                    KeyAndValueRef::Binary(_, v) => {
                        if config.should_mask(key) {
                            "**MASKED-BINARY**".to_string()
                        } else {
                            general_purpose::STANDARD.encode(v.as_ref())
                        }
                    }
                };

                Some((key.to_string(), value))
            })
            .collect()
    }
}
