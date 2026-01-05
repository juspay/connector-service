use common_utils::consts;
use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Superposition-inspired configuration with context-based overrides
#[derive(Debug, Deserialize, Serialize)]
struct SuperpositionConfig {
    #[serde(rename = "default-config")]
    default_config: HashMap<String, ConfigValue>,
    dimensions: HashMap<String, DimensionDef>,
    #[serde(rename = "context", default)]
    contexts: HashMap<String, HashMap<String, toml::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConfigValue {
    value: toml::Value,
    #[allow(dead_code)]
    schema: toml::Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct DimensionDef {
    #[allow(dead_code)]
    position: u32,
    #[allow(dead_code)]
    schema: toml::Value,
}

/// Loads and resolves Superposition TOML configuration based on environment context
pub fn load_superposition_config(
    environment: &consts::Env,
) -> Result<HashMap<String, toml::Value>, config::ConfigError> {
    // Read the superposition.toml file
    let config_path = superposition_config_path();
    let toml_content = std::fs::read_to_string(&config_path).map_err(|e| {
        config::ConfigError::Message(format!(
            "Failed to read superposition.toml: {}",
            e
        ))
    })?;

    // Parse the TOML file
    let parsed_config: SuperpositionConfig = toml::from_str(&toml_content).map_err(|e| {
        config::ConfigError::Message(format!("Failed to parse superposition.toml: {}", e))
    })?;

    // Resolve configuration for the current environment
    let resolved = resolve_config(&parsed_config, environment)?;

    Ok(resolved)
}

/// Resolves the Superposition config for a given environment context
fn resolve_config(
    config: &SuperpositionConfig,
    environment: &consts::Env,
) -> Result<HashMap<String, toml::Value>, config::ConfigError> {
    let mut resolved = HashMap::new();

    // Start with default config values
    for (key, config_value) in &config.default_config {
        resolved.insert(key.clone(), config_value.value.clone());
    }

    // Apply context overrides for matching environment
    let env_str = environment.to_string().to_lowercase();

    // Match contexts like "environment=sandbox" or "environment=development"
    for (context_key, overrides) in &config.contexts {
        if context_matches(context_key, &env_str) {
            // Apply all overrides from this context
            for (key, value) in overrides {
                resolved.insert(key.clone(), value.clone());
            }
        }
    }

    Ok(resolved)
}

/// Check if a context key matches the current environment
fn context_matches(context_key: &str, env_str: &str) -> bool {
    // Context keys are like "environment=sandbox" or "environment=development"
    context_key
        .split(';')
        .any(|part| {
            let part = part.trim();
            if let Some((_dim, value)) = part.split_once('=') {
                value.trim_matches('"') == env_str
            } else {
                false
            }
        })
}

/// Converts resolved flat config into nested TOML structure
pub fn build_config_toml(
    resolved: &HashMap<String, toml::Value>,
) -> Result<String, config::ConfigError> {
    let mut toml_parts = Vec::new();

    // Group keys by prefix to create nested structures
    let mut grouped: HashMap<String, Vec<(String, &toml::Value)>> = HashMap::new();

    for (key, value) in resolved {
        if let Some((prefix, suffix)) = key.split_once('_') {
            grouped
                .entry(prefix.to_string())
                .or_default()
                .push((suffix.to_string(), value));
        }
    }

    // Build nested TOML sections
    for (section, entries) in &grouped {
        match section.as_str() {
            "common" => {
                toml_parts.push("[common]".to_string());
                for (key, value) in entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(value)));
                }
                toml_parts.push(String::new());
            }
            "server" => {
                toml_parts.push("[server]".to_string());
                for (key, value) in entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(value)));
                }
                toml_parts.push(String::new());
            }
            "metrics" => {
                toml_parts.push("[metrics]".to_string());
                for (key, value) in entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(value)));
                }
                toml_parts.push(String::new());
            }
            "proxy" => {
                toml_parts.push("[proxy]".to_string());
                for (key, value) in entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(value)));
                }
                toml_parts.push(String::new());
            }
            "log" => {
                // Handle log.console and log.kafka subsections
                let mut console_entries = Vec::new();
                let mut kafka_entries = Vec::new();

                for (key, value) in entries {
                    if let Some((subsection, subkey)) = key.split_once('_') {
                        match subsection {
                            "console" => console_entries.push((subkey.to_string(), *value)),
                            "kafka" => kafka_entries.push((subkey.to_string(), *value)),
                            _ => {}
                        }
                    }
                }

                if !console_entries.is_empty() {
                    toml_parts.push("[log.console]".to_string());
                    for (key, value) in console_entries {
                        toml_parts.push(format!("{} = {}", key, toml_value_to_string(&value)));
                    }
                    toml_parts.push(String::new());
                }

                if !kafka_entries.is_empty() {
                    toml_parts.push("[log.kafka]".to_string());
                    for (key, value) in kafka_entries {
                        toml_parts.push(format!("{} = {}", key, toml_value_to_string(&value)));
                    }
                    toml_parts.push(String::new());
                }
            }
            "connector" => {
                // Handle connector URLs - build [connectors] section
                if !toml_parts.iter().any(|s| s == "[connectors]") {
                    toml_parts.push("[connectors]".to_string());
                }

                // Group by connector name
                let mut connector_map: HashMap<String, Vec<(String, &toml::Value)>> = HashMap::new();
                for (key, value) in entries {
                    if let Some((connector_name, url_type)) = key.split_once('_') {
                        connector_map
                            .entry(connector_name.to_string())
                            .or_default()
                            .push((url_type.to_string(), value));
                    }
                }

                for (connector, urls) in connector_map {
                    for (url_type, value) in urls {
                        toml_parts.push(format!(
                            "{}.{} = {}",
                            connector,
                            url_type,
                            toml_value_to_string(value)
                        ));
                    }
                }
                toml_parts.push(String::new());
            }
            "events" => {
                toml_parts.push("[events]".to_string());
                // Handle events subsections
                let mut transformations = Vec::new();
                let mut static_values = Vec::new();
                let mut main_entries = Vec::new();

                for (key, value) in entries {
                    if let Some(rest) = key.strip_prefix("transformations_") {
                        transformations.push((rest.to_string(), *value));
                    } else if let Some(rest) = key.strip_prefix("static_values_") {
                        static_values.push((rest.to_string(), *value));
                    } else {
                        main_entries.push((key.clone(), *value));
                    }
                }

                for (key, value) in main_entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(&value)));
                }
                toml_parts.push(String::new());

                if !transformations.is_empty() {
                    toml_parts.push("[events.transformations]".to_string());
                    for (key, value) in transformations {
                        toml_parts.push(format!("\"{}\" = {}", key.replace('_', "."), toml_value_to_string(&value)));
                    }
                    toml_parts.push(String::new());
                }

                if !static_values.is_empty() {
                    toml_parts.push("[events.static_values]".to_string());
                    for (key, value) in static_values {
                        toml_parts.push(format!("\"{}\" = {}", key.replace('_', "."), toml_value_to_string(&value)));
                    }
                    toml_parts.push(String::new());
                }
            }
            "test" => {
                toml_parts.push("[test]".to_string());
                for (key, value) in entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(value)));
                }
                toml_parts.push(String::new());
            }
            "lineage" => {
                toml_parts.push("[lineage]".to_string());
                for (key, value) in entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(value)));
                }
                toml_parts.push(String::new());
            }
            "api_tags" => {
                // Handle api_tags.tags subsection
                let mut tags_entries = Vec::new();
                for (key, value) in entries {
                    if let Some(tag_key) = key.strip_prefix("tags_") {
                        tags_entries.push((tag_key.to_string(), *value));
                    }
                }

                if !tags_entries.is_empty() {
                    toml_parts.push("[api_tags.tags]".to_string());
                    for (key, value) in tags_entries {
                        toml_parts.push(format!("{} = {}", key, toml_value_to_string(&value)));
                    }
                    toml_parts.push(String::new());
                }
            }
            "unmasked_headers" => {
                toml_parts.push("[unmasked_headers]".to_string());
                for (key, value) in entries {
                    toml_parts.push(format!("{} = {}", key, toml_value_to_string(value)));
                }
                toml_parts.push(String::new());
            }
            _ => {}
        }
    }

    Ok(toml_parts.join("\n"))
}

/// Converts TOML value to string representation
fn toml_value_to_string(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => format!("\"{}\"", s),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(toml_value_to_string).collect();
            format!("[{}]", items.join(", "))
        }
        toml::Value::Datetime(dt) => format!("\"{}\"", dt),
        toml::Value::Table(_) => "{}".to_string(),
    }
}

fn superposition_config_path() -> PathBuf {
    let mut path = crate::configs::workspace_path();
    path.push("config");
    path.push("superposition.toml");
    path
}
