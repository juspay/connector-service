use common_utils::consts;
use std::collections::HashMap;
use std::path::PathBuf;

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

    // Parse using official Superposition parser
    let parsed_config = superposition_core::toml_parser::parse(&toml_content).map_err(|e| {
        config::ConfigError::Message(format!("Failed to parse superposition.toml: {:?}", e))
    })?;

    // Resolve configuration for the current environment
    let resolved = resolve_config(&parsed_config, environment)?;

    Ok(resolved)
}

/// Resolves the Superposition config for a given environment context
fn resolve_config(
    config: &superposition_core::toml_parser::Config,
    environment: &consts::Env,
) -> Result<HashMap<String, toml::Value>, config::ConfigError> {
    let mut resolved = HashMap::new();

    // Start with default config values
    for (key, config_value) in &config.default_configs {
        resolved.insert(key.clone(), config_value.value.clone());
    }

    // Apply context overrides for matching environment (environment-only contexts)
    let env_str = environment.to_string().to_lowercase();

    for context in &config.contexts {
        // Check if this context matches just the environment (no connector specified)
        if context_matches_environment(&context.condition, &env_str) && !has_connector_dimension(&context.condition) {
            // Apply overrides from this context
            for (override_key, override_id) in &context.override_with_keys {
                if let Some(override_value) = config.overrides.get(&override_id.get_key()) {
                    resolved.insert(override_key.clone(), override_value.clone());
                }
            }
        }
    }

    // Now resolve connector-specific URLs
    // We need to iterate through all known connectors and resolve each one
    if let Some(connector_enum) = config.dimensions.get("connector") {
        let connectors = extract_connector_list(&connector_enum.schema);

        for connector_name in connectors {
            // Resolve this connector's configuration
            let connector_config = resolve_connector_config(config, &connector_name, &env_str)?;

            // Add to resolved map with connector_ prefix
            for (key, value) in connector_config {
                let full_key = format!("connector_{}_{}", connector_name, key);
                resolved.insert(full_key, value);
            }
        }
    }

    Ok(resolved)
}

/// Resolves configuration for a specific connector in the given environment
fn resolve_connector_config(
    config: &superposition_core::toml_parser::Config,
    connector: &str,
    environment: &str,
) -> Result<HashMap<String, toml::Value>, config::ConfigError> {
    let mut connector_config = HashMap::new();

    // Start with default connector values from default-config
    for (key, config_value) in &config.default_configs {
        if key.starts_with("connector_") && !key.starts_with("connector_base_url") {
            // This is a connector-specific config key like connector_secondary_base_url
            // Extract the suffix (e.g., "secondary_base_url" from "connector_secondary_base_url")
            if let Some(suffix) = key.strip_prefix("connector_") {
                connector_config.insert(suffix.to_string(), config_value.value.clone());
            }
        } else if key == "connector_base_url"
                || key == "connector_secondary_base_url"
                || key == "connector_third_base_url"
                || key == "connector_dispute_base_url"
                || key == "connector_base_url_bank_redirects" {
            // Direct connector URL keys
            if let Some(suffix) = key.strip_prefix("connector_") {
                connector_config.insert(suffix.to_string(), config_value.value.clone());
            }
        }
    }

    // Apply connector-specific overrides (connector=X contexts)
    for context in &config.contexts {
        if context_matches_connector(&context.condition, connector) {
            let env_matches = if let Some(env_value) = context.condition.get("environment") {
                env_value.as_str().map(|s| s == environment).unwrap_or(true)
            } else {
                true // No environment constraint, matches all environments
            };

            if env_matches {
                // Apply overrides from this context
                for (override_key, override_id) in &context.override_with_keys {
                    if override_key.starts_with("connector_") {
                        if let Some(override_value) = config.overrides.get(&override_id.get_key()) {
                            if let Some(suffix) = override_key.strip_prefix("connector_") {
                                connector_config.insert(suffix.to_string(), override_value.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(connector_config)
}

/// Check if a context condition matches the current environment
fn context_matches_environment(condition: &HashMap<String, serde_json::Value>, env_str: &str) -> bool {
    if let Some(env_value) = condition.get("environment") {
        if let Some(env_string) = env_value.as_str() {
            return env_string == env_str;
        }
    }
    false
}

/// Check if a context has a connector dimension
fn has_connector_dimension(condition: &HashMap<String, serde_json::Value>) -> bool {
    condition.contains_key("connector")
}

/// Check if a context matches a specific connector
fn context_matches_connector(condition: &HashMap<String, serde_json::Value>, connector: &str) -> bool {
    if let Some(connector_value) = condition.get("connector") {
        if let Some(connector_string) = connector_value.as_str() {
            return connector_string == connector;
        }
    }
    false
}

/// Extract the list of connectors from the connector dimension schema
fn extract_connector_list(schema: &serde_json::Value) -> Vec<String> {
    if let Some(enum_values) = schema.get("enum") {
        if let Some(array) = enum_values.as_array() {
            return array
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
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
                        // Only add if value is not empty
                        if let toml::Value::String(s) = value {
                            if !s.is_empty() {
                                toml_parts.push(format!(
                                    "{}.{} = {}",
                                    connector,
                                    url_type,
                                    toml_value_to_string(value)
                                ));
                            }
                        }
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
