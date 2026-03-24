//! Scenario generator core module
//!
//! Generates test scenarios from declarative specs.

pub mod proto_utils;
pub mod types;

use crate::generator_core::proto_utils::{is_field_optional, message_name_for_suite};
use crate::generator_core::types::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;

/// Maximum number of scenarios to generate (prevents memory exhaustion)
const SCENARIO_LIMIT: usize = 10000;

/// Generate scenarios for a suite using specified groups
///
/// Algorithm:
/// 1. Always generate base scenarios from "required" group
/// 2. If groups array is empty: multiply all groups together (current behavior)
/// 3. If groups array has entries: process required + each group sequentially
///    - Base scenarios + variant for each group
pub fn generate_scenarios(
    suite: &str,
    groups: &[&str],
) -> Result<BTreeMap<String, Scenario>, GeneratorError> {
    // Load spec and payment methods
    let spec = load_spec(suite)?;
    let payment_methods = load_payment_methods(suite)?;

    // Resolve the proto message name for this suite (drives optional field detection)
    let message_name = message_name_for_suite(suite);

    // Get required group fields
    let required_group = spec
        .groups
        .get("required")
        .ok_or_else(|| GeneratorError::GroupNotFound("required".to_string()))?;

    // Generate base combinations from required group
    let base_combinations = generate_combinations(
        &required_group.fields,
        &payment_methods,
        false,
        message_name,
    )?;

    let mut all_scenarios: BTreeMap<String, Scenario> = BTreeMap::new();

    if groups.is_empty() {
        // Empty array: use ALL groups together (multiply all)
        let mut all_fields = required_group.fields.clone();

        // Add all other groups
        for (group_name, group) in &spec.groups {
            if group_name != "required" {
                for (field_name, field_spec) in &group.fields {
                    all_fields.insert(field_name.clone(), field_spec.clone());
                }
            }
        }

        // Generate all combinations (with limit when using all groups)
        let combinations =
            generate_combinations(&all_fields, &payment_methods, true, message_name)?;

        for combo in combinations {
            let scenario = build_scenario(&combo, &spec)?;
            let name = generate_scenario_name(&combo);
            all_scenarios.insert(name, scenario);
        }
    } else {
        // Non-empty array: process required + each group sequentially

        // First, add base scenarios (required only)
        for base_combo in &base_combinations {
            let scenario = build_scenario(base_combo, &spec)?;
            let name = generate_scenario_name(base_combo);
            all_scenarios.insert(name, scenario);
        }

        // Then, for each group in the array, create variant scenarios
        for group_name in groups {
            if *group_name == "required" {
                continue; // Skip required, already done
            }

            let group = spec
                .groups
                .get(*group_name)
                .ok_or_else(|| GeneratorError::GroupNotFound(group_name.to_string()))?;

            // Generate group combinations
            let group_combinations =
                generate_combinations(&group.fields, &payment_methods, false, message_name)?;

            // Create variant scenarios: base + group combination
            for base_combo in &base_combinations {
                for group_combo in &group_combinations {
                    // Merge base and group combinations
                    let merged_combo = merge_combinations(base_combo, group_combo);
                    let mut scenario = build_scenario(&merged_combo, &spec)?;

                    // Generate variant name
                    let base_name = generate_scenario_name(base_combo);
                    let group_suffix = generate_group_suffix(group_combo);
                    let variant_name = format!("{}_{}", base_name, group_suffix);

                    // Merge depends_on from both
                    let base_depends_on: HashSet<String> = base_combo
                        .iter()
                        .flat_map(|f| f.depends_on.clone())
                        .collect();
                    let group_depends_on: HashSet<String> = group_combo
                        .iter()
                        .flat_map(|f| f.depends_on.clone())
                        .collect();
                    let combined_depends_on: HashSet<String> =
                        base_depends_on.union(&group_depends_on).cloned().collect();
                    scenario.depends_on = combined_depends_on.into_iter().collect();

                    all_scenarios.insert(variant_name, scenario);
                }
            }
        }
    }

    Ok(all_scenarios)
}

/// Load generator spec from suite directory
fn load_spec(suite: &str) -> Result<GeneratorSpec, GeneratorError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let spec_path = PathBuf::from(manifest_dir)
        .join("src")
        .join("global_suites")
        .join(format!("{}_suite", suite))
        .join("generator_specs.json");

    let content = fs::read_to_string(&spec_path)
        .map_err(|e| GeneratorError::SpecRead(format!("{}: {}", spec_path.display(), e)))?;

    serde_json::from_str(&content).map_err(|e| GeneratorError::SpecParse(e.to_string()))
}

/// Load payment methods data for a suite
fn load_payment_methods(suite: &str) -> Result<PaymentMethodsData, GeneratorError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let pm_path = PathBuf::from(manifest_dir)
        .join("src")
        .join("global_suites")
        .join(format!("{}_suite", suite))
        .join("generator_payment_methods.json");

    if !pm_path.exists() {
        return Ok(PaymentMethodsData::new());
    }

    let content = fs::read_to_string(&pm_path)
        .map_err(|e| GeneratorError::PaymentMethodsRead(format!("{}: {}", pm_path.display(), e)))?;

    serde_json::from_str(&content).map_err(|e| GeneratorError::PaymentMethodsRead(e.to_string()))
}

/// A field with its selected variant value
#[derive(Debug, Clone)]
struct FieldCombination {
    name: String,
    value: Value,
    is_present: bool,  // true = present in request, false = absent (omitted)
    is_optional: bool, // true = field is optional in proto
    variant_value: Option<String>,
    assertion: Option<FieldAssertion>,
    depends_on: Vec<String>,
}

/// Generate all combinations of field variants
fn generate_combinations(
    fields: &BTreeMap<String, FieldSpec>,
    payment_methods: &PaymentMethodsData,
    limit_to_scenarios: bool,
    message_name: &str,
) -> Result<Vec<Vec<FieldCombination>>, GeneratorError> {
    // Collect field options
    let mut field_options: Vec<Vec<FieldCombination>> = Vec::new();
    let mut total_combinations: usize = 1;
    let mut would_exceed_limit = false;

    for (field_name, field_spec) in fields {
        let options =
            generate_field_options(field_name, field_spec, payment_methods, message_name)?;

        // Check if we're exceeding limit
        total_combinations = total_combinations.saturating_mul(options.len());
        if total_combinations > SCENARIO_LIMIT {
            would_exceed_limit = true;
            // Continue collecting - we'll truncate later
        }

        field_options.push(options);
    }

    // Cartesian product of all field options
    let combinations = cartesian_product(field_options);

    // If we exceeded limit and are in the mode that requires truncation, truncate and warn
    if would_exceed_limit && limit_to_scenarios {
        eprintln!(
            "Warning: {} combinations would be generated, limiting to first {}",
            total_combinations, SCENARIO_LIMIT
        );
        let truncated: Vec<Vec<FieldCombination>> =
            combinations.into_iter().take(SCENARIO_LIMIT).collect();
        Ok(truncated)
    } else {
        Ok(combinations)
    }
}

/// Generate all variant options for a single field
/// Checks proto for optionality and creates absent/present variants
fn generate_field_options(
    field_name: &str,
    spec: &FieldSpec,
    payment_methods: &PaymentMethodsData,
    message_name: &str,
) -> Result<Vec<FieldCombination>, GeneratorError> {
    let mut options = Vec::new();

    // Check if field is optional in proto
    let is_optional = is_field_optional(message_name, field_name);

    // Generate present options (same logic as before)
    let present_options = generate_present_options(field_name, spec, payment_methods)?;

    if is_optional {
        // Add absent option first
        options.push(FieldCombination {
            name: field_name.to_string(),
            value: Value::Null, // Will be omitted from req_body
            is_present: false,
            is_optional: true,
            variant_value: None,
            assertion: None,
            depends_on: vec![],
        });

        // Add all present options
        for mut opt in present_options {
            opt.is_present = true;
            opt.is_optional = true;
            options.push(opt);
        }
    } else {
        // Not optional - only present options
        for mut opt in present_options {
            opt.is_present = true;
            opt.is_optional = false;
            options.push(opt);
        }
    }

    Ok(options)
}

/// Generate present options for a field (original logic)
fn generate_present_options(
    field_name: &str,
    spec: &FieldSpec,
    payment_methods: &PaymentMethodsData,
) -> Result<Vec<FieldCombination>, GeneratorError> {
    let mut options = Vec::new();

    match spec.source.as_str() {
        "static" => {
            if let Some(ref variants) = spec.variants {
                // Has variants - generate one option per variant
                for variant_value in variants.values() {
                    let value =
                        build_field_value(field_name, spec, Some(variant_value), payment_methods)?;
                    let assertion = spec
                        .assertions
                        .as_ref()
                        .and_then(|a| a.get(variant_value).cloned());

                    options.push(FieldCombination {
                        name: field_name.to_string(),
                        value,
                        is_present: true,
                        is_optional: false,
                        variant_value: Some(variant_value.clone()),
                        assertion,
                        depends_on: vec![],
                    });
                }
            } else {
                // No variants - single static value
                let value = build_field_value(field_name, spec, None, payment_methods)?;
                options.push(FieldCombination {
                    name: field_name.to_string(),
                    value,
                    is_present: true,
                    is_optional: false,
                    variant_value: None,
                    assertion: None,
                    depends_on: vec![],
                });
            }
        }
        "enum" => {
            if let Some(ref variants) = spec.variants {
                for variant_value in variants.values() {
                    let value = json!(variant_value);
                    let assertion = spec
                        .assertions
                        .as_ref()
                        .and_then(|a| a.get(variant_value).cloned());

                    options.push(FieldCombination {
                        name: field_name.to_string(),
                        value,
                        is_present: true,
                        is_optional: false,
                        variant_value: Some(variant_value.clone()),
                        assertion,
                        depends_on: vec![],
                    });
                }
            }
        }
        "auto" => {
            options.push(FieldCombination {
                name: field_name.to_string(),
                value: json!("auto generate"),
                is_present: true,
                is_optional: false,
                variant_value: None,
                assertion: None,
                depends_on: vec![],
            });
        }
        "data_file" => {
            if let Some(ref variants) = spec.variants {
                for variant_value in variants.values() {
                    // Lookup payment method in data file
                    let value = if let Some(pm_data) = payment_methods.get(variant_value) {
                        pm_data.clone()
                    } else {
                        json!("context dependent")
                    };

                    options.push(FieldCombination {
                        name: field_name.to_string(),
                        value,
                        is_present: true,
                        is_optional: false,
                        variant_value: Some(variant_value.clone()),
                        assertion: None,
                        depends_on: vec![],
                    });
                }
            }
        }
        "prev_service" => {
            let depends_on = spec.suite.clone().unwrap_or_default();
            options.push(FieldCombination {
                name: field_name.to_string(),
                value: json!("context dependent"),
                is_present: true,
                is_optional: false,
                variant_value: None,
                assertion: None,
                depends_on: if depends_on.is_empty() {
                    vec![]
                } else {
                    vec![depends_on]
                },
            });
        }
        _ => {
            return Err(GeneratorError::InvalidSource(format!(
                "Field {} has unknown source: {}",
                field_name, spec.source
            )));
        }
    }

    Ok(options)
}

/// Build a field value, optionally with a variant
fn build_field_value(
    _field_name: &str,
    spec: &FieldSpec,
    variant_value: Option<&str>,
    _payment_methods: &PaymentMethodsData,
) -> Result<Value, GeneratorError> {
    match &spec.value {
        Some(base_value) => {
            let mut value = base_value.clone();

            // If there's a variant, inject it
            if let Some(variant) = variant_value {
                if let Some(ref variants) = spec.variants {
                    if let Some(field_name) = variants.field_name() {
                        if let Value::Object(ref mut obj) = value {
                            obj.insert(field_name.to_string(), json!(variant));
                        }
                    }
                }
            }

            Ok(value)
        }
        None => {
            if let Some(variant) = variant_value {
                Ok(json!(variant))
            } else {
                Ok(json!(null))
            }
        }
    }
}

/// Compute cartesian product of field options
/// Stops early if limit is reached to prevent memory issues
fn cartesian_product(fields: Vec<Vec<FieldCombination>>) -> Vec<Vec<FieldCombination>> {
    if fields.is_empty() {
        return vec![vec![]];
    }

    let mut result = vec![vec![]];
    for field_options in fields {
        let mut new_result = Vec::new();
        for existing in &result {
            for option in &field_options {
                let mut combined = existing.clone();
                combined.push(option.clone());
                new_result.push(combined);

                // Stop early if we hit the limit
                if new_result.len() >= SCENARIO_LIMIT {
                    return new_result;
                }
            }
        }
        result = new_result;

        // Check limit between iterations too
        if result.len() >= SCENARIO_LIMIT {
            break;
        }
    }
    result
}

/// Build a single scenario from a field combination
fn build_scenario(
    combination: &[FieldCombination],
    spec: &GeneratorSpec,
) -> Result<Scenario, GeneratorError> {
    // Build req_body
    let mut req_body = serde_json::Map::new();
    let mut depends_on = HashSet::new();
    let mut variant_assertions: Vec<&FieldAssertion> = Vec::new();

    for field in combination {
        // Skip absent fields (optional fields marked as absent)
        if !field.is_present {
            continue;
        }

        // Insert field value into req_body
        insert_nested_field(&mut req_body, &field.name, field.value.clone());

        // Collect dependencies
        for dep in &field.depends_on {
            depends_on.insert(dep.clone());
        }

        // Collect variant assertions
        if let Some(ref assertion) = field.assertion {
            variant_assertions.push(assertion);
        }
    }

    // Build assertions by merging base with variant assertions
    let assertions = build_assertions(&spec.success, &variant_assertions);

    Ok(Scenario {
        req_body: Value::Object(req_body),
        assertions,
        depends_on: depends_on.into_iter().collect(),
    })
}

/// Insert a field value, handling nested paths like "amount.currency"
fn insert_nested_field(obj: &mut serde_json::Map<String, Value>, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();

    if parts.len() == 1 {
        // Simple field
        obj.insert(parts[0].to_string(), value);
        return;
    }

    // Build nested structure bottom-up
    // Start with the innermost value
    let mut current_value = value;

    // Build from the inside out (excluding the first part which goes in obj)
    for part in parts[1..].iter().rev() {
        let mut new_obj = serde_json::Map::new();
        new_obj.insert(part.to_string(), current_value);
        current_value = Value::Object(new_obj);
    }

    // Now merge with existing structure at top level
    let first_part = parts[0];
    if let Some(existing) = obj.get_mut(first_part) {
        // Merge recursively
        merge_values(existing, current_value);
    } else {
        obj.insert(first_part.to_string(), current_value);
    }
}

/// Recursively merge two JSON values
fn merge_values(target: &mut Value, source: Value) {
    match (target, source) {
        (Value::Object(target_obj), Value::Object(source_obj)) => {
            for (key, source_val) in source_obj {
                if let Some(target_val) = target_obj.get_mut(&key) {
                    merge_values(target_val, source_val);
                } else {
                    target_obj.insert(key, source_val);
                }
            }
        }
        (target, source) => {
            *target = source;
        }
    }
}

/// Build final assertions by merging base with variant assertions
/// Base assertion is merged with variant assertions (variant overrides if conflict)
fn build_assertions(base: &Assertions, variant_assertions: &[&FieldAssertion]) -> Assertions {
    let mut status = base.status.clone();
    let error = base.error.clone();
    let must_exist = base.must_exist.clone();

    // Merge variant assertions (variant overrides base on conflict)
    for variant_assertion in variant_assertions {
        // Variant status replaces base status
        status = variant_assertion.status.clone();
        // Note: In the future, could merge error and must_exist too if needed
    }

    Assertions {
        status,
        error,
        must_exist,
    }
}

/// Generate scenario name from field combination
/// Creates unique name including all field variants to avoid overwrites
fn generate_scenario_name(combination: &[FieldCombination]) -> String {
    // Start with base fields
    let auth_type = find_field_value(combination, "auth_type");
    let payment_method = find_variant_value(combination, "payment_method");
    let currency = find_variant_value_nested(combination, "amount", "currency");

    let mut parts = Vec::new();

    // Base parts (required fields)
    if let Some(at) = auth_type {
        parts.push(at);
    }
    if let Some(pm) = payment_method {
        parts.push(pm);
    }
    if let Some(curr) = currency {
        parts.push(curr);
    }

    // Add variant suffixes for fields with variants or meaningful values
    for field in combination {
        // Skip base fields already added
        if field.name == "auth_type" || field.name == "payment_method" || field.name == "amount" {
            continue;
        }

        // If field is optional and absent, mark it
        if field.is_optional && !field.is_present {
            parts.push(format!("{}_absent", sanitize_name(&field.name)));
            continue;
        }

        // If field has a variant value, include it
        if let Some(ref variant) = field.variant_value {
            parts.push(format!(
                "{}_{}_present",
                sanitize_name(&field.name),
                variant.to_lowercase()
            ));
        } else if let Value::String(ref s) = field.value {
            // For static string values that aren't placeholders
            if s != "auto generate" && s != "context dependent" && !s.is_empty() {
                parts.push(format!(
                    "{}_{}_present",
                    sanitize_name(&field.name),
                    s.to_lowercase()
                ));
            } else {
                // Present but with placeholder value
                parts.push(format!("{}_present", sanitize_name(&field.name)));
            }
        } else if let Value::Bool(b) = field.value {
            // Include boolean values
            parts.push(format!("{}_{}_present", sanitize_name(&field.name), b));
        } else {
            // Present with other value type
            parts.push(format!("{}_present", sanitize_name(&field.name)));
        }
    }

    if parts.is_empty() {
        "scenario".to_string()
    } else {
        parts.join("_")
    }
}

/// Find a field's value from combination
fn find_field_value(combination: &[FieldCombination], field_name: &str) -> Option<String> {
    combination
        .iter()
        .find(|f| f.name == field_name)
        .map(|f| match &f.value {
            Value::String(s) => s.clone(),
            _ => f.value.to_string().trim_matches('"').to_string(),
        })
}

/// Find a field's variant value
fn find_variant_value(combination: &[FieldCombination], field_name: &str) -> Option<String> {
    combination
        .iter()
        .find(|f| f.name == field_name)
        .and_then(|f| f.variant_value.clone())
}

/// Find a nested field's variant value (e.g., amount.currency)
fn find_variant_value_nested(
    combination: &[FieldCombination],
    parent_field: &str,
    child_field: &str,
) -> Option<String> {
    combination
        .iter()
        .find(|f| f.name == parent_field)
        .and_then(|f| {
            if let Value::Object(ref obj) = f.value {
                obj.get(child_field).map(|v| match v {
                    Value::String(s) => s.clone(),
                    _ => v.to_string().trim_matches('"').to_string(),
                })
            } else {
                None
            }
        })
}

/// Merge two field combinations (base + group)
fn merge_combinations(
    base: &[FieldCombination],
    group: &[FieldCombination],
) -> Vec<FieldCombination> {
    let mut merged = base.to_vec();

    // Add all fields from group combination
    for group_field in group {
        // Check if field already exists in base
        if let Some(existing) = merged.iter_mut().find(|f| f.name == group_field.name) {
            // Replace with group field
            *existing = group_field.clone();
        } else {
            // Add new field
            merged.push(group_field.clone());
        }
    }

    merged
}

/// Generate suffix for group variant name
fn generate_group_suffix(combination: &[FieldCombination]) -> String {
    // Build suffix from variant values
    let parts: Vec<String> = combination
        .iter()
        .filter_map(|f| {
            // Use field name and variant value
            if let Some(ref variant) = f.variant_value {
                Some(format!(
                    "{}_{}",
                    sanitize_name(&f.name),
                    variant.to_lowercase()
                ))
            } else {
                // For non-variant fields, just use field name if it has a meaningful value
                match &f.value {
                    Value::String(s) if s != "auto generate" && s != "context dependent" => {
                        Some(format!("{}_{}", sanitize_name(&f.name), s.to_lowercase()))
                    }
                    _ => None,
                }
            }
        })
        .collect();

    if parts.is_empty() {
        "variant".to_string()
    } else {
        parts.join("_")
    }
}

/// Sanitize field name for use in scenario name
fn sanitize_name(name: &str) -> String {
    name.replace('.', "_").replace(" ", "_")
}

/// Write scenarios to JSON file (scenario.json)
/// Merges with existing scenarios - replaces if name matches, adds if new
pub fn write_scenarios(
    suite: &str,
    scenarios: &BTreeMap<String, Scenario>,
) -> Result<(), GeneratorError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let output_path = PathBuf::from(manifest_dir)
        .join("src")
        .join("global_suites")
        .join(format!("{}_suite", suite))
        .join("scenario.json");

    // Load existing scenarios if file exists
    let mut existing_scenarios: BTreeMap<String, Value> = if output_path.exists() {
        let content = fs::read_to_string(&output_path).map_err(|e| {
            GeneratorError::SpecRead(format!("Failed to read {}: {}", output_path.display(), e))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            GeneratorError::SpecParse(format!("Failed to parse existing scenarios: {}", e))
        })?
    } else {
        BTreeMap::new()
    };

    // Convert new scenarios to the expected format and merge
    for (name, scenario) in scenarios {
        let mut scenario_obj = serde_json::Map::new();
        scenario_obj.insert("grpc_req".to_string(), scenario.req_body.clone());

        // Build assert in the expected format
        let mut assert_obj = serde_json::Map::new();
        assert_obj.insert(
            "status".to_string(),
            json!({
                "one_of": scenario.assertions.status.iter().map(|s| json!(s)).collect::<Vec<_>>()
            }),
        );
        assert_obj.insert(
            "error".to_string(),
            json!({
                "must_not_exist": scenario.assertions.error == "must_not_exist"
            }),
        );
        // Add must_exist fields from spec (e.g., "access_token" for create_access_token, "connector_transaction_id" for authorize)
        for field in &scenario.assertions.must_exist {
            assert_obj.insert(
                field.clone(),
                json!({
                    "must_exist": true
                }),
            );
        }

        scenario_obj.insert("assert".to_string(), Value::Object(assert_obj));
        scenario_obj.insert("is_default".to_string(), json!(false));

        // Insert or replace
        existing_scenarios.insert(name.clone(), Value::Object(scenario_obj));
    }

    let json = serde_json::to_string_pretty(&existing_scenarios)
        .map_err(|e| GeneratorError::SpecParse(format!("Failed to serialize scenarios: {}", e)))?;

    fs::write(&output_path, json).map_err(|e| {
        GeneratorError::SpecRead(format!("Failed to write {}: {}", output_path.display(), e))
    })?;

    println!(
        "Updated {} scenarios in {} (total: {})",
        scenarios.len(),
        output_path.display(),
        existing_scenarios.len()
    );
    Ok(())
}
