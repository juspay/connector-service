use serde_json::Value;

/// Applies RFC 7396 JSON Merge Patch semantics.
///
/// Behavior:
/// - object keys in `patch` are recursively merged into `target`
/// - `null` values in `patch` remove keys from `target`
/// - scalar/array/object value replacement happens for non-object pairs
/// - extra keys present only in `patch` are added to `target`
pub fn json_merge_patch(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(target_map), Value::Object(patch_map)) => {
            for (key, patch_value) in patch_map {
                if patch_value.is_null() {
                    target_map.remove(key);
                    continue;
                }

                if let Some(target_value) = target_map.get_mut(key) {
                    json_merge_patch(target_value, patch_value);
                } else {
                    target_map.insert(key.clone(), patch_value.clone());
                }
            }
        }
        (target_value, patch_value) => {
            *target_value = patch_value.clone();
        }
    }
}