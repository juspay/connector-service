//! Patch helpers for applying partial config overrides.
//!
//! Summary:
//! - Each config struct derives `config_patch_derive::Patch` to generate a `*Patch` type.
//! - Patch fields are optional; missing fields do not change the base config.
//! - Nested structs use `#[patch(nested)]` or `#[patch(nested_all)]` to recurse.
//! - Optional fields (`Option<T>`) use `Option<Option<T>>` in patches to allow clearing
//!   with `null` while keeping "missing" as "no change".

use serde::Deserialize;

pub trait Patch<P> {
    fn apply(&mut self, patch: P);
}

/// Deserialize `Option<Option<T>>` while preserving "missing vs null" semantics.
///
/// - Missing field => `None` (no change)
/// - Field present with `null` => `Some(None)` (clear)
/// - Field present with value => `Some(Some(value))` (replace)
pub fn deserialize_option_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = Option::<T>::deserialize(deserializer)?;
    Ok(Some(value))
}

pub fn apply_replace<T>(target: &mut T, patch: Option<T>) {
    if let Some(value) = patch {
        *target = value;
    }
}

pub fn apply_option_value<T>(target: &mut Option<T>, patch: Option<Option<T>>) {
    if let Some(value) = patch {
        *target = value;
    }
}

pub fn apply_nested<T, P>(target: &mut T, patch: Option<P>)
where
    T: Patch<P>,
{
    if let Some(value) = patch {
        target.apply(value);
    }
}

pub fn apply_optional_patch<T, P>(target: &mut Option<T>, patch: Option<Option<P>>)
where
    T: Patch<P> + Default,
{
    match patch {
        None => {}
        Some(None) => {
            *target = None;
        }
        Some(Some(patch_value)) => {
            let mut value = target.take().unwrap_or_default();
            value.apply(patch_value);
            *target = Some(value);
        }
    }
}
