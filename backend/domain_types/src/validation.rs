//! Validation helper for collecting multiple field errors
//!
//! This module provides a fluent API for building validation errors
//! that can report multiple missing or invalid fields at once,
//! improving developer experience by showing all issues in a single error.

use std::collections::HashMap;

use crate::errors::ConnectorError;

/// Helper for accumulating validation errors across multiple fields
///
/// # Example
/// ```
/// use domain_types::validation::ValidationError;
///
/// let mut validation = ValidationError::new();
///
/// if billing_address.is_none() {
///     validation.add_missing_field("billing.address");
/// }
/// if email.is_none() {
///     validation.add_missing_field("email");
/// }
///
/// // Returns error only if there are validation failures
/// validation.check()?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct ValidationError {
    field_errors: HashMap<String, String>,
}

impl ValidationError {
    /// Create a new empty validation error collector
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a missing field error with default message
    pub fn add_missing_field(&mut self, field_name: &str) -> &mut Self {
        self.field_errors.insert(
            field_name.to_string(),
            "This field is required".to_string(),
        );
        self
    }

    /// Add a field error with custom message
    pub fn add_field_error(&mut self, field_name: &str, message: &str) -> &mut Self {
        self.field_errors
            .insert(field_name.to_string(), message.to_string());
        self
    }

    /// Add a field error if condition is true
    pub fn add_if(&mut self, condition: bool, field_name: &str, message: &str) -> &mut Self {
        if condition {
            self.add_field_error(field_name, message);
        }
        self
    }

    /// Require a field to be present, adding error if missing
    pub fn require_field<T>(
        &mut self,
        field_name: &str,
        value: Option<&T>,
        message: &str,
    ) -> &mut Self {
        if value.is_none() {
            self.add_field_error(field_name, message);
        }
        self
    }

    /// Require multiple fields at once
    ///
    /// # Example
    /// ```
    /// validation.require_all(&[
    ///     ("card.number", card.number.is_some(), "Card number required"),
    ///     ("card.expiry", card.expiry.is_some(), "Expiry required"),
    /// ]);
    /// ```
    pub fn require_all(
        &mut self,
        checks: &[(&str, bool, &str)], // (field_name, is_present, message)
    ) -> &mut Self {
        for (field_name, is_present, message) in checks {
            if !is_present {
                self.add_field_error(field_name, message);
            }
        }
        self
    }

    /// Check if there are any validation errors
    pub fn has_errors(&self) -> bool {
        !self.field_errors.is_empty()
    }

    /// Get the number of validation errors
    pub fn error_count(&self) -> usize {
        self.field_errors.len()
    }

    /// Get reference to field errors map
    pub fn field_errors(&self) -> &HashMap<String, String> {
        &self.field_errors
    }

    /// Consume self and return error if there are validation failures
    pub fn check(self) -> Result<(), ConnectorError> {
        if self.has_errors() {
            Err(ConnectorError::ValidationFailed {
                field_errors: self.field_errors,
            })
        } else {
            Ok(())
        }
    }

    /// Convert into ConnectorError without checking if empty
    /// (use when you know there are errors)
    pub fn into_error(self) -> ConnectorError {
        ConnectorError::ValidationFailed {
            field_errors: self.field_errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_validation_passes() {
        let validation = ValidationError::new();
        assert!(validation.check().is_ok());
    }

    #[test]
    fn test_single_field_error() {
        let mut validation = ValidationError::new();
        validation.add_missing_field("card_number");

        let result = validation.check();
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_field_errors() {
        let mut validation = ValidationError::new();
        validation
            .add_missing_field("card_number")
            .add_missing_field("card_expiry")
            .add_field_error("cvv", "CVV must be 3-4 digits");

        assert_eq!(validation.error_count(), 3);
        assert!(validation.has_errors());
    }

    #[test]
    fn test_require_field() {
        let mut validation = ValidationError::new();

        let some_value = Some("present");
        let none_value: Option<&str> = None;

        validation
            .require_field("field1", some_value.as_ref(), "Should not error")
            .require_field("field2", none_value.as_ref(), "Should error");

        assert_eq!(validation.error_count(), 1);
        assert!(validation.field_errors().contains_key("field2"));
    }
}
