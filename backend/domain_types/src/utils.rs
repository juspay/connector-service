use error_stack::{Result, ResultExt};
use serde::Serialize;

use crate::errors::ParsingError;

/// Trait for converting from one foreign type to another
pub trait ForeignTryFrom<F>: Sized {
    /// Custom error for conversion failure
    type Error;

    /// Convert from a foreign type to the current type and return an error if the conversion fails
    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

pub trait ForeignFrom<F>: Sized {
    /// Convert from a foreign type to the current type and return an error if the conversion fails
    fn foreign_from(from: F) -> Self;
}

pub trait ValueExt {
    /// Convert `serde_json::Value` into type `<T>` by using `serde::Deserialize`
    fn parse_value<T>(self, type_name: &'static str) -> Result<T, ParsingError>
    where
        T: serde::de::DeserializeOwned;
}

impl ValueExt for serde_json::Value {
    fn parse_value<T>(self, type_name: &'static str) -> Result<T, ParsingError>
    where
        T: serde::de::DeserializeOwned,
    {
        let debug = format!(
            "Unable to parse {type_name} from serde_json::Value: {:?}",
            &self
        );
        serde_json::from_value::<T>(self)
            .change_context(ParsingError::StructParseFailure(type_name))
            .attach_printable_lazy(|| debug)
    }
}

pub trait Encode<'e>
where
    Self: 'e + std::fmt::Debug,
{
    fn encode_to_value(&'e self) -> Result<serde_json::Value, ParsingError>
    where
        Self: Serialize;
}

impl<'e, A> Encode<'e> for A
where
    Self: 'e + std::fmt::Debug,
{
    fn encode_to_value(&'e self) -> Result<serde_json::Value, ParsingError>
    where
        Self: Serialize,
    {
        serde_json::to_value(self)
            .change_context(ParsingError::EncodeError("json-value"))
            .attach_printable_lazy(|| format!("Unable to convert {self:?} to a value"))
    }
}
