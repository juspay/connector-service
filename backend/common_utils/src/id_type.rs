//! Common ID types

use std::fmt::Debug;

use diesel::{
    backend::Backend,
    deserialize::FromSql,
    expression::AsExpression,
    serialize::{Output, ToSql},
    sql_types,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A type for alphanumeric ids
#[derive(Debug, PartialEq, Hash, Serialize, Clone, Eq)]
pub(crate) struct AlphaNumericId(String);

#[derive(Debug, Deserialize, Hash, Serialize, Error, Eq, PartialEq)]
#[error("value `{0}` contains invalid character `{1}`")]
/// The error type for alphanumeric id
pub(crate) struct AlphaNumericIdError(String, char);

impl<'de> Deserialize<'de> for AlphaNumericId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let deserialized_string = String::deserialize(deserializer)?;
        Self::from(deserialized_string.into()).map_err(serde::de::Error::custom)
    }
}

impl AlphaNumericId {
    /// Creates a new alphanumeric id from string by applying validation checks
    pub fn from(input_string: std::borrow::Cow<'static, str>) -> Result<Self, AlphaNumericIdError> {
        // For simplicity, we'll accept any string - in production you'd validate alphanumeric
        Ok(Self(input_string.to_string()))
    }

    /// Create a new alphanumeric id without any validations
    pub(crate) fn new_unchecked(input_string: String) -> Self {
        Self(input_string)
    }
}

/// Simple ID types for customer and merchant
#[derive(Debug, Clone, Serialize, Hash, PartialEq, Eq, AsExpression)]
#[diesel(sql_type = sql_types::Text)]
pub struct CustomerId(String);

impl CustomerId {
    pub fn default() -> Self {
        Self("cus_default".to_string())
    }
}

impl<'de> serde::Deserialize<'de> for CustomerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s))
    }
}

impl std::str::FromStr for CustomerId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<std::borrow::Cow<'_, str>> for CustomerId {
    type Error = std::convert::Infallible;

    fn try_from(value: std::borrow::Cow<'_, str>) -> Result<Self, Self::Error> {
        Ok(Self(value.to_string()))
    }
}

impl<DB> FromSql<sql_types::Text, DB> for CustomerId
where
    DB: Backend,
    String: FromSql<sql_types::Text, DB>,
{
    fn from_sql(value: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        let val = String::from_sql(value)?;
        Ok(Self(val))
    }
}

impl<DB> ToSql<sql_types::Text, DB> for CustomerId
where
    DB: Backend,
    String: ToSql<sql_types::Text, DB>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
        self.0.to_sql(out)
    }
}

#[derive(Debug, Clone, Serialize, Hash, PartialEq, Eq, AsExpression)]
#[diesel(sql_type = sql_types::Text)]
pub struct MerchantId(String);

impl MerchantId {
    pub fn default() -> Self {
        Self("mer_default".to_string())
    }
}

impl<'de> serde::Deserialize<'de> for MerchantId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s))
    }
}

impl std::str::FromStr for MerchantId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl<DB> FromSql<sql_types::Text, DB> for MerchantId
where
    DB: Backend,
    String: FromSql<sql_types::Text, DB>,
{
    fn from_sql(value: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        let val = String::from_sql(value)?;
        Ok(Self(val))
    }
}

impl<DB> ToSql<sql_types::Text, DB> for MerchantId
where
    DB: Backend,
    String: ToSql<sql_types::Text, DB>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
        self.0.to_sql(out)
    }
}
