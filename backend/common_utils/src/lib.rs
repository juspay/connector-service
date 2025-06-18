//! Common utilities for connector service

pub mod errors;
pub mod ext_traits;
pub mod id_type;
pub mod pii;
pub mod request;
pub mod types;

// Re-export commonly used items
pub use errors::{CustomResult, ParsingError, ValidationError};
pub use id_type::{CustomerId, MerchantId};
pub use pii::{Email, SecretSerdeValue};
pub use request::{Method, Request, RequestContent};
pub use types::{
    AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector, MinorUnit, MinorUnitForConnector,
    StringMajorUnit, StringMajorUnitForConnector, StringMinorUnit,
};
