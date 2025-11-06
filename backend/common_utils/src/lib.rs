//! Common utilities for connector service

// Mock types for masking (always available since hyperswitch_masking has compatibility issues)
pub mod masking {
    use serde::{Deserialize, Serialize as SerdeSerialize};
    use std::fmt;
    
    pub trait Strategy<T> {
        fn fmt(val: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result;
    }
    
    #[derive(Debug, Clone, SerdeSerialize, Deserialize, PartialEq, Eq, Hash)]
    pub struct Secret<T, S = ()>(pub T, std::marker::PhantomData<S>);
    
    #[cfg(feature = "masking")]
    impl<T> prost::Message for Secret<T>
    where
        T: prost::Message,
    {
        fn encode_raw(&self, buf: &mut impl prost::bytes::BufMut)
        {
            self.0.encode_raw(buf)
        }

        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: prost::encoding::WireType,
            buf: &mut impl prost::bytes::Buf,
            ctx: prost::encoding::DecodeContext,
        ) -> ::core::result::Result<(), prost::DecodeError>
        {
            self.0.merge_field(tag, wire_type, buf, ctx)
        }

        fn encoded_len(&self) -> usize {
            self.0.encoded_len()
        }

        fn clear(&mut self) {
            self.0.clear()
        }
    }
    
    pub type StrongSecret<T, S = ()> = Secret<T, S>;
    
    impl<T> Secret<T> {
        pub fn new(value: T) -> Self {
            Self(value, std::marker::PhantomData)
        }
    }
    
    impl<T, S> From<T> for Secret<T, S> {
        fn from(value: T) -> Self {
            Self(value, std::marker::PhantomData)
        }
    }
    
    impl<T, S> std::ops::Deref for Secret<T, S> {
        type Target = T;
        
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    
    impl<T: Default, S> Default for Secret<T, S> {
        fn default() -> Self {
            Self(T::default(), std::marker::PhantomData)
        }
    }
    
    #[derive(Debug, Clone, SerdeSerialize, Deserialize, PartialEq, Eq, Hash)]
    pub struct Maskable<T>(pub T);
    
    impl<T> From<T> for Maskable<T> {
        fn from(value: T) -> Self {
            Self(value)
        }
    }
    
    impl<T> Maskable<T> {
        pub fn new_normal(value: T) -> Self {
            Self(value)
        }
        
        pub fn new_masked(_value: Secret<T>) -> Self {
            // When masking is disabled, just extract the inner value
            Self(_value.0)
        }
    }
    
    pub trait ExposeInterface<T> {
        fn expose(self) -> T;
    }
    
    impl<T, S> ExposeInterface<T> for Secret<T, S> {
        fn expose(self) -> T {
            self.0
        }
    }
    
    pub struct WithType;
    
    impl WithType {
        pub fn fmt<T: AsRef<str>>(val: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", val.as_ref())
        }
    }
    
    // Mock additional types needed for compatibility
    pub trait ErasedMaskSerialize {}
    
    impl serde::Serialize for dyn ErasedMaskSerialize {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str("masked_data")
        }
    }
    
    pub fn masked_serialize<T: serde::Serialize>(_value: &T) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(_value)
    }
    
    pub trait SerializableSecret {}
    
    pub trait Serialize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}
    
    pub trait PeekInterface<T> {
        fn peek(&self) -> &T;
    }
    
    impl<T, S> PeekInterface<T> for Secret<T, S> {
        fn peek(&self) -> &T {
            &self.0
        }
    }
}

// Always export the mock types
pub use masking::{Strategy, Secret, Maskable, ExposeInterface, WithType, PeekInterface, StrongSecret};

pub mod crypto;
pub mod custom_serde;
pub mod errors;
pub mod ext_traits;
pub mod fp_utils;
pub mod id_type;
pub mod lineage;
pub mod macros;
pub mod metadata;
pub mod new_types;
pub mod pii;
pub mod request;
pub mod types;
// Re-export commonly used items
pub use errors::{CustomResult, EventPublisherError, ParsingError, ValidationError};
#[cfg(feature = "kafka")]
pub use event_publisher::{emit_event_with_config, init_event_publisher};

#[cfg(not(feature = "kafka"))]
pub fn init_event_publisher(_config: &events::EventConfig) -> CustomResult<(), ()> {
    Ok(())
}
#[cfg(not(feature = "kafka"))]
pub fn emit_event_with_config(_event: events::Event, _config: &events::EventConfig) {
    // No-op when kafka feature is disabled
}

pub use global_id::{CellId, GlobalPaymentId};
pub use id_type::{CustomerId, MerchantId};
pub use pii::{Email, SecretSerdeValue};
pub use request::{Method, Request, RequestContent};
pub use types::{
    AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector, MinorUnit, MinorUnitForConnector,
    StringMajorUnit, StringMajorUnitForConnector, StringMinorUnit,
};
pub mod events;
pub mod global_id;

pub mod consts;
#[cfg(feature = "kafka")]
pub mod event_publisher;

fn generate_ref_id_with_default_length<const MAX_LENGTH: u8, const MIN_LENGTH: u8>(
    prefix: &str,
) -> id_type::LengthId<MAX_LENGTH, MIN_LENGTH> {
    id_type::LengthId::<MAX_LENGTH, MIN_LENGTH>::new(prefix)
}

/// Generate a time-ordered (time-sortable) unique identifier using the current time
#[inline]
pub fn generate_time_ordered_id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::now_v7().as_simple())
}

pub mod date_time {
    #[cfg(feature = "async_ext")]
    use std::time::Instant;
    use std::{marker::PhantomData, num::NonZeroU8};
    use serde::{Deserialize, Serialize as SerdeSerialize};

    // use crate::masking::{Deserialize, Serialize};
    use time::{
        format_description::{
            well_known::iso8601::{Config, EncodedConfig, Iso8601, TimePrecision},
            BorrowedFormatItem,
        },
        OffsetDateTime, PrimitiveDateTime,
    };

    /// Enum to represent date formats
    #[derive(Debug)]
    pub enum DateFormat {
        /// Format the date in 20191105081132 format
        YYYYMMDDHHmmss,
        /// Format the date in 20191105 format
        YYYYMMDD,
        /// Format the date in 201911050811 format
        YYYYMMDDHHmm,
        /// Format the date in 05112019081132 format
        DDMMYYYYHHmmss,
    }

    /// Create a new [`PrimitiveDateTime`] with the current date and time in UTC.
    pub fn now() -> PrimitiveDateTime {
        let utc_date_time = OffsetDateTime::now_utc();
        PrimitiveDateTime::new(utc_date_time.date(), utc_date_time.time())
    }

    /// Convert from OffsetDateTime to PrimitiveDateTime
    pub fn convert_to_pdt(offset_time: OffsetDateTime) -> PrimitiveDateTime {
        PrimitiveDateTime::new(offset_time.date(), offset_time.time())
    }

    /// Return the UNIX timestamp of the current date and time in UTC
    pub fn now_unix_timestamp() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    /// Calculate execution time for a async block in milliseconds
    #[cfg(feature = "async_ext")]
    pub async fn time_it<T, Fut: futures::Future<Output = T>, F: FnOnce() -> Fut>(
        block: F,
    ) -> (T, f64) {
        let start = Instant::now();
        let result = block().await;
        (result, start.elapsed().as_secs_f64() * 1000f64)
    }

    /// Return the given date and time in UTC with the given format Eg: format: YYYYMMDDHHmmss Eg: 20191105081132
    pub fn format_date(
        date: PrimitiveDateTime,
        format: DateFormat,
    ) -> Result<String, time::error::Format> {
        let format = <&[BorrowedFormatItem<'_>]>::from(format);
        date.format(&format)
    }

    /// Return the current date and time in UTC with the format [year]-[month]-[day]T[hour]:[minute]:[second].mmmZ Eg: 2023-02-15T13:33:18.898Z
    pub fn date_as_yyyymmddthhmmssmmmz() -> Result<String, time::error::Format> {
        const ISO_CONFIG: EncodedConfig = Config::DEFAULT
            .set_time_precision(TimePrecision::Second {
                decimal_digits: NonZeroU8::new(3),
            })
            .encode();
        now().assume_utc().format(&Iso8601::<ISO_CONFIG>)
    }

    impl From<DateFormat> for &[BorrowedFormatItem<'_>] {
        fn from(format: DateFormat) -> Self {
            match format {
                DateFormat::YYYYMMDDHHmmss => time::macros::format_description!("[year repr:full][month padding:zero repr:numerical][day padding:zero][hour padding:zero repr:24][minute padding:zero][second padding:zero]"),
                DateFormat::YYYYMMDD => time::macros::format_description!("[year repr:full][month padding:zero repr:numerical][day padding:zero]"),
                DateFormat::YYYYMMDDHHmm => time::macros::format_description!("[year repr:full][month padding:zero repr:numerical][day padding:zero][hour padding:zero repr:24][minute padding:zero]"),
                DateFormat::DDMMYYYYHHmmss => time::macros::format_description!("[day padding:zero][month padding:zero repr:numerical][year repr:full][hour padding:zero repr:24][minute padding:zero][second padding:zero]"),
            }
        }
    }

    /// Format the date in 05112019 format
    #[derive(Debug, Clone)]
    pub struct DDMMYYYY;
    /// Format the date in 20191105 format
    #[derive(Debug, Clone)]
    pub struct YYYYMMDD;
    /// Format the date in 20191105081132 format
    #[derive(Debug, Clone)]
    pub struct YYYYMMDDHHmmss;

    /// To serialize the date in Dateformats like YYYYMMDDHHmmss, YYYYMMDD, DDMMYYYY
    #[derive(Debug, Deserialize, Clone)]
    pub struct DateTime<T: TimeStrategy> {
        inner: PhantomData<T>,
        value: PrimitiveDateTime,
    }

    impl<T: TimeStrategy> From<PrimitiveDateTime> for DateTime<T> {
        fn from(value: PrimitiveDateTime) -> Self {
            Self {
                inner: PhantomData,
                value,
            }
        }
    }

    /// Time strategy for the Date, Eg: YYYYMMDDHHmmss, YYYYMMDD, DDMMYYYY
    pub trait TimeStrategy {
        /// Stringify the date as per the Time strategy
        fn fmt(input: &PrimitiveDateTime, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
    }

    impl<T: TimeStrategy> crate::masking::Serialize for DateTime<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.collect_str(self)
        }
    }

    impl<T: TimeStrategy> std::fmt::Display for DateTime<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            T::fmt(&self.value, f)
        }
    }

    impl TimeStrategy for DDMMYYYY {
        fn fmt(input: &PrimitiveDateTime, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let year = input.year();
            #[allow(clippy::as_conversions)]
            let month = input.month() as u8;
            let day = input.day();
            let output = format!("{day:02}{month:02}{year}");
            f.write_str(&output)
        }
    }

    impl TimeStrategy for YYYYMMDD {
        fn fmt(input: &PrimitiveDateTime, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let year = input.year();
            #[allow(clippy::as_conversions)]
            let month: u8 = input.month() as u8;
            let day = input.day();
            let output = format!("{year}{month:02}{day:02}");
            f.write_str(&output)
        }
    }

    impl TimeStrategy for YYYYMMDDHHmmss {
        fn fmt(input: &PrimitiveDateTime, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let year = input.year();
            #[allow(clippy::as_conversions)]
            let month = input.month() as u8;
            let day = input.day();
            let hour = input.hour();
            let minute = input.minute();
            let second = input.second();
            let output = format!("{year}{month:02}{day:02}{hour:02}{minute:02}{second:02}");
            f.write_str(&output)
        }
    }
}
