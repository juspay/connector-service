/// Use the well-known ISO 8601 format when serializing and deserializing an
/// [`PrimitiveDateTime`][PrimitiveDateTime].
///
/// [PrimitiveDateTime]: ::time::PrimitiveDateTime
pub mod iso8601 {
    use std::num::NonZeroU8;

    use serde::{ser::Error as _, Deserializer, Serialize, Serializer};
    use time::{
        format_description::well_known::{
            iso8601::{Config, EncodedConfig, TimePrecision},
            Iso8601,
        },
        serde::iso8601,
        PrimitiveDateTime, UtcOffset,
    };

    const FORMAT_CONFIG: EncodedConfig = Config::DEFAULT
        .set_time_precision(TimePrecision::Second {
            decimal_digits: NonZeroU8::new(3),
        })
        .encode();

    /// Serialize a [`PrimitiveDateTime`] using the well-known ISO 8601 format.
    pub fn serialize<S>(date_time: &PrimitiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        date_time
            .assume_utc()
            .format(&Iso8601::<FORMAT_CONFIG>)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }

    /// Deserialize an [`PrimitiveDateTime`] from its ISO 8601 representation.
    pub fn deserialize<'a, D>(deserializer: D) -> Result<PrimitiveDateTime, D::Error>
    where
        D: Deserializer<'a>,
    {
        iso8601::deserialize(deserializer).map(|offset_date_time| {
            let utc_date_time = offset_date_time.to_offset(UtcOffset::UTC);
            PrimitiveDateTime::new(utc_date_time.date(), utc_date_time.time())
        })
    }

    /// Use the well-known ISO 8601 format when serializing and deserializing an
    /// [`Option<PrimitiveDateTime>`][PrimitiveDateTime].
    ///
    /// [PrimitiveDateTime]: ::time::PrimitiveDateTime
    pub mod option {
        use serde::Serialize;
        use time::format_description::well_known::Iso8601;

        use super::*;

        /// Serialize an [`Option<PrimitiveDateTime>`] using the well-known ISO 8601 format.
        pub fn serialize<S>(
            date_time: &Option<PrimitiveDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            date_time
                .map(|date_time| date_time.assume_utc().format(&Iso8601::<FORMAT_CONFIG>))
                .transpose()
                .map_err(S::Error::custom)?
                .serialize(serializer)
        }

        /// Deserialize an [`Option<PrimitiveDateTime>`] from its ISO 8601 representation.
        pub fn deserialize<'a, D>(deserializer: D) -> Result<Option<PrimitiveDateTime>, D::Error>
        where
            D: Deserializer<'a>,
        {
            iso8601::option::deserialize(deserializer).map(|option_offset_date_time| {
                option_offset_date_time.map(|offset_date_time| {
                    let utc_date_time = offset_date_time.to_offset(UtcOffset::UTC);
                    PrimitiveDateTime::new(utc_date_time.date(), utc_date_time.time())
                })
            })
        }
    }
    /// Use the well-known ISO 8601 format which is without timezone when serializing and deserializing an
    /// [`Option<PrimitiveDateTime>`][PrimitiveDateTime].
    ///
    /// [PrimitiveDateTime]: ::time::PrimitiveDateTime
    pub mod option_without_timezone {
        use serde::{de, Deserialize, Serialize};
        use time::macros::format_description;

        use super::*;

        /// Serialize an [`Option<PrimitiveDateTime>`] using the well-known ISO 8601 format which is without timezone.
        pub fn serialize<S>(
            date_time: &Option<PrimitiveDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            date_time
                .map(|date_time| {
                    let format =
                        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
                    date_time.assume_utc().format(format)
                })
                .transpose()
                .map_err(S::Error::custom)?
                .serialize(serializer)
        }

        /// Deserialize an [`Option<PrimitiveDateTime>`] from its ISO 8601 representation.
        pub fn deserialize<'a, D>(deserializer: D) -> Result<Option<PrimitiveDateTime>, D::Error>
        where
            D: Deserializer<'a>,
        {
            Option::deserialize(deserializer)?
                .map(|time_string| {
                    let format =
                        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
                    PrimitiveDateTime::parse(time_string, format).map_err(|_| {
                        de::Error::custom(format!(
                            "Failed to parse PrimitiveDateTime from {time_string}"
                        ))
                    })
                })
                .transpose()
        }
    }
}

/// Serde wrapper for prost_types to enable serialization/deserialization
pub mod prost_types_wrapper {
    use prost_types::{ListValue, Struct, Value};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    /// Wrapper type that implements Serialize and Deserialize for prost_types::Struct
    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct SerializableStruct(pub Struct);

    impl From<Struct> for SerializableStruct {
        fn from(s: Struct) -> Self {
            Self(s)
        }
    }

    impl From<SerializableStruct> for serde_json::Value {
        fn from(s: SerializableStruct) -> Self {
            convert_struct_to_json(&s.0)
        }
    }

    impl From<SerializableStruct> for Struct {
        fn from(s: SerializableStruct) -> Self {
            s.0
        }
    }

    impl SerializableStruct {
        pub fn get(&self, key: &str) -> Option<&Value> {
            self.0.fields.get(key)
        }
    }

    impl ::prost::Message for SerializableStruct {
        fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
            self.0.encode_raw(buf)
        }

        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: ::prost::encoding::WireType,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: ::prost::encoding::DecodeContext,
        ) -> Result<(), ::prost::DecodeError> {
            ::prost::Message::merge_field(&mut self.0, tag, wire_type, buf, ctx)
        }

        fn encoded_len(&self) -> usize {
            self.0.encoded_len()
        }

        fn clear(&mut self) {
            self.0.clear()
        }
    }

    impl Serialize for SerializableStruct {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let json_value = convert_struct_to_json(&self.0);
            json_value.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for SerializableStruct {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let json_value = serde_json::Value::deserialize(deserializer)?;
            let struct_value = convert_json_to_struct(json_value);
            Ok(Self(struct_value))
        }
    }

    /// Wrapper type for prost_types::Value
    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct SerializableValue(pub Value);

    impl From<Value> for SerializableValue {
        fn from(v: Value) -> Self {
            Self(v)
        }
    }

    impl From<SerializableValue> for Value {
        fn from(v: SerializableValue) -> Self {
            v.0
        }
    }

    impl Serialize for SerializableValue {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let json_value = convert_value_to_json(&self.0);
            json_value.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for SerializableValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let json_value = serde_json::Value::deserialize(deserializer)?;
            let value = convert_json_to_value(json_value);
            Ok(Self(value))
        }
    }

    fn convert_struct_to_json(s: &Struct) -> serde_json::Value {
        let map: serde_json::Map<String, serde_json::Value> = s
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), convert_value_to_json(v)))
            .collect();
        serde_json::Value::Object(map)
    }

    fn convert_value_to_json(value: &Value) -> serde_json::Value {
        use prost_types::value::Kind;

        match &value.kind {
            Some(kind) => match kind {
                Kind::NullValue(_) => serde_json::Value::Null,
                Kind::NumberValue(n) => serde_json::Number::from_f64(*n)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null),
                Kind::StringValue(s) => serde_json::Value::String(s.clone()),
                Kind::BoolValue(b) => serde_json::Value::Bool(*b),
                Kind::StructValue(s) => convert_struct_to_json(s),
                Kind::ListValue(list) => {
                    let array: Vec<serde_json::Value> =
                        list.values.iter().map(convert_value_to_json).collect();
                    serde_json::Value::Array(array)
                }
            },
            None => serde_json::Value::Null,
        }
    }

    fn convert_json_to_struct(json: serde_json::Value) -> Struct {
        match json {
            serde_json::Value::Object(map) => {
                let fields = map
                    .into_iter()
                    .map(|(k, v)| (k, convert_json_to_value(v)))
                    .collect();
                Struct { fields }
            }
            _ => Struct {
                fields: BTreeMap::new(),
            },
        }
    }

    fn convert_json_to_value(json: serde_json::Value) -> Value {
        use prost_types::value::Kind;

        let kind = match json {
            serde_json::Value::Null => Kind::NullValue(0),
            serde_json::Value::Bool(b) => Kind::BoolValue(b),
            serde_json::Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    Kind::NumberValue(f)
                } else {
                    Kind::StringValue(n.to_string())
                }
            }
            serde_json::Value::String(s) => Kind::StringValue(s),
            serde_json::Value::Array(arr) => {
                let values = arr.into_iter().map(convert_json_to_value).collect();
                Kind::ListValue(ListValue { values })
            }
            serde_json::Value::Object(obj) => {
                let fields = obj
                    .into_iter()
                    .map(|(k, v)| (k, convert_json_to_value(v)))
                    .collect();
                Kind::StructValue(Struct { fields })
            }
        };

        Value { kind: Some(kind) }
    }
}

/// Use the UNIX timestamp when serializing and deserializing an
/// [`PrimitiveDateTime`][PrimitiveDateTime].
///
/// [PrimitiveDateTime]: ::time::PrimitiveDateTime
pub mod timestamp {

    use serde::{Deserializer, Serialize, Serializer};
    use time::{serde::timestamp, PrimitiveDateTime, UtcOffset};

    /// Serialize a [`PrimitiveDateTime`] using UNIX timestamp.
    pub fn serialize<S>(date_time: &PrimitiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        date_time
            .assume_utc()
            .unix_timestamp()
            .serialize(serializer)
    }

    /// Deserialize an [`PrimitiveDateTime`] from UNIX timestamp.
    pub fn deserialize<'a, D>(deserializer: D) -> Result<PrimitiveDateTime, D::Error>
    where
        D: Deserializer<'a>,
    {
        timestamp::deserialize(deserializer).map(|offset_date_time| {
            let utc_date_time = offset_date_time.to_offset(UtcOffset::UTC);
            PrimitiveDateTime::new(utc_date_time.date(), utc_date_time.time())
        })
    }

    /// Use the UNIX timestamp when serializing and deserializing an
    /// [`Option<PrimitiveDateTime>`][PrimitiveDateTime].
    ///
    /// [PrimitiveDateTime]: ::time::PrimitiveDateTime
    pub mod option {
        use serde::Serialize;

        use super::*;

        /// Serialize an [`Option<PrimitiveDateTime>`] from UNIX timestamp.
        pub fn serialize<S>(
            date_time: &Option<PrimitiveDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            date_time
                .map(|date_time| date_time.assume_utc().unix_timestamp())
                .serialize(serializer)
        }

        /// Deserialize an [`Option<PrimitiveDateTime>`] from UNIX timestamp.
        pub fn deserialize<'a, D>(deserializer: D) -> Result<Option<PrimitiveDateTime>, D::Error>
        where
            D: Deserializer<'a>,
        {
            timestamp::option::deserialize(deserializer).map(|option_offset_date_time| {
                option_offset_date_time.map(|offset_date_time| {
                    let utc_date_time = offset_date_time.to_offset(UtcOffset::UTC);
                    PrimitiveDateTime::new(utc_date_time.date(), utc_date_time.time())
                })
            })
        }
    }
}
