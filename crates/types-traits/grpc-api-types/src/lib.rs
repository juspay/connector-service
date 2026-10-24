#![allow(clippy::large_enum_variant)]
#![allow(clippy::uninlined_format_args)]
#![allow(legacy_derive_helpers)]

pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("connector_service_descriptor");

mod types {
    tonic::include_proto!("types");
}

pub mod payments {
    pub use super::types::*;
}

/// Serializes a plain-string proto secret through [`hyperswitch_masking::Secret`], so the
/// masking serializer (`hyperswitch_masking::masked_serialize`) redacts it while any other
/// serializer emits the raw value. Wired onto secret fields by `build.rs`.
pub fn serialize_masked_string<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde::Serialize::serialize(
        &hyperswitch_masking::Secret::<String>::new(value.to_owned()),
        serializer,
    )
}

/// Optional variant of [`serialize_masked_string`].
pub fn serialize_masked_opt_string<S>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde::Serialize::serialize(
        &value
            .as_ref()
            .map(|inner| hyperswitch_masking::Secret::<String>::new(inner.clone())),
        serializer,
    )
}

pub mod health_check {
    tonic::include_proto!("grpc.health.v1");
}

pub mod payouts {
    pub use super::types::*;
}

pub mod surcharge {
    pub use super::types::*;
}

pub mod frm {
    pub use super::types::*;
}

pub mod auto_populate {
    include!(concat!(env!("OUT_DIR"), "/auto_populate_generated.rs"));
    pub use generated::*;
}
