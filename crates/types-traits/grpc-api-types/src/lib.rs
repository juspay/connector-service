#![allow(clippy::large_enum_variant)]
#![allow(clippy::uninlined_format_args)]
#![allow(legacy_derive_helpers)]

pub mod masked_fields {
    use hyperswitch_masking::Secret;
    use serde::{Serialize, Serializer};
    pub fn secret_string<S: Serializer>(v: &str, s: S) -> Result<S::Ok, S::Error> {
        Secret::<String>::new(v.to_owned()).serialize(s)
    }
    pub fn optional_secret_string<S: Serializer>(
        v: &Option<String>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        v.clone().map(Secret::<String>::new).serialize(s)
    }
}

pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("connector_service_descriptor");

mod types {
    tonic::include_proto!("types");
}

pub mod payments {
    pub use super::types::*;
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
