//! Generated code from proto files

#![allow(clippy::all)]
#![allow(warnings)]

pub const FILE_DESCRIPTOR_SET: &[u8] = 
    include_bytes!("connector_service_descriptor.bin");

pub mod payments {
    include!("ucs.v2.rs");
}

pub mod health_check {
    include!("grpc.health.v1.rs");
}
