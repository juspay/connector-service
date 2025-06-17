pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("connector_service_descriptor");

// Include the auto-generated enum deserializer functions from g2h
include!(concat!(env!("OUT_DIR"), "/enum_deserializer.rs"));

pub mod payments {
    tonic::include_proto!("ucs.payments");
}

pub mod health_check {
    tonic::include_proto!("grpc.health.v1");
}

mod test_enum_deserializer;
