pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("connector_service_descriptor");

pub mod payments {
    tonic::include_proto!("ucs.v2");
}

pub mod health_check {
    tonic::include_proto!("grpc.health.v1");
}
