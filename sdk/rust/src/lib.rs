pub mod connector_client;

pub use connector_client::ConnectorClient;

// Re-export proto types that SDK users need.
pub use grpc_api_types::payments::{
    connector_auth, BodyKeyAuth, CertificateAuth as CertificateAuthProto,
    Connector as ConnectorName, ConnectorAuth, ConnectorConfig, HeaderKeyAuth, MultiAuthKeyAuth,
    NoKeyAuth, SignatureKeyAuth, TemporaryAuth,
};
