use common_utils::metadata::MaskedMetadata;
use domain_types::{
    connector_types::ConnectorEnum, router_data::ConnectorAuthType, utils::ForeignTryFrom,
};

use grpc_api_types::payments as proto;
use std::collections::HashMap;

use crate::utils::FfiError;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct FfiConnectorConfig {
    pub connector: ConnectorEnum,
    pub connector_auth_type: ConnectorAuthType,
}

#[derive(Debug, serde::Deserialize)]
pub struct FfiRequestData<T> {
    pub payload: T,
    pub extracted_metadata: FfiConnectorConfig,
    #[serde(skip_deserializing)]
    pub masked_metadata: Option<MaskedMetadata>,
}

impl ForeignTryFrom<proto::ConnectorConfig> for FfiConnectorConfig {
    type Error = FfiError;

    fn foreign_try_from(config: proto::ConnectorConfig) -> error_stack::Result<Self, Self::Error> {
        let proto_connector = proto::Connector::try_from(config.connector).map_err(|_| {
            FfiError::InvalidField(format!("unknown Connector variant: {}", config.connector))
        })?;

        let connector = ConnectorEnum::foreign_try_from(proto_connector)
            .map_err(|e| FfiError::InvalidField(format!("unsupported connector: {e:?}")))?;


        let auth = config
            .auth
            .ok_or_else(|| FfiError::MissingField("auth".into()))?;

        let connector_auth_type = ConnectorAuthType::foreign_try_from(auth)
            .map_err(|e| FfiError::InvalidField(format!("invalid auth: {e:?}")))?;


        Ok(FfiConnectorConfig {
            connector,
            connector_auth_type,
        })
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ProxyConfig {
    pub idle_pool_connection_timeout: Option<u64>,
    pub bypass_proxy_urls: Option<Vec<String>>,
    pub mitm_proxy_enabled: Option<bool>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ClientConfig {
    pub timeout_ms: Option<u64>,
    pub connect_timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CallOptions {
    pub proxy_config: Option<ProxyConfig>,
    pub client_config: Option<ClientConfig>,
}

#[derive(Debug, serde::Deserialize)]
pub struct FfiApiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}
