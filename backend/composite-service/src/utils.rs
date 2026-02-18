use std::str::FromStr;

use common_utils::consts::X_CONNECTOR_NAME;
use domain_types::connector_types::ConnectorEnum;

pub fn connector_from_composite_authorize_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> Result<ConnectorEnum, Box<tonic::Status>> {
    metadata
        .get(X_CONNECTOR_NAME)
        .ok_or_else(|| {
            Box::new(tonic::Status::invalid_argument(
                "missing x-connector metadata",
            ))
        })
        .and_then(|connector| {
            connector.to_str().map_err(|_| {
                Box::new(tonic::Status::invalid_argument(
                    "invalid x-connector metadata value",
                ))
            })
        })
        .and_then(|connector_from_metadata| {
            ConnectorEnum::from_str(connector_from_metadata).map_err(|err| {
                Box::new(tonic::Status::invalid_argument(format!(
                    "invalid connector in request metadata: {err}"
                )))
            })
        })
}

pub fn grpc_connector_from_connector_enum(connector: &ConnectorEnum) -> i32 {
    let grpc_connector_name = connector.to_string().to_ascii_uppercase();
    let grpc_connector =
        grpc_api_types::payments::Connector::from_str_name(grpc_connector_name.as_str())
            .unwrap_or(grpc_api_types::payments::Connector::Unspecified);
    i32::from(grpc_connector)
}
