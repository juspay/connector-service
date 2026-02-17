use std::str::FromStr;

use common_utils::consts::X_CONNECTOR_NAME;
use domain_types::connector_types::ConnectorEnum;

pub fn connector_from_composite_authorize_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> Result<ConnectorEnum, tonic::Status> {
    let connector_from_metadata = match metadata.get(X_CONNECTOR_NAME) {
        Some(connector) => connector
            .to_str()
            .map_err(|_| tonic::Status::invalid_argument("invalid x-connector metadata value"))?,
        None => {
            return Err(tonic::Status::invalid_argument(
                "missing x-connector metadata",
            ))
        }
    };

    ConnectorEnum::from_str(connector_from_metadata).map_err(|err| {
        tonic::Status::invalid_argument(format!("invalid connector in request metadata: {err}"))
    })
}

pub fn grpc_connector_from_connector_enum(connector: &ConnectorEnum) -> i32 {
    let grpc_connector_name = connector.to_string().to_ascii_uppercase();
    grpc_api_types::payments::Connector::from_str_name(grpc_connector_name.as_str())
        .unwrap_or(grpc_api_types::payments::Connector::Unspecified) as i32
}
