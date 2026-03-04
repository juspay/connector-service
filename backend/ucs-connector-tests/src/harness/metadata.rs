use tonic::Request;

use crate::harness::credentials::ConnectorAuth;

pub fn add_authorizedotnet_metadata<T>(
    request: &mut Request<T>,
    auth: &ConnectorAuth,
    merchant_id: &str,
    tenant_id: &str,
    request_id: &str,
    connector_request_reference_id: &str,
) {
    request.metadata_mut().append(
        "x-connector",
        "authorizedotnet".parse().expect("valid x-connector header"),
    );
    request
        .metadata_mut()
        .append("x-auth", "body-key".parse().expect("valid x-auth header"));
    request.metadata_mut().append(
        "x-api-key",
        auth.api_key.parse().expect("valid x-api-key header"),
    );
    request
        .metadata_mut()
        .append("x-key1", auth.key1.parse().expect("valid x-key1 header"));
    request.metadata_mut().append(
        "x-merchant-id",
        merchant_id.parse().expect("valid x-merchant-id header"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        tenant_id.parse().expect("valid x-tenant-id header"),
    );
    request.metadata_mut().append(
        "x-request-id",
        request_id.parse().expect("valid x-request-id header"),
    );
    request.metadata_mut().append(
        "x-connector-request-reference-id",
        connector_request_reference_id
            .parse()
            .expect("valid x-connector-request-reference-id header"),
    );
}
