use common_utils::{
    consts::{
        X_API_KEY, X_API_SECRET, X_AUTH, X_AUTH_KEY_MAP, X_CONNECTOR_AUTH, X_KEY1, X_KEY2,
    },
    errors::CustomResult,
};
use domain_types::{
    connector_types,
    errors::{ApiError, ApplicationErrorResponse},
    router_data::ConnectorSpecificAuth,
    utils::ForeignTryFrom,
};
use error_stack::{Report, ResultExt};
use std::collections::HashMap;
use tonic::metadata;
use ucs_env::logger;

use crate::metadata::parse_metadata;

/// Extracts typed `ConnectorAuth` from the `X-Connector-Auth` header (JSON).
///
/// Returns `Ok(Some(...))` if header is present and valid,
/// `Ok(None)` if header is absent (legitimate fallback case),
/// `Err(...)` if header is present but malformed.
fn extract_connector_auth_from_header(
    metadata: &metadata::MetadataMap,
) -> CustomResult<Option<grpc_api_types::payments::ConnectorAuth>, ApplicationErrorResponse> {
    metadata
        .get(X_CONNECTOR_AUTH)
        .map(|value| {
            value
                .to_str()
                .change_context(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_CONNECTOR_AUTH_HEADER".to_string(),
                    error_identifier: 400,
                    error_message: "X-Connector-Auth header contains non-ASCII characters"
                        .to_string(),
                    error_object: None,
                }))
                .and_then(|header_str| {
                    serde_json::from_str(header_str).change_context(
                        ApplicationErrorResponse::BadRequest(ApiError {
                            sub_code: "INVALID_CONNECTOR_AUTH_JSON".to_string(),
                            error_identifier: 400,
                            error_message: "Failed to parse X-Connector-Auth header as JSON"
                                .to_string(),
                            error_object: None,
                        }),
                    )
                })
        })
        .transpose()
}

/// Resolves connector auth by trying the typed `X-Connector-Auth` header first,
/// then falling back to legacy `x-auth` / `x-api-key` / `x-key1` headers.
pub fn resolve_connector_auth(
    metadata: &metadata::MetadataMap,
    connector: &connector_types::ConnectorEnum,
) -> CustomResult<ConnectorSpecificAuth, ApplicationErrorResponse> {
    extract_connector_auth_from_header(metadata)?.map_or_else(
        || {
            logger::debug!(
                "X-Connector-Auth header not found, falling back to legacy headers for connector: {}",
                connector
            );
            auth_from_metadata(metadata, connector)
        },
        |typed_auth| {
            logger::debug!(
                "Connector specific auth found in X-Connector-Auth header for connector: {}",
                connector
            );
            ConnectorSpecificAuth::foreign_try_from(typed_auth).map_err(|_| {
                Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "AUTH_CONVERSION_FAILED".to_string(),
                    error_identifier: 400,
                    error_message: "Failed to convert auth from X-Connector-Auth header".to_string(),
                    error_object: None,
                }))
            })
        },
    )
}

/// Extracts connector-specific auth from metadata headers.
/// Uses the connector name to determine which variant to create.
pub fn auth_from_metadata(
    metadata: &metadata::MetadataMap,
    connector: &connector_types::ConnectorEnum,
) -> CustomResult<ConnectorSpecificAuth, ApplicationErrorResponse> {
    let generic_auth = generic_auth_from_metadata(metadata)?;
    ConnectorSpecificAuth::foreign_try_from((&generic_auth, connector)).map_err(|_| {
        Report::new(ApplicationErrorResponse::BadRequest(ApiError {
            sub_code: "AUTH_CONVERSION_FAILED".to_string(),
            error_identifier: 400,
            error_message: format!("Failed to convert legacy auth for connector: {}", connector),
            error_object: None,
        }))
    })
}

/// Extracts generic auth type from metadata headers.
/// This is the legacy format that uses key1, key2, etc.
pub fn generic_auth_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<domain_types::router_data::ConnectorAuthType, ApplicationErrorResponse> {
    use domain_types::router_data::ConnectorAuthType;

    let auth = parse_metadata(metadata, X_AUTH)?;

    #[allow(clippy::wildcard_in_or_patterns)]
    match auth {
        "header-key" => Ok(ConnectorAuthType::HeaderKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
        }),
        "body-key" => Ok(ConnectorAuthType::BodyKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
            key1: parse_metadata(metadata, X_KEY1)?.to_string().into(),
        }),
        "signature-key" => Ok(ConnectorAuthType::SignatureKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
            key1: parse_metadata(metadata, X_KEY1)?.to_string().into(),
            api_secret: parse_metadata(metadata, X_API_SECRET)?.to_string().into(),
        }),
        "multi-auth-key" => Ok(ConnectorAuthType::MultiAuthKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
            key1: parse_metadata(metadata, X_KEY1)?.to_string().into(),
            key2: parse_metadata(metadata, X_KEY2)?.to_string().into(),
            api_secret: parse_metadata(metadata, X_API_SECRET)?.to_string().into(),
        }),
        "no-key" => Ok(ConnectorAuthType::NoKey),
        "temporary-auth" => Ok(ConnectorAuthType::TemporaryAuth),
        "currency-auth-key" => {
            let auth_key_map_str = parse_metadata(metadata, X_AUTH_KEY_MAP)?;
            let auth_key_map: HashMap<
                common_enums::enums::Currency,
                common_utils::pii::SecretSerdeValue,
            > = serde_json::from_str(auth_key_map_str).change_context(
                ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_AUTH_KEY_MAP".to_string(),
                    error_identifier: 400,
                    error_message: "Invalid auth-key-map format".to_string(),
                    error_object: None,
                }),
            )?;
            Ok(ConnectorAuthType::CurrencyAuthKey { auth_key_map })
        }
        "certificate-auth" | _ => Err(Report::new(ApplicationErrorResponse::BadRequest(
            ApiError {
                sub_code: "INVALID_AUTH_TYPE".to_string(),
                error_identifier: 400,
                error_message: format!("Invalid auth type: {auth}"),
                error_object: None,
            },
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::resolve_connector_auth;
    use common_utils::consts;
    use domain_types::{connector_types, router_data::ConnectorSpecificAuth};
    use hyperswitch_masking::ExposeInterface;
    use tonic::metadata::MetadataMap;

    /// Build JSON for a Stripe ConnectorAuth header value.
    fn stripe_auth_json(api_key: &str) -> String {
        format!(
            r#"{{"auth_type":{{"Stripe":{{"api_key":"{}"}}}}}}"#,
            api_key
        )
    }

    /// Build a MetadataMap with a typed `X-Connector-Auth` JSON header for Stripe.
    fn metadata_with_typed_auth(api_key: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        let json = stripe_auth_json(api_key);
        metadata.insert(
            consts::X_CONNECTOR_AUTH,
            json.parse().expect("valid x-connector-auth header"),
        );
        metadata
    }

    /// Build a MetadataMap with legacy `x-auth` / `x-api-key` headers.
    fn metadata_with_legacy_auth(api_key: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            consts::X_AUTH,
            "header-key".parse().expect("valid x-auth header"),
        );
        metadata.insert(
            consts::X_API_KEY,
            api_key.parse().expect("valid x-api-key header"),
        );
        metadata
    }

    #[test]
    fn connector_auth_resolves_from_typed_header() {
        let metadata = metadata_with_typed_auth("typed-key-value");

        let auth = resolve_connector_auth(&metadata, &connector_types::ConnectorEnum::Stripe)
            .expect("typed header auth should resolve");

        match auth {
            ConnectorSpecificAuth::Stripe { api_key } => {
                assert_eq!(api_key.expose(), "typed-key-value");
            }
            _ => panic!("expected stripe auth"),
        }
    }

    #[test]
    fn connector_auth_falls_back_to_legacy_headers() {
        let metadata = metadata_with_legacy_auth("legacy-key-value");

        let auth = resolve_connector_auth(&metadata, &connector_types::ConnectorEnum::Stripe)
            .expect("legacy header auth should resolve");

        match auth {
            ConnectorSpecificAuth::Stripe { api_key } => {
                assert_eq!(api_key.expose(), "legacy-key-value");
            }
            _ => panic!("expected stripe auth"),
        }
    }

    #[test]
    fn connector_auth_prefers_typed_header_over_legacy() {
        let mut metadata = metadata_with_legacy_auth("legacy-key-value");
        let json = stripe_auth_json("typed-key-value");
        metadata.insert(
            consts::X_CONNECTOR_AUTH,
            json.parse().expect("valid x-connector-auth header"),
        );

        let auth = resolve_connector_auth(&metadata, &connector_types::ConnectorEnum::Stripe)
            .expect("typed header should take precedence");

        match auth {
            ConnectorSpecificAuth::Stripe { api_key } => {
                assert_eq!(api_key.expose(), "typed-key-value");
            }
            _ => panic!("expected stripe auth"),
        }
    }

    #[test]
    fn connector_auth_fails_when_no_auth_present() {
        let metadata = MetadataMap::new();

        let result = resolve_connector_auth(&metadata, &connector_types::ConnectorEnum::Stripe);

        assert!(result.is_err());
    }
}
