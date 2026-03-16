use std::sync::Arc;

use common_utils::metadata::MaskedMetadata;
use domain_types::{connector_types::ConnectorEnum, router_data::ConnectorSpecificConfig};
use hyperswitch_masking::Secret;
use grpc_api_types::payments::PaymentMethod;

use crate::config::*;
use crate::error_parsing::*;
use crate::patching::*;
use crate::probe_engine::*;
use crate::registry::*;
use crate::requests::*;
use crate::types::*;

/// Get connector-specific metadata JSON for connectors that require it
pub(crate) fn connector_feature_data_json(connector: &ConnectorEnum) -> Option<String> {
    let config = get_config();
    let name = format!("{connector:?}").to_lowercase();

    // First check if config has metadata for this connector
    if let Some(meta) = config.connector_metadata.get(&name) {
        return Some(meta.clone());
    }

    // Fall back to default if available
    config.connector_metadata.get("default").cloned()
}

pub(crate) fn probe_capture(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_capture_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::capture_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_capture_request,
    )
}

pub(crate) fn probe_refund(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_refund_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::refund_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_refund_request,
    )
}

pub(crate) fn probe_void(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_void_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::void_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_void_request,
    )
}

pub(crate) fn probe_get(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_get_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::get_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_get_request,
    )
}

pub(crate) fn probe_reverse(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_reverse_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::reverse_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

pub(crate) fn probe_create_order(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_create_order_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_order_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

pub(crate) fn probe_setup_recurring(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_setup_recurring_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    let result = run_probe(
        req,
        |req| {
            ffi::services::payments::setup_recurring_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_setup_recurring_request,
    );
    // Debug: log setup_recurring result for Stripe
    if format!("{connector:?}").to_lowercase() == "stripe" && result.status != "supported" {
        eprintln!(
            "  DEBUG setup_recurring for {:?}: status={}, error={:?}",
            connector, result.status, result.error
        );
    }
    result
}

pub(crate) fn probe_recurring_charge(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_recurring_charge_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::charge_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_recurring_charge_request,
    )
}

pub(crate) fn probe_create_customer(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_create_customer_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

pub(crate) fn probe_tokenize(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_tokenize_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::tokenize_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

pub(crate) fn probe_create_access_token(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_create_access_token_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_access_token_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

pub(crate) fn probe_create_session_token(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_create_session_token_request();
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::create_session_token_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

pub(crate) fn probe_pre_authenticate(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_pre_authenticate_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::pre_authenticate_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        |_, _| {},
    )
}

pub(crate) fn probe_authenticate(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_authenticate_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::authenticate_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_authenticate_request,
    )
}

pub(crate) fn probe_post_authenticate(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let mut req = base_post_authenticate_request();
    if is_oauth_connector(connector) {
        req.state = Some(mock_connector_state());
    }
    if let Some(meta) = connector_feature_data_json(connector) {
        req.connector_feature_data = Some(Secret::new(meta));
    }
    run_probe(
        req,
        |req| {
            ffi::services::payments::post_authenticate_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_post_authenticate_request,
    )
}

pub(crate) fn probe_accept_dispute(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_accept_dispute_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::accept_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_accept_dispute_request,
    )
}

pub(crate) fn probe_submit_evidence(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_submit_evidence_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::submit_evidence_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_submit_evidence_request,
    )
}

pub(crate) fn probe_defend_dispute(
    connector: &ConnectorEnum,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    let req = base_defend_dispute_request();
    run_probe(
        req,
        |req| {
            ffi::services::payments::defend_req_transformer::<PciFfi>(
                req,
                config,
                connector.clone(),
                auth.clone(),
                metadata,
            )
        },
        patch_defend_dispute_request,
    )
}

/// Authorize probe — handles a single PM type
pub(crate) fn probe_authorize(
    connector: &ConnectorEnum,
    pm_name: &str,
    pm: PaymentMethod,
    config: &Arc<ucs_env::configs::Config>,
    auth: ConnectorSpecificConfig,
    metadata: &MaskedMetadata,
) -> FlowResult {
    // Pre-populate connector_feature_data for connectors that require it
    let connector_meta = connector_feature_data_json(connector);

    // Check if this is an OAuth connector that needs a cached access token
    let is_oauth = get_config().is_oauth_connector(connector);

    let mut result = if is_oauth {
        run_probe(
            base_authorize_request_with_state(pm, connector_meta, mock_connector_state()),
            |req| {
                ffi::services::payments::authorize_req_transformer::<PciFfi>(
                    req,
                    config,
                    connector.clone(),
                    auth.clone(),
                    metadata,
                )
            },
            patch_authorize_request,
        )
    } else {
        run_probe(
            base_authorize_request_with_meta(pm, connector_meta),
            |req| {
                ffi::services::payments::authorize_req_transformer::<PciFfi>(
                    req,
                    config,
                    connector.clone(),
                    auth.clone(),
                    metadata,
                )
            },
            patch_authorize_request,
        )
    };

    // For wallet PM types the probe uses internal workaround formats (decrypted
    // Apple Pay data, connector-specific fake GPay tokens) that users would never
    // send in production. Replace the payment_method part of the proto_request with
    // the correct real-world encrypted format so the published docs are accurate.
    if result.status == "supported" {
        if let Some(doc_pm) = doc_payment_method_override(pm_name) {
            if let Some(ref mut proto_req) = result.proto_request {
                proto_req["payment_method"] = doc_pm;
            }
        }
    }

    result
}
