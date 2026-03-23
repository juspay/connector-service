use common_enums::WebhookTransformationStatus;
use domain_types::{
    errors::{ApiError, ApplicationErrorResponse},
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorSpecificAuth,
    types::CardConversionHelper,
    utils::ForeignTryFrom,
};
use error_stack::ResultExt;
use grpc_api_types::payments::{
    event_content, DisputeResponse, EventAckResponse, EventContent, EventServiceHandleResponse,
    EventStatus, PaymentServiceGetResponse, RefundResponse, WebhookEventType,
};
use interfaces::api::ApplicationResponse;

use crate::types::ConnectorData;

/// Core webhook event processing shared by both the gRPC server and the FFI layer.
///
/// Caller is responsible for:
/// 1. Parsing `request_details` and `webhook_secrets` from the raw proto payload.
/// 2. Computing `source_verified` (the gRPC server may use an async external call;
///    the FFI layer uses only synchronous local verification).
///
/// This function then: determines the event type, dispatches to the appropriate
/// content helper, and assembles the final `EventServiceHandleResponse`.
pub fn process_webhook_event<
    T: PaymentMethodDataTypes
        + Default
        + Eq
        + std::fmt::Debug
        + Send
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + Sync
        + CardConversionHelper<T>
        + 'static,
>(
    connector_data: ConnectorData<T>,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorSpecificAuth>,
    source_verified: bool,
) -> error_stack::Result<EventServiceHandleResponse, ApplicationErrorResponse> {
    let event_type = connector_data
        .connector
        .get_event_type(
            request_details.clone(),
            webhook_secrets.clone(),
            connector_auth_details.clone(),
        )
        .change_context(ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "WEBHOOK_EVENT_TYPE_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while determining webhook event type".to_string(),
            error_object: None,
        }))?;

    let api_event_type = WebhookEventType::foreign_try_from(event_type.clone()).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "WEBHOOK_EVENT_TYPE_CONVERSION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while converting webhook event type".to_string(),
            error_object: None,
        }),
    )?;

    let event_response = if event_type.is_payment_event() {
        get_payments_webhook_content(
            connector_data.clone(),
            request_details.clone(),
            webhook_secrets,
            connector_auth_details,
        )?
    } else if event_type.is_refund_event() {
        get_refunds_webhook_content(
            connector_data.clone(),
            request_details.clone(),
            webhook_secrets,
            connector_auth_details,
        )?
    } else if event_type.is_dispute_event() {
        get_disputes_webhook_content(
            connector_data.clone(),
            request_details.clone(),
            webhook_secrets,
            connector_auth_details,
        )?
    } else {
        // Default: treat as payment event (mandate, payout, recovery, misc).
        get_payments_webhook_content(
            connector_data.clone(),
            request_details.clone(),
            webhook_secrets,
            connector_auth_details,
        )?
    };

    let webhook_status = match event_response.content {
        Some(event_content::Content::IncompleteTransformation(_)) => EventStatus::Incomplete,
        _ => EventStatus::Complete,
    };

    let webhook_api_response = connector_data
        .connector
        .get_webhook_api_response(request_details, None)
        .ok()
        .and_then(|resp| match resp {
            ApplicationResponse::StatusOk => Some(EventAckResponse {
                status_code: 200,
                headers: std::collections::HashMap::new(),
                body: Vec::new(),
            }),
            ApplicationResponse::TextPlain(body) => {
                let mut headers = std::collections::HashMap::new();
                headers.insert("content-type".to_string(), "text/plain".to_string());
                Some(EventAckResponse {
                    status_code: 200,
                    headers,
                    body: body.into_bytes(),
                })
            }
            ApplicationResponse::Json(json_body) => {
                let mut headers = std::collections::HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                serde_json::to_vec(&json_body).ok().map(|body| EventAckResponse {
                    status_code: 200,
                    headers,
                    body,
                })
            }
            _ => None,
        });

    Ok(EventServiceHandleResponse {
        event_type: api_event_type.into(),
        event_content: Some(event_response),
        source_verified,
        merchant_event_id: None,
        event_status: webhook_status as i32,
        event_ack_response: webhook_api_response,
    })
}

pub fn get_payments_webhook_content<
    T: PaymentMethodDataTypes + std::fmt::Debug + Default + Send + Sync + 'static,
>(
    connector_data: ConnectorData<T>,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorSpecificAuth>,
) -> error_stack::Result<EventContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_payment_webhook(
            request_details.clone(),
            webhook_secrets,
            connector_auth_details,
        )
        .change_context(ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "WEBHOOK_PROCESSING_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while processing payment webhook".to_string(),
            error_object: None,
        }))?;

    match webhook_details.transformation_status {
        WebhookTransformationStatus::Complete => {
            let response = PaymentServiceGetResponse::foreign_try_from(webhook_details)
                .change_context(ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
                    error_identifier: 500,
                    error_message: "Error while constructing response".to_string(),
                    error_object: None,
                }))?;

            Ok(EventContent {
                content: Some(
                    event_content::Content::PaymentsResponse(response),
                ),
            })
        }
        WebhookTransformationStatus::Incomplete => {
            let resource_object = connector_data
                .connector
                .get_webhook_resource_object(request_details)
                .change_context(ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "WEBHOOK_RESOURCE_ERROR".to_string(),
                    error_identifier: 500,
                    error_message: "Error while getting webhook resource object".to_string(),
                    error_object: None,
                }))?;
            let resource_object_vec = serde_json::to_vec(&resource_object).change_context(
                ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "SERIALIZATION_ERROR".to_string(),
                    error_identifier: 500,
                    error_message: "Error while serializing resource object".to_string(),
                    error_object: None,
                }),
            )?;

            Ok(EventContent {
                content: Some(
                    event_content::Content::IncompleteTransformation(
                        grpc_api_types::payments::IncompleteTransformationResponse {
                            resource_object: resource_object_vec,
                            reason: "Payment information required".to_string(),
                        },
                    ),
                ),
            })
        }
    }
}

pub fn get_refunds_webhook_content<
    T: PaymentMethodDataTypes
        + Default
        + Eq
        + std::fmt::Debug
        + Send
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + Sync
        + CardConversionHelper<T>
        + 'static,
>(
    connector_data: ConnectorData<T>,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorSpecificAuth>,
) -> error_stack::Result<EventContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_refund_webhook(request_details, webhook_secrets, connector_auth_details)
        .change_context(ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "WEBHOOK_PROCESSING_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while processing refund webhook".to_string(),
            error_object: None,
        }))?;

    let response = RefundResponse::foreign_try_from(webhook_details).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while constructing response".to_string(),
            error_object: None,
        }),
    )?;

    Ok(EventContent {
        content: Some(event_content::Content::RefundsResponse(response)),
    })
}

pub fn get_disputes_webhook_content<
    T: PaymentMethodDataTypes
        + Default
        + Eq
        + std::fmt::Debug
        + Send
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + Sync
        + CardConversionHelper<T>
        + 'static,
>(
    connector_data: ConnectorData<T>,
    request_details: domain_types::connector_types::RequestDetails,
    webhook_secrets: Option<domain_types::connector_types::ConnectorWebhookSecrets>,
    connector_auth_details: Option<ConnectorSpecificAuth>,
) -> error_stack::Result<EventContent, ApplicationErrorResponse> {
    let webhook_details = connector_data
        .connector
        .process_dispute_webhook(request_details, webhook_secrets, connector_auth_details)
        .change_context(ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "WEBHOOK_PROCESSING_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while processing dispute webhook".to_string(),
            error_object: None,
        }))?;

    let response = DisputeResponse::foreign_try_from(webhook_details).change_context(
        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: "RESPONSE_CONSTRUCTION_ERROR".to_string(),
            error_identifier: 500,
            error_message: "Error while constructing response".to_string(),
            error_object: None,
        }),
    )?;

    Ok(EventContent {
        content: Some(
            event_content::Content::DisputesResponse(response),
        ),
    })
}
