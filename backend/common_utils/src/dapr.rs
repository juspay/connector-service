use anyhow::{Context as _, Result};
use dapr::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct EulerAuditEvent {
    pub timestamp: String,
    pub hostname: String,
    #[serde(rename = "x-request-id")]
    pub x_request_id: String,
    pub message_number: String,
    pub message: Value,
    pub action: String,
    pub gateway: String,
    pub category: String,
    pub entity: String,
    pub error_code: String,
    pub error_reason: String,
    pub schema_version: String,
    pub udf_txn_uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutgoingRequestMessage {
    pub latency: Option<u64>,
    pub request_time: String,
    pub res_code: Option<u16>,
    pub req_type: String,
    pub url: String,
    pub req_body: Option<Value>,
    pub res_body: Option<Value>,
    pub req_headers: Option<Value>,
    pub res_headers: Option<Value>,
    pub stage: String,
    pub data: Option<Value>,
    pub log_type: String,
}

// Define FlowName enum locally to avoid circular dependency
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowName {
    Authorize,
    Refund,
    Capture,
    Void,
    Psync,
    Rsync,
    AcceptDispute,
    SubmitEvidence,
    DefendDispute,
    Dsync,
    IncomingWebhook,
    SetupMandate,
    CreateOrder,
}

impl FlowName {
    pub fn to_api_tag(&self) -> ApiTag {
        match self {
            Self::Authorize => ApiTag::InitTxn,
            Self::Refund => ApiTag::InitRefund,
            Self::Capture => ApiTag::InitCapture,
            Self::Void => ApiTag::InitRefund, // Void is similar to refund in terms of API tag
            Self::Psync => ApiTag::TxnSync,
            Self::Rsync => ApiTag::RefundSync,
            Self::AcceptDispute | Self::SubmitEvidence | Self::DefendDispute | Self::Dsync => {
                ApiTag::OutgoingRequest
            }
            Self::IncomingWebhook => ApiTag::IncomingRequest,
            Self::SetupMandate => ApiTag::InitMandate,
            Self::CreateOrder => ApiTag::CreateOrder,
        }
    }
}

pub enum ApiTag {
    CreateOrder,
    InitTxn,
    InitCapture,
    InitAuthorization,
    InitRefund,
    TxnSync,
    RefundSync,
    OrderSync,
    Authentication,
    TriggerOtp,
    VerifyOtp,
    ResendOtp,
    CheckEnrollment,
    InitEnrollment,
    ProcessAcsResult,
    ResolveCardToken,
    UpdateCardToken,
    GetCardInfo,
    LockerAddCard,
    LockerDeleteCard,
    GatewayListCard,
    GetCardInfoList,
    GatewayGetToken,
    LinkWallet,
    DelinkWallet,
    RefreshWallet,
    TopupWallet,
    WalletEligibility,
    GetWalletToken,
    RefreshWalletToken,
    VerifyWalletToken,
    InitMandate,
    ExecuteMandate,
    RevokeMandate,
    PauseMandate,
    ResumeMandate,
    MigrateMandate,
    SubscriptionStatus,
    MandateSync,
    MandateNotification,
    CheckRisk,
    NotifyRisk,
    RiskRollback,
    ValidateBankAccount,
    ValidateCustomerAccount,
    BalanceInquiry,
    VerifyVpa,
    GetVpa,
    Reconciliation,
    DetailedReconciliation,
    SplitSettlementTransfer,
    GetSettlementId,
    UpdateSplitSettlementDetails,
    OutgoingRequest,
    IncomingRequest,
}

impl ApiTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreateOrder => "GW_CREATE_ORDER",
            Self::InitTxn => "GW_INIT_TXN",
            Self::InitCapture => "GW_INIT_CAPTURE",
            Self::InitAuthorization => "GW_INIT_AUTHORIZATION",
            Self::InitRefund => "GW_INIT_REFUND",
            Self::TxnSync => "GW_TXN_SYNC",
            Self::RefundSync => "GW_REFUND_SYNC",
            Self::OrderSync => "GW_ORDER_SYNC",
            Self::Authentication => "GW_AUTHENTICATION",
            Self::TriggerOtp => "GW_TRIGGER_OTP",
            Self::VerifyOtp => "GW_VERIFY_OTP",
            Self::ResendOtp => "GW_RESEND_OTP",
            Self::CheckEnrollment => "GW_CHECK_ENROLLMENT",
            Self::InitEnrollment => "GW_INIT_ENROLLMENT",
            Self::ProcessAcsResult => "GW_PROCESS_ACS_RESULT",
            Self::ResolveCardToken => "GW_RESOLVE_CARD_TOKEN",
            Self::UpdateCardToken => "GW_UPDATE_CARD_TOKEN",
            Self::GetCardInfo => "GW_GET_CARD_INFO",
            Self::LockerAddCard => "GW_LOCKER_ADD_CARD",
            Self::LockerDeleteCard => "GW_LOCKER_DELETE_CARD",
            Self::GatewayListCard => "GW_GATEWAY_LIST_CARD",
            Self::GetCardInfoList => "GW_GET_CARD_INFO_LIST",
            Self::GatewayGetToken => "GW_GATEWAY_GET_TOKEN",
            Self::LinkWallet => "GW_LINK_WALLET",
            Self::DelinkWallet => "GW_DELINK_WALLET",
            Self::RefreshWallet => "GW_REFRESH_WALLET",
            Self::TopupWallet => "GW_TOPUP_WALLET",
            Self::WalletEligibility => "GW_WALLET_ELIGIBILITY",
            Self::GetWalletToken => "GW_GET_WALLET_TOKEN",
            Self::RefreshWalletToken => "GW_REFRESH_WALLET_TOKEN",
            Self::VerifyWalletToken => "GW_VERIFY_WALLET_TOKEN",
            Self::InitMandate => "GW_INIT_MANDATE",
            Self::ExecuteMandate => "GW_EXECUTE_MANDATE",
            Self::RevokeMandate => "GW_REVOKE_MANDATE",
            Self::PauseMandate => "GW_PAUSE_MANDATE",
            Self::ResumeMandate => "GW_RESUME_MANDATE",
            Self::MigrateMandate => "GW_MIGRATE_MANDATE",
            Self::SubscriptionStatus => "GW_SUBSCRIPTION_STATUS",
            Self::MandateSync => "GW_MANDATE_SYNC",
            Self::MandateNotification => "GW_MANDATE_NOTIFICATION",
            Self::CheckRisk => "GW_CHECK_RISK",
            Self::NotifyRisk => "GW_NOTIFY_RISK",
            Self::RiskRollback => "GW_RISK_ROLLBACK",
            Self::ValidateBankAccount => "GW_VALIDATE_BANK_ACCOUNT",
            Self::ValidateCustomerAccount => "GW_VALIDATE_CUSTOMER_ACCOUNT",
            Self::BalanceInquiry => "GW_BALANCE_INQUIRY",
            Self::VerifyVpa => "GW_VERIFY_VPA",
            Self::GetVpa => "GW_GET_VPA",
            Self::Reconciliation => "GW_RECONCILATION",
            Self::DetailedReconciliation => "GW_DETAILED_RECONCILATION",
            Self::SplitSettlementTransfer => "GW_SPLIT_SETTLEMENT_TRANFER",
            Self::GetSettlementId => "GW_GET_SETTLEMENT_ID",
            Self::UpdateSplitSettlementDetails => "GW_UPDATE_SPLIT_SETTLEMENT_DETAILS",
            Self::OutgoingRequest => "OUTGOING_REQUEST",
            Self::IncomingRequest => "INCOMING_REQUEST",
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventStage {
    RequestReceived,
    RequestSent,
    ResponseReceived,
    Error,
}

impl EventStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestReceived => "REQUEST_RECEIVED_FOR_FLOW",
            Self::RequestSent => "TXN_INITIATED_WITH_CONNECTOR",
            Self::ResponseReceived => "RESPONSE_RECEIVED_FROM_CONNECTOR",
            Self::Error => "ERROR_RECEIVED",
        }
    }
}

/// Create a Dapr client connection
pub async fn create_client() -> Result<Client<dapr::client::TonicClient>> {
    let dapr_port = std::env::var("DAPR_GRPC_PORT").unwrap_or_else(|_| "50001".to_string());
    let addr = format!("http://localhost:{dapr_port}");

    info!("Connecting to Dapr sidecar at: {}", addr);

    let client = Client::<dapr::client::TonicClient>::connect(addr)
        .await
        .context("Failed to connect to Dapr sidecar")?;

    info!("Successfully connected to Dapr sidecar");
    Ok(client)
}

/// Publish an Euler audit event through Dapr using the SDK client
pub async fn publish_event(event: EulerAuditEvent) -> Result<()> {
    info!("Request to publish Euler audit event through Dapr SDK");
    info!("Event details: {:?}", event);

    let event_json = serde_json::to_string(&event)?;
    let mut client = create_client().await?;

    let pubsub_name =
        std::env::var("DAPR_PUBSUB_NAME").unwrap_or_else(|_| "kafka-pubsub".to_string());
    let topic = "audit-trail-events".to_string();
    let content_type = "application/json".to_string();

    let mut metadata = HashMap::<String, String>::new();
    metadata.insert("action".to_string(), event.action.clone());
    metadata.insert("category".to_string(), event.category.clone());
    metadata.insert("gateway".to_string(), event.gateway.clone());

    client
        .publish_event(
            &pubsub_name,
            &topic,
            &content_type,
            event_json.into_bytes(),
            Some(metadata),
        )
        .await
        .context("Failed to publish audit event through Dapr SDK")?;

    info!(
        "Successfully published Euler audit event to pubsub component: {}",
        pubsub_name
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ConnectorEventData {
    pub flow_name: FlowName,
    pub connector: String,
    pub stage: EventStage,
    pub url: String,
    pub request_id: Option<String>,
    pub txn_uuid: Option<String>,
    pub req_body: Option<Value>,
    pub res_body: Option<Value>,
    pub req_headers: Option<Value>,
    pub res_headers: Option<Value>,
    pub latency: Option<u64>,
    pub res_code: Option<u16>,
    pub error_code: Option<String>,
    pub error_reason: Option<String>,
}

/// Create an Euler audit event for connector calls - unified approach
pub fn create_event_data(event_data: ConnectorEventData) -> EulerAuditEvent {
    let now = chrono::Utc::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let request_time = now.to_rfc3339();

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "connector-service".to_string());

    let message_number = "1".to_string();
    let api_tag = event_data.flow_name.to_api_tag();

    let outgoing_message = OutgoingRequestMessage {
        latency: event_data.latency,
        request_time,
        res_code: event_data.res_code,
        req_type: "EXTERNAL".to_string(),
        url: event_data.url.clone(),
        req_body: event_data.req_body,
        res_body: event_data.res_body,
        req_headers: event_data.req_headers,
        res_headers: event_data.res_headers,
        stage: event_data.stage.as_str().to_string(),
        data: None,
        log_type: "API_CALL".to_string(),
    };

    let message = serde_json::to_value(outgoing_message).unwrap_or_else(|_| serde_json::json!({}));

    EulerAuditEvent {
        timestamp,
        hostname,
        x_request_id: event_data.request_id.unwrap_or_else(|| "null".to_string()),
        message_number,
        message,
        action: api_tag.as_str().to_string(),
        gateway: event_data.connector.to_uppercase(),
        category: "OUTGOING_API".to_string(),
        entity: api_tag.as_str().to_string(),
        error_code: event_data.error_code.unwrap_or_else(|| "null".to_string()),
        error_reason: event_data
            .error_reason
            .unwrap_or_else(|| "null".to_string()),
        schema_version: "V2".to_string(),
        udf_txn_uuid: event_data.txn_uuid.unwrap_or_else(|| "null".to_string()),
    }
}

/// Unified function to emit connector events - replaces all the separate emit_*_event functions
#[allow(clippy::too_many_arguments)]
pub async fn emit_event(
    flow_name: FlowName,
    connector: &str,
    stage: EventStage,
    url: &str,
    request_id: Option<String>,
    txn_uuid: Option<String>,
    req_body: Option<Value>,
    res_body: Option<Value>,
    req_headers: Option<Value>,
    res_headers: Option<Value>,
    latency: Option<u64>,
    res_code: Option<u16>,
    error_code: Option<String>,
    error_reason: Option<String>,
) -> Result<()> {
    let event_data = ConnectorEventData {
        flow_name,
        connector: connector.to_string(),
        stage,
        url: url.to_string(),
        request_id,
        txn_uuid,
        req_body,
        res_body,
        req_headers,
        res_headers,
        latency,
        res_code,
        error_code,
        error_reason,
    };

    let audit_event = create_event_data(event_data);
    publish_event(audit_event).await
}
