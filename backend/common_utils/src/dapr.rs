use anyhow::{Context as _, Result};
use dapr::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericEvent {
    pub timestamp: String,
    pub flow_type: String,
    pub connector: String,
    pub stage: String,
    pub url: String,
    pub request_id: Option<String>,
    pub transaction_id: Option<String>,
    pub latency: Option<u64>,
    pub status_code: Option<u16>,
    pub error_code: Option<String>,
    pub error_reason: Option<String>,

    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

/// Configuration for the generic events system
#[derive(Debug, Clone, Deserialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub pubsub_component: String,
    pub topic: String,
    #[serde(default)]
    pub transformations: HashMap<String, String>, // target_path → source_field
    #[serde(default)]
    pub static_values: HashMap<String, String>, // target_path → static_value
    #[serde(default)]
    pub extractions: HashMap<String, String>, // target_path → extraction_path
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pubsub_component: "kafka-pubsub".to_string(),
            topic: "connector-events".to_string(),
            transformations: HashMap::new(),
            static_values: HashMap::new(),
            extractions: HashMap::new(),
        }
    }
}

/// Context data available for event processing
#[derive(Debug, Clone)]
pub struct EventContext {
    pub request_data: Option<serde_json::Value>,
    pub response_data: Option<serde_json::Value>,
    pub request_headers: Option<serde_json::Value>,
    pub response_headers: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

impl Default for EventContext {
    fn default() -> Self {
        Self {
            request_data: None,
            response_data: None,
            request_headers: None,
            response_headers: None,
            metadata: None,
        }
    }
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

pub struct EventProcessor {
    config: EventConfig,
}

impl EventProcessor {
    pub fn new(config: EventConfig) -> Self {
        Self { config }
    }

    pub fn process_event(
        &self,
        base_event: &GenericEvent,
        context: &EventContext,
    ) -> serde_json::Value {
        let mut result = serde_json::json!({});

        // 1. Apply transformations (field mappings)
        for (target_path, source_field) in &self.config.transformations {
            if let Some(value) = self.get_field_value(base_event, source_field) {
                self.set_nested_value(&mut result, target_path, value);
            }
        }

        // 2. Apply static values
        for (target_path, static_value) in &self.config.static_values {
            let value = serde_json::json!(static_value);
            self.set_nested_value(&mut result, target_path, value);
        }

        // 3. Apply extractions
        for (target_path, extraction_path) in &self.config.extractions {
            if let Some(value) = self.extract_from_context(context, extraction_path) {
                self.set_nested_value(&mut result, target_path, value);
            }
        }

        result
    }

    /// Get a field value from the base event
    fn get_field_value(&self, event: &GenericEvent, field_name: &str) -> Option<serde_json::Value> {
        match field_name {
            "timestamp" => Some(serde_json::json!(event.timestamp)),
            "flow_type" => Some(serde_json::json!(event.flow_type)),
            "connector" => Some(serde_json::json!(event.connector)),
            "stage" => Some(serde_json::json!(event.stage)),
            "url" => Some(serde_json::json!(event.url)),
            "request_id" => event.request_id.as_ref().map(|v| serde_json::json!(v)),
            "transaction_id" => event.transaction_id.as_ref().map(|v| serde_json::json!(v)),
            "latency" => event.latency.map(|v| serde_json::json!(v)),
            "status_code" => event.status_code.map(|v| serde_json::json!(v)),
            "error_code" => event.error_code.as_ref().map(|v| serde_json::json!(v)),
            "error_reason" => event.error_reason.as_ref().map(|v| serde_json::json!(v)),
            _ => {
                // Check additional fields
                event.additional_fields.get(field_name).cloned()
            }
        }
    }

    /// Extract values from context using dot notation paths
    fn extract_from_context(
        &self,
        context: &EventContext,
        extraction_path: &str,
    ) -> Option<serde_json::Value> {
        let path_parts: Vec<&str> = extraction_path.split('.').collect();
        if path_parts.is_empty() {
            return None;
        }

        let source = match path_parts[0] {
            "request_data" => context.request_data.as_ref()?,
            "response_data" => context.response_data.as_ref()?,
            "request_headers" => context.request_headers.as_ref()?,
            "response_headers" => context.response_headers.as_ref()?,
            "metadata" => context.metadata.as_ref()?,
            _ => return None,
        };

        let mut current = source;
        for part in &path_parts[1..] {
            current = current.get(part)?;
        }

        Some(current.clone())
    }

    fn set_nested_value(
        &self,
        target: &mut serde_json::Value,
        path: &str,
        value: serde_json::Value,
    ) {
        let path_parts: Vec<&str> = path.split('.').collect();

        if path_parts.len() == 1 {
            target[path_parts[0]] = value;
            return;
        }

        let mut current = target;
        for (i, part) in path_parts.iter().enumerate() {
            if i == path_parts.len() - 1 {
                current[*part] = value;
                break;
            } else {
                if !current[*part].is_object() {
                    current[*part] = serde_json::json!({});
                }
                current = &mut current[*part];
            }
        }
    }
}

pub async fn publish_to_dapr(
    event: serde_json::Value,
    pubsub_component: &str,
    topic: &str,
) -> Result<()> {
    info!(
        "Publishing generic event to Dapr: component={}, topic={}",
        pubsub_component, topic
    );

    let event_json = serde_json::to_string(&event)?;
    let mut client = create_client().await?;

    let content_type = "application/json".to_string();
    let metadata = HashMap::<String, String>::new();

    client
        .publish_event(
            pubsub_component,
            topic,
            &content_type,
            event_json.into_bytes(),
            Some(metadata),
        )
        .await
        .context("Failed to publish generic event through Dapr SDK")?;

    info!(
        "Successfully published generic event to pubsub component: {}",
        pubsub_component
    );
    Ok(())
}

pub fn create_generic_event_from_legacy(event_data: &ConnectorEventData) -> GenericEvent {
    let now = chrono::Utc::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();

    GenericEvent {
        timestamp,
        flow_type: event_data.flow_name.to_api_tag().as_str().to_string(),
        connector: event_data.connector.clone(),
        stage: event_data.stage.as_str().to_string(),
        url: event_data.url.clone(),
        request_id: event_data.request_id.clone(),
        transaction_id: event_data.txn_uuid.clone(),
        latency: event_data.latency,
        status_code: event_data.res_code,
        error_code: event_data.error_code.clone(),
        error_reason: event_data.error_reason.clone(),
        additional_fields: HashMap::new(),
    }
}

pub fn create_event_context_from_legacy(event_data: &ConnectorEventData) -> EventContext {
    EventContext {
        request_data: event_data.req_body.clone(),
        response_data: event_data.res_body.clone(),
        request_headers: event_data.req_headers.clone(),
        response_headers: event_data.res_headers.clone(),
        metadata: None,
    }
}

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

    let generic_event = create_generic_event_from_legacy(&event_data);
    let context = create_event_context_from_legacy(&event_data);

    let config = EventConfig {
        enabled: true,
        pubsub_component: "kafka-pubsub".to_string(),
        topic: "audit-trail-events".to_string(),
        transformations: [
            ("gateway".to_string(), "connector".to_string()),
            ("udf_txn_uuid".to_string(), "transaction_id".to_string()),
            ("x-request-id".to_string(), "request_id".to_string()),
        ]
        .into_iter()
        .collect(),
        static_values: [
            ("hostname".to_string(), "connector-service".to_string()),
            ("schema_version".to_string(), "V2".to_string()),
            ("category".to_string(), "OUTGOING_API".to_string()),
        ]
        .into_iter()
        .collect(),
        extractions: [
            ("message.req_body".to_string(), "request_data".to_string()),
            ("message.res_body".to_string(), "response_data".to_string()),
        ]
        .into_iter()
        .collect(),
    };

    if !config.enabled {
        return Ok(());
    }

    let processor = EventProcessor::new(config.clone());
    let processed_event = processor.process_event(&generic_event, &context);

    publish_to_dapr(processed_event, &config.pubsub_component, &config.topic).await
}

pub async fn emit_event_with_config(
    base_event: GenericEvent,
    context: EventContext,
    config: &EventConfig,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let processor = EventProcessor::new(config.clone());
    let processed_event = processor.process_event(&base_event, &context);

    publish_to_dapr(processed_event, &config.pubsub_component, &config.topic).await
}
