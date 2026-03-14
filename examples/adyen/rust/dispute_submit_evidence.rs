// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: DisputeService.SubmitEvidence
//
// SDK: sdk/rust (native Rust — uses hyperswitch_payments_client)
// Build: cargo check -p hyperswitch-payments-client  (from repo root)

use grpc_api_types::payments::{Connector, ConnectorConfig, Environment, DisputeServiceSubmitEvidenceRequest};
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {
    let config = ConnectorConfig {
        connector: Connector::Adyen.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };

    let client = ConnectorClient::new(config);

    // Build request with probe-verified field values.
    // Note: sensitive fields use Secret::new("value") and card_number uses .try_into().
    // See sdk/rust/examples/basic.rs for the full type-safe construction pattern.
    let request = DisputeServiceSubmitEvidenceRequest {
    merchant_dispute_id: Some("probe_dispute_001".to_string()),  // Identification
    connector_transaction_id: Some("probe_txn_001".to_string()),
    dispute_id: Some("probe_dispute_id_001".to_string()),
    // evidence_documents: [{"evidence_type": "SERVICE_DOCUMENTATION", "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116], "file_mime_type": "application/pdf"}]  // Collection of evidence documents
        ..Default::default()
    };

    let response = client.dispute_submit_evidence(request).await.unwrap();
    println!("Status: {:?}", response.status());
}
