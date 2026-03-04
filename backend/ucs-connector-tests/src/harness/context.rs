use grpc_api_types::payments::PaymentServiceAuthorizeRequest;
use uuid::Uuid;

use crate::harness::generators::GeneratedCase;

#[derive(Clone, Debug)]
pub struct FlowContext {
    pub case: GeneratedCase,
    pub merchant_customer_id: String,
    pub connector_customer_id: Option<String>,
    pub connector_transaction_id: Option<String>,
    pub amount_minor: i64,
    pub merchant_refund_id: Option<String>,
}

impl FlowContext {
    pub fn new(case: GeneratedCase, prefix: &str) -> Self {
        let merchant_customer_id = format!("{}_cust_{}", prefix, Uuid::new_v4());
        Self {
            amount_minor: case.amount_minor,
            case,
            merchant_customer_id,
            connector_customer_id: None,
            connector_transaction_id: None,
            merchant_refund_id: None,
        }
    }

    pub fn apply_customer_to_authorize(&self, request: &mut PaymentServiceAuthorizeRequest) {
        if let (Some(customer), Some(connector_customer_id)) = (
            request.customer.as_mut(),
            self.connector_customer_id.clone(),
        ) {
            customer.connector_customer_id = Some(connector_customer_id);
        }
    }

    pub fn require_connector_transaction_id(&self, context: &str) -> String {
        self.connector_transaction_id
            .clone()
            .unwrap_or_else(|| panic!("{context}: missing connector_transaction_id in context"))
    }

    pub fn set_connector_transaction_id(&mut self, connector_transaction_id: Option<String>) {
        if let Some(value) = connector_transaction_id {
            self.connector_transaction_id = Some(value);
        }
    }

    pub fn next_merchant_refund_id(&mut self, prefix: &str) -> String {
        let value = format!("{}_refund_{}", prefix, Uuid::new_v4());
        self.merchant_refund_id = Some(value.clone());
        value
    }
}
