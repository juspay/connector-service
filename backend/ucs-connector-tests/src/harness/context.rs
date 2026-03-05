use grpc_api_types::payments::{
    identifier::IdType, ConnectorState, CustomerServiceCreateResponse, Identifier, Money,
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse, PaymentServiceGetRequest, PaymentServiceGetResponse,
    PaymentServiceRefundRequest, PaymentServiceVoidRequest, PaymentServiceVoidResponse,
    RefundResponse,
};
use hyperswitch_masking::Secret;
use uuid::Uuid;

use crate::harness::generators::GeneratedInputVariant;

#[derive(Clone, Debug)]
pub struct FlowContext {
    pub case: GeneratedInputVariant,
    pub merchant_customer_id: String,
    pub connector_customer_id: Option<String>,
    pub connector_transaction_id: Option<String>,
    pub amount_minor: i64,
    pub merchant_refund_id: Option<String>,
    pub propagated_metadata: Option<Secret<String>>,
    pub propagated_connector_feature_data: Option<Secret<String>>,
    pub propagated_state: Option<ConnectorState>,
    pub propagated_capture_method: Option<i32>,
    pub propagated_amount: Option<Money>,
    pub propagated_merchant_order_id: Option<String>,
    pub requested_connector_transaction_id: Option<String>,
}

impl FlowContext {
    pub fn new(case: GeneratedInputVariant, prefix: &str) -> Self {
        let merchant_customer_id = format!("{}_cust_{}", prefix, Uuid::new_v4());
        Self {
            amount_minor: case.amount_minor,
            case,
            merchant_customer_id,
            connector_customer_id: None,
            connector_transaction_id: None,
            merchant_refund_id: None,
            propagated_metadata: None,
            propagated_connector_feature_data: None,
            propagated_state: None,
            propagated_capture_method: None,
            propagated_amount: None,
            propagated_merchant_order_id: None,
            requested_connector_transaction_id: None,
        }
    }

    pub fn apply_customer_to_authorize(&mut self, request: &mut PaymentServiceAuthorizeRequest) {
        if let (Some(customer), Some(connector_customer_id)) = (
            request.customer.as_mut(),
            self.connector_customer_id.clone(),
        ) {
            customer.connector_customer_id = Some(connector_customer_id);
        }

        if request.metadata.is_none() {
            request.metadata = self.propagated_metadata.clone();
        }
        if request.connector_feature_data.is_none() {
            request.connector_feature_data = self.propagated_connector_feature_data.clone();
        }
        if request.state.is_none() {
            request.state = self.propagated_state.clone();
        }
        if request.merchant_order_id.is_none() {
            request.merchant_order_id = self.propagated_merchant_order_id.clone();
        }

        self.remember_authorize_request_fields(request);
    }

    pub fn apply_to_capture_request(&mut self, request: &mut PaymentServiceCaptureRequest) {
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .requested_connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }

        if request.metadata.is_none() {
            request.metadata = self.propagated_metadata.clone();
        }
        if request.connector_feature_data.is_none() {
            request.connector_feature_data = self.propagated_connector_feature_data.clone();
        }
        if request.state.is_none() {
            request.state = self.propagated_state.clone();
        }
        if request.capture_method.is_none() {
            request.capture_method = self.propagated_capture_method;
        }
        if request.merchant_order_id.is_none() {
            request.merchant_order_id = self.propagated_merchant_order_id.clone();
        }

        self.remember_capture_request_fields(request);
    }

    pub fn apply_to_get_request(&mut self, request: &mut PaymentServiceGetRequest) {
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .requested_connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }

        if request.amount.is_none() {
            request.amount = self.propagated_amount.clone();
        }
        if request.capture_method.is_none() {
            request.capture_method = self.propagated_capture_method;
        }
        if request.metadata.is_none() {
            request.metadata = self.propagated_metadata.clone();
        }
        if request.connector_feature_data.is_none() {
            request.connector_feature_data = self.propagated_connector_feature_data.clone();
        }
        if request.state.is_none() {
            request.state = self.propagated_state.clone();
        }

        self.remember_get_request_fields(request);
    }

    pub fn apply_to_void_request(&mut self, request: &mut PaymentServiceVoidRequest) {
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .requested_connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }

        if request.metadata.is_none() {
            request.metadata = self.propagated_metadata.clone();
        }
        if request.connector_feature_data.is_none() {
            request.connector_feature_data = self.propagated_connector_feature_data.clone();
        }
        if request.state.is_none() {
            request.state = self.propagated_state.clone();
        }
        if request.merchant_order_id.is_none() {
            request.merchant_order_id = self.propagated_merchant_order_id.clone();
        }

        self.remember_void_request_fields(request);
    }

    pub fn apply_to_refund_request(&mut self, request: &mut PaymentServiceRefundRequest) {
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }
        if request.connector_transaction_id.is_none() {
            request.connector_transaction_id = self
                .requested_connector_transaction_id
                .clone()
                .map(identifier_from_value);
        }

        if request.metadata.is_none() {
            request.metadata = self.propagated_metadata.clone();
        }
        if request.connector_feature_data.is_none() {
            request.connector_feature_data = self.propagated_connector_feature_data.clone();
        }
        if request.state.is_none() {
            request.state = self.propagated_state.clone();
        }
        if request.capture_method.is_none() {
            request.capture_method = self.propagated_capture_method;
        }
        if request.customer_id.is_none() {
            request.customer_id = Some(self.merchant_customer_id.clone());
        }

        self.remember_refund_request_fields(request);
    }

    fn remember_authorize_request_fields(&mut self, request: &PaymentServiceAuthorizeRequest) {
        self.capture_common_request_fields(
            request.metadata.clone(),
            request.connector_feature_data.clone(),
            request.state.clone(),
            request.capture_method,
            request.amount.clone(),
            request.merchant_order_id.clone(),
        );
    }

    fn remember_capture_request_fields(&mut self, request: &PaymentServiceCaptureRequest) {
        self.requested_connector_transaction_id =
            extract_identifier_value(request.connector_transaction_id.as_ref());

        self.capture_common_request_fields(
            request.metadata.clone(),
            request.connector_feature_data.clone(),
            request.state.clone(),
            request.capture_method,
            None,
            request.merchant_order_id.clone(),
        );
    }

    fn remember_get_request_fields(&mut self, request: &PaymentServiceGetRequest) {
        self.requested_connector_transaction_id =
            extract_identifier_value(request.connector_transaction_id.as_ref());

        self.capture_common_request_fields(
            request.metadata.clone(),
            request.connector_feature_data.clone(),
            request.state.clone(),
            request.capture_method,
            request.amount.clone(),
            None,
        );
    }

    fn remember_void_request_fields(&mut self, request: &PaymentServiceVoidRequest) {
        self.requested_connector_transaction_id =
            extract_identifier_value(request.connector_transaction_id.as_ref());

        self.capture_common_request_fields(
            request.metadata.clone(),
            request.connector_feature_data.clone(),
            request.state.clone(),
            None,
            request.amount.clone(),
            request.merchant_order_id.clone(),
        );
    }

    fn remember_refund_request_fields(&mut self, request: &PaymentServiceRefundRequest) {
        self.requested_connector_transaction_id =
            extract_identifier_value(request.connector_transaction_id.as_ref());

        self.capture_common_request_fields(
            request.metadata.clone(),
            request.connector_feature_data.clone(),
            request.state.clone(),
            request.capture_method,
            request.refund_amount.clone(),
            None,
        );
    }

    fn capture_common_request_fields(
        &mut self,
        metadata: Option<Secret<String>>,
        connector_feature_data: Option<Secret<String>>,
        state: Option<ConnectorState>,
        capture_method: Option<i32>,
        amount: Option<Money>,
        merchant_order_id: Option<String>,
    ) {
        if metadata.is_some() {
            self.propagated_metadata = metadata;
        }
        if connector_feature_data.is_some() {
            self.propagated_connector_feature_data = connector_feature_data;
        }
        if state.is_some() {
            self.propagated_state = state;
        }
        if capture_method.is_some() {
            self.propagated_capture_method = capture_method;
        }
        if amount.is_some() {
            self.propagated_amount = amount;
        }
        if merchant_order_id.is_some() {
            self.propagated_merchant_order_id = merchant_order_id;
        }
    }

    pub fn capture_from_customer_create_response(
        &mut self,
        response: &CustomerServiceCreateResponse,
    ) {
        if !response.connector_customer_id.trim().is_empty() {
            self.connector_customer_id = Some(response.connector_customer_id.clone());
        }
    }

    pub fn capture_from_authorize_response(&mut self, response: &PaymentServiceAuthorizeResponse) {
        self.set_connector_transaction_id(extract_identifier_value(
            response.connector_transaction_id.as_ref(),
        ));

        if response.connector_feature_data.is_some() {
            self.propagated_connector_feature_data = response.connector_feature_data.clone();
        }
        if response.state.is_some() {
            self.propagated_state = response.state.clone();
        }
    }

    pub fn capture_from_capture_response(&mut self, response: &PaymentServiceCaptureResponse) {
        self.set_connector_transaction_id(extract_identifier_value(
            response.connector_transaction_id.as_ref(),
        ));

        if response.connector_feature_data.is_some() {
            self.propagated_connector_feature_data = response.connector_feature_data.clone();
        }
        if response.state.is_some() {
            self.propagated_state = response.state.clone();
        }
    }

    pub fn capture_from_get_response(&mut self, response: &PaymentServiceGetResponse) {
        self.set_connector_transaction_id(extract_identifier_value(
            response.connector_transaction_id.as_ref(),
        ));

        if response.metadata.is_some() {
            self.propagated_metadata = response.metadata.clone();
        }
        if response.state.is_some() {
            self.propagated_state = response.state.clone();
        }
        if response.capture_method.is_some() {
            self.propagated_capture_method = response.capture_method;
        }
        if response.amount.is_some() {
            self.propagated_amount = response.amount.clone();
        }
        if response.merchant_order_id.is_some() {
            self.propagated_merchant_order_id = response.merchant_order_id.clone();
        }
        if response.connector_customer_id.is_some() {
            self.connector_customer_id = response.connector_customer_id.clone();
        }
    }

    pub fn capture_from_void_response(&mut self, response: &PaymentServiceVoidResponse) {
        self.set_connector_transaction_id(extract_identifier_value(
            response.connector_transaction_id.as_ref(),
        ));

        if response.connector_feature_data.is_some() {
            self.propagated_connector_feature_data = response.connector_feature_data.clone();
        }
        if response.state.is_some() {
            self.propagated_state = response.state.clone();
        }
    }

    pub fn capture_from_refund_response(&mut self, response: &RefundResponse) {
        self.set_connector_transaction_id(extract_identifier_value(
            response.connector_transaction_id.as_ref(),
        ));

        if response.metadata.is_some() {
            self.propagated_metadata = response.metadata.clone();
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

fn extract_identifier_value(identifier: Option<&Identifier>) -> Option<String> {
    identifier
        .and_then(|value| value.id_type.as_ref())
        .and_then(|id_type| match id_type {
            IdType::Id(id) | IdType::EncodedData(id) => Some(id.clone()),
            IdType::NoResponseIdMarker(_) => None,
        })
}

fn identifier_from_value(value: String) -> Identifier {
    Identifier {
        id_type: Some(IdType::Id(value)),
    }
}
