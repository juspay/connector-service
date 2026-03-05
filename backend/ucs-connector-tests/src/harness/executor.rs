use tonic::Request;
use uuid::Uuid;

use crate::harness::{
    credentials::{load_connector_auth, ConnectorAuth},
    metadata::add_connector_metadata,
    server::{spawn, UcsServer},
};

pub struct ConnectorExecutor {
    server: UcsServer,
    auth: ConnectorAuth,
    connector: String,
    merchant_id: String,
    tenant_id: String,
}

impl ConnectorExecutor {
    pub async fn new(connector: &str) -> Self {
        let server = spawn().await.expect("UCS server should start");
        let auth = load_connector_auth(connector)
            .unwrap_or_else(|_| panic!("{connector} creds should load"));

        Self {
            server,
            auth,
            connector: connector.to_string(),
            merchant_id: "test_merchant".to_string(),
            tenant_id: "default".to_string(),
        }
    }

    pub fn payment_client(
        &self,
    ) -> grpc_api_types::payments::payment_service_client::PaymentServiceClient<
        tonic::transport::Channel,
    > {
        self.server.payment_client()
    }

    pub fn customer_client(
        &self,
    ) -> grpc_api_types::payments::customer_service_client::CustomerServiceClient<
        tonic::transport::Channel,
    > {
        self.server.customer_client()
    }

    pub fn request_with_ids<T>(
        &self,
        payload: T,
        request_id: &str,
        connector_request_reference_id: &str,
    ) -> Request<T> {
        let mut request = Request::new(payload);
        add_connector_metadata(
            &mut request,
            &self.connector,
            &self.auth,
            &self.merchant_id,
            &self.tenant_id,
            request_id,
            connector_request_reference_id,
        );
        request
    }

    pub fn request_from_case<T>(
        &self,
        payload: T,
        case: &crate::harness::generators::GeneratedInputVariant,
    ) -> Request<T> {
        self.request_with_ids(
            payload,
            &case.request_id,
            &case.connector_request_reference_id,
        )
    }

    pub fn step_ids(flow_name: &str, step_name: &str) -> (String, String) {
        let id = Uuid::new_v4().to_string();
        (
            format!("{}_{}_req_{}", flow_name, step_name, id),
            format!("{}_{}_ref_{}", flow_name, step_name, id),
        )
    }
}

pub struct AuthorizedotnetExecutor {
    inner: ConnectorExecutor,
}

impl AuthorizedotnetExecutor {
    pub async fn new() -> Self {
        Self {
            inner: ConnectorExecutor::new("authorizedotnet").await,
        }
    }

    pub fn payment_client(
        &self,
    ) -> grpc_api_types::payments::payment_service_client::PaymentServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.payment_client()
    }

    pub fn customer_client(
        &self,
    ) -> grpc_api_types::payments::customer_service_client::CustomerServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.customer_client()
    }

    pub fn request_with_ids<T>(
        &self,
        payload: T,
        request_id: &str,
        connector_request_reference_id: &str,
    ) -> Request<T> {
        self.inner
            .request_with_ids(payload, request_id, connector_request_reference_id)
    }

    pub fn request_from_case<T>(
        &self,
        payload: T,
        case: &crate::harness::generators::GeneratedInputVariant,
    ) -> Request<T> {
        self.inner.request_from_case(payload, case)
    }

    pub fn step_ids(flow_name: &str, step_name: &str) -> (String, String) {
        ConnectorExecutor::step_ids(flow_name, step_name)
    }
}

pub struct AdyenExecutor {
    inner: ConnectorExecutor,
}

impl AdyenExecutor {
    pub async fn new() -> Self {
        Self {
            inner: ConnectorExecutor::new("adyen").await,
        }
    }

    pub fn payment_client(
        &self,
    ) -> grpc_api_types::payments::payment_service_client::PaymentServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.payment_client()
    }

    pub fn customer_client(
        &self,
    ) -> grpc_api_types::payments::customer_service_client::CustomerServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.customer_client()
    }

    pub fn request_with_ids<T>(
        &self,
        payload: T,
        request_id: &str,
        connector_request_reference_id: &str,
    ) -> Request<T> {
        self.inner
            .request_with_ids(payload, request_id, connector_request_reference_id)
    }

    pub fn request_from_case<T>(
        &self,
        payload: T,
        case: &crate::harness::generators::GeneratedInputVariant,
    ) -> Request<T> {
        self.inner.request_from_case(payload, case)
    }

    pub fn step_ids(flow_name: &str, step_name: &str) -> (String, String) {
        ConnectorExecutor::step_ids(flow_name, step_name)
    }
}

pub struct StripeExecutor {
    inner: ConnectorExecutor,
}

impl StripeExecutor {
    pub async fn new() -> Self {
        Self {
            inner: ConnectorExecutor::new("stripe").await,
        }
    }

    pub fn payment_client(
        &self,
    ) -> grpc_api_types::payments::payment_service_client::PaymentServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.payment_client()
    }

    pub fn customer_client(
        &self,
    ) -> grpc_api_types::payments::customer_service_client::CustomerServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.customer_client()
    }

    pub fn request_with_ids<T>(
        &self,
        payload: T,
        request_id: &str,
        connector_request_reference_id: &str,
    ) -> Request<T> {
        self.inner
            .request_with_ids(payload, request_id, connector_request_reference_id)
    }

    pub fn request_from_case<T>(
        &self,
        payload: T,
        case: &crate::harness::generators::GeneratedInputVariant,
    ) -> Request<T> {
        self.inner.request_from_case(payload, case)
    }

    pub fn step_ids(flow_name: &str, step_name: &str) -> (String, String) {
        ConnectorExecutor::step_ids(flow_name, step_name)
    }
}

pub struct CybersourceExecutor {
    inner: ConnectorExecutor,
}

impl CybersourceExecutor {
    pub async fn new() -> Self {
        Self {
            inner: ConnectorExecutor::new("cybersource").await,
        }
    }

    pub fn payment_client(
        &self,
    ) -> grpc_api_types::payments::payment_service_client::PaymentServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.payment_client()
    }

    pub fn customer_client(
        &self,
    ) -> grpc_api_types::payments::customer_service_client::CustomerServiceClient<
        tonic::transport::Channel,
    > {
        self.inner.customer_client()
    }

    pub fn request_with_ids<T>(
        &self,
        payload: T,
        request_id: &str,
        connector_request_reference_id: &str,
    ) -> Request<T> {
        self.inner
            .request_with_ids(payload, request_id, connector_request_reference_id)
    }

    pub fn request_from_case<T>(
        &self,
        payload: T,
        case: &crate::harness::generators::GeneratedInputVariant,
    ) -> Request<T> {
        self.inner.request_from_case(payload, case)
    }

    pub fn step_ids(flow_name: &str, step_name: &str) -> (String, String) {
        ConnectorExecutor::step_ids(flow_name, step_name)
    }
}
