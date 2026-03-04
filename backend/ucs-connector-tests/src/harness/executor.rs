use tonic::Request;
use uuid::Uuid;

use crate::harness::{
    credentials::{load_body_key_auth, ConnectorAuth},
    metadata::add_authorizedotnet_metadata,
    server::{spawn, UcsServer},
};

pub struct AuthorizedotnetExecutor {
    server: UcsServer,
    auth: ConnectorAuth,
    merchant_id: String,
    tenant_id: String,
}

impl AuthorizedotnetExecutor {
    pub async fn new() -> Self {
        let server = spawn().await.expect("UCS server should start");
        let auth = load_body_key_auth("authorizedotnet").expect("Authorize.Net creds should load");

        Self {
            server,
            auth,
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
        add_authorizedotnet_metadata(
            &mut request,
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
        case: &crate::harness::generators::GeneratedCase,
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
