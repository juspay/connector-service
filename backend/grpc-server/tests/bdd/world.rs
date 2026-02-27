use std::{
    future::Future,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use grpc_api_types::payments::{
    payment_service_client::PaymentServiceClient, refund_service_client::RefundServiceClient,
    CaptureMethod, PaymentStatus, RefundStatus,
};
use hyperswitch_masking::ExposeInterface;
use tonic::transport::Channel;
use tonic::Request;

/// World state for Stripe BDD tests
///
/// This struct holds all the state needed to execute Stripe payment flow tests
/// using Cucumber BDD framework. It maintains the gRPC clients, test data,
/// and tracks the state across test steps.
#[derive(Debug, cucumber::World)]
#[world(init = Self::init)]
pub struct StripeWorld {
    /// gRPC client for payment operations
    pub payment_client: PaymentServiceClient<Channel>,
    /// gRPC client for refund operations
    pub refund_client: RefundServiceClient<Channel>,
    /// Server future for cleanup
    server_future: Option<tokio::task::JoinHandle<()>>,

    // Connector configuration
    pub connector_name: String,
    pub auth_type: String,
    pub merchant_id: String,

    // Test data
    pub test_card_number: String,
    pub payment_amount: i64,
    pub currency: String,
    pub capture_method: CaptureMethod,

    // Test results
    pub last_payment_status: Option<PaymentStatus>,
    pub last_transaction_id: Option<String>,
    pub last_refund_status: Option<RefundStatus>,
    pub last_refund_id: Option<String>,
    pub error: Option<String>,
}

impl StripeWorld {
    /// Initialize the world with gRPC clients connected to the test server
    pub async fn init() -> Result<Self> {
        let config = ucs_env::configs::Config::new()?;
        let base_config = Arc::new(config);
        let server = grpc_server::app::Service::new(base_config.clone()).await;

        // Create server and channel using Unix socket
        let (server_fut, channel) = Self::create_test_server(server, base_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create test server: {}", e))?;

        // Spawn server in background
        let handle = tokio::spawn(async move {
            server_fut.await;
        });

        let payment_client = PaymentServiceClient::new(channel.clone());
        let refund_client = RefundServiceClient::new(channel);

        Ok(Self {
            payment_client,
            refund_client,
            server_future: Some(handle),
            connector_name: String::new(),
            auth_type: String::new(),
            merchant_id: String::new(),
            test_card_number: String::new(),
            payment_amount: 1000,
            currency: "USD".to_string(),
            capture_method: CaptureMethod::Automatic,
            last_payment_status: None,
            last_transaction_id: None,
            last_refund_status: None,
            last_refund_id: None,
            error: None,
        })
    }

    /// Create test server with Unix socket
    async fn create_test_server(
        service: grpc_server::app::Service,
        base_config: Arc<ucs_env::configs::Config>,
    ) -> Result<
        (impl Future<Output = ()> + Send + 'static, Channel),
        Box<dyn std::error::Error>,
    > {
        use std::path::PathBuf;
        use tempfile::NamedTempFile;
        use tokio::net::UnixListener;
        use tokio_stream::wrappers::UnixListenerStream;
        use tonic::transport::Endpoint;
        use tower::service_fn;

        let socket = NamedTempFile::new()?;
        let socket_path: PathBuf = socket.path().into();
        std::fs::remove_file(&socket_path)?;

        let uds = UnixListener::bind(&socket_path)?;
        let stream = UnixListenerStream::new(uds);

        // Build server
        let router = Self::build_server(service, base_config);

        let serve_future = async move {
            let result = router.serve_with_incoming(stream).await;
            assert!(result.is_ok());
        };

        // Create channel
        let channel = Endpoint::try_from("http://any.url")?
            .connect_with_connector(service_fn(move |_: http::Uri| {
                let path = socket_path.clone();
                async move {
                    let unix_stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(unix_stream))
                }
            }))
            .await?;

        Ok((serve_future, channel))
    }

    /// Build gRPC server with all services
    fn build_server(
        service: grpc_server::app::Service,
        config: Arc<ucs_env::configs::Config>,
    ) -> tonic::transport::server::Router {
        use tonic::transport::Server;

        // Interceptor that adds config to request extensions
        #[derive(Clone)]
        struct ConfigInterceptor {
            config: Arc<ucs_env::configs::Config>,
        }

        impl tonic::service::Interceptor for ConfigInterceptor {
            fn call(
                &mut self,
                mut req: Request<()>,
            ) -> Result<Request<()>, tonic::Status> {
                req.extensions_mut().insert(self.config.clone());
                Ok(req)
            }
        }

        let interceptor = ConfigInterceptor { config };

        Server::builder()
            .add_service(grpc_api_types::health_check::health_server::HealthServer::new(
                service.health_check_service,
            ))
            .add_service(
                grpc_api_types::payments::payment_service_server::PaymentServiceServer::with_interceptor(
                    service.payments_service,
                    interceptor.clone(),
                ),
            )
            .add_service(
                grpc_api_types::payments::refund_service_server::RefundServiceServer::with_interceptor(
                    service.refunds_service,
                    interceptor.clone(),
                ),
            )
            .add_service(
                grpc_api_types::payments::recurring_payment_service_server::RecurringPaymentServiceServer::with_interceptor(
                    service.recurring_payment_service,
                    interceptor.clone(),
                ),
            )
            .add_service(
                grpc_api_types::payments::dispute_service_server::DisputeServiceServer::with_interceptor(
                    service.disputes_service,
                    interceptor.clone(),
                ),
            )
            .add_service(
                grpc_api_types::payments::payment_method_service_server::PaymentMethodServiceServer::with_interceptor(
                    service.payment_method_service,
                    interceptor.clone(),
                ),
            )
            .add_service(
                grpc_api_types::payments::customer_service_server::CustomerServiceServer::with_interceptor(
                    service.customer_service,
                    interceptor.clone(),
                ),
            )
            .add_service(
                grpc_api_types::payments::merchant_authentication_service_server::MerchantAuthenticationServiceServer::with_interceptor(
                    service.merchant_authentication_service,
                    interceptor.clone(),
                ),
            )
            .add_service(
                grpc_api_types::payments::payment_method_authentication_service_server::PaymentMethodAuthenticationServiceServer::with_interceptor(
                    service.payment_method_authentication_service,
                    interceptor,
                ),
            )
    }

    /// Add required metadata headers to gRPC requests
    pub fn add_metadata<T>(&self, request: &mut Request<T>) {
        let auth = crate::utils::credential_utils::load_connector_auth(&self.connector_name)
            .expect("Failed to load Stripe credentials");

        let api_key = match auth {
            domain_types::router_data::ConnectorAuthType::HeaderKey { api_key } => api_key.expose(),
            _ => panic!("Expected HeaderKey auth type for Stripe"),
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        request
            .metadata_mut()
            .append("x-connector", self.connector_name.parse().unwrap());
        request
            .metadata_mut()
            .append("x-auth", self.auth_type.parse().unwrap());
        request
            .metadata_mut()
            .append("x-api-key", api_key.parse().unwrap());
        request
            .metadata_mut()
            .append("x-merchant-id", self.merchant_id.parse().unwrap());
        request.metadata_mut().append(
            "x-request-id",
            format!("bdd_test_{}", timestamp).parse().unwrap(),
        );
        request
            .metadata_mut()
            .append("x-tenant-id", "default".parse().unwrap());
        request.metadata_mut().append(
            "x-connector-request-reference-id",
            format!("bdd_ref_{}", timestamp).parse().unwrap(),
        );
    }
}

impl Drop for StripeWorld {
    fn drop(&mut self) {
        // Clean up server task if still running
        if let Some(handle) = self.server_future.take() {
            handle.abort();
        }
    }
}
