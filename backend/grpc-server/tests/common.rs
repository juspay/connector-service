use std::{future::Future, sync::Arc};

use grpc_api_types::{
    health_check::health_client::HealthClient,
    payments::{
        payment_service_client::PaymentServiceClient, refund_service_client::RefundServiceClient,
    },
};
use http::Uri;
use hyper_util::rt::TokioIo; // Add this import
use tempfile::NamedTempFile;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Endpoint, Server};
use tower::service_fn;
use ucs_env::configs::Config;

/// Interceptor that adds config to request extensions.
///
/// Note: Tests use interceptors instead of layers because:
/// - Interceptors work seamlessly with `serve_with_incoming()` in tests
/// - Layers have type constraints (Error = Status vs Infallible) incompatible with test setup
/// - Production uses RequestExtensionsLayer with `serve_with_shutdown()`
/// - This achieves the same goal (config in extensions) for testing
#[derive(Clone)]
struct ConfigInterceptor {
    config: Arc<Config>,
}

impl tonic::service::Interceptor for ConfigInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.extensions_mut().insert(self.config.clone());
        Ok(req)
    }
}

pub trait AutoClient {
    fn new(channel: Channel) -> Self;
}
impl AutoClient for PaymentServiceClient<Channel> {
    fn new(channel: Channel) -> Self {
        Self::new(channel)
    }
}
impl AutoClient for HealthClient<Channel> {
    fn new(channel: Channel) -> Self {
        Self::new(channel)
    }
}

impl AutoClient for RefundServiceClient<Channel> {
    fn new(channel: Channel) -> Self {
        Self::new(channel)
    }
}

/// # Panics
///
/// Will panic if the socket file cannot be created or removed
pub async fn server_and_client_stub<T>(
    service: grpc_server::app::Service,
    base_config: Arc<Config>,
) -> Result<(impl Future<Output = ()>, T), Box<dyn std::error::Error>>
where
    T: AutoClient,
{
    let socket = NamedTempFile::new()?;
    let socket = Arc::new(socket.into_temp_path());
    std::fs::remove_file(&*socket)?;

    let uds = UnixListener::bind(&*socket)?;
    let stream = UnixListenerStream::new(uds);

    // Create interceptor that adds config to request extensions
    let interceptor = ConfigInterceptor {
        config: base_config,
    };

    let serve_future = async move {
        let result = Server::builder()
            .add_service(
                grpc_api_types::health_check::health_server::HealthServer::new(
                    service.health_check_service,
                ),
            )
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
            .serve_with_incoming(stream)
            .await;
        // Server must be running fine...
        assert!(result.is_ok());
    };

    let socket = Arc::clone(&socket);
    // Connect to the server over a Unix socket
    // The URL will be ignored.
    let channel = Endpoint::try_from("http://any.url")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = Arc::clone(&socket);
            async move {
                // Wrap the UnixStream with TokioIo to make it compatible with hyper
                let unix_stream = tokio::net::UnixStream::connect(&*socket).await?;
                Ok::<_, std::io::Error>(TokioIo::new(unix_stream))
            }
        }))
        .await?;

    let client = T::new(channel);

    Ok((serve_future, client))
}

#[macro_export]
macro_rules! grpc_test {
    ($client:ident, $c_type:ty, $body:block) => {
        let config = configs::Config::new().expect("Failed while parsing config");
        let base_config = std::sync::Arc::new(config);
        let server = app::Service::new(base_config.clone()).await;
        let (server_fut, mut $client) =
            common::server_and_client_stub::<$c_type>(server, base_config)
                .await
                .expect("Failed to create the server client pair");
        let response = async { $body };

        tokio::select! {
            _ = server_fut => panic!("Server failed"),
            _ = response => {}
        }
    };
}
