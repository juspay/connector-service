use std::{error::Error, sync::Arc};

use grpc_api_types::payments::{
    customer_service_client::CustomerServiceClient, payment_service_client::PaymentServiceClient,
};
use http::Uri;
use hyper_util::rt::TokioIo;
use tempfile::{NamedTempFile, TempPath};
use tokio::{net::UnixListener, task::JoinHandle};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Endpoint, Server};
use tower::service_fn;
use ucs_env::configs::Config;

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

pub struct UcsServer {
    channel: Channel,
    task: JoinHandle<()>,
    _socket: Arc<TempPath>,
}

impl UcsServer {
    pub fn payment_client(&self) -> PaymentServiceClient<Channel> {
        PaymentServiceClient::new(self.channel.clone())
    }

    pub fn customer_client(&self) -> CustomerServiceClient<Channel> {
        CustomerServiceClient::new(self.channel.clone())
    }
}

impl Drop for UcsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn() -> Result<UcsServer, Box<dyn Error>> {
    let config = Arc::new(Config::new()?);
    let service = grpc_server::app::Service::new(config.clone()).await;

    let socket = NamedTempFile::new()?;
    let socket = Arc::new(socket.into_temp_path());
    std::fs::remove_file(&*socket)?;

    let uds = UnixListener::bind(&*socket)?;
    let stream = UnixListenerStream::new(uds);

    let interceptor = ConfigInterceptor { config };
    let router = Server::builder()
        .add_service(
            grpc_api_types::payments::payment_service_server::PaymentServiceServer::with_interceptor(
                service.payments_service,
                interceptor.clone(),
            ),
        )
        .add_service(
            grpc_api_types::payments::customer_service_server::CustomerServiceServer::with_interceptor(
                service.customer_service,
                interceptor,
            ),
        );

    let task = tokio::spawn(async move {
        let _ = router.serve_with_incoming(stream).await;
    });

    let socket_clone = Arc::clone(&socket);
    let channel = Endpoint::try_from("http://any.url")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = Arc::clone(&socket_clone);
            async move {
                let unix_stream = tokio::net::UnixStream::connect(&*socket).await?;
                Ok::<_, std::io::Error>(TokioIo::new(unix_stream))
            }
        }))
        .await?;

    Ok(UcsServer {
        channel,
        task,
        _socket: socket,
    })
}
