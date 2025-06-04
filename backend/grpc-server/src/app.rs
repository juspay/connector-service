use crate::consts;
use crate::{configs, error::ConfigurationError, interceptor, logger, metrics, utils};
use axum::http;
use grpc_api_types::{
    health_check::health_server,
    payments::{payment_service_handler, payment_service_server},
};
use std::{future::Future, net};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::oneshot,
};
use tonic::transport::Server;
use tower_http::{request_id::MakeRequestUuid, trace as tower_trace};

use grpc_api_types::health_check::health_handler;

/// # Panics
///
/// Will panic if redis connection establishment fails or signal handling fails
pub async fn server_builder(config: configs::Config) -> Result<(), ConfigurationError> {
    let server_config = config.server.clone();
    let socket_addr = net::SocketAddr::new(server_config.host.parse()?, server_config.port);

    // Signal handler
    let (tx, rx) = oneshot::channel();

    #[allow(clippy::expect_used)]
    tokio::spawn(async move {
        let mut sig_int =
            signal(SignalKind::interrupt()).expect("Failed to initialize SIGINT signal handler");
        let mut sig_term =
            signal(SignalKind::terminate()).expect("Failed to initialize SIGTERM signal handler");
        let mut sig_quit =
            signal(SignalKind::quit()).expect("Failed to initialize QUIT signal handler");
        let mut sig_hup =
            signal(SignalKind::hangup()).expect("Failed to initialize SIGHUP signal handler");

        tokio::select! {
            _ = sig_int.recv() => {
                logger::info!("Received SIGINT");
                tx.send(()).expect("Failed to send SIGINT signal");
            }
            _ = sig_term.recv() => {
                logger::info!("Received SIGTERM");
                tx.send(()).expect("Failed to send SIGTERM signal");
            }
            _ = sig_quit.recv() => {
                logger::info!("Received QUIT");
                tx.send(()).expect("Failed to send QUIT signal");
            }
            _ = sig_hup.recv() => {
                logger::info!("Received SIGHUP");
                tx.send(()).expect("Failed to send SIGHUP signal");
            }
        }
    });

    #[allow(clippy::expect_used)]
    let shutdown_signal = async {
        rx.await.expect("Failed to receive shutdown signal");
        logger::info!("Shutdown signal received");
    };

    let service = Service::new(config.clone());

    logger::info!(host = %server_config.host, port = %server_config.port, r#type = ?server_config.type_, "starting connector service");

    match server_config.type_ {
        configs::ServiceType::Grpc => {
            service
                .await
                .grpc_server(socket_addr, shutdown_signal)
                .await?
        }
        configs::ServiceType::Http => {
            service
                .await
                .http_server(socket_addr, shutdown_signal)
                .await?
        }
    }

    Ok(())
}

pub struct Service {
    pub health_check_service: crate::server::health_check::HealthCheck,
    pub payments_service: crate::server::payments::Payments,
}

impl Service {
    /// # Panics
    ///
    /// Will panic either if database password, hash key isn't present in configs or unable to
    /// deserialize any of the above keys
    #[allow(clippy::expect_used)]
    pub async fn new(config: configs::Config) -> Self {
        Self {
            health_check_service: crate::server::health_check::HealthCheck,
            payments_service: crate::server::payments::Payments { config },
        }
    }

    pub async fn http_server(
        self,
        socket: net::SocketAddr,
        shutdown_signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ConfigurationError> {
        let logging_layer = tower_trace::TraceLayer::new_for_http()
            .make_span_with(|request: &axum::extract::Request<_>| {
                utils::record_fields_from_header(request)
            })
            .on_request(tower_trace::DefaultOnRequest::new().level(tracing::Level::INFO))
            .on_response(
                tower_trace::DefaultOnResponse::new()
                    .level(tracing::Level::INFO)
                    .latency_unit(tower_http::LatencyUnit::Micros),
            )
            .on_failure(
                tower_trace::DefaultOnFailure::new()
                    .latency_unit(tower_http::LatencyUnit::Micros)
                    .level(tracing::Level::ERROR),
            );

        let request_id_layer = tower_http::request_id::SetRequestIdLayer::new(
            http::HeaderName::from_static(consts::X_REQUEST_ID),
            MakeRequestUuid,
        );

        let propagate_request_id_layer = tower_http::request_id::PropagateRequestIdLayer::new(
            http::HeaderName::from_static(consts::X_REQUEST_ID),
        );

        let router = axum::Router::new()
            .layer(logging_layer)
            .layer(request_id_layer)
            .layer(propagate_request_id_layer)
            .merge(health_handler(self.health_check_service))
            .merge(payment_service_handler(self.payments_service));

        let listener = tokio::net::TcpListener::bind(socket).await?;

        axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(shutdown_signal)
            .await?;

        Ok(())
    }

    pub async fn grpc_server(
        self,
        socket: net::SocketAddr,
        shutdown_signal: impl Future<Output = ()>,
    ) -> Result<(), ConfigurationError> {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(grpc_api_types::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        let logging_layer = tower_trace::TraceLayer::new_for_http()
            .make_span_with(|request: &http::request::Request<_>| {
                utils::record_fields_from_header(request)
            })
            .on_request(tower_trace::DefaultOnRequest::new().level(tracing::Level::INFO))
            .on_response(
                tower_trace::DefaultOnResponse::new()
                    .level(tracing::Level::INFO)
                    .latency_unit(tower_http::LatencyUnit::Micros),
            )
            .on_failure(
                tower_trace::DefaultOnFailure::new()
                    .latency_unit(tower_http::LatencyUnit::Micros)
                    .level(tracing::Level::ERROR),
            );

        let request_id_layer = tower_http::request_id::SetRequestIdLayer::new(
            http::HeaderName::from_static(consts::X_REQUEST_ID),
            MakeRequestUuid,
        );
        let propagate_request_id_layer = tower_http::request_id::PropagateRequestIdLayer::new(
            http::HeaderName::from_static(consts::X_REQUEST_ID),
        );

        Server::builder()
            .layer(interceptor::GrpcLoggingLayer)
            .layer(logging_layer)
            .layer(request_id_layer)
            .layer(propagate_request_id_layer)
            .add_service(reflection_service)
            .add_service(health_server::HealthServer::new(self.health_check_service))
            .add_service(payment_service_server::PaymentServiceServer::new(
                self.payments_service,
            ))
            .serve_with_shutdown(socket, shutdown_signal)
            .await?;

        Ok(())
    }
}

pub async fn metrics_server_builder(config: configs::Config) -> Result<(), ConfigurationError> {
    let listener = config.metrics.tcp_listener().await?;

    let router = axum::Router::new().route(
        "/metrics",
        axum::routing::get(|| async {
            let output = metrics::metrics_handler().await;
            match output {
                Ok(metrics) => Ok(metrics),
                Err(error) => {
                    tracing::error!(?error, "Error fetching metrics");

                    Err((
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Error fetching metrics".to_string(),
                    ))
                }
            }
        }),
    );

    axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(async {
            let output = tokio::signal::ctrl_c().await;
            tracing::error!(?output, "shutting down");
        })
        .await?;

    Ok(())
}
