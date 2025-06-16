use crate::consts;
use crate::{configs, error::ConfigurationError, logger, metrics, utils};
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
            .merge(payment_service_handler(self.payments_service.clone()))
            .merge(simple_payment_handler(self.payments_service));

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

fn simple_payment_handler(payments_service: crate::server::payments::Payments) -> axum::Router {
    use axum::extract::State;
    use axum::response::IntoResponse;
    use axum::Json;
    use grpc_api_types::payments::*;
    use std::sync::Arc;

    #[derive(serde::Deserialize)]
    struct SimplePaymentAuthorizeRequest {
        amount: i64,
        currency: String,                    // Will be converted from string to enum
        payment_method: String,              // Will be converted from string to enum
        payment_method_type: Option<String>, // Will be converted from string to enum
        auth_type: String,                   // Will be converted from string to enum
        payment_method_data: Option<PaymentMethodData>,
        connector_customer: Option<String>,
        address: Option<PaymentAddress>,
        connector_meta_data: Option<Vec<u8>>,
        access_token: Option<AccessToken>,
        session_token: Option<String>,
        payment_method_token: Option<PaymentMethodToken>,
        connector_request_reference_id: String,
        order_tax_amount: Option<i64>,
        email: Option<String>,
        customer_name: Option<String>,
        capture_method: Option<String>, // Will be converted from string to enum
        return_url: Option<String>,
        webhook_url: Option<String>,
        complete_authorize_url: Option<String>,
        setup_future_usage: Option<String>, // Will be converted from string to enum
        off_session: Option<bool>,
        customer_acceptance: Option<CustomerAcceptance>,
        browser_info: Option<BrowserInformation>,
        order_category: Option<String>,
        enrolled_for_3ds: bool,
        payment_experience: Option<String>, // Will be converted from string to enum
        request_incremental_authorization: bool,
        authentication_data: Option<AuthenticationData>,
        request_extended_authorization: Option<bool>,
        minor_amount: i64,
        merchant_order_reference_id: Option<String>,
        shipping_cost: Option<i64>,
        all_keys_required: Option<bool>,
    }

    async fn simple_payment_authorize(
        State(payments_service): State<Arc<crate::server::payments::Payments>>,
        headers: axum::http::HeaderMap,
        Json(simple_req): Json<SimplePaymentAuthorizeRequest>,
    ) -> impl IntoResponse {
        // Convert string enums to protobuf enum values
        let currency = match Currency::from_str_name(&simple_req.currency) {
            Some(c) => c as i32,
            None => {
                return axum::response::Response::builder()
                    .status(400)
                    .body(axum::body::Body::from(format!(
                        "Invalid currency: {}",
                        simple_req.currency
                    )))
                    .unwrap()
            }
        };

        let payment_method = match PaymentMethod::from_str_name(&simple_req.payment_method) {
            Some(pm) => pm as i32,
            None => {
                return axum::response::Response::builder()
                    .status(400)
                    .body(axum::body::Body::from(format!(
                        "Invalid payment_method: {}",
                        simple_req.payment_method
                    )))
                    .unwrap()
            }
        };

        let auth_type = match AuthenticationType::from_str_name(&simple_req.auth_type) {
            Some(at) => at as i32,
            None => {
                return axum::response::Response::builder()
                    .status(400)
                    .body(axum::body::Body::from(format!(
                        "Invalid auth_type: {}",
                        simple_req.auth_type
                    )))
                    .unwrap()
            }
        };

        let payment_method_type = if let Some(pmt_str) = &simple_req.payment_method_type {
            match PaymentMethodType::from_str_name(pmt_str) {
                Some(pmt) => Some(pmt as i32),
                None => {
                    return axum::response::Response::builder()
                        .status(400)
                        .body(axum::body::Body::from(format!(
                            "Invalid payment_method_type: {}",
                            pmt_str
                        )))
                        .unwrap()
                }
            }
        } else {
            None
        };

        let capture_method = if let Some(cm_str) = &simple_req.capture_method {
            match CaptureMethod::from_str_name(cm_str) {
                Some(cm) => Some(cm as i32),
                None => {
                    return axum::response::Response::builder()
                        .status(400)
                        .body(axum::body::Body::from(format!(
                            "Invalid capture_method: {}",
                            cm_str
                        )))
                        .unwrap()
                }
            }
        } else {
            None
        };

        let setup_future_usage = if let Some(sfu_str) = &simple_req.setup_future_usage {
            match FutureUsage::from_str_name(sfu_str) {
                Some(sfu) => Some(sfu as i32),
                None => {
                    return axum::response::Response::builder()
                        .status(400)
                        .body(axum::body::Body::from(format!(
                            "Invalid setup_future_usage: {}",
                            sfu_str
                        )))
                        .unwrap()
                }
            }
        } else {
            None
        };

        let payment_experience = if let Some(pe_str) = &simple_req.payment_experience {
            match PaymentExperience::from_str_name(pe_str) {
                Some(pe) => Some(pe as i32),
                None => {
                    return axum::response::Response::builder()
                        .status(400)
                        .body(axum::body::Body::from(format!(
                            "Invalid payment_experience: {}",
                            pe_str
                        )))
                        .unwrap()
                }
            }
        } else {
            None
        };

        // Create the protobuf request with all fields
        let grpc_request = PaymentsAuthorizeRequest {
            amount: simple_req.amount,
            currency,
            payment_method,
            payment_method_data: simple_req.payment_method_data,
            connector_customer: simple_req.connector_customer,
            address: simple_req.address,
            auth_type,
            connector_meta_data: simple_req.connector_meta_data,
            access_token: simple_req.access_token,
            session_token: simple_req.session_token,
            payment_method_token: simple_req.payment_method_token,
            connector_request_reference_id: simple_req.connector_request_reference_id,
            order_tax_amount: simple_req.order_tax_amount,
            email: simple_req.email,
            customer_name: simple_req.customer_name,
            capture_method,
            return_url: simple_req.return_url,
            webhook_url: simple_req.webhook_url,
            complete_authorize_url: simple_req.complete_authorize_url,
            setup_future_usage,
            off_session: simple_req.off_session,
            customer_acceptance: simple_req.customer_acceptance,
            browser_info: simple_req.browser_info,
            order_category: simple_req.order_category,
            enrolled_for_3ds: simple_req.enrolled_for_3ds,
            payment_experience,
            payment_method_type,
            request_incremental_authorization: simple_req.request_incremental_authorization,
            authentication_data: simple_req.authentication_data,
            request_extended_authorization: simple_req.request_extended_authorization,
            minor_amount: simple_req.minor_amount,
            merchant_order_reference_id: simple_req.merchant_order_reference_id,
            shipping_cost: simple_req.shipping_cost,
            all_keys_required: simple_req.all_keys_required,
        };

        // Convert headers to metadata
        let metadata_map = tonic::metadata::MetadataMap::from_headers(headers);
        let request =
            tonic::Request::from_parts(metadata_map, axum::http::Extensions::new(), grpc_request);

        // Call the existing gRPC service
        use grpc_api_types::payments::payment_service_server::PaymentService;
        match payments_service.payment_authorize(request).await {
            Ok(response) => {
                let response_body = response.into_inner();
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_string(&response_body).unwrap(),
                    ))
                    .unwrap()
            }
            Err(status) => axum::response::Response::builder()
                .status(500)
                .body(axum::body::Body::from(format!(
                    "gRPC error: {}",
                    status.message()
                )))
                .unwrap(),
        }
    }

    axum::Router::new()
        .route(
            "/payments/authorize",
            axum::routing::post(simple_payment_authorize),
        )
        .with_state(Arc::new(payments_service))
}
