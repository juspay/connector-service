use grpc_server::{self, app, configs, logger};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[allow(clippy::expect_used)]
    let config = configs::Config::new().expect("Failed while parsing config");

    let _guard = logger::setup(
        &config.log,
        grpc_server::service_name!(),
        [grpc_server::service_name!(), "grpc_server", "tower_http"],
    );

    // TEMP: Initialize router_env logger to see injector logs
    std::env::set_var("ROUTER_ENV_LOG_LEVEL", "debug");
    // Try to initialize router_env logger if available

    let metrics_server = app::metrics_server_builder(config.clone());
    let server = app::server_builder(config);

    #[allow(clippy::expect_used)]
    tokio::try_join!(metrics_server, server)?;

    Ok(())
}
