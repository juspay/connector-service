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

    let metrics_server = app::metrics_server_builder(config.clone());
    let server = app::server_builder(config);

    #[allow(clippy::expect_used)]
    tokio::try_join!(metrics_server, server)?;

    Ok(())
}
