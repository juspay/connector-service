use grpc_server::{self, app, configs, logger};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build tokio runtime with increased thread stack size
    // Default tokio stack is ~8MB; we increase to 32MB for safety
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)  // Match default worker count
        .thread_stack_size(32 * 1024 * 1024)  // 32MB stack per thread
        .thread_name("grpc-worker")
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    // Block the async main on this runtime
    rt.block_on(async_main())
}

#[allow(clippy::unwrap_in_result)]
async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(debug_assertions)]
    verify_other_config_files();
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

#[cfg(debug_assertions)]
fn verify_other_config_files() {
    use std::path::PathBuf;

    use crate::configs;
    let config_file_names = vec!["production.toml", "sandbox.toml"];
    let mut config_path = PathBuf::new();
    config_path.push(configs::workspace_path());
    let config_directory: String = "config".into();
    config_path.push(config_directory);
    for config_file_name in config_file_names {
        config_path.push(config_file_name);
        #[allow(clippy::panic)]
        let _ = configs::Config::new_with_config_path(Some(config_path.clone()))
            .unwrap_or_else(|_| panic!("Update {config_file_name} with the default config values"));
        config_path.pop();
    }
}
