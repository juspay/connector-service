use grpc_server::{self, app, configs, logger};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    use crate::configs;
    use std::path::PathBuf;
    let config_file_names = vec!["production.toml", "sandbox.toml"];
    let mut config_path = PathBuf::new();
    config_path.push(configs::workspace_path());
    let config_directory: String = "config".into();
    config_path.push(config_directory);
    for config_file_name in config_file_names {
        config_path.push(config_file_name);
        #[allow(clippy::expect_used)]
        let _ = configs::Config::new_with_config_path(Some(config_path.clone()))
            .expect(format!("Update {} with the default config values", config_file_name).as_str());
        config_path.pop();
    }
}
