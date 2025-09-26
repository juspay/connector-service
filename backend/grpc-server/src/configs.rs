use std::path::PathBuf;

use common_utils::{consts, events::EventConfig};
use domain_types::types::{Connectors, Proxy};

use crate::{error::ConfigurationError, logger::config::Log};

#[derive(Clone, serde::Deserialize, Debug)]
pub struct Config {
    pub common: Common,
    pub server: Server,
    pub metrics: MetricsServer,
    pub log: Log,
    pub proxy: Proxy,
    pub connectors: Connectors,
    #[serde(default)]
    pub events: EventConfig,
    #[serde(default)]
    pub lineage: LineageConfig,
}

#[derive(Clone, serde::Deserialize, Debug, Default)]
pub struct LineageConfig {
    /// Enable processing of x-lineage-ids header
    pub enabled: bool,
    /// Custom header name (default: x-lineage-ids)
    #[serde(default = "default_lineage_header")]
    pub header_name: String,
    /// Prefix for lineage fields in events
    #[serde(default = "default_lineage_prefix")]
    pub field_prefix: String,
}

fn default_lineage_header() -> String {
    consts::X_LINEAGE_IDS.to_string()
}

fn default_lineage_prefix() -> String {
    consts::LINEAGE_FIELD_PREFIX.to_string()
}

#[derive(Clone, serde::Deserialize, Debug)]
pub struct Common {
    pub environment: consts::Env,
}

impl Common {
    pub fn validate(&self) -> Result<(), config::ConfigError> {
        let Self { environment } = self;
        match environment {
            consts::Env::Development | consts::Env::Production | consts::Env::Sandbox => Ok(()),
        }
    }
}

#[derive(Clone, serde::Deserialize, Debug)]
pub struct Server {
    pub host: String,
    pub port: u16,
    #[serde(rename = "type", default)]
    pub type_: ServiceType,
}

#[derive(Clone, serde::Deserialize, Debug)]
pub struct MetricsServer {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    #[default]
    Grpc,
    Http,
}

impl Config {
    /// Function to build the configuration by picking it from default locations
    pub fn new() -> Result<Self, config::ConfigError> {
        Self::new_with_config_path(None)
    }

    /// Function to build the configuration by picking it from default locations
    pub fn new_with_config_path(
        explicit_config_path: Option<PathBuf>,
    ) -> Result<Self, config::ConfigError> {
        let env = consts::Env::current_env();
        let config_path = Self::config_path(&env, explicit_config_path);

        let config = Self::builder(&env)?
            .add_source(config::File::from(config_path).required(false))
            .add_source(
                config::Environment::with_prefix(consts::ENV_PREFIX)
                    .try_parsing(true)
                    .separator("__")
                    .list_separator(",")
                    .with_list_parse_key("proxy.bypass_proxy_urls")
                    .with_list_parse_key("redis.cluster_urls")
                    .with_list_parse_key("database.tenants")
                    .with_list_parse_key("log.kafka.brokers")
                    .with_list_parse_key("events.brokers"),
            )
            .build()?;

        #[allow(clippy::print_stderr)]
        let config: Self = serde_path_to_error::deserialize(config).map_err(|error| {
            eprintln!("Unable to deserialize application configuration: {error}");
            error.into_inner()
        })?;

        // Validate the environment field
        config.common.validate()?;

        Ok(config)
    }

    pub fn builder(
        environment: &consts::Env,
    ) -> Result<config::ConfigBuilder<config::builder::DefaultState>, config::ConfigError> {
        config::Config::builder()
            // Here, it should be `set_override()` not `set_default()`.
            // "env" can't be altered by config field.
            // Should be single source of truth.
            .set_override("env", environment.to_string())
    }

    /// Config path.
    pub fn config_path(
        environment: &consts::Env,
        explicit_config_path: Option<PathBuf>,
    ) -> PathBuf {
        let mut config_path = PathBuf::new();
        if let Some(explicit_config_path_val) = explicit_config_path {
            config_path.push(explicit_config_path_val);
        } else {
            let config_directory: String = "config".into();
            let config_file_name = environment.config_path();

            config_path.push(workspace_path());
            config_path.push(config_directory);
            config_path.push(config_file_name);
        }
        config_path
    }
}

impl Server {
    pub async fn tcp_listener(&self) -> Result<tokio::net::TcpListener, ConfigurationError> {
        let loc = format!("{}:{}", self.host, self.port);

        tracing::info!(loc = %loc, "binding the server");

        Ok(tokio::net::TcpListener::bind(loc).await?)
    }
}

impl MetricsServer {
    pub async fn tcp_listener(&self) -> Result<tokio::net::TcpListener, ConfigurationError> {
        let loc = format!("{}:{}", self.host, self.port);

        tracing::info!(loc = %loc, "binding the server");

        Ok(tokio::net::TcpListener::bind(loc).await?)
    }
}

pub fn workspace_path() -> PathBuf {
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let mut path = PathBuf::from(manifest_dir);
        path.pop();
        path.pop();
        path
    } else {
        PathBuf::from(".")
    }
}
