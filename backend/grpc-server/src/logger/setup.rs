//! Setup logging subsystem.
use std::collections::{HashMap, HashSet};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

use super::config;

/// Contains guards necessary for logging
#[derive(Debug)]
pub struct TelemetryGuard {
    _log_guards: Vec<WorkerGuard>,
}

/// Setup logging sub-system specifying the logging configuration, service (binary) name, and a
/// list of external crates for which a more verbose logging must be enabled. All crates within the
/// current cargo workspace are automatically considered for verbose logging.
pub fn setup(
    config: &config::Log,
    service_name: &str,
    crates_to_filter: impl AsRef<[&'static str]>,
) -> Result<TelemetryGuard, log_utils::LoggerError> {
    let static_top_level_fields = HashMap::from_iter([
        ("service".to_string(), serde_json::json!(service_name)),
        (
            "build_version".to_string(),
            serde_json::json!(crate::version!()),
        ),
    ]);

    let console_config = if config.console.enabled {
        let console_filter_directive =
            config
                .console
                .filtering_directive
                .clone()
                .unwrap_or_else(|| {
                    get_envfilter_directive(
                        tracing::Level::WARN,
                        config.console.level.into_level(),
                        crates_to_filter.as_ref(),
                    )
                });
        let log_format = match config.console.log_format {
            config::LogFormat::Default => log_utils::ConsoleLogFormat::HumanReadable,
            config::LogFormat::Json => {
                // Disable color or emphasis related ANSI escape codes for JSON formats
                error_stack::Report::set_color_mode(error_stack::fmt::ColorMode::None);

                log_utils::ConsoleLogFormat::CompactJson
            }
        };

        Some(log_utils::ConsoleLoggingConfig {
            level: config.console.level.into_level(),
            log_format,
            filtering_directive: Some(console_filter_directive),
            print_filtering_directive: log_utils::DirectivePrintTarget::Stderr,
        })
    } else {
        None
    };

    let logger_config = log_utils::LoggerConfig {
        static_top_level_fields,
        top_level_keys: HashSet::new(),
        persistent_keys: HashSet::new(),
        log_span_lifecycles: true,
        additional_fields_placement: log_utils::AdditionalFieldsPlacement::TopLevel,
        file_config: None,
        console_config,
        global_filtering_directive: None,
    };

    let logging_components = log_utils::build_logging_components(logger_config)?;

    let mut subscriber_layers = Vec::new();

    subscriber_layers.push(logging_components.storage_layer.boxed());
    if let Some(console_layer) = logging_components.console_log_layer {
        subscriber_layers.push(console_layer);
    }

    tracing_subscriber::registry()
        .with(subscriber_layers)
        .init();

    // Returning the TelemetryGuard for logs to be printed and metrics to be collected until it is
    // dropped
    Ok(TelemetryGuard {
        _log_guards: logging_components.guards,
    })
}

fn get_envfilter_directive(
    default_log_level: tracing::Level,
    filter_log_level: tracing::Level,
    crates_to_filter: impl AsRef<[&'static str]>,
) -> String {
    let mut explicitly_handled_targets = build_info::cargo_workspace_members!();
    explicitly_handled_targets.extend(build_info::framework_libs_workspace_members());
    explicitly_handled_targets.extend(crates_to_filter.as_ref());

    // +1 for the default log level added as a directive
    let num_directives = explicitly_handled_targets.len() + 1;

    explicitly_handled_targets
        .into_iter()
        .map(|crate_name| crate_name.replace('-', "_"))
        .zip(std::iter::repeat(filter_log_level))
        .fold(
            {
                let mut directives = Vec::with_capacity(num_directives);
                directives.push(default_log_level.to_string());
                directives
            },
            |mut directives, (target, level)| {
                directives.push(format!("{target}={level}"));
                directives
            },
        )
        .join(",")
}
