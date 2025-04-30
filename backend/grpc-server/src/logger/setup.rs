//! Setup logging subsystem.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, util::SubscriberInitExt, EnvFilter, Layer};

use super::{config, formatter::FormattingLayer, storage::StorageSubscription};

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
) -> TelemetryGuard {
    let mut guards = Vec::new();

    let subscriber = tracing_subscriber::registry().with(StorageSubscription);

    // Setup console logging
    if config.console.enabled {
        let (console_writer, guard) = tracing_appender::non_blocking(std::io::stdout());
        guards.push(guard);

        let console_filter = get_envfilter(
            config.console.filtering_directive.as_ref(),
            config::Level(tracing::Level::INFO),
            config.console.level,
            &crates_to_filter,
        );

        #[allow(clippy::print_stderr)]
        {
            eprintln!("Using console logging filter: {console_filter}");
        }

        match config.console.log_format {
            config::LogFormat::Default => {
                let logging_layer = fmt::layer()
                    .with_timer(fmt::time::time())
                    .pretty()
                    .with_writer(console_writer)
                    .with_filter(console_filter);

                subscriber.with(logging_layer).init();
            }
            config::LogFormat::Json => {
                error_stack::Report::set_color_mode(error_stack::fmt::ColorMode::None);
                let logging_layer =
                    FormattingLayer::new(service_name, console_writer).with_filter(console_filter);
                subscriber.with(logging_layer).init();
            }
        }
    } else {
        subscriber.init();
    };

    // Returning the TelemetryGuard for logs to be printed and metrics to be collected until it is
    // dropped
    TelemetryGuard {
        _log_guards: guards,
    }
}

fn get_envfilter(
    filtering_directive: Option<&String>,
    default_log_level: config::Level,
    filter_log_level: config::Level,
    crates_to_filter: impl AsRef<[&'static str]>,
) -> EnvFilter {
    filtering_directive
        .map(|filter| {
            // Try to create target filter from specified filtering directive, if set

            // Safety: If user is overriding the default filtering directive, then we need to panic
            // for invalid directives.
            #[allow(clippy::expect_used)]
            EnvFilter::builder()
                .with_default_directive(default_log_level.into_level().into())
                .parse(filter)
                .expect("Invalid EnvFilter filtering directive")
        })
        .unwrap_or_else(|| {
            // Construct a default target filter otherwise
            let mut workspace_members = crate::cargo_workspace_members!();
            workspace_members.extend(crates_to_filter.as_ref());

            workspace_members
                .drain()
                .zip(std::iter::repeat(filter_log_level.into_level()))
                .fold(
                    EnvFilter::default().add_directive(default_log_level.into_level().into()),
                    |env_filter, (target, level)| {
                        // Safety: This is a hardcoded basic filtering directive. If even the basic
                        // filter is wrong, it's better to panic.
                        #[allow(clippy::expect_used)]
                        env_filter.add_directive(
                            format!("{target}={level}")
                                .parse()
                                .expect("Invalid EnvFilter directive format"),
                        )
                    },
                )
        })
}
