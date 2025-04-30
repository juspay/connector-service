pub mod config;

pub mod formatter;
pub mod setup;
pub use setup::setup;

pub mod env;
pub mod storage;

pub use tracing::{debug, error, event as log, info, warn};
pub use tracing_attributes::instrument;

/// Obtain the crates in the current cargo workspace as a `HashSet`.
///
/// This macro requires that [`set_cargo_workspace_members_env()`] function be called in the
/// build script of the crate where this macro is being called.
///
/// # Errors
///
/// Causes a compilation error if the `CARGO_WORKSPACE_MEMBERS` environment variable is unset.
#[macro_export]
macro_rules! cargo_workspace_members {
    () => {
        env!("CARGO_WORKSPACE_MEMBERS")
            .split(',')
            .collect::<std::collections::HashSet<&'static str>>()
    };
}
