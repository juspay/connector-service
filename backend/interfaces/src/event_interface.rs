//! Event emitting related interface and error types

#![warn(missing_docs, missing_debug_implementations)]

use common_utils::errors::CustomResult;

/// Trait defining the interface for event management
#[async_trait::async_trait]
pub trait EventInterface: Sync + Send + dyn_clone::DynClone {
    /// Emit an event with the given data
    async fn emit_event(&mut self, event_type: &str, data: &[u8]) -> CustomResult<(), EventError>;
}

dyn_clone::clone_trait_object!(EventInterface);

/// Errors that may occur during event emitting functionalities
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// An error occurred when emitting an event.
    #[error("Failed to emit event")]
    EventEmissionFailed,
}
