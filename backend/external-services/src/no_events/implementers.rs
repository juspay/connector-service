//! Trait implementations for No events client

use common_utils::errors::CustomResult;
use error_stack::report;
use interfaces::event_interface::{EventError, EventInterface};

use crate::no_events::core::NoEvents;

#[async_trait::async_trait]
impl EventInterface for NoEvents {
    async fn emit_event(&self, event_type: &str, data: &[u8]) -> CustomResult<(), EventError> {
        self.emit_event(event_type, data)
            .await
            .map_err(|_| report!(EventError::EventEmissionFailed))
    }
}
