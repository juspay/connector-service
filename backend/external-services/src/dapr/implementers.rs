//! Trait implementations for Dapr client

use common_utils::errors::CustomResult;
use error_stack::ResultExt;
use interfaces::event_interface::{EventError, EventInterface};

use crate::dapr::core::DaprClient;

#[async_trait::async_trait]
impl EventInterface for DaprClient {
    async fn emit_event(&mut self, event_type: &str, data: &[u8]) -> CustomResult<(), EventError> {
        self.emit_event(event_type, data)
            .await
            .change_context(EventError::EventEmissionFailed)
    }
}
