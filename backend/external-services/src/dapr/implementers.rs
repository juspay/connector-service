//! Trait implementations for Dapr client

use common_utils::errors::CustomResult;
use error_stack::ResultExt;
use interfaces::event_interface::{EventError, EventInterface};

use crate::dapr::core::DaprClient;

#[async_trait::async_trait]
impl EventInterface for DaprClient {
    async fn emit_event(&self, event_type: &str, data: &[u8]) -> CustomResult<(), EventError> {
        // Call the DaprClient's emit_event method directly to avoid recursion
        DaprClient::emit_event(self, event_type, data)
            .await
            .change_context(EventError::EventEmissionFailed)
    }
}
