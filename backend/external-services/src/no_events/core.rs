//! No event emission core functionalities

/// No events type
#[derive(Debug, Clone)]
pub struct NoEvents;

impl NoEvents {
    /// Event emission functionality (no-op)
    pub async fn emit_event(&mut self, _event_type: &str, _data: &[u8]) -> Result<(), ()> {
        // No-op implementation
        Ok(())
    }
}
