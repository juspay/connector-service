use super::ConnectorOverride;

/// Default override strategy that relies purely on JSON override files.
#[derive(Debug, Clone)]
pub struct DefaultConnectorOverride {
    connector: String,
    deferred_paths: Vec<String>,
}

impl DefaultConnectorOverride {
    /// Creates a default strategy bound to a connector name.
    pub fn new(connector: String) -> Self {
        Self {
            connector,
            deferred_paths: Vec::new(),
        }
    }

    /// Creates a strategy with additional context-deferred paths.
    pub fn with_deferred_paths(connector: String, deferred_paths: Vec<String>) -> Self {
        Self {
            connector,
            deferred_paths,
        }
    }
}

impl ConnectorOverride for DefaultConnectorOverride {
    fn connector_name(&self) -> &str {
        &self.connector
    }

    fn extra_context_deferred_paths(&self) -> Vec<String> {
        self.deferred_paths.clone()
    }
}
