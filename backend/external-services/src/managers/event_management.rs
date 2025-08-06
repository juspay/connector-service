//! Event management util module

use std::sync::Arc;

use common_utils::errors::CustomResult;
use error_stack::ResultExt;
use interfaces::event_interface::{EventError, EventInterface};

#[cfg(feature = "dapr")]
use crate::dapr;

/// Enum representing configuration options for event management.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(tag = "event_manager")]
#[serde(rename_all = "snake_case")]
pub enum EventManagementConfig {
    /// Dapr configuration
    #[cfg(feature = "dapr")]
    Dapr {
        /// Dapr config
        dapr: dapr::core::DaprConfig,
    },

    /// Variant representing no event emission
    #[default]
    NoEvents,
}

impl EventManagementConfig {
    /// Verifies that the client configuration is usable
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            #[cfg(feature = "dapr")]
            Self::Dapr { dapr } => dapr.validate(),

            Self::NoEvents => Ok(()),
        }
    }

    /// Retrieves the appropriate event client based on the configuration.
    pub async fn get_event_management_client(
        &self,
    ) -> CustomResult<Arc<dyn EventInterface>, EventError> {
        Ok(match self {
            #[cfg(feature = "dapr")]
            Self::Dapr { dapr } => Arc::new(
                crate::dapr::core::DaprClient::new(dapr)
                    .await
                    .change_context(EventError::EventEmissionFailed)?,
            ),

            Self::NoEvents => Arc::new(crate::no_events::core::NoEvents),
        })
    }

    /// Converts EventManagementConfig to EventConfig for compatibility with external services
    pub fn to_event_config(&self) -> common_utils::dapr::EventConfig {
        match self {
            #[cfg(feature = "dapr")]
            Self::Dapr { dapr } => dapr.to_event_config(),

            Self::NoEvents => common_utils::dapr::EventConfig::default(),
        }
    }
}
