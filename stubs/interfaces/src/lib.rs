// Stub implementations for interfaces

use hyperswitch_masking::{Mask, Maskable, Secret};
use serde::{Deserialize, Serialize};

pub mod api {
    use serde::{Deserialize, Serialize};

    pub trait ConnectorCommon {
        fn get_id(&self) -> &'static str;
        fn get_name(&self) -> &'static str;
    }
}

pub mod connector_integration_v2 {
    pub trait ConnectorIntegrationV2 {}
}

pub mod connector_types {
    // Re-export from domain_types
    pub use crate::stubs::domain_types::connector_types::*;
}

pub mod events {
    pub mod connector_api_logs {
        pub struct ConnectorEvent;
    }
}

pub mod verification {
    use hyperswitch_masking::Secret;

    pub struct ConnectorSourceVerificationSecrets {
        pub secret: Option<Secret<String>>,
    }

    pub trait SourceVerification {}
}