// Stub implementations for common_utils

use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

pub mod errors {
    use error_stack::Context;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ConnectorError {
        #[error("Request construction failed")]
        RequestConstructionFailed,
        #[error("Response deserialization failed")]
        ResponseDeserializationFailed,
        #[error("Network error")]
        NetworkError,
        #[error("Authentication failed")]
        AuthenticationFailed,
        #[error("Invalid request")]
        InvalidRequest,
    }
}

pub mod ext_traits {
    pub trait ByteSliceExt {
        fn to_string(&self) -> String;
    }

    impl ByteSliceExt for &[u8] {
        fn to_string(&self) -> String {
            String::from_utf8_lossy(self).to_string()
        }
    }
}

pub mod types {
    use super::errors::ConnectorError;
    use error_stack::ResultExt;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StringMinorUnit(pub String);

    impl StringMinorUnit {
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl FromStr for StringMinorUnit {
        type Err = ConnectorError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(StringMinorUnit(s.to_string()))
        }
    }
}

pub type CustomResult<T, E> = error_stack::Result<T, E>;