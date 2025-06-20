pub const X_TENANT_ID: &str = "x-tenant-id";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    Development,
    Release,
}

impl Env {
    pub const fn current_env() -> Self {
        if cfg!(debug_assertions) {
            Self::Development
        } else {
            Self::Release
        }
    }

    pub const fn config_path(self) -> &'static str {
        match self {
            Self::Development => "development.toml",
            Self::Release => "production.toml",
        }
    }
}

impl std::fmt::Display for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Development => write!(f, "development"),
            Self::Release => write!(f, "release"),
        }
    }
}

/// Header key for request ID
pub const X_REQUEST_ID: &str = "x-request-id";
pub const X_CONNECTOR: &str = "x-connector";
pub const X_MERCHANT_ID: &str = "x-merchant-id";
pub const NAME: &str = "UCS";

// pub(crate) const BASE64_ENGINE: base64::engine::GeneralPurpose =
//     base64::engine::general_purpose::STANDARD;
