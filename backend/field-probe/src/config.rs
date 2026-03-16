use std::collections::HashMap;
use std::sync::OnceLock;
use domain_types::connector_types::ConnectorEnum;
use grpc_api_types::payments::PaymentMethod;
use serde::Deserialize;

// ── Operational config (probe-config.toml) ────────────────────────────────────

/// Configuration for the field-probe, loaded from probe-config.toml
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ProbeConfig {
    pub(crate) probe: ProbeSettings,
    pub(crate) access_token: AccessTokenConfig,
    pub(crate) oauth_connectors: Vec<OAuthConnector>,
    /// Connectors to skip (exclude from probing). All others are probed.
    pub(crate) skip_connectors: Vec<String>,
    pub(crate) payment_methods: HashMap<String, bool>,
    pub(crate) connector_metadata: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ProbeSettings {
    pub(crate) max_iterations: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct AccessTokenConfig {
    pub(crate) token: String,
    pub(crate) token_type: String,
    pub(crate) expires_in_seconds: i64,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OAuthConnector {
    pub(crate) name: String,
}

impl ProbeConfig {
    pub(crate) fn load() -> Self {
        let config_paths = [
            "backend/field-probe/probe-config.toml",
            "probe-config.toml",
            concat!(env!("CARGO_MANIFEST_DIR"), "/probe-config.toml"),
        ];
        for path in &config_paths {
            if let Ok(contents) = std::fs::read_to_string(path) {
                eprintln!("Loaded config from: {path}");
                return toml::from_str(&contents)
                    .unwrap_or_else(|e| panic!("Failed to parse {path}: {e}"));
            }
        }
        eprintln!("Warning: No probe-config.toml found, using defaults");
        Self::default()
    }

    pub(crate) fn is_oauth_connector(&self, connector: &ConnectorEnum) -> bool {
        let name = format!("{connector:?}").to_lowercase();
        self.oauth_connectors.iter().any(|c| c.name.to_lowercase() == name)
    }

    pub(crate) fn get_enabled_payment_methods(&self) -> Vec<(&'static str, fn() -> PaymentMethod)> {
        let all_methods = crate::registry::authorize_pm_variants_static();
        all_methods
            .into_iter()
            .filter(|(name, _)| self.payment_methods.get(*name).copied().unwrap_or(true))
            .collect()
    }
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            probe: ProbeSettings { max_iterations: 30 },
            access_token: AccessTokenConfig {
                token: "probe_access_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in_seconds: 3600,
            },
            oauth_connectors: vec![
                OAuthConnector { name: "airwallex".to_string() },
                OAuthConnector { name: "globalpay".to_string() },
                OAuthConnector { name: "jpmorgan".to_string() },
                OAuthConnector { name: "iatapay".to_string() },
                OAuthConnector { name: "getnet".to_string() },
                OAuthConnector { name: "payload".to_string() },
                OAuthConnector { name: "paypal".to_string() },
                OAuthConnector { name: "truelayer".to_string() },
                OAuthConnector { name: "volt".to_string() },
            ],
            skip_connectors: vec![],
            payment_methods: HashMap::new(),
            connector_metadata: HashMap::new(),
        }
    }
}

static PROBE_CONFIG: OnceLock<ProbeConfig> = OnceLock::new();

pub(crate) fn get_config() -> &'static ProbeConfig {
    PROBE_CONFIG.get_or_init(ProbeConfig::load)
}

pub(crate) fn max_iterations() -> usize {
    get_config().probe.max_iterations
}

// ── Patch config (patch-config.toml) ─────────────────────────────────────────

/// Grouped patch rules loaded from patch-config.toml.
/// Sections map to parent structs; keys are field names; values carry aliases + type + value.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct PatchConfig {
    // ── authorize: grouped by proto parent ──────────────────────────────────
    #[serde(default)]
    pub(crate) billing_address: HashMap<String, FieldPatchSpec>,
    #[serde(default)]
    pub(crate) shipping_address: HashMap<String, FieldPatchSpec>,
    #[serde(default)]
    pub(crate) browser_info: HashMap<String, FieldPatchSpec>,
    #[serde(default)]
    pub(crate) customer: HashMap<String, FieldPatchSpec>,
    #[serde(default)]
    pub(crate) top_level: HashMap<String, FieldPatchSpec>,
    /// Multi-field patches where one error name sets several (parent, field) pairs.
    #[serde(default)]
    pub(crate) multi: Vec<MultiPatchEntry>,

    // ── other flows: flat field → spec (key is logical name, field is struct path) ──
    #[serde(default)]
    pub(crate) capture: HashMap<String, FlowFieldSpec>,
    #[serde(default)]
    pub(crate) refund: HashMap<String, FlowFieldSpec>,
    #[serde(rename = "void", default)]
    pub(crate) void_flow: HashMap<String, FlowFieldSpec>,
    #[serde(default)]
    pub(crate) get: HashMap<String, FlowFieldSpec>,
    #[serde(default)]
    pub(crate) setup_recurring: HashMap<String, FlowFieldSpec>,
    #[serde(default)]
    pub(crate) recurring_charge: HashMap<String, FlowFieldSpec>,
}

/// One entry in a grouped authorize section: aliases + how to set the field.
/// The key is the struct field name; parent is implicit from the section.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct FieldPatchSpec {
    pub(crate) aliases: Vec<String>,
    #[serde(rename = "type")]
    pub(crate) value_type: PatchValueType,
    pub(crate) value: Option<String>,
}

/// One entry in a non-authorize flow section.
/// The key is a logical name; `field` is the actual struct field to set.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct FlowFieldSpec {
    pub(crate) field: String,
    pub(crate) aliases: Vec<String>,
    #[serde(rename = "type")]
    pub(crate) value_type: PatchValueType,
    pub(crate) value: Option<String>,
}

/// A [[multi]] entry: one or more aliases → list of (parent, field, value) actions.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct MultiPatchEntry {
    pub(crate) aliases: Vec<String>,
    pub(crate) actions: Vec<PatchAction>,
}

/// One action inside a multi-patch entry.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PatchAction {
    pub(crate) parent: PatchParent,
    pub(crate) field: String,
    #[serde(rename = "type")]
    pub(crate) value_type: PatchValueType,
    pub(crate) value: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub(crate) enum PatchParent {
    #[serde(rename = "billing_address")]  BillingAddress,
    #[serde(rename = "shipping_address")] ShippingAddress,
    #[serde(rename = "browser_info")]     BrowserInfo,
    #[serde(rename = "customer")]         Customer,
    #[serde(rename = "top_level")]        TopLevel,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub(crate) enum PatchValueType {
    #[serde(rename = "secret_string")]            SecretString,
    #[serde(rename = "string")]                   Str,
    #[serde(rename = "bool")]                     Bool,
    #[serde(rename = "i32")]                      I32,
    #[serde(rename = "country_us")]               CountryUs,
    #[serde(rename = "future_usage_off_session")]  FutureUsageOffSession,
    /// Sets the amount field to usd_money(1000); no `value` needed.
    #[serde(rename = "usd_money")]                UsdMoney,
    /// Populates the entire browser_info struct with probe defaults; no `value` needed.
    #[serde(rename = "full_browser_info")]         FullBrowserInfo,
}

impl PatchConfig {
    pub(crate) fn load() -> Self {
        let config_paths = [
            "backend/field-probe/patch-config.toml",
            "patch-config.toml",
            concat!(env!("CARGO_MANIFEST_DIR"), "/patch-config.toml"),
        ];
        for path in &config_paths {
            if let Ok(contents) = std::fs::read_to_string(path) {
                eprintln!("Loaded patch config from: {path}");
                return toml::from_str(&contents)
                    .unwrap_or_else(|e| panic!("Failed to parse {path}: {e}"));
            }
        }
        eprintln!("Warning: No patch-config.toml found, patch dispatch will use Rust-only fallback");
        Self::default()
    }
}

static PATCH_CONFIG: OnceLock<PatchConfig> = OnceLock::new();

pub(crate) fn get_patch_config() -> &'static PatchConfig {
    PATCH_CONFIG.get_or_init(PatchConfig::load)
}
