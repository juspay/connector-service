use domain_types::types::VaultConfig;
use hyperswitch_masking::{PeekInterface, Secret};
use std::collections::HashMap;

/// Error types for vault operations
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Invalid vault configuration: {0}")]
    InvalidConfiguration(String),
    #[error("URL transformation failed: {0}")]
    UrlTransformationFailed(String),
    #[error("Request transformation failed: {0}")]
    RequestTransformationFailed(String),
    #[error("Vault proxy not supported for this connector")]
    UnsupportedVaultProxy,
}

/// Transform request URL for vault routing
/// This is used by connectors to modify their base URL when vault is enabled
///
/// # Network Proxies
/// - VGS: Transforms URL to route through VGS proxy
/// - Evervault: URL remains unchanged (uses HTTP CONNECT proxy)
///
/// # Application Proxies
/// - Hyperswitch Vault: Routes through proxy endpoint
/// - TokenEx: URL remains unchanged (uses headers)
/// - Basis Theory: Routes through proxy endpoint
pub fn transform_connector_url(
    original_url: &str,
    vault_config: &VaultConfig,
) -> Result<String, VaultError> {
    match vault_config {
        VaultConfig::Vgs(config) => {
            let url = reqwest::Url::parse(original_url)
                .map_err(|e| VaultError::UrlTransformationFailed(e.to_string()))?;

            let environment_subdomain = match config.environment {
                domain_types::types::VgsEnvironment::Sandbox => "sandbox",
                domain_types::types::VgsEnvironment::Production => "live",
            };

            let vgs_url = format!(
                "https://{}.{}.verygoodproxy.com{}",
                config.tenant_id,
                environment_subdomain,
                url.path()
            );

            Ok(if let Some(query) = url.query() {
                format!("{}?{}", vgs_url, query)
            } else {
                vgs_url
            })
        }
        VaultConfig::BasisTheory(config) => {
            // Basis Theory routes through their proxy URL
            Ok(config.proxy_url.clone())
        }
        VaultConfig::HyperswitchVault(config) => {
            // Hyperswitch Vault routes through their proxy URL
            Ok(config.proxy_url.clone())
        }
        // Evervault and TokenEx don't transform URLs at this level
        VaultConfig::Evervault(_) | VaultConfig::TokenEx(_) => Ok(original_url.to_string()),
    }
}

/// Get vault-specific headers for application proxies
///
/// Returns headers that need to be added to the request for vault authentication.
/// Network proxies (VGS, Evervault) handle authentication at the connection level.
pub fn get_vault_headers(
    vault_config: &VaultConfig,
    original_url: Option<&str>,
) -> Result<HashMap<String, Secret<String>>, VaultError> {
    let mut headers = HashMap::new();

    match vault_config {
        VaultConfig::Evervault(config) => {
            headers.insert(
                "X-Evervault-App-ID".to_string(),
                Secret::new(config.app_id.clone()),
            );
            headers.insert(
                "Proxy-Authorization".to_string(),
                Secret::new(format!("Bearer {}", config.api_key.peek())),
            );
        }
        VaultConfig::HyperswitchVault(config) => {
            headers.insert(
                "x-api-key".to_string(),
                Secret::new(config.api_key.peek().to_string()),
            );
            headers.insert(
                "x-profile-id".to_string(),
                Secret::new(config.profile_id.clone()),
            );
        }
        VaultConfig::TokenEx(config) => {
            headers.insert(
                "TX-ApiKey".to_string(),
                Secret::new(config.api_key.peek().to_string()),
            );
            headers.insert(
                "TX-TokenExID".to_string(),
                Secret::new(config.tokenex_id.clone()),
            );
        }
        VaultConfig::BasisTheory(config) => {
            headers.insert(
                "BT-API-KEY".to_string(),
                Secret::new(config.api_key.peek().to_string()),
            );
            if let Some(url) = original_url {
                headers.insert("BT-PROXY-URL".to_string(), Secret::new(url.to_string()));
            }
            if let Some(proxy_id) = &config.proxy_id {
                headers.insert("BT-PROXY-ID".to_string(), Secret::new(proxy_id.clone()));
            }
        }
        // VGS doesn't add headers, it uses URL transformation
        VaultConfig::Vgs(_) => {}
    }

    Ok(headers)
}

/// Check if the vault configuration uses a network proxy
///
/// Network proxies (VGS, Evervault) route traffic at the network level.
/// Application proxies (Hyperswitch, TokenEx, Basis Theory) handle
/// tokenization at the application level.
pub fn is_network_proxy(vault_config: &VaultConfig) -> bool {
    matches!(
        vault_config,
        VaultConfig::Vgs(_) | VaultConfig::Evervault(_)
    )
}

/// Get proxy configuration for network proxies
///
/// Returns the proxy URL that should be used with reqwest's Proxy configuration.
/// For Evervault, this returns the relay URL.
/// For VGS, returns None as VGS uses URL transformation, not HTTP proxy.
pub fn get_network_proxy_url(vault_config: &VaultConfig) -> Option<String> {
    match vault_config {
        VaultConfig::Evervault(config) => Some(format!(
            "https://{}.relay.evervault.com:443",
            config.team_id
        )),
        _ => None,
    }
}

/// Get the base URL for a connector when vault is enabled
///
/// This is a convenience function that connectors can use in their
/// `base_url()` method to automatically route through vault when enabled.
///
/// # Security
/// This function returns a `Result` instead of silently falling back to the
/// original URL. If vault transformation fails, the error is propagated to
/// prevent sensitive data from being sent to the wrong destination.
///
/// Example usage in a connector:
/// ```rust,ignore
/// fn base_url(&self, connectors: &Connectors) -> Result<String, VaultError> {
///     let base = connectors.stripe.base_url.clone();
///     get_vault_aware_url(&base, vault_config)
/// }
/// ```
pub fn get_vault_aware_url(
    original_url: &str,
    vault_config: Option<&VaultConfig>,
) -> Result<String, VaultError> {
    match vault_config {
        Some(config) => transform_connector_url(original_url, config),
        None => Ok(original_url.to_string()),
    }
}

/// Bridge: Convert a TOML-based `VaultConfig` into the runtime `ExternalVaultProxyConfig`
/// used by the injector call path. This enables the TOML config to serve as a fallback
/// when no `x-external-vault-metadata` header is present in the gRPC request.
///
/// Currently supported:
/// - `VaultConfig::Vgs` → `VaultConnectorType::Proxy` + `VgsMetadata`
/// - `VaultConfig::HyperswitchVault` → `VaultConnectorType::Transformation` + `HyperswitchVaultMetadata`
///
/// Unsupported providers (Evervault, TokenEx, BasisTheory) return `None`.
#[cfg(feature = "injector-client")]
pub fn vault_config_to_external_proxy_config(
    config: &VaultConfig,
) -> Option<crate::service::ExternalVaultProxyConfig> {
    use crate::service::{
        ExternalVaultProxyConfig, ExternalVaultProxyMetadata, HyperswitchVaultMetadata,
        VaultConnectorAuth, VaultConnectorType, VgsMetadata,
    };
    use url::Url;

    match config {
        VaultConfig::Vgs(vgs) => {
            let environment_subdomain = match vgs.environment {
                domain_types::types::VgsEnvironment::Sandbox => "sandbox",
                domain_types::types::VgsEnvironment::Production => "live",
            };
            let proxy_url_str = format!(
                "https://{}.{}.verygoodproxy.com",
                vgs.tenant_id, environment_subdomain
            );
            let proxy_url = Url::parse(&proxy_url_str)
                .inspect_err(|e| {
                    tracing::warn!("Failed to parse VGS proxy URL: {:?}", e);
                })
                .ok()?;
            let certificate = vgs
                .ca_certificate
                .clone()
                .map(Secret::new)
                .unwrap_or_else(|| Secret::new(String::new()));

            Some(ExternalVaultProxyConfig {
                vault_connector_type: VaultConnectorType::Proxy,
                vault_connector_id: Some("vgs".to_string()),
                metadata: ExternalVaultProxyMetadata::VgsMetadata(VgsMetadata {
                    proxy_url,
                    certificate,
                }),
            })
        }
        VaultConfig::HyperswitchVault(hsv) => {
            let vault_endpoint = Url::parse(&hsv.proxy_url)
                .inspect_err(|e| {
                    tracing::warn!("Failed to parse HyperswitchVault endpoint URL: {:?}", e);
                })
                .ok()?;

            Some(ExternalVaultProxyConfig {
                vault_connector_type: VaultConnectorType::Transformation,
                vault_connector_id: Some("hyperswitch_vault".to_string()),
                metadata: ExternalVaultProxyMetadata::HyperswitchVaultMetadata(
                    HyperswitchVaultMetadata {
                        vault_endpoint,
                        vault_auth_data: VaultConnectorAuth {
                            api_key: hsv.api_key.clone(),
                            // HyperswitchVault uses profile_id as the "secret" component
                            api_secret: Secret::new(hsv.profile_id.clone()),
                        },
                    },
                ),
            })
        }
        VaultConfig::Evervault(_) | VaultConfig::TokenEx(_) | VaultConfig::BasisTheory(_) => {
            tracing::warn!(
                "TOML-to-ExternalVaultProxyConfig bridge not yet implemented for this vault provider"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::types::{
        BasisTheoryConfig, EvervaultConfig, HyperswitchEnvironment, HyperswitchVaultConfig,
        TokenExConfig, TokenExTokenScheme, VgsConfig, VgsEnvironment,
    };

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_vgs_url_transformation_sandbox() {
        let config = VaultConfig::Vgs(VgsConfig {
            tenant_id: "tnt123".to_string(),
            environment: VgsEnvironment::Sandbox,
            ca_certificate: None,
        });

        let result = transform_connector_url("https://api.stripe.com/v1/charges", &config);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://tnt123.sandbox.verygoodproxy.com/v1/charges"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_vgs_url_transformation_production() {
        let config = VaultConfig::Vgs(VgsConfig {
            tenant_id: "tnt456".to_string(),
            environment: VgsEnvironment::Production,
            ca_certificate: None,
        });

        let result = transform_connector_url("https://api.stripe.com/v1/charges", &config);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://tnt456.live.verygoodproxy.com/v1/charges"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_vgs_url_with_query_params() {
        let config = VaultConfig::Vgs(VgsConfig {
            tenant_id: "tnt789".to_string(),
            environment: VgsEnvironment::Sandbox,
            ca_certificate: None,
        });

        let result = transform_connector_url("https://api.stripe.com/v1/charges?limit=10", &config);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "https://tnt789.sandbox.verygoodproxy.com/v1/charges?limit=10"
        );
    }

    #[test]
    fn test_is_network_proxy() {
        let vgs = VaultConfig::Vgs(VgsConfig {
            tenant_id: "test".to_string(),
            environment: VgsEnvironment::Sandbox,
            ca_certificate: None,
        });
        assert!(is_network_proxy(&vgs));

        let evervault = VaultConfig::Evervault(EvervaultConfig {
            team_id: "team123".to_string(),
            app_id: "app456".to_string(),
            api_key: Secret::new("key".to_string()),
        });
        assert!(is_network_proxy(&evervault));

        let hyperswitch = VaultConfig::HyperswitchVault(HyperswitchVaultConfig {
            api_key: Secret::new("key".to_string()),
            profile_id: "pro123".to_string(),
            proxy_url: "https://proxy.example.com".to_string(),
            environment: HyperswitchEnvironment::Sandbox,
        });
        assert!(!is_network_proxy(&hyperswitch));
    }

    #[test]
    fn test_get_vault_headers_evervault() {
        let config = VaultConfig::Evervault(EvervaultConfig {
            team_id: "team123".to_string(),
            app_id: "app456".to_string(),
            api_key: Secret::new("test_key".to_string()),
        });

        let headers = get_vault_headers(&config, None).unwrap();
        assert_eq!(headers.get("X-Evervault-App-ID").unwrap().peek(), "app456");
        assert!(headers
            .get("Proxy-Authorization")
            .unwrap()
            .peek()
            .starts_with("Bearer "));
    }

    #[test]
    fn test_get_vault_headers_hyperswitch() {
        let config = VaultConfig::HyperswitchVault(HyperswitchVaultConfig {
            api_key: Secret::new("hs_key".to_string()),
            profile_id: "pro_abc123".to_string(),
            proxy_url: "https://proxy.example.com".to_string(),
            environment: HyperswitchEnvironment::Sandbox,
        });

        let headers = get_vault_headers(&config, None).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap().peek(), "hs_key");
        assert_eq!(headers.get("x-profile-id").unwrap().peek(), "pro_abc123");
    }

    #[test]
    fn test_get_vault_headers_tokenex() {
        let config = VaultConfig::TokenEx(TokenExConfig {
            api_key: Secret::new("tx_key".to_string()),
            tokenex_id: "tx_12345".to_string(),
            tgapi_url: "https://tgapi.tokenex.com".to_string(),
            default_token_scheme: domain_types::types::TokenExTokenScheme::TokenFour,
        });

        let headers = get_vault_headers(&config, None).unwrap();
        assert_eq!(headers.get("TX-ApiKey").unwrap().peek(), "tx_key");
        assert_eq!(headers.get("TX-TokenExID").unwrap().peek(), "tx_12345");
    }

    #[test]
    fn test_get_vault_headers_basis_theory() {
        let config = VaultConfig::BasisTheory(BasisTheoryConfig {
            api_key: Secret::new("bt_key".to_string()),
            proxy_url: "https://proxy.basistheory.com".to_string(),
            proxy_id: Some("proxy_123".to_string()),
        });

        let headers =
            get_vault_headers(&config, Some("https://api.stripe.com/v1/charges")).unwrap();
        assert_eq!(headers.get("BT-API-KEY").unwrap().peek(), "bt_key");
        assert_eq!(
            headers.get("BT-PROXY-URL").unwrap().peek(),
            "https://api.stripe.com/v1/charges"
        );
        assert_eq!(headers.get("BT-PROXY-ID").unwrap().peek(), "proxy_123");
    }

    #[test]
    fn test_get_vault_headers_vgs() {
        let config = VaultConfig::Vgs(VgsConfig {
            tenant_id: "tnt123".to_string(),
            environment: VgsEnvironment::Sandbox,
            ca_certificate: None,
        });

        let headers = get_vault_headers(&config, None).unwrap();
        assert!(headers.is_empty());
    }
}
