use common_enums;
use common_utils::errors::CustomResult;
use domain_types::{
    errors::ConnectorError,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    connector_types::PaymentFlowData,
};
use grpc_api_types::payments::AccessToken;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

/// State structure to send back to Hyperswitch for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorState {
    pub access_token: Option<AccessToken>,
}

impl ConnectorState {
    pub fn new() -> Self {
        Self {
            access_token: None,
        }
    }

    pub fn with_access_token(access_token: AccessToken) -> Self {
        Self {
            access_token: Some(access_token),
        }
    }
}

impl Default for ConnectorState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AccessTokenManager;

impl AccessTokenManager {
    pub fn should_refresh_token(access_token: &Option<String>) -> bool {
        access_token.is_none()
    }

    pub fn supports_access_token(connector_name: &str, payment_method: common_enums::PaymentMethod) -> bool {
        matches!(
            (connector_name, payment_method),
            ("volt", _)
        )
    }

    pub async fn ensure_access_token<T: AccessTokenAuth<(), (), AccessToken>>(
        connector: &T,
        payment_flow_data: &mut domain_types::connector_types::PaymentFlowData,
        connector_auth_details: &ConnectorAuthType,
        connector_name: &str,
    ) -> CustomResult<(), ConnectorError> {
        if Self::supports_access_token(connector_name, payment_flow_data.payment_method) 
            && Self::should_refresh_token(&payment_flow_data.access_token) {
            
            tracing::info!("Generating access token for connector: {}", connector_name);
            
            let token_router_data = RouterDataV2::<(), domain_types::connector_types::PaymentFlowData, (), AccessToken> {
                flow: std::marker::PhantomData,
                resource_common_data: payment_flow_data.clone(),
                connector_auth_type: connector_auth_details.clone(),
                request: (),
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };
            
            let access_token = connector.get_access_token(&token_router_data).await?;
            
            tracing::info!("Successfully generated access token for connector: {}", connector_name);
            payment_flow_data.access_token = Some(access_token.token);
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Handle OAuth token generation for ConnectorData directly
    pub async fn ensure_access_token_for_connector_data(
        connector_data: &crate::types::ConnectorData,
        payment_flow_data: &mut domain_types::connector_types::PaymentFlowData,
        connector_auth_details: &ConnectorAuthType,
        connector_name: &str,
    ) -> CustomResult<(), ConnectorError> {
        if Self::supports_access_token(connector_name, payment_flow_data.payment_method) 
            && Self::should_refresh_token(&payment_flow_data.access_token) {
            
            tracing::info!("Generating access token for connector: {}", connector_name);
            
            match connector_data.connector_name {
                domain_types::connector_types::ConnectorEnum::Volt => {
                    let volt = crate::connectors::Volt::new();
                    
                    let token_router_data = RouterDataV2::<(), domain_types::connector_types::PaymentFlowData, (), AccessToken> {
                        flow: std::marker::PhantomData,
                        resource_common_data: payment_flow_data.clone(),
                        connector_auth_type: connector_auth_details.clone(),
                        request: (),
                        response: Err(domain_types::router_data::ErrorResponse::default()),
                    };
                    
                    let access_token = volt.get_access_token(&token_router_data).await?;
                    payment_flow_data.access_token = Some(access_token.token);
                    
                    tracing::info!("Successfully generated access token for connector: {}", connector_name);
                    Ok(())
                }
                _ => {
                    Ok(())
                }
            }
        } else {
            // No token refresh needed
            Ok(())
        }
    }
}

pub struct AddAccessTokenResult {
    pub access_token_result: Result<Option<AccessToken>, ConnectorError>,
    pub connector_supports_access_token: bool,
}

pub trait AccessTokenAuth<F, Req, Res> {
    fn get_access_token(
        &self,
        router_data: &RouterDataV2<F, PaymentFlowData, Req, Res>,
    ) -> impl std::future::Future<Output = CustomResult<AccessToken, ConnectorError>> + Send;
}

#[derive(Debug, Clone)]
pub struct AccessTokenRequestData {
    pub app_id: Secret<String>,
    pub id: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for AccessTokenRequestData {
    type Error = ConnectorError;
    
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                app_id: api_key.clone(),
                id: None,
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                app_id: api_key.clone(),
                id: Some(key1.clone()),
            }),
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                app_id: api_key.clone(),
                id: Some(key1.clone()),
            }),
            ConnectorAuthType::MultiAuthKey { api_key, key1, .. } => Ok(Self {
                app_id: api_key.clone(),
                id: Some(key1.clone()),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType),
        }
    }
}

pub fn create_auth_header(access_token: &AccessToken) -> String {
    format!("{} {}", access_token.token_type, access_token.token)
}