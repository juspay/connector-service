
use domain_types::{
    connector_flow::*,
    connector_types::*,
    errors::ConnectorError,
    payouts::payouts_types::*,
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
};

use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};


use crate::types::ResponseRouterData;
// ===== AUTH TYPE =====

pub struct ItaubankAuthType {
    pub client_id: Secret<String>,
    pub client_secret: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for ItaubankAuthType {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(config: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match config {
            ConnectorSpecificConfig::Itaubank {
                client_id,
                client_secret,
                ..
            } => Ok(Self {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ===== ERROR RESPONSE =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaubankErrorResponse {
    pub code: Option<String>,
    pub message: Option<String>,
    #[serde(rename = "statusCode")]
    pub status_code: Option<u16>,
}

// ===== ACCESS TOKEN REQUEST/RESPONSE =====

#[derive(Debug, Serialize)]
pub struct ItaubankAccessTokenRequest {
    pub grant_type: String,
    pub client_id: Secret<String>,
    pub client_secret: Secret<String>,
}

impl
    TryFrom<
        &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    > for ItaubankAccessTokenRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        req: &RouterDataV2<
            CreateAccessToken,
            PaymentFlowData,
            AccessTokenRequestData,
            AccessTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = ItaubankAuthType::try_from(&req.connector_config)?;
        Ok(Self {
            grant_type: "client_credentials".to_string(),
            client_id: auth.client_id,
            client_secret: auth.client_secret,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ItaubankAccessTokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
}

// ===== PAYOUT TRANSFER REQUEST/RESPONSE =====

#[derive(Debug, Serialize)]
pub struct ItaubankTransferRequest {
    pub valor_pagamento: String,
    pub data_pagamento: String,
    pub chave: Option<String>,
    pub referencia_empresa: Option<String>,
    pub identificacao_comprovante: Option<String>,
    pub informacoes_entre_usuarios: Option<String>,
    pub recebedor: Option<ItaubankRecebedor>,
}

#[derive(Debug, Serialize)]
pub struct ItaubankRecebedor {
    pub tipo_conta: Option<String>,
    pub agencia: Option<i64>,
    pub conta: Option<String>,
    pub tipo_pessoa: Option<String>,
    pub documento: Option<i64>,
    pub modulo_sispag: Option<String>,
}

impl
    TryFrom<
        &RouterDataV2<
            PayoutTransfer,
            PayoutFlowData,
            PayoutTransferRequest,
            PayoutTransferResponse,
        >,
    > for ItaubankTransferRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        req: &RouterDataV2<
            PayoutTransfer,
            PayoutFlowData,
            PayoutTransferRequest,
            PayoutTransferResponse,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = req.request.amount;
        // Convert MinorUnit to a string with 2 decimal places (e.g. 400 -> "4.00")
        #[allow(clippy::as_conversions)]
        let amount_str = format!("{:.2}", amount.0 as f64 / 100.0);

        Ok(Self {
            valor_pagamento: amount_str,
            data_pagamento: "2026-03-26".to_string(),
            chave: req.request.connector_payout_id.clone(),
            referencia_empresa: req.request.merchant_payout_id.clone(),
            identificacao_comprovante: None,
            informacoes_entre_usuarios: None,
            recebedor: None,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ItaubankTransferResponse {
    pub id: Option<String>,
    #[serde(rename = "status")]
    pub transfer_status: Option<String>,
    pub mensagem: Option<String>,
}

impl ItaubankTransferResponse {
    pub fn status(&self) -> common_enums::PayoutStatus {
        match self.transfer_status.as_deref().unwrap_or("unknown") {
            "APROVADO" | "CONFIRMADO" | "EFETIVADO" => common_enums::PayoutStatus::Success,
            "PENDENTE" | "EM_PROCESSAMENTO" => common_enums::PayoutStatus::Initiated,
            "REJEITADO" | "CANCELADO" => common_enums::PayoutStatus::Failure,
            _ => common_enums::PayoutStatus::Initiated,
        }
    }
}

// ===== PSYNC RESPONSE (placeholder for macro) =====

impl
    TryFrom<
        ResponseRouterData<
            ItaubankErrorResponse,
            Self,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: ResponseRouterData<
            ItaubankErrorResponse,
            Self,
        >,
    ) -> Result<Self, Self::Error> {
        Err(ConnectorError::NotImplemented("PSync for Itaubank".to_string()).into())
    }
}

// ===== PAYOUT TRANSFER RESPONSE =====

impl TryFrom<ItaubankTransferResponse> for PayoutTransferResponse {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: ItaubankTransferResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            merchant_payout_id: None,
            payout_status: response.status(),
            connector_payout_id: response.id,
            status_code: 200,
        })
    }
}
