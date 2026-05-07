use common_utils::StringMajorUnit;
use domain_types::{
    connector_flow::{Authorize, ServerAuthenticationToken},
    connector_types::{
        PaymentsAuthorizeData, PaymentsResponseData, ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
    },
    errors::{ConnectorError, IntegrationError},
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    types::{PaymentFlowData, PaymentMethodDataTypes},
};
use error_stack;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

#[derive(Debug, Clone)]
pub struct FiatpeAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for FiatpeAuthType {
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Fiatpe { api_key, .. } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                IntegrationError::FailedToObtainAuthType {
                    context: IntegrationErrorContext::default(),
                }
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatpeErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiatpeAccessTokenRequest {
    pub api_key: Secret<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &RouterDataV2<
            ServerAuthenticationToken,
            PaymentFlowData,
            ServerAuthenticationTokenRequestData,
            ServerAuthenticationTokenResponseData,
        >,
    > for FiatpeAccessTokenRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: &RouterDataV2<
            ServerAuthenticationToken,
            PaymentFlowData,
            ServerAuthenticationTokenRequestData,
            ServerAuthenticationTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = FiatpeAuthType::try_from(&item.connector_config)?;
        Ok(Self {
            api_key: auth.api_key,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiatpeAccessTokenResponse {
    pub access_token: Secret<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
}

impl<F> TryFrom<ResponseRouterData<FiatpeAccessTokenResponse, Self>>
    for RouterDataV2<
        F,
        PaymentFlowData,
        ServerAuthenticationTokenRequestData,
        ServerAuthenticationTokenResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FiatpeAccessTokenResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(ServerAuthenticationTokenResponseData {
                access_token: item.response.access_token,
                expires_in: Some(item.response.expires_in.unwrap_or(3600)),
                token_type: item.response.token_type.or(Some("Bearer".to_string())),
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FiatpePaymentsRequest {
    pub request: String,
    pub access_token: Secret<String>,
    pub payment_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_cvv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_vpa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_upi_intent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_expiry_date: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for FiatpePaymentsRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let request_data = &item.request;

        let base_request = FiatpeBaseRequest {
            external_transaction_id: request_data.reference_id.clone(),
            mobile_number: request_data.customer_phone.clone().unwrap_or_default(),
            email: request_data.email.clone().unwrap_or_default(),
            name: request_data.customer_name.clone().unwrap_or_default(),
            return_url: request_data
                .return_url
                .clone()
                .map(|url| url.to_string())
                .unwrap_or_default(),
            base_amount: request_data.amount.clone(),
            processing_fee: "0".to_string(),
            gst_on_processing_fee: "0".to_string(),
            callback_url: request_data
                .webhook_url
                .clone()
                .map(|url| url.to_string())
                .unwrap_or_default(),
            udf1: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
        };

        let encoded_request = base64::encode(serde_json::to_string(&base_request)?);

        Ok(Self {
            request: encoded_request,
            access_token: Secret::new(request_data.access_token.clone().unwrap_or_default()),
            payment_mode: get_payment_mode(&item.payment_method_data)?,
            card_cvv: None,
            bank_code: None,
            card_number: None,
            payer_vpa: None,
            enable_upi_intent: None,
            card_expiry_date: None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct FiatpeBaseRequest {
    pub external_transaction_id: String,
    pub mobile_number: String,
    pub email: String,
    pub name: String,
    pub return_url: String,
    pub base_amount: StringMajorUnit,
    pub processing_fee: String,
    pub gst_on_processing_fee: String,
    pub callback_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf5: Option<String>,
}

fn get_payment_mode<T: PaymentMethodDataTypes>(
    payment_method_data: &T,
) -> Result<String, IntegrationError> {
    let pmt =
        serde_json::to_string(payment_method_data).map_err(|_| IntegrationError::InvalidData {
            field: "payment_method_data",
            reason: "Failed to serialize payment method data",
        })?;

    if pmt.contains("CreditCard") {
        Ok("CC".to_string())
    } else if pmt.contains("DebitCard") {
        Ok("DC".to_string())
    } else if pmt.contains("Upi") {
        Ok("UPI".to_string())
    } else if pmt.contains("NetBanking") {
        Ok("NB".to_string())
    } else {
        Err(IntegrationError::NotSupported {
            message: "Unsupported payment method",
        }
        .into())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiatpePaymentsResponse {
    pub response: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_string: Option<String>,
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<FiatpePaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FiatpePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let decoded_response = base64::decode(&item.response.response)?;
        let inner_response: FiatpeInnerResponse = serde_json::from_slice(&decoded_response)?;

        Ok(Self {
            response: Ok(PaymentsResponseData {
                connector_transaction_id: Some(inner_response.transaction_id),
                redirect_form: None,
                payment_method_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                charge_id: None,
                psync_res: None,
                capture_method: None,
                minor_amount: None,
                currency: None,
                status: map_fiatpe_status(&inner_response.status)?,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct FiatpeInnerResponse {
    pub transaction_id: String,
    pub status: String,
}

fn map_fiatpe_status(status: &str) -> Result<domain_types::enums::AttemptStatus, ConnectorError> {
    match status {
        "SUCCESS" => Ok(domain_types::enums::AttemptStatus::Charged),
        "PENDING" => Ok(domain_types::enums::AttemptStatus::Pending),
        "FAILED" => Ok(domain_types::enums::AttemptStatus::Failure),
        _ => Ok(domain_types::enums::AttemptStatus::Pending),
    }
}
