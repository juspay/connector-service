use crate::types::ResponseRouterData;
use base64::{engine::general_purpose::STANDARD, Engine};
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct WorldpayAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                username: api_key.to_owned(),
                password: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

impl WorldpayAuthType {
    pub fn generate_authorization_header(&self) -> String {
        let credentials = format!("{}:{}", self.username.peek(), self.password.peek());
        let encoded_credentials = STANDARD.encode(credentials);
        format!("Basic {}", encoded_credentials)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldpayErrorResponse {
    #[serde(rename = "errorName")]
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayPaymentsRequest {
    #[serde(rename = "transactionReference")]
    pub transaction_reference: String,
    pub merchant: WorldpayMerchant,
    pub instruction: WorldpayInstruction,
}

#[derive(Debug, Serialize)]
pub struct WorldpayMerchant {
    pub entity: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayInstruction {
    pub method: String,
    #[serde(rename = "paymentInstrument")]
    pub payment_instrument: WorldpayPaymentInstrument,
    pub narrative: WorldpayNarrative,
    pub value: WorldpayValue,
}

#[derive(Debug, Serialize)]
pub struct WorldpayPaymentInstrument {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(rename = "cardNumber")]
    pub card_number: Secret<String>,
    #[serde(rename = "cardHolderName")]
    pub card_holder_name: Option<Secret<String>>,
    #[serde(rename = "expiryDate")]
    pub expiry_date: WorldpayExpiryDate,
    pub cvc: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayExpiryDate {
    pub month: u8,
    pub year: u16,
}

#[derive(Debug, Serialize)]
pub struct WorldpayNarrative {
    pub line1: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayValue {
    pub amount: i64,
    pub currency: String,
}

impl<U: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<U>, PaymentsResponseData>,
    > for WorldpayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<U>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method_data = &item.request.payment_method_data;
        
        let payment_instrument = match payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                // Use Debug formatting as a fallback to get string representation
                // This works because Debug trait is guaranteed by PaymentMethodDataTypes
                let card_number_debug = format!("{:?}", card_data.card_number.0);
                // Remove any debug formatting artifacts like quotes
                let card_number_str = card_number_debug.trim_matches('"').to_string();

                WorldpayPaymentInstrument {
                    instrument_type: "plain".to_string(),
                    card_number: Secret::new(card_number_str),
                    card_holder_name: card_data.card_holder_name.clone(),
                    expiry_date: WorldpayExpiryDate {
                        month: card_data.card_exp_month.peek().parse::<u8>().map_err(|_| {
                            errors::ConnectorError::InvalidDataFormat {
                                field_name: "card_exp_month",
                            }
                        })?,
                        year: card_data.card_exp_year.peek().parse::<u16>().map_err(|_| {
                            errors::ConnectorError::InvalidDataFormat {
                                field_name: "card_exp_year",
                            }
                        })?,
                    },
                    cvc: Some(card_data.card_cvc.clone()),
                }
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Payment method".to_string())
                ))
            }
        };

        Ok(Self {
            transaction_reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            merchant: WorldpayMerchant {
                entity: "default".to_string(),
            },
            instruction: WorldpayInstruction {
                method: "card".to_string(),
                payment_instrument,
                narrative: WorldpayNarrative {
                    line1: "Payment".to_string(),
                },
                value: WorldpayValue {
                    amount: item.request.minor_amount.get_amount_as_i64(),
                    currency: item.request.currency.to_string(),
                },
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayPaymentsResponse {
    pub outcome: String,
    #[serde(rename = "transactionReference")]
    pub transaction_reference: String,
    #[serde(rename = "schemeReference")]
    pub scheme_reference: Option<String>,
    pub issuer: Option<WorldpayIssuer>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayIssuer {
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            WorldpayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.outcome.as_str() {
            "authorized" => AttemptStatus::Authorized,
            "sentForSettlement" => AttemptStatus::Charged,
            "refused" => AttemptStatus::Failure,
            "sentForCancellation" => AttemptStatus::Voided,
            "3dsDeviceDataRequired" | "3dsChallenged" => AttemptStatus::AuthenticationPending,
            "3dsAuthenticationFailed" | "3dsUnavailable" => AttemptStatus::AuthenticationFailed,
            "fraudHighRisk" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let scheme_reference = item.response.scheme_reference.clone();
        let transaction_reference = item.response.transaction_reference.clone();
        
        let connector_transaction_id = scheme_reference
            .clone()
            .unwrap_or_else(|| transaction_reference.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: scheme_reference,
                connector_response_reference_id: Some(transaction_reference),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
