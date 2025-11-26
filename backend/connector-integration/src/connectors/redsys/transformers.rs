use super::{requests, responses};
use base64::Engine;
use common_enums::AttemptStatus;
use common_utils::{
    crypto::{self, EncodeMessage, SignMessage},
    ext_traits::Encode,
};
use domain_types::{
    connector_flow::{Capture, PSync, PreAuthenticate, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsCaptureData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{self, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::connectors::redsys::RedsysRouterData;
use crate::types::ResponseRouterData;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
pub const SIGNATURE_VERSION: &str = "HMAC_SHA256_V1";
pub const DS_VERSION: &str = "0.0";
pub const XMLNS_WEB_URL: &str = "http://webservices.apl02.redsys.es";
pub const REDSYS_SOAP_ACTION: &str = "consultaOperaciones";

type Error = error_stack::Report<errors::ConnectorError>;

pub struct RedsysAuthType {
    pub(super) merchant_id: Secret<String>,
    pub(super) terminal_id: Secret<String>,
    pub(super) sha256_pwd: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RedsysTransaction {
    #[serde(rename = "Ds_SignatureVersion")]
    ds_signature_version: String,
    #[serde(rename = "Ds_MerchantParameters")]
    ds_merchant_parameters: Secret<String>,
    #[serde(rename = "Ds_Signature")]
    ds_signature: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for RedsysAuthType {
    type Error = Error;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } = auth_type
        {
            Ok(Self {
                merchant_id: api_key.to_owned(),
                terminal_id: key1.to_owned(),
                sha256_pwd: api_secret.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
        }
    }
}

fn des_encrypt(
    message: &str,
    key: &str,
) -> Result<Vec<u8>, error_stack::Report<errors::ConnectorError>> {
    let iv_array = [0u8; common_utils::crypto::TripleDesEde3CBC::TRIPLE_DES_IV_LENGTH];
    let iv = iv_array.to_vec();
    let key_bytes = BASE64_ENGINE
        .decode(key)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Base64 decoding failed")?;
    let triple_des = common_utils::crypto::TripleDesEde3CBC::new(
        Some(common_enums::CryptoPadding::ZeroPadding),
        iv,
    )
    .change_context(errors::ConnectorError::RequestEncodingFailed)
    .attach_printable("Triple DES encryption failed")?;
    let encrypted = triple_des
        .encode_message(&key_bytes, message.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Triple DES encryption failed")?;
    let expected_len =
        encrypted.len() - common_utils::crypto::TripleDesEde3CBC::TRIPLE_DES_IV_LENGTH;
    let encrypted_trimmed = encrypted
        .get(..expected_len)
        .ok_or(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Failed to trim encrypted data to the expected length")?;
    Ok(encrypted_trimmed.to_vec())
}

fn get_signature(
    order_id: &str,
    params: &str,
    key: &str,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    let secret_ko = des_encrypt(order_id, key)?;
    let result = crypto::HmacSha256::sign_message(
        &common_utils::crypto::HmacSha256,
        &secret_ko,
        params.as_bytes(),
    )
    .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    let encoded = BASE64_ENGINE.encode(result);
    Ok(encoded)
}

pub trait SignatureCalculationData {
    fn get_merchant_parameters(&self) -> Result<String, Error>;
    fn get_order_id(&self) -> String;
}

impl SignatureCalculationData for requests::RedsysPaymentRequest {
    fn get_merchant_parameters(&self) -> Result<String, Error> {
        self.encode_to_string_of_json()
            .change_context(errors::ConnectorError::RequestEncodingFailed)
    }

    fn get_order_id(&self) -> String {
        self.ds_merchant_order.clone()
    }
}

impl SignatureCalculationData for requests::RedsysOperationRequest {
    fn get_merchant_parameters(&self) -> Result<String, Error> {
        self.encode_to_string_of_json()
            .change_context(errors::ConnectorError::RequestEncodingFailed)
    }

    fn get_order_id(&self) -> String {
        self.ds_merchant_order.clone()
    }
}

impl<T> TryFrom<(&T, &RedsysAuthType)> for RedsysTransaction
where
    T: SignatureCalculationData,
{
    type Error = Error;
    fn try_from(data: (&T, &RedsysAuthType)) -> Result<Self, Self::Error> {
        let (request_data, auth) = data;
        let merchant_parameters = request_data.get_merchant_parameters()?;
        let ds_merchant_parameters = BASE64_ENGINE.encode(&merchant_parameters);
        let sha256_pwd = auth.sha256_pwd.clone().expose();
        let ds_merchant_order = request_data.get_order_id();
        let signature = get_signature(&ds_merchant_order, &ds_merchant_parameters, &sha256_pwd)?;
        Ok(Self {
            ds_signature_version: SIGNATURE_VERSION.to_string(),
            ds_merchant_parameters: Secret::new(ds_merchant_parameters),
            ds_signature: Secret::new(signature),
        })
    }
}

impl TryFrom<responses::DsResponse> for AttemptStatus {
    type Error = Error;

    fn try_from(ds_response: responses::DsResponse) -> Result<Self, Self::Error> {
        match ds_response.0.as_str() {
            code if code.starts_with("00") && code != "0002" => Ok(Self::Charged),
            "0900" => Ok(Self::Charged),
            "0400" | "0481" | "0940" | "9915" => Ok(Self::Voided),
            "0950" => Ok(Self::VoidFailed),
            "0112" | "0195" | "8210" | "8220" | "9998" | "9999" => Ok(Self::AuthenticationPending),
            "0129" | "0184" | "9256" | "9257" => Ok(Self::AuthenticationFailed),
            "0107" | "0300" => Ok(Self::Pending),
            unknown_status => Err(errors::ConnectorError::ResponseHandlingFailed)
                .attach_printable(format!(
                    "Received unknown payment status: {}",
                    unknown_status
                ))?,
        }
    }
}

impl TryFrom<responses::DsResponse> for common_enums::RefundStatus {
    type Error = Error;
    fn try_from(ds_response: responses::DsResponse) -> Result<Self, Self::Error> {
        match ds_response.0.as_str() {
            "0900" => Ok(Self::Success),
            "9999" => Ok(Self::Pending),
            "0950" | "0172" | "174" => Ok(Self::Failure),
            unknown_status => Err(errors::ConnectorError::ResponseHandlingFailed)
                .attach_printable(format!("Received unknown refund status:{unknown_status}"))?,
        }
    }
}

impl<T>
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for requests::RedsysPreAuthenticateRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
    T::Inner: Clone,
{
    type Error = Error;

    fn try_from(
        item: RedsysRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = RedsysAuthType::try_from(&router_data.connector_auth_type)?;
        let payment_method_data = router_data.request.payment_method_data.as_ref().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            },
        )?;

        let card = match payment_method_data {
            payment_method_data::PaymentMethodData::Card(card_data) => Ok(card_data),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only card payments are supported".to_string(),
            )),
        }?;

        let currency =
            router_data
                .request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?;

        let ds_merchant_order = if router_data
            .resource_common_data
            .connector_request_reference_id
            .len()
            <= 12
        {
            Ok(router_data
                .resource_common_data
                .connector_request_reference_id
                .clone())
        } else {
            Err(errors::ConnectorError::RequestEncodingFailed).attach_printable(
                "Connector request reference id length should be less than or equal to 12",
            )
        }?;

        let payment_request = requests::RedsysPaymentRequest {
            ds_merchant_amount: crate::connectors::redsys::RedsysAmountConvertor::convert(
                router_data.request.amount,
                currency,
            )?,
            ds_merchant_currency: currency.iso_4217().to_owned(),
            ds_merchant_emv3ds: Some(requests::RedsysEmvThreeDsRequestData {
                three_d_s_info: requests::RedsysThreeDsInfo::CardData,
                protocol_version: None,
                browser_accept_header: None,
                browser_user_agent: None,
                browser_java_enabled: None,
                browser_javascript_enabled: None,
                browser_language: None,
                browser_color_depth: None,
                browser_screen_height: None,
                browser_screen_width: None,
                browser_t_z: None,
                browser_i_p: None,
                three_d_s_server_trans_i_d: None,
                notification_u_r_l: None,
                three_d_s_comp_ind: None,
                cres: None,
                billing_data: None,
                shipping_data: None,
            }),
            ds_merchant_expirydate: Secret::new(format!(
                "{}{}",
                card.card_exp_year.peek(),
                card.card_exp_month.peek()
            )),
            ds_merchant_merchantcode: auth.merchant_id.clone(),
            ds_merchant_order,
            ds_merchant_pan: cards::CardNumber::try_from(card.card_number.peek().to_string())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Invalid card number")?,
            ds_merchant_terminal: auth.terminal_id.clone(),
            ds_merchant_transactiontype: requests::RedsysTransactionType::Payment,
            ds_merchant_cvv2: card.card_cvc.clone(),
        };

        let transaction = RedsysTransaction::try_from((&payment_request, &auth))?;
        Ok(transaction)
    }
}

impl<T>
    TryFrom<
        RedsysRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for requests::RedsysCaptureRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = Error;

    fn try_from(
        item: RedsysRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = RedsysAuthType::try_from(&router_data.connector_auth_type)?;
        let connector_transaction_id = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => Ok(id.clone()),
            _ => Err(errors::ConnectorError::MissingConnectorTransactionID),
        }?;

        let amount_to_capture =
            common_utils::types::MinorUnit::new(router_data.request.amount_to_capture);

        let capture_request = requests::RedsysOperationRequest {
            ds_merchant_order: connector_transaction_id,
            ds_merchant_merchantcode: auth.merchant_id.clone(),
            ds_merchant_terminal: auth.terminal_id.clone(),
            ds_merchant_currency: router_data.request.currency.iso_4217().to_owned(),
            ds_merchant_transactiontype: requests::RedsysTransactionType::Confirmation,
            ds_merchant_amount: crate::connectors::redsys::RedsysAmountConvertor::convert(
                amount_to_capture,
                router_data.request.currency,
            )?,
        };

        let transaction = RedsysTransaction::try_from((&capture_request, &auth))?;
        Ok(transaction)
    }
}

impl<T>
    TryFrom<
        RedsysRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for requests::RedsysVoidRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = Error;

    fn try_from(
        item: RedsysRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = RedsysAuthType::try_from(&router_data.connector_auth_type)?;
        let connector_transaction_id = router_data.request.connector_transaction_id.clone();
        let currency =
            router_data
                .request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?;
        let amount =
            router_data
                .request
                .amount
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "amount",
                })?;

        let void_request = requests::RedsysOperationRequest {
            ds_merchant_order: connector_transaction_id,
            ds_merchant_merchantcode: auth.merchant_id.clone(),
            ds_merchant_terminal: auth.terminal_id.clone(),
            ds_merchant_currency: currency.iso_4217().to_owned(),
            ds_merchant_transactiontype: requests::RedsysTransactionType::Cancellation,
            ds_merchant_amount: crate::connectors::redsys::RedsysAmountConvertor::convert(
                amount, currency,
            )?,
        };

        let transaction = RedsysTransaction::try_from((&void_request, &auth))?;
        Ok(transaction)
    }
}

impl<T>
    TryFrom<
        RedsysRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for requests::RedsysRefundRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = Error;

    fn try_from(
        item: RedsysRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = RedsysAuthType::try_from(&router_data.connector_auth_type)?;
        let refund_amount = common_utils::types::MinorUnit::new(router_data.request.refund_amount);

        let refund_request = requests::RedsysOperationRequest {
            ds_merchant_order: router_data.request.connector_transaction_id.clone(),
            ds_merchant_merchantcode: auth.merchant_id.clone(),
            ds_merchant_terminal: auth.terminal_id.clone(),
            ds_merchant_currency: router_data.request.currency.iso_4217().to_owned(),
            ds_merchant_transactiontype: requests::RedsysTransactionType::Refund,
            ds_merchant_amount: crate::connectors::redsys::RedsysAmountConvertor::convert(
                refund_amount,
                router_data.request.currency,
            )?,
        };

        let transaction = RedsysTransaction::try_from((&refund_request, &auth))?;
        Ok(transaction)
    }
}

fn to_connector_response_data<T>(connector_response: &str) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    let decoded_bytes = BASE64_ENGINE
        .decode(connector_response)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        .attach_printable("Failed to decode Base64")?;

    let response_data: T = serde_json::from_slice(&decoded_bytes)
        .change_context(errors::ConnectorError::ResponseHandlingFailed)?;

    Ok(response_data)
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        PreAuthenticate,
        PaymentFlowData,
        PaymentsPreAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            responses::RedsysResponse::RedsysResponse(ref transaction) => {
                let response_data: responses::RedsysPaymentsResponse = to_connector_response_data(
                    &transaction.ds_merchant_parameters.clone().expose(),
                )?;

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: AttemptStatus::AuthenticationPending,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::PreAuthenticateResponse {
                        redirection_data: None,
                        connector_response_reference_id: Some(response_data.ds_order),
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            responses::RedsysResponse::RedsysErrorResponse(ref err) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: err.error_code.clone(),
                    message: err.error_code.clone(),
                    reason: Some(err.error_code.clone()),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..item.router_data
            }),
        }
    }
}

impl
    TryFrom<
        ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            responses::RedsysResponse::RedsysResponse(ref transaction) => {
                let response_data: responses::RedsysOperationsResponse =
                    to_connector_response_data(
                        &transaction.ds_merchant_parameters.clone().expose(),
                    )?;

                let attempt_status = AttemptStatus::try_from(response_data.ds_response.clone())?;

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: attempt_status,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.ds_order.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: Some(response_data.ds_order),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            responses::RedsysResponse::RedsysErrorResponse(ref err) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: err.error_code.clone(),
                    message: err.error_code.clone(),
                    reason: Some(err.error_code.clone()),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..item.router_data
            }),
        }
    }
}

impl
    TryFrom<
        ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            responses::RedsysResponse::RedsysResponse(ref transaction) => {
                let response_data: responses::RedsysOperationsResponse =
                    to_connector_response_data(
                        &transaction.ds_merchant_parameters.clone().expose(),
                    )?;

                let attempt_status = AttemptStatus::try_from(response_data.ds_response.clone())?;

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: attempt_status,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.ds_order.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: Some(response_data.ds_order),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    }),
                    ..item.router_data
                })
            }
            responses::RedsysResponse::RedsysErrorResponse(ref err) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::VoidFailed,
                    ..item.router_data.resource_common_data
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    code: err.error_code.clone(),
                    message: err.error_code.clone(),
                    reason: Some(err.error_code.clone()),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..item.router_data
            }),
        }
    }
}

impl
    TryFrom<
        ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = match item.response {
            responses::RedsysResponse::RedsysResponse(ref transaction) => {
                let response_data: responses::RedsysOperationsResponse =
                    to_connector_response_data(
                        &transaction.ds_merchant_parameters.clone().expose(),
                    )?;

                let refund_status =
                    common_enums::RefundStatus::try_from(response_data.ds_response.clone())?;

                Ok(RefundsResponseData {
                    connector_refund_id: response_data.ds_order,
                    refund_status,
                    status_code: item.http_code,
                })
            }
            responses::RedsysResponse::RedsysErrorResponse(ref err) => {
                Err(domain_types::router_data::ErrorResponse {
                    code: err.error_code.clone(),
                    message: err.error_code.clone(),
                    reason: Some(err.error_code.clone()),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                })
            }
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

pub fn get_transaction_type(
    status: AttemptStatus,
    capture_method: Option<common_enums::CaptureMethod>,
) -> Result<String, errors::ConnectorError> {
    match status {
        AttemptStatus::AuthenticationPending
        | AttemptStatus::AuthenticationSuccessful
        | AttemptStatus::Started
        | AttemptStatus::Authorizing
        | AttemptStatus::Authorized
        | AttemptStatus::DeviceDataCollectionPending => match capture_method {
            Some(common_enums::CaptureMethod::Automatic) | None => Ok("0".to_owned()),
            Some(common_enums::CaptureMethod::Manual) => Ok("1".to_owned()),
            Some(capture_method) => Err(errors::ConnectorError::NotSupported {
                message: capture_method.to_string(),
                connector: "redsys",
            }),
        },
        AttemptStatus::VoidInitiated => Ok("9".to_owned()),
        AttemptStatus::PartialChargedAndChargeable | AttemptStatus::CaptureInitiated => {
            Ok("2".to_owned())
        }
        AttemptStatus::Pending => match capture_method {
            Some(common_enums::CaptureMethod::Automatic) | None => Ok("0".to_owned()),
            Some(common_enums::CaptureMethod::Manual) => Ok("2".to_owned()),
            Some(capture_method) => Err(errors::ConnectorError::NotSupported {
                message: capture_method.to_string(),
                connector: "redsys",
            }),
        },
        other_attempt_status => Err(errors::ConnectorError::NotSupported {
            message: format!("Payment sync after terminal status: {other_attempt_status} payment"),
            connector: "redsys",
        }),
    }
}

pub fn construct_sync_request(
    order_id: String,
    transaction_type: String,
    auth: RedsysAuthType,
) -> Result<Vec<u8>, Error> {
    let transaction_data = requests::RedsysSyncRequest {
        ds_merchant_code: auth.merchant_id,
        ds_terminal: auth.terminal_id,
        ds_transaction_type: transaction_type,
        ds_order: order_id.clone(),
    };

    let version = requests::RedsysVersionData {
        ds_version: DS_VERSION.to_owned(),
        message: requests::Message {
            transaction: transaction_data,
        },
    };

    let version_data = quick_xml::se::to_string(&version)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

    let signature = get_signature(&order_id, &version_data, auth.sha256_pwd.peek())?;

    let messages = requests::Messages {
        version,
        signature,
        signature_version: SIGNATURE_VERSION.to_owned(),
    };

    let cdata = quick_xml::se::to_string(&messages)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

    let body = format!(
        r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="{}"><soapenv:Header/><soapenv:Body><web:consultaOperaciones><cadenaXML><![CDATA[{}]]></cadenaXML></web:consultaOperaciones></soapenv:Body></soapenv:Envelope>"#,
        XMLNS_WEB_URL, cdata
    );

    Ok(body.as_bytes().to_vec())
}

impl
    TryFrom<
        ResponseRouterData<
            responses::RedsysSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let message_data = item
            .response
            .body
            .consultaoperacionesresponse
            .consultaoperacionesreturn
            .messages
            .version
            .message;

        let (status, response) = match (message_data.response, message_data.errormsg) {
            (Some(response), None) => {
                if let Some(ds_response) = response.ds_response {
                    let attempt_status = AttemptStatus::try_from(ds_response.clone())?;

                    let payment_response = Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(response.ds_order.clone()),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: Some(response.ds_order.clone()),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    });
                    (attempt_status, payment_response)
                } else {
                    let payment_response = Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(response.ds_order.clone()),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: Some(response.ds_order.clone()),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    });

                    (
                        item.router_data.resource_common_data.status,
                        payment_response,
                    )
                }
            }
            (None, Some(errormsg)) => {
                let error_code = errormsg.ds_errorcode.clone();
                let response = Err(domain_types::router_data::ErrorResponse {
                    code: error_code.clone(),
                    message: error_code.clone(),
                    reason: Some(error_code),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
                (item.router_data.resource_common_data.status, response)
            }
            (Some(_), Some(_)) | (None, None) => {
                Err(errors::ConnectorError::ResponseHandlingFailed)?
            }
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            responses::RedsysSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let message_data = item
            .response
            .body
            .consultaoperacionesresponse
            .consultaoperacionesreturn
            .messages
            .version
            .message;

        let response = match (message_data.response, message_data.errormsg) {
            (None, Some(errormsg)) => {
                let error_code = errormsg.ds_errorcode.clone();
                Err(domain_types::router_data::ErrorResponse {
                    code: error_code.clone(),
                    message: error_code.clone(),
                    reason: Some(error_code),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                })
            }
            (Some(response), None) => {
                if let Some(ds_response) = response.ds_response {
                    let refund_status = common_enums::RefundStatus::try_from(ds_response.clone())?;

                    Ok(RefundsResponseData {
                        connector_refund_id: response.ds_order,
                        refund_status,
                        status_code: item.http_code,
                    })
                } else {
                    Ok(RefundsResponseData {
                        connector_refund_id: response.ds_order,
                        refund_status: common_enums::RefundStatus::Pending,
                        status_code: item.http_code,
                    })
                }
            }
            (Some(_), Some(_)) | (None, None) => {
                Err(errors::ConnectorError::ResponseHandlingFailed)?
            }
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}
