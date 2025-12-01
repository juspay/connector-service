use super::{requests, responses};
use base64::Engine;
use common_enums::AttemptStatus;
use common_utils::{
    crypto::{self, EncodeMessage, SignMessage},
    ext_traits::Encode,
};
use domain_types::{
    connector_flow::{
        Authenticate, Capture, PSync, PostAuthenticate, PreAuthenticate, RSync, Refund, Void,
    },
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthenticateData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{self, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::connectors::redsys::RedsysRouterData;
use crate::types::ResponseRouterData;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
pub const SIGNATURE_VERSION: &str = "HMAC_SHA256_V1";
pub const DS_VERSION: &str = "0.0";
pub const XMLNS_WEB_URL: &str = "http://webservices.apl02.redsys.es";
pub const REDSYS_SOAP_ACTION: &str = "consultaOperaciones";

type Error = error_stack::Report<errors::ConnectorError>;

fn get_redsys_attempt_status(
    ds_response: responses::DsResponse,
    capture_method: Option<common_enums::CaptureMethod>,
) -> Result<AttemptStatus, Error> {
    // Redsys consistently provides a 4-digit response code, where numbers ranging from 0000 to 0099 indicate successful transactions
    if ds_response.0.starts_with("00") && ds_response.0.as_str() != "0002" {
        match capture_method {
            Some(common_enums::CaptureMethod::Automatic) | None => Ok(AttemptStatus::Charged),
            Some(common_enums::CaptureMethod::Manual) => Ok(AttemptStatus::Authorized),
            _ => Err(errors::ConnectorError::CaptureMethodNotSupported.into()),
        }
    } else {
        match ds_response.0.as_str() {
            "0900" => Ok(AttemptStatus::Charged),
            "0400" | "0481" | "0940" | "9915" => Ok(AttemptStatus::Voided),
            "0950" => Ok(AttemptStatus::VoidFailed),
            "0112" | "0195" | "8210" | "8220" | "9998" | "9999" => {
                Ok(AttemptStatus::AuthenticationPending)
            }
            "0129" | "0184" | "9256" | "9257" => Ok(AttemptStatus::AuthenticationFailed),
            "0107" | "0300" => Ok(AttemptStatus::Pending),
            "0101" | "0102" | "0104" | "0106" | "0110" | "0114" | "0115" | "0116" | "0117"
            | "0118" | "0121" | "0123" | "0125" | "0126" | "0130" | "0162" | "0163" | "0171"
            | "0172" | "0173" | "0174" | "0180" | "0181" | "0182" | "0187" | "0190" | "0191"
            | "0193" | "0201" | "0202" | "0204" | "0206" | "0290" | "0881" | "0904" | "0909"
            | "0912" | "0913" | "0941" | "0944" | "0945" | "0965" | "9912" | "9064" | "9078"
            | "9093" | "9094" | "9104" | "9218" | "9253" | "9261" | "9997" | "0002" => {
                Ok(AttemptStatus::Failure)
            }
            error => Err(errors::ConnectorError::ResponseHandlingFailed)
                .attach_printable(format!("Received Unknown Status:{error}"))?,
        }
    }
}

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

        if !router_data.request.enrolled_for_3ds {
            return Err(errors::ConnectorError::NotSupported {
                message: "Non-3DS payments".to_string(),
                connector: "redsys",
            })?;
        }

        if router_data.resource_common_data.auth_type != common_enums::AuthenticationType::ThreeDs {
            return Err(errors::ConnectorError::NotSupported {
                message: format!(
                    "Authentication type {:?}",
                    router_data.resource_common_data.auth_type
                ),
                connector: "redsys",
            })?;
        }

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

        let billing_data = requests::RedsysBillingData::try_from_address(
            router_data.resource_common_data.get_optional_billing(),
        )?;
        let shipping_data = requests::RedsysShippingData::try_from_address(
            router_data.resource_common_data.get_optional_shipping(),
        )?;

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
                billing_data,
                shipping_data,
            }),
            ds_merchant_expirydate: Secret::new(format!(
                "{}{}",
                card.get_card_expiry_year_2_digit()?.peek(),
                card.card_exp_month.peek()
            )),
            ds_merchant_merchantcode: auth.merchant_id.clone(),
            ds_merchant_order,
            ds_merchant_pan: cards::CardNumber::try_from(card.card_number.peek().to_string())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Invalid card number")?,
            ds_merchant_terminal: auth.terminal_id.clone(),
            ds_merchant_transactiontype: if router_data.request.is_auto_capture()? {
                requests::RedsysTransactionType::Payment
            } else {
                requests::RedsysTransactionType::Preauthorization
            },
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

                let redirection_data = if let Some(ref emv3ds) = response_data.ds_emv3ds {
                    let three_d_s_server_trans_i_d = emv3ds
                        .three_d_s_server_trans_i_d
                        .clone()
                        .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;

                    if let Some(ref three_ds_method_url) = emv3ds.three_d_s_method_u_r_l {
                        let three_d_s_method_notification_u_r_l =
                            item.router_data.request.get_webhook_url()?;

                        let threeds_invoke_request = requests::RedsysThreedsInvokeRequest {
                            three_d_s_server_trans_i_d: three_d_s_server_trans_i_d.clone(),
                            three_d_s_method_notification_u_r_l,
                        };

                        // Encode to JSON then Base64
                        use common_utils::ext_traits::Encode;
                        let three_ds_data_string = threeds_invoke_request
                            .encode_to_string_of_json()
                            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

                        let three_ds_method_data = BASE64_ENGINE.encode(&three_ds_data_string);

                        let mut form_fields = std::collections::HashMap::new();
                        form_fields.insert("threeDSMethodData".to_string(), three_ds_method_data);

                        Some(Box::new(
                            domain_types::router_response_types::RedirectForm::Form {
                                endpoint: three_ds_method_url.clone(),
                                method: common_utils::request::Method::Post,
                                form_fields,
                            },
                        ))
                    } else {
                        // Exempt flow: no redirection
                        None
                    }
                } else {
                    None
                };

                // Extract three_d_s_server_trans_i_d for response_ref_id
                let response_ref_id = response_data
                    .ds_emv3ds
                    .as_ref()
                    .and_then(|emv3ds| emv3ds.three_d_s_server_trans_i_d.clone());

                // Extract protocol_version and store in connector_meta_data
                let connector_meta_data = if let Some(emv3ds) = response_data.ds_emv3ds.as_ref() {
                    let mut meta_data = item
                        .router_data
                        .resource_common_data
                        .connector_meta_data
                        .clone()
                        .and_then(|secret| secret.expose().as_object().cloned())
                        .unwrap_or_default();
                    meta_data.insert(
                        "version".to_string(),
                        serde_json::json!(emv3ds.protocol_version),
                    );
                    Some(Secret::new(serde_json::Value::Object(meta_data)))
                } else {
                    item.router_data
                        .resource_common_data
                        .connector_meta_data
                        .clone()
                };

                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: AttemptStatus::AuthenticationPending,
                        connector_meta_data,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(PaymentsResponseData::PreAuthenticateResponse {
                        redirection_data,
                        connector_response_reference_id: response_ref_id,
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

impl<T>
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for requests::RedsysAuthenticateRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
    T::Inner: Clone,
{
    type Error = Error;

    fn try_from(
        item: RedsysRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = RedsysAuthType::try_from(&router_data.connector_auth_type)?;

        // Get ds_merchant_order from connector_request_reference_id
        // In UCS: this is populated from request_ref_id in the proto request
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
                "connector_request_reference_id length should be less than or equal to 12 for Redsys ds_merchant_order",
            )
        }?;

        // Get threeDSServerTransID and message_version
        // First try from authentication_data, if not available, construct from connector_meta_data
        let (three_d_s_server_trans_i_d, message_version) =
            if let Some(auth_data) = &router_data.request.authentication_data {
                // authentication_data is already populated
                let trans_id = auth_data.threeds_server_transaction_id.clone().ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "authentication_data.threeds_server_transaction_id",
                    },
                )?;
                let version = auth_data.message_version.clone().ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "authentication_data.message_version",
                    },
                )?;
                (trans_id, version)
            } else {
                // Extract from connector_meta_data (stored by PreAuthenticate)
                let connector_meta = router_data
                    .resource_common_data
                    .connector_meta_data
                    .as_ref()
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_meta_data",
                    })?;

                let meta_value = connector_meta.clone().expose();
                let meta_obj = meta_value
                    .as_object()
                    .ok_or(errors::ConnectorError::ParsingFailed)?;

                // Get threeds_server_transaction_id from reference_id (stored by PreAuthenticate as connector_response_reference_id)
                let trans_id = router_data
                    .resource_common_data
                    .reference_id
                    .clone()
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "reference_id (threeds_server_transaction_id)",
                    })?;

                // Get version from connector_meta_data and convert to SemanticVersion
                let version_str = meta_obj.get("version").and_then(|v| v.as_str()).ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_meta_data.version",
                    },
                )?;

                let version = common_utils::types::SemanticVersion::from_str(version_str)
                    .change_context(errors::ConnectorError::ParsingFailed)
                    .attach_printable("Failed to parse version from connector_meta_data")?;

                (trans_id, version)
            };

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

        let billing_data = requests::RedsysBillingData::try_from_address(
            router_data.resource_common_data.get_optional_billing(),
        )?;
        let shipping_data = requests::RedsysShippingData::try_from_address(
            router_data.resource_common_data.get_optional_shipping(),
        )?;

        // Get notification URL (complete_authorize_url for Redsys to send authentication results)
        let notification_url = router_data
            .request
            .continue_redirection_url
            .as_ref()
            .map(|url| url.to_string());

        let emv3ds_data = requests::RedsysEmvThreeDsRequestData {
            three_d_s_info: requests::RedsysThreeDsInfo::AuthenticationData,
            protocol_version: Some(message_version.to_string()),
            three_d_s_server_trans_i_d: Some(three_d_s_server_trans_i_d),
            notification_u_r_l: notification_url,
            browser_accept_header: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.accept_header.clone()),
            browser_user_agent: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.user_agent.clone().map(Secret::new)),
            browser_java_enabled: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.java_enabled),
            browser_javascript_enabled: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.java_script_enabled),
            browser_language: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.language.clone()),
            browser_color_depth: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.color_depth.map(|d| d.to_string())),
            browser_screen_height: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.screen_height.map(|h| h.to_string())),
            browser_screen_width: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.screen_width.map(|w| w.to_string())),
            browser_t_z: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.time_zone.map(|tz| tz.to_string())),
            browser_i_p: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|b| b.ip_address.map(|ip| Secret::new(ip.to_string()))),
            three_d_s_comp_ind: Some(requests::RedsysThreeDSCompInd::N),
            billing_data,
            shipping_data,
            cres: None,
        };

        let payment_request = requests::RedsysPaymentRequest {
            ds_merchant_amount: crate::connectors::redsys::RedsysAmountConvertor::convert(
                router_data.request.amount,
                currency,
            )?,
            ds_merchant_currency: currency.iso_4217().to_owned(),
            ds_merchant_emv3ds: Some(emv3ds_data),
            ds_merchant_expirydate: Secret::new(format!(
                "{}{}",
                card.get_card_expiry_year_2_digit()?.peek(),
                card.card_exp_month.peek()
            )),
            ds_merchant_merchantcode: auth.merchant_id.clone(),
            ds_merchant_order,
            ds_merchant_pan: cards::CardNumber::try_from(card.card_number.peek().to_string())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Invalid card number")?,
            ds_merchant_terminal: auth.terminal_id.clone(),
            ds_merchant_transactiontype: if router_data.request.is_auto_capture()? {
                requests::RedsysTransactionType::Payment
            } else {
                requests::RedsysTransactionType::Preauthorization
            },
            ds_merchant_cvv2: card.card_cvc.clone(),
        };

        let transaction = RedsysTransaction::try_from((&payment_request, &auth))?;
        Ok(transaction)
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        Authenticate,
        PaymentFlowData,
        PaymentsAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            responses::RedsysResponse::RedsysResponse(ref transaction) => {
                let response_data: responses::RedsysPaymentsResponse = to_connector_response_data(
                    &transaction.ds_merchant_parameters.clone().expose(),
                )?;

                // Build authentication_data from version and threeDSServerTransID
                // This will be passed to PostAuthenticate flow

                // Get message_version: first try from request's authentication_data,
                // if not available, extract from connector_meta_data
                let message_version = if let Some(auth_data) =
                    &item.router_data.request.authentication_data
                {
                    auth_data.message_version.clone()
                } else {
                    // Extract from connector_meta_data (stored by PreAuthenticate)
                    item.router_data
                        .resource_common_data
                        .connector_meta_data
                        .as_ref()
                        .and_then(|meta| {
                            let meta_value = meta.clone().expose();
                            meta_value
                                .as_object()
                                .and_then(|obj| obj.get("version"))
                                .and_then(|v| v.as_str())
                                .and_then(|version_str| {
                                    common_utils::types::SemanticVersion::from_str(version_str).ok()
                                })
                        })
                };

                let authentication_data =
                    Some(domain_types::router_request_types::AuthenticationData {
                        threeds_server_transaction_id: Some(
                            item.router_data
                                .resource_common_data
                                .reference_id
                                .clone()
                                .ok_or(errors::ConnectorError::MissingRequiredField {
                                    field_name: "reference_id (threeDSServerTransID)",
                                })?,
                        ),
                        message_version,
                        trans_status: None,
                        eci: None,
                        cavv: None,
                        ucaf_collection_indicator: None,
                        ds_trans_id: None,
                        acs_transaction_id: None,
                        transaction_id: None,
                    });

                // Check for frictionless authentication (ds_response exists)
                if let Some(ds_response) = response_data.ds_response {
                    let status = get_redsys_attempt_status(
                        ds_response.clone(),
                        item.router_data.request.capture_method,
                    )?;

                    // Frictionless authentication completed
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            connector_meta_data: item
                                .router_data
                                .resource_common_data
                                .connector_meta_data,
                            ..item.router_data.resource_common_data
                        },
                        response: Ok(PaymentsResponseData::AuthenticateResponse {
                            redirection_data: None,
                            authentication_data,
                            connector_response_reference_id: Some(response_data.ds_order),
                            status_code: item.http_code,
                        }),
                        ..item.router_data
                    })
                } else {
                    // Challenge authentication required (check for acs_url and creq)
                    let redirection_data = response_data
                        .ds_emv3ds
                        .as_ref()
                        .and_then(|emv3ds| {
                            emv3ds.acs_u_r_l.as_ref().and_then(|acs_url| {
                                emv3ds
                                    .creq
                                    .as_ref()
                                    .map(|creq| build_threeds_form(acs_url, creq))
                            })
                        })
                        .transpose()?;

                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status: AttemptStatus::AuthenticationPending,
                            connector_meta_data: item
                                .router_data
                                .resource_common_data
                                .connector_meta_data,
                            ..item.router_data.resource_common_data
                        },
                        response: Ok(PaymentsResponseData::AuthenticateResponse {
                            redirection_data: redirection_data.map(Box::new),
                            authentication_data,
                            connector_response_reference_id: Some(response_data.ds_order),
                            status_code: item.http_code,
                        }),
                        ..item.router_data
                    })
                }
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

impl<T>
    TryFrom<
        RedsysRouterData<
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for requests::RedsysPostAuthenticateRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
    T::Inner: Clone,
{
    type Error = Error;

    fn try_from(
        item: RedsysRouterData<
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = RedsysAuthType::try_from(&router_data.connector_auth_type)?;

        // Get ds_merchant_order from connector_request_reference_id (same as Authenticate flow)
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
                "connector_request_reference_id length should be less than or equal to 12 for Redsys ds_merchant_order",
            )
        }?;

        // Get authentication data from Authenticate flow response (always present)
        let auth_data = router_data.request.authentication_data.as_ref().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "authentication_data (from Authenticate flow)",
            },
        )?;

        // Get threeDSServerTransID from authentication_data
        // Note: This is used as directory_server_id in 3DS Method scenario
        let three_d_s_server_trans_i_d = auth_data.threeds_server_transaction_id.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "threeds_server_transaction_id in authentication_data",
            },
        )?;

        // Get protocol version from authentication_data (populated by Authenticate flow)
        let message_version = auth_data
            .message_version
            .as_ref()
            .map(|v| v.to_string())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "message_version in authentication_data",
            })?;

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

        let billing_data = requests::RedsysBillingData::try_from_address(
            router_data.resource_common_data.get_optional_billing(),
        )?;
        let shipping_data = requests::RedsysShippingData::try_from_address(
            router_data.resource_common_data.get_optional_shipping(),
        )?;

        // Check if this is a challenge response (has cres) or 3DS Method completion (no cres)
        let redirect_response = router_data
            .request
            .redirect_response
            .as_ref()
            .and_then(|resp| resp.params.clone());

        // Build EMV3DS data based on scenario
        let emv3ds_data = if let Some(redirect_params) = redirect_response {
            // ========================================
            // Scenario A: Challenge Response (has cres)
            // ========================================
            let cres = redirect_params.expose();

            requests::RedsysEmvThreeDsRequestData {
                three_d_s_info: requests::RedsysThreeDsInfo::ChallengeResponse,
                protocol_version: Some(message_version.clone()),
                cres: Some(cres),
                three_d_s_server_trans_i_d: None,
                notification_u_r_l: None,
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
                three_d_s_comp_ind: None,
                billing_data,
                shipping_data,
            }
        } else {
            let three_d_s_comp_ind = requests::RedsysThreeDSCompInd::N;

            // Get notification URL (complete_authorize_url for Redsys to send authentication results)
            let notification_url = router_data
                .request
                .continue_redirection_url
                .as_ref()
                .map(|url| url.to_string());

            requests::RedsysEmvThreeDsRequestData {
                three_d_s_info: requests::RedsysThreeDsInfo::AuthenticationData,
                protocol_version: Some(message_version.clone()),
                three_d_s_server_trans_i_d: Some(three_d_s_server_trans_i_d.clone()), // From authentication_data
                notification_u_r_l: notification_url,
                browser_accept_header: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.accept_header.clone()),
                browser_user_agent: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.user_agent.clone().map(Secret::new)),
                browser_java_enabled: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.java_enabled),
                browser_javascript_enabled: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.java_script_enabled),
                browser_language: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.language.clone()),
                browser_color_depth: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.color_depth.map(|d| d.to_string())),
                browser_screen_height: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.screen_height.map(|h| h.to_string())),
                browser_screen_width: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.screen_width.map(|w| w.to_string())),
                browser_t_z: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.time_zone.map(|tz| tz.to_string())),
                browser_i_p: router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|b| b.ip_address.map(|ip| Secret::new(ip.to_string()))),
                three_d_s_comp_ind: Some(three_d_s_comp_ind),
                cres: None,
                billing_data,
                shipping_data,
            }
        };

        let payment_request = requests::RedsysPaymentRequest {
            ds_merchant_amount: crate::connectors::redsys::RedsysAmountConvertor::convert(
                router_data.request.amount,
                currency,
            )?,
            ds_merchant_currency: currency.iso_4217().to_owned(),
            ds_merchant_emv3ds: Some(emv3ds_data),
            ds_merchant_expirydate: Secret::new(format!(
                "{}{}",
                card.get_card_expiry_year_2_digit()?.peek(),
                card.card_exp_month.peek()
            )),
            ds_merchant_merchantcode: auth.merchant_id.clone(),
            ds_merchant_order,
            ds_merchant_pan: cards::CardNumber::try_from(card.card_number.peek().to_string())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Invalid card number")?,
            ds_merchant_terminal: auth.terminal_id.clone(),
            ds_merchant_transactiontype: if router_data.request.is_auto_capture()? {
                requests::RedsysTransactionType::Payment
            } else {
                requests::RedsysTransactionType::Preauthorization
            },
            ds_merchant_cvv2: card.card_cvc.clone(),
        };

        let transaction = RedsysTransaction::try_from((&payment_request, &auth))?;
        Ok(transaction)
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        PostAuthenticate,
        PaymentFlowData,
        PaymentsPostAuthenticateData<T>,
        PaymentsResponseData,
    >
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            responses::RedsysResponse,
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            responses::RedsysResponse::RedsysResponse(ref transaction) => {
                let response_data: responses::RedsysPaymentsResponse = to_connector_response_data(
                    &transaction.ds_merchant_parameters.clone().expose(),
                )?;

                if let Some(ds_response) = response_data.ds_response {
                    let attempt_status = AttemptStatus::try_from(ds_response.clone())?;

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
                } else {
                    Err(errors::ConnectorError::ResponseHandlingFailed)
                        .attach_printable("Missing ds_response in final payment result")?
                }
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

// Helper implementations for address data conversion
impl requests::RedsysBillingData {
    pub fn try_from_address(
        address: Option<&domain_types::payment_address::Address>,
    ) -> Result<Option<Self>, domain_types::errors::ConnectorError> {
        match address {
            Some(addr) => {
                let address_details = addr.address.as_ref();
                if let Some(details) = address_details {
                    // Apply state code mapping (converts long names to short codes)
                    let state = details.state.as_ref().and_then(|state_val| {
                        let state_str = state_val.peek();
                        domain_types::utils::convert_spain_state_to_code(state_str)
                            .ok()
                            .map(Secret::new)
                    });

                    Ok(Some(Self {
                        bill_addr_city: details.city.clone(),
                        bill_addr_country: details.country.map(|c| c.to_string()),
                        bill_addr_line1: details.line1.clone(),
                        bill_addr_line2: details.line2.clone(),
                        bill_addr_line3: details.line3.clone(),
                        bill_addr_postal_code: details.zip.clone(),
                        bill_addr_state: state,
                    }))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

impl requests::RedsysShippingData {
    pub fn try_from_address(
        address: Option<&domain_types::payment_address::Address>,
    ) -> Result<Option<Self>, domain_types::errors::ConnectorError> {
        match address {
            Some(addr) => {
                let address_details = addr.address.as_ref();
                if let Some(details) = address_details {
                    let state = details.state.as_ref().and_then(|state_val| {
                        let state_str = state_val.peek();
                        domain_types::utils::convert_spain_state_to_code(state_str)
                            .ok()
                            .map(Secret::new)
                    });

                    Ok(Some(Self {
                        ship_addr_city: details.city.clone(),
                        ship_addr_country: details.country.map(|c| c.to_string()),
                        ship_addr_line1: details.line1.clone(),
                        ship_addr_line2: details.line2.clone(),
                        ship_addr_line3: details.line3.clone(),
                        ship_addr_postal_code: details.zip.clone(),
                        ship_addr_state: state,
                    }))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

// Helper functions for code reusability

/// Helper function to build redirect form for 3DS challenge
fn build_threeds_form(acs_url: &str, creq: &str) -> Result<RedirectForm, Error> {
    let mut form_fields = std::collections::HashMap::new();
    form_fields.insert("creq".to_string(), creq.to_string());

    Ok(RedirectForm::Form {
        endpoint: acs_url.to_string(),
        method: common_utils::request::Method::Post,
        form_fields,
    })
}
