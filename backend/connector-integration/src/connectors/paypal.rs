use domain_types::{
    connector_flow::{Authorize, Capture, CreateOrder, PSync, RSync, Refund, Void},
    connector_types::{
        ConnectorServiceTrait, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        PaymentAuthorizeV2, PaymentCapture as PaymentCaptureTrait, PaymentOrderCreate as PaymentOrderCreateTrait, 
        PaymentSyncV2, PaymentVoidV2, RefundSyncV2 as RefundSyncV2Trait, RefundV2 as RefundV2Trait,
        ValidationTrait, IncomingWebhook,
    },
};

use std::fmt::Write;

use base64::Engine;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use crate::{with_error_response_body, with_response_body};

use error_stack::{ResultExt};

use hyperswitch_common_utils::{
    ext_traits::ByteSliceExt,
    errors::CustomResult,
    request::{RequestContent},
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector,MinorUnit},
};

use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};

use hyperswitch_interfaces::{
    api::{self, ConnectorCommon},
    connector_integration_v2::ConnectorIntegrationV2,
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    configs::Connectors,
};

use hyperswitch_masking::{Maskable, PeekInterface, Secret, Mask,ExposeInterface};

pub mod transformers;
use transformers::{self as paypal, PaypalAuthType, PaypalErrorResponse, PaypalRouterData, ForeignTryFrom, ErrorCodeAndMessage};

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

#[derive(Clone)]
pub struct Paypal {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Paypal {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}

impl Paypal {
    pub fn get_order_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        //Handled error response separately for Orders as the end point is different for Orders - (Authorize) and Payments - (Capture, void, refund, rsync).
        //Error response have different fields for Orders and Payments.
        let response: paypal::PaypalOrderErrorResponse = res
            .response
            .parse_struct("Paypal ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));

        let error_reason = response.details.clone().map(|order_errors| {
            order_errors
                .iter()
                .map(|error| {
                    let mut reason = format!("description - {}", error.description);
                    if let Some(value) = &error.value {
                        reason.push_str(&format!(", value - {value}"));
                    }
                    if let Some(field) = error
                        .field
                        .as_ref()
                        .and_then(|field| field.split('/').next_back())
                    {
                        reason.push_str(&format!(", field - {field}"));
                    }
                    reason.push(';');
                    reason
                })
                .collect::<String>()
        });
        let errors_list = response.details.unwrap_or_default();
        let option_error_code_message =
            get_error_code_error_message_based_on_priority(
                self.clone(),
                errors_list
                    .into_iter()
                    .map(|errors| errors.into())
                    .collect(),
            );
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: option_error_code_message
                .clone()
                .map(|error_code_message| error_code_message.error_code)
                .unwrap_or(NO_ERROR_CODE.to_string()),
            message: option_error_code_message
                .map(|error_code_message| error_code_message.error_message)
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason: error_reason.or(Some(response.message)),
            attempt_status: None,
            connector_transaction_id: response.debug_id,
            // network_advice_code: None,
            // network_decline_code: None,
            // network_error_message: None,
        })
    }
}

impl ConnectorCommon for Paypal {
    fn id(&self) -> &'static str {
        "paypal"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.paypal.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = paypal::PaypalAuthType::try_from(auth_type)?;
        let credentials = auth.get_credentials()?;

        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            credentials.get_client_secret().into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: paypal::PaypalPaymentErrorResponse = res
            .response
            .parse_struct("Paypal ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        let error_reason = response
            .details
            .clone()
            .map(|error_details| {
                error_details
                    .iter()
                    .try_fold(String::new(), |mut acc, error| {
                        if let Some(description) = &error.description {
                            write!(acc, "description - {} ;", description)
                                .change_context(
                                    errors::ConnectorError::ResponseDeserializationFailed,
                                )
                                .attach_printable("Failed to concatenate error details")
                                .map(|_| acc)
                        } else {
                            Ok(acc)
                        }
                    })
            })
            .transpose()?;
        let reason = match error_reason {
            Some(err_reason) => err_reason
                .is_empty()
                .then(|| response.message.to_owned())
                .or(Some(err_reason)),
            None => Some(response.message.to_owned()),
        };
        let errors_list = response.details.unwrap_or_default();
        let option_error_code_message =
            get_error_code_error_message_based_on_priority(
                self.clone(),
                errors_list
                    .into_iter()
                    .map(|errors| errors.into())
                    .collect(),
            );

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: option_error_code_message
                .clone()
                .map(|error_code_message| error_code_message.error_code)
                .unwrap_or(NO_ERROR_CODE.to_string()),
            message: option_error_code_message
                .map(|error_code_message| error_code_message.error_message)
                .unwrap_or(NO_ERROR_MESSAGE.to_string()),
            reason,
            attempt_status: None,
            connector_transaction_id: response.debug_id,
            // network_advice_code: None,
            // network_decline_code: None,
            // network_error_message: None,
        })
    }
}

impl ValidationTrait for Paypal {}
impl ConnectorServiceTrait for Paypal {}
impl PaymentAuthorizeV2 for Paypal {}
impl PaymentSyncV2 for Paypal {}
impl PaymentOrderCreateTrait for Paypal {}
impl PaymentVoidV2 for Paypal {}
impl RefundSyncV2Trait for Paypal {}
impl RefundV2Trait for Paypal {}
impl PaymentCaptureTrait for Paypal {}
impl IncomingWebhook for Paypal {}

impl
    ConnectorIntegrationV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Paypal
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> 
    where
        Self: ConnectorIntegrationV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
        {
        let access_token = req.resource_common_data
            .access_token
            .clone()
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        let key = &req.resource_common_data.connector_request_reference_id;
        let auth = paypal::PaypalAuthType::try_from(&req.connector_auth_type)?;

        let mut headers: Vec<(String, Maskable<String>)> = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", access_token).into_masked(),
            ),
            (
                paypal::auth_headers::PREFER.to_string(),
                "return=representation".to_string().into(),
            ),
            (
                paypal::auth_headers::PAYPAL_REQUEST_ID.to_string(),
                key.to_string().into_masked(),
            ),
        ];

        if let Ok(paypal::PaypalConnectorCredentials::PartnerIntegration(credentials)) =
            auth.get_credentials()
        {
            let auth_assertion_header =
                construct_auth_assertion_header(&credentials.payer_id, &credentials.client_id);
            headers.extend(vec![
                (
                    paypal::auth_headers::PAYPAL_AUTH_ASSERTION.to_string(),
                    auth_assertion_header.to_string().into_masked(),
                ),
                (
                    paypal::auth_headers::PAYPAL_PARTNER_ATTRIBUTION_ID.to_string(),
                    "HyperSwitchPPCP_SP".to_string().into(),
                ),
            ])
        } else {
            headers.extend(vec![(
                paypal::auth_headers::PAYPAL_PARTNER_ATTRIBUTION_ID.to_string(),
                "HyperSwitchlegacy_Ecom".to_string().into(),
            )])
        }
        Ok(headers)
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        match &req.request.payment_method_data {
            PaymentMethodData::Wallet(WalletData::PaypalSdk(paypal_wallet_data)) => {
                let authorize_url = if is_auto_capture(&req.request)? {
                    "capture".to_string()
                } else {
                    "authorize".to_string()
                };
                Ok(format!(
                    "{}v2/checkout/orders/{}/{authorize_url}",
                    req.resource_common_data.connectors.paypal.base_url,
                    paypal_wallet_data.token
                ))
            }
            _ => Ok(format!("{}v2/checkout/orders", req.resource_common_data.connectors.paypal.base_url)),
        }
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let amount = convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;
        let shipping_cost = convert_amount(
            self.amount_converter,
            req.request.shipping_cost.unwrap_or(MinorUnit::zero()),
            req.request.currency,
        )?;
        let connector_router_data =
            paypal::PaypalRouterData::try_from((amount, Some(shipping_cost), None, None, req))?;
        let connector_req = paypal::PaypalPaymentsRequest::try_from(&connector_router_data)?;
        Ok(Some(RequestContent::Json(Box::new(connector_req))))
    }

    fn handle_response_v2(
        &self,
        data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: paypal::PaypalAuthResponse =
            res.response
                .parse_struct("paypal PaypalAuthResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        match response {
            paypal::PaypalAuthResponse::PaypalOrdersResponse(response) => {
                with_response_body!(event_builder, response);
                RouterDataV2::foreign_try_from((
                    response,
                    data.clone(),
                    res.status_code,
                ))
            }
            paypal::PaypalAuthResponse::PaypalRedirectResponse(response) => {
                with_response_body!(event_builder, response);
                RouterDataV2::foreign_try_from((
                    response,
                    data.clone(),
                    res.status_code,
                ))
            }
            paypal::PaypalAuthResponse::PaypalThreeDsResponse(response) => {
                with_response_body!(event_builder, response);
                RouterDataV2::foreign_try_from((
                    response,
                    data.clone(),
                    res.status_code,
                ))
            }
        }
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.get_order_error_response(res, event_builder)
    }
}

impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Paypal {}
impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Paypal {}
impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Paypal {}
impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Paypal {}
impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Paypal {}
impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Paypal {} 

//
pub(crate) fn get_error_code_error_message_based_on_priority(
    connector: impl ConnectorErrorTypeMapping,
    error_list: Vec<ErrorCodeAndMessage>,
) -> Option<ErrorCodeAndMessage> {
    let error_type_list = error_list
        .iter()
        .map(|error| {
            connector
                .get_connector_error_type(error.error_code.clone(), error.error_message.clone())
        })
        .collect::<Vec<ConnectorErrorType>>();
    let mut error_zip_list = error_list
        .iter()
        .zip(error_type_list.iter())
        .collect::<Vec<(&ErrorCodeAndMessage, &ConnectorErrorType)>>();
    error_zip_list.sort_by_key(|&(_, error_type)| error_type);
    error_zip_list
        .first()
        .map(|&(error_code_message, _)| error_code_message)
        .cloned()
}

pub trait ConnectorErrorTypeMapping {
    fn get_connector_error_type(
        &self,
        _error_code: String,
        _error_message: String,
    ) -> ConnectorErrorType {
        ConnectorErrorType::UnknownError
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
//Priority of connector_error_type
pub enum ConnectorErrorType {
    UserError = 2,
    BusinessError = 3,
    TechnicalError = 4,
    UnknownError = 1,
}

impl ConnectorErrorTypeMapping for Paypal {
    fn get_connector_error_type(
        &self,
        error_code: String,
        _error_message: String,
    ) -> ConnectorErrorType {
        match error_code.as_str() {
            "CANNOT_BE_NEGATIVE" => ConnectorErrorType::UserError,
            "CANNOT_BE_ZERO_OR_NEGATIVE" => ConnectorErrorType::UserError,
            "CARD_EXPIRED" => ConnectorErrorType::UserError,
            "DECIMAL_PRECISION" => ConnectorErrorType::UserError,
            "DUPLICATE_INVOICE_ID" => ConnectorErrorType::UserError,
            "INSTRUMENT_DECLINED" => ConnectorErrorType::BusinessError,
            "INTERNAL_SERVER_ERROR" => ConnectorErrorType::TechnicalError,
            "INVALID_ACCOUNT_STATUS" => ConnectorErrorType::BusinessError,
            "INVALID_CURRENCY_CODE" => ConnectorErrorType::UserError,
            "INVALID_PARAMETER_SYNTAX" => ConnectorErrorType::UserError,
            "INVALID_PARAMETER_VALUE" => ConnectorErrorType::UserError,
            "INVALID_RESOURCE_ID" => ConnectorErrorType::UserError,
            "INVALID_STRING_LENGTH" => ConnectorErrorType::UserError,
            "MISSING_REQUIRED_PARAMETER" => ConnectorErrorType::UserError,
            "PAYER_ACCOUNT_LOCKED_OR_CLOSED" => ConnectorErrorType::BusinessError,
            "PAYER_ACCOUNT_RESTRICTED" => ConnectorErrorType::BusinessError,
            "PAYER_CANNOT_PAY" => ConnectorErrorType::BusinessError,
            "PERMISSION_DENIED" => ConnectorErrorType::BusinessError,
            "INVALID_ARRAY_MAX_ITEMS" => ConnectorErrorType::UserError,
            "INVALID_ARRAY_MIN_ITEMS" => ConnectorErrorType::UserError,
            "INVALID_COUNTRY_CODE" => ConnectorErrorType::UserError,
            "NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "PAYPAL_REQUEST_ID_REQUIRED" => ConnectorErrorType::UserError,
            "MALFORMED_REQUEST_JSON" => ConnectorErrorType::UserError,
            "PERMISSION_DENIED_FOR_DONATION_ITEMS" => ConnectorErrorType::BusinessError,
            "MALFORMED_REQUEST" => ConnectorErrorType::TechnicalError,
            "AMOUNT_MISMATCH" => ConnectorErrorType::UserError,
            "BILLING_ADDRESS_INVALID" => ConnectorErrorType::UserError,
            "CITY_REQUIRED" => ConnectorErrorType::UserError,
            "DONATION_ITEMS_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "DUPLICATE_REFERENCE_ID" => ConnectorErrorType::UserError,
            "INVALID_PAYER_ID" => ConnectorErrorType::UserError,
            "ITEM_TOTAL_REQUIRED" => ConnectorErrorType::UserError,
            "MAX_VALUE_EXCEEDED" => ConnectorErrorType::UserError,
            "MISSING_PICKUP_ADDRESS" => ConnectorErrorType::UserError,
            "MULTI_CURRENCY_ORDER" => ConnectorErrorType::BusinessError,
            "MULTIPLE_ITEM_CATEGORIES" => ConnectorErrorType::UserError,
            "MULTIPLE_SHIPPING_ADDRESS_NOT_SUPPORTED" => ConnectorErrorType::UserError,
            "MULTIPLE_SHIPPING_TYPE_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "PAYEE_ACCOUNT_INVALID" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_LOCKED_OR_CLOSED" => ConnectorErrorType::UserError,
            "REFERENCE_ID_REQUIRED" => ConnectorErrorType::UserError,
            "PAYMENT_SOURCE_CANNOT_BE_USED" => ConnectorErrorType::BusinessError,
            "PAYMENT_SOURCE_DECLINED_BY_PROCESSOR" => ConnectorErrorType::BusinessError,
            "PAYMENT_SOURCE_INFO_CANNOT_BE_VERIFIED" => ConnectorErrorType::BusinessError,
            "POSTAL_CODE_REQUIRED" => ConnectorErrorType::UserError,
            "SHIPPING_ADDRESS_INVALID" => ConnectorErrorType::UserError,
            "TAX_TOTAL_MISMATCH" => ConnectorErrorType::UserError,
            "TAX_TOTAL_REQUIRED" => ConnectorErrorType::UserError,
            "UNSUPPORTED_INTENT" => ConnectorErrorType::BusinessError,
            "UNSUPPORTED_PAYMENT_INSTRUCTION" => ConnectorErrorType::UserError,
            "SHIPPING_TYPE_NOT_SUPPORTED_FOR_CLIENT" => ConnectorErrorType::BusinessError,
            "UNSUPPORTED_SHIPPING_TYPE" => ConnectorErrorType::BusinessError,
            "PREFERRED_SHIPPING_OPTION_AMOUNT_MISMATCH" => ConnectorErrorType::UserError,
            "CARD_CLOSED" => ConnectorErrorType::BusinessError,
            "ORDER_CANNOT_BE_SAVED" => ConnectorErrorType::BusinessError,
            "SAVE_ORDER_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "FIELD_NOT_PATCHABLE" => ConnectorErrorType::UserError,
            "AMOUNT_NOT_PATCHABLE" => ConnectorErrorType::UserError,
            "INVALID_PATCH_OPERATION" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_NOT_SUPPORTED" => ConnectorErrorType::UserError,
            "PAYEE_ACCOUNT_NOT_VERIFIED" => ConnectorErrorType::UserError,
            "PAYEE_NOT_CONSENTED" => ConnectorErrorType::UserError,
            "INVALID_JSON_POINTER_FORMAT" => ConnectorErrorType::BusinessError,
            "INVALID_PARAMETER" => ConnectorErrorType::UserError,
            "NOT_PATCHABLE" => ConnectorErrorType::BusinessError,
            "PATCH_VALUE_REQUIRED" => ConnectorErrorType::UserError,
            "PATCH_PATH_REQUIRED" => ConnectorErrorType::UserError,
            "REFERENCE_ID_NOT_FOUND" => ConnectorErrorType::UserError,
            "SHIPPING_OPTION_NOT_SELECTED" => ConnectorErrorType::UserError,
            "SHIPPING_OPTIONS_NOT_SUPPORTED" => ConnectorErrorType::BusinessError,
            "MULTIPLE_SHIPPING_OPTION_SELECTED" => ConnectorErrorType::UserError,
            "ORDER_ALREADY_COMPLETED" => ConnectorErrorType::BusinessError,
            "ACTION_DOES_NOT_MATCH_INTENT" => ConnectorErrorType::BusinessError,
            "AGREEMENT_ALREADY_CANCELLED" => ConnectorErrorType::BusinessError,
            "BILLING_AGREEMENT_NOT_FOUND" => ConnectorErrorType::BusinessError,
            "DOMESTIC_TRANSACTION_REQUIRED" => ConnectorErrorType::BusinessError,
            "ORDER_NOT_APPROVED" => ConnectorErrorType::UserError,
            "MAX_NUMBER_OF_PAYMENT_ATTEMPTS_EXCEEDED" => ConnectorErrorType::TechnicalError,
            "PAYEE_BLOCKED_TRANSACTION" => ConnectorErrorType::BusinessError,
            "TRANSACTION_LIMIT_EXCEEDED" => ConnectorErrorType::UserError,
            "TRANSACTION_RECEIVING_LIMIT_EXCEEDED" => ConnectorErrorType::BusinessError,
            "TRANSACTION_REFUSED" => ConnectorErrorType::TechnicalError,
            "ORDER_ALREADY_AUTHORIZED" => ConnectorErrorType::BusinessError,
            "AUTH_CAPTURE_NOT_ENABLED" => ConnectorErrorType::BusinessError,
            "AMOUNT_CANNOT_BE_SPECIFIED" => ConnectorErrorType::BusinessError,
            "AUTHORIZATION_AMOUNT_EXCEEDED" => ConnectorErrorType::UserError,
            "AUTHORIZATION_CURRENCY_MISMATCH" => ConnectorErrorType::UserError,
            "MAX_AUTHORIZATION_COUNT_EXCEEDED" => ConnectorErrorType::BusinessError,
            "ORDER_COMPLETED_OR_VOIDED" => ConnectorErrorType::BusinessError,
            "ORDER_EXPIRED" => ConnectorErrorType::BusinessError,
            "INVALID_PICKUP_ADDRESS" => ConnectorErrorType::UserError,
            "CONSENT_NEEDED" => ConnectorErrorType::UserError,
            "COMPLIANCE_VIOLATION" => ConnectorErrorType::BusinessError,
            "REDIRECT_PAYER_FOR_ALTERNATE_FUNDING" => ConnectorErrorType::TechnicalError,
            "ORDER_ALREADY_CAPTURED" => ConnectorErrorType::UserError,
            "TRANSACTION_BLOCKED_BY_PAYEE" => ConnectorErrorType::BusinessError,
            "NOT_ENABLED_FOR_CARD_PROCESSING" => ConnectorErrorType::BusinessError,
            "PAYEE_NOT_ENABLED_FOR_CARD_PROCESSING" => ConnectorErrorType::BusinessError,
            _ => ConnectorErrorType::UnknownError,
        }
    }
}

fn construct_auth_assertion_header(
    payer_id: &Secret<String>,
    client_id: &Secret<String>,
) -> String {
    let algorithm = BASE64_ENGINE
        .encode("{\"alg\":\"none\"}")
        .to_string();
    let merchant_credentials = format!(
        "{{\"iss\":\"{}\",\"payer_id\":\"{}\"}}",
        client_id.clone().expose(),
        payer_id.clone().expose()
    );
    let encoded_credentials = BASE64_ENGINE
        .encode(merchant_credentials)
        .to_string();
    format!("{algorithm}.{encoded_credentials}.")
}

fn is_auto_capture(data:&PaymentsAuthorizeData) -> Result<bool, errors::ConnectorError> {
    match data.capture_method {
        Some(hyperswitch_common_enums::CaptureMethod::Automatic)
        |None => Ok(true),
        Some(hyperswitch_common_enums::CaptureMethod::Manual) => Ok(false),
        Some(_) => Err(errors::ConnectorError::CaptureMethodNotSupported),
    }
}

fn convert_amount<T>(
    amount_convertor: &dyn AmountConvertor<Output = T>,
    amount: MinorUnit,
    currency: hyperswitch_common_enums::Currency,
) -> Result<T, error_stack::Report<errors::ConnectorError>> {
    amount_convertor
        .convert(amount, currency)
        .change_context(errors::ConnectorError::AmountConversionFailed)
}
