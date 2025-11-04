use common_utils::{
    errors::CustomResult,
    request::Method,
    types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

// Import the EaseBuzz type for use in trait implementations
use super::EaseBuzz;

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    txnid: String,
    amount: StringMinorUnit,
    currency: String,
    name: Option<String>,
    email: Option<Email>,
    phone: Option<String>,
    productinfo: String,
    surl: String,
    furl: String,
    udf1: Option<String>,
    udf2: Option<String>,
    udf3: Option<String>,
    udf4: Option<String>,
    udf5: Option<String>,
    udf6: Option<String>,
    udf7: Option<String>,
    udf8: Option<String>,
    udf9: Option<String>,
    udf10: Option<String>,
    hash: Secret<String>,
    address1: Option<String>,
    address2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    zipcode: Option<String>,
    pg: Option<String>,
    customer_unique_id: Option<String>,
    split_payments: Option<String>,
    sub_merchant_id: Option<String>,
    merchant_name: Option<String>,
    custom_note: Option<String>,
    show_payment_mode: Option<String>,
    card_holder_name: Option<String>,
    card_number: Option<String>,
    card_cvv: Option<String>,
    card_expiry: Option<String>,
    card_bank_code: Option<String>,
    card_bank_name: Option<String>,
    card_emi: Option<String>,
    card_bank_emi_tenure: Option<String>,
    card_token: Option<String>,
    card_brand: Option<String>,
    card_type: Option<String>,
    card_isin: Option<String>,
    card_bin: Option<String>,
    card_last_four: Option<String>,
    card_name: Option<String>,
    card_network: Option<String>,
    card_country: Option<String>,
    card_issuer: Option<String>,
    card_product: Option<String>,
    card_category: Option<String>,
    card_level: Option<String>,
    card_class: Option<String>,
    card_program: Option<String>,
    card_scheme: Option<String>,
    card_region: Option<String>,
    card_currency: Option<String>,
    card_settlement: Option<String>,
    card_settlement_currency: Option<String>,
    card_settlement_amount: Option<String>,
    card_settlement_date: Option<String>,
    card_settlement_status: Option<String>,
    card_settlement_reference: Option<String>,
    card_settlement_remarks: Option<String>,
    card_settlement_bank: Option<String>,
    card_settlement_branch: Option<String>,
    card_settlement_account: Option<String>,
    card_settlement_ifsc: Option<String>,
    card_settlement_upi: Option<String>,
    card_settlement_qr: Option<String>,
    card_settlement_link: Option<String>,
    card_settlement_url: Option<String>,
    card_settlement_redirect: Option<String>,
    card_settlement_callback: Option<String>,
    card_settlement_webhook: Option<String>,
    card_settlement_notification: Option<String>,
    card_settlement_email: Option<String>,
    card_settlement_sms: Option<String>,
    card_settlement_push: Option<String>,
    card_settlement_whatsapp: Option<String>,
    card_settlement_telegram: Option<String>,
    card_settlement_slack: Option<String>,
    card_settlement_discord: Option<String>,
    card_settlement_teams: Option<String>,
    card_settlement_zoom: Option<String>,
    card_settlement_skype: Option<String>,
    card_settlement_signal: Option<String>,
    card_settlement_viber: Option<String>,
    card_settlement_line: Option<String>,
    card_settlement_wechat: Option<String>,
    card_settlement_kakao: Option<String>,
    card_settlement_hangouts: Option<String>,
    card_settlement_allo: Option<String>,
    card_settlement_imessage: Option<String>,
    card_settlement_facetime: Option<String>,
    card_settlement_duo: Option<String>,
    card_settlement_meet: Option<String>,
    card_settlement_gmeet: Option<String>,
    card_settlement_zoom_meeting: Option<String>,
    card_settlement_zoom_webinar: Option<String>,
    card_settlement_zoom_breakout: Option<String>,
    card_settlement_zoom_chat: Option<String>,
    card_settlement_zoom_poll: Option<String>,
    card_settlement_zoom_qa: Option<String>,
    card_settlement_zoom_whiteboard: Option<String>,
    card_settlement_zoom_share: Option<String>,
    card_settlement_zoom_record: Option<String>,
    card_settlement_zoom_live: Option<String>,
    card_settlement_zoom_stream: Option<String>,
    card_settlement_zoom_broadcast: Option<String>,
    card_settlement_zoom_webcast: Option<String>,
    card_settlement_zoom_conference: Option<String>,
    card_settlement_zoom_presentation: Option<String>,
    card_settlement_zoom_slideshow: Option<String>,
    card_settlement_zoom_document: Option<String>,
    card_settlement_zoom_spreadsheet: Option<String>,
    card_settlement_zoom_form: Option<String>,
    card_settlement_zoom_survey: Option<String>,
    card_settlement_zoom_quiz: Option<String>,
    card_settlement_zoom_test: Option<String>,
    card_settlement_zoom_exam: Option<String>,
    card_settlement_zoom_interview: Option<String>,
    card_settlement_zoom_discussion: Option<String>,
    card_settlement_zoom_debate: Option<String>,
    card_settlement_zoom_panel: Option<String>,
    card_settlement_zoom_forum: Option<String>,
    card_settlement_zoom_workshop: Option<String>,
    card_settlement_zoom_training: Option<String>,
    card_settlement_zoom_course: Option<String>,
    card_settlement_zoom_class: Option<String>,
    card_settlement_zoom_lecture: Option<String>,
    card_settlement_zoom_seminar: Option<String>,
    card_settlement_zoom_webinar_series: Option<String>,
    card_settlement_zoom_conference_series: Option<String>,
    card_settlement_zoom_summit: Option<String>,
    card_settlement_zoom_expo: Option<String>,
    card_settlement_zoom_fair: Option<String>,
    card_settlement_zoom_festival: Option<String>,
    card_settlement_zoom_carnival: Option<String>,
    card_settlement_zoom_celebration: Option<String>,
    card_settlement_zoom_party: Option<String>,
    card_settlement_zoom_event: Option<String>,
    card_settlement_zoom_function: Option<String>,
    card_settlement_zoom_ceremony: Option<String>,
    card_settlement_zoom_ritual: Option<String>,
    card_settlement_zoom_tradition: Option<String>,
    card_settlement_zoom_custom: Option<String>,
    card_settlement_zoom_special: Option<String>,
    card_settlement_zoom_unique: Option<String>,
    card_settlement_zoom_rare: Option<String>,
    card_settlement_zoom_exclusive: Option<String>,
    card_settlement_zoom_premium: Option<String>,
    card_settlement_zoom_vip: Option<String>,
    card_settlement_zoom_elite: Option<String>,
    card_settlement_zoom_luxury: Option<String>,
    card_settlement_zoom_deluxe: Option<String>,
    card_settlement_zoom_platinum: Option<String>,
    card_settlement_zoom_gold: Option<String>,
    card_settlement_zoom_silver: Option<String>,
    card_settlement_zoom_bronze: Option<String>,
    card_settlement_zoom_copper: Option<String>,
    card_settlement_zoom_iron: Option<String>,
    card_settlement_zoom_steel: Option<String>,
    card_settlement_zoom_aluminum: Option<String>,
    card_settlement_zoom_titanium: Option<String>,
    card_settlement_zoom_platinum_plus: Option<String>,
    card_settlement_zoom_gold_plus: Option<String>,
    card_settlement_zoom_silver_plus: Option<String>,
    card_settlement_zoom_bronze_plus: Option<String>,
    card_settlement_zoom_copper_plus: Option<String>,
    card_settlement_zoom_iron_plus: Option<String>,
    card_settlement_zoom_steel_plus: Option<String>,
    card_settlement_zoom_aluminum_plus: Option<String>,
    card_settlement_zoom_titanium_plus: Option<String>,
    card_settlement_zoom_platinum_pro: Option<String>,
    card_settlement_zoom_gold_pro: Option<String>,
    card_settlement_zoom_silver_pro: Option<String>,
    card_settlement_zoom_bronze_pro: Option<String>,
    card_settlement_zoom_copper_pro: Option<String>,
    card_settlement_zoom_iron_pro: Option<String>,
    card_settlement_zoom_steel_pro: Option<String>,
    card_settlement_zoom_aluminum_pro: Option<String>,
    card_settlement_zoom_titanium_pro: Option<String>,
    card_settlement_zoom_platinum_max: Option<String>,
    card_settlement_zoom_gold_max: Option<String>,
    card_settlement_zoom_silver_max: Option<String>,
    card_settlement_zoom_bronze_max: Option<String>,
    card_settlement_zoom_copper_max: Option<String>,
    card_settlement_zoom_iron_max: Option<String>,
    card_settlement_zoom_steel_max: Option<String>,
    card_settlement_zoom_aluminum_max: Option<String>,
    card_settlement_zoom_titanium_max: Option<String>,
    card_settlement_zoom_platinum_ultra: Option<String>,
    card_settlement_zoom_gold_ultra: Option<String>,
    card_settlement_zoom_silver_ultra: Option<String>,
    card_settlement_zoom_bronze_ultra: Option<String>,
    card_settlement_zoom_copper_ultra: Option<String>,
    card_settlement_zoom_iron_ultra: Option<String>,
    card_settlement_zoom_steel_ultra: Option<String>,
    card_settlement_zoom_aluminum_ultra: Option<String>,
    card_settlement_zoom_titanium_ultra: Option<String>,
    card_settlement_zoom_platinum_ultimate: Option<String>,
    card_settlement_zoom_gold_ultimate: Option<String>,
    card_settlement_zoom_silver_ultimate: Option<String>,
    card_settlement_zoom_bronze_ultimate: Option<String>,
    card_settlement_zoom_copper_ultimate: Option<String>,
    card_settlement_zoom_iron_ultimate: Option<String>,
    card_settlement_zoom_steel_ultimate: Option<String>,
    card_settlement_zoom_aluminum_ultimate: Option<String>,
    card_settlement_zoom_titanium_ultimate: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    txnid: String,
    amount: StringMinorUnit,
    email: Option<Email>,
    phone: Option<String>,
    key: String,
    hash: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponse {
    Success(EaseBuzzPaymentsResponseData),
    Error(EaseBuzzErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponseData {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub txnid: String,
    pub status: bool,
    pub amount: StringMinorUnit,
    pub currency: String,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: String,
}

// Dummy types for unsupported flows
#[derive(Default, Debug, Serialize)]
pub struct EaseBuzzDummyRequest;

#[derive(Debug, Deserialize, Serialize)]
pub struct EaseBuzzDummyResponse {
    pub status: String,
}



impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
    TryFrom<
        EaseBuzzRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Only support UPI payment methods
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                txnid: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                amount,
                currency: item.router_data.request.currency.to_string(),
                name: None, // TODO: Extract from router_data when available
                email: item.router_data.request.email.clone(),
                phone: None, // TODO: Extract from router_data when available
                productinfo: "UPI Payment".to_string(),
                surl: return_url.clone(),
                furl: return_url,
                udf1: None,
                udf2: None,
                udf3: None,
                udf4: None,
                udf5: None,
                udf6: None,
                udf7: None,
                udf8: None,
                udf9: None,
                udf10: None,
                hash: Secret::new("generated_hash".to_string()), // In production, generate proper hash
                address1: None,
                address2: None,
                city: None,
                state: None,
                country: None,
                zipcode: None,
                pg: Some("UPI".to_string()),
                customer_unique_id: Some(customer_id.get_string_repr().to_string()),
                split_payments: None,
                sub_merchant_id: None,
                merchant_name: None,
                custom_note: None,
                show_payment_mode: None,
                card_holder_name: None,
                card_number: None,
                card_cvv: None,
                card_expiry: None,
                card_bank_code: None,
                card_bank_name: None,
                card_emi: None,
                card_bank_emi_tenure: None,
                card_token: None,
                card_brand: None,
                card_type: None,
                card_isin: None,
                card_bin: None,
                card_last_four: None,
                card_name: None,
                card_network: None,
                card_country: None,
                card_issuer: None,
                card_product: None,
                card_category: None,
                card_level: None,
                card_class: None,
                card_program: None,
                card_scheme: None,
                card_region: None,
                card_currency: None,
                card_settlement: None,
                card_settlement_currency: None,
                card_settlement_amount: None,
                card_settlement_date: None,
                card_settlement_status: None,
                card_settlement_reference: None,
                card_settlement_remarks: None,
                card_settlement_bank: None,
                card_settlement_branch: None,
                card_settlement_account: None,
                card_settlement_ifsc: None,
                card_settlement_upi: None,
                card_settlement_qr: None,
                card_settlement_link: None,
                card_settlement_url: None,
                card_settlement_redirect: None,
                card_settlement_callback: None,
                card_settlement_webhook: None,
                card_settlement_notification: None,
                card_settlement_email: None,
                card_settlement_sms: None,
                card_settlement_push: None,
                card_settlement_whatsapp: None,
                card_settlement_telegram: None,
                card_settlement_slack: None,
                card_settlement_discord: None,
                card_settlement_teams: None,
                card_settlement_zoom: None,
                card_settlement_skype: None,
                card_settlement_signal: None,
                card_settlement_viber: None,
                card_settlement_line: None,
                card_settlement_wechat: None,
                card_settlement_kakao: None,
                card_settlement_hangouts: None,
                card_settlement_allo: None,
                card_settlement_imessage: None,
                card_settlement_facetime: None,
                card_settlement_duo: None,
                card_settlement_meet: None,
                card_settlement_gmeet: None,
                card_settlement_zoom_meeting: None,
                card_settlement_zoom_webinar: None,
                card_settlement_zoom_breakout: None,
                card_settlement_zoom_chat: None,
                card_settlement_zoom_poll: None,
                card_settlement_zoom_qa: None,
                card_settlement_zoom_whiteboard: None,
                card_settlement_zoom_share: None,
                card_settlement_zoom_record: None,
                card_settlement_zoom_live: None,
                card_settlement_zoom_stream: None,
                card_settlement_zoom_broadcast: None,
                card_settlement_zoom_webcast: None,
                card_settlement_zoom_conference: None,
                card_settlement_zoom_presentation: None,
                card_settlement_zoom_slideshow: None,
                card_settlement_zoom_document: None,
                card_settlement_zoom_spreadsheet: None,
                card_settlement_zoom_form: None,
                card_settlement_zoom_survey: None,
                card_settlement_zoom_quiz: None,
                card_settlement_zoom_test: None,
                card_settlement_zoom_exam: None,
                card_settlement_zoom_interview: None,
                card_settlement_zoom_discussion: None,
                card_settlement_zoom_debate: None,
                card_settlement_zoom_panel: None,
                card_settlement_zoom_forum: None,
                card_settlement_zoom_workshop: None,
                card_settlement_zoom_training: None,
                card_settlement_zoom_course: None,
                card_settlement_zoom_class: None,
                card_settlement_zoom_lecture: None,
                card_settlement_zoom_seminar: None,
                card_settlement_zoom_webinar_series: None,
                card_settlement_zoom_conference_series: None,
                card_settlement_zoom_summit: None,
                card_settlement_zoom_expo: None,
                card_settlement_zoom_fair: None,
                card_settlement_zoom_festival: None,
                card_settlement_zoom_carnival: None,
                card_settlement_zoom_celebration: None,
                card_settlement_zoom_party: None,
                card_settlement_zoom_event: None,
                card_settlement_zoom_function: None,
                card_settlement_zoom_ceremony: None,
                card_settlement_zoom_ritual: None,
                card_settlement_zoom_tradition: None,
                card_settlement_zoom_custom: None,
                card_settlement_zoom_special: None,
                card_settlement_zoom_unique: None,
                card_settlement_zoom_rare: None,
                card_settlement_zoom_exclusive: None,
                card_settlement_zoom_premium: None,
                card_settlement_zoom_vip: None,
                card_settlement_zoom_elite: None,
                card_settlement_zoom_luxury: None,
                card_settlement_zoom_deluxe: None,
                card_settlement_zoom_platinum: None,
                card_settlement_zoom_gold: None,
                card_settlement_zoom_silver: None,
                card_settlement_zoom_bronze: None,
                card_settlement_zoom_copper: None,
                card_settlement_zoom_iron: None,
                card_settlement_zoom_steel: None,
                card_settlement_zoom_aluminum: None,
                card_settlement_zoom_titanium: None,
                card_settlement_zoom_platinum_plus: None,
                card_settlement_zoom_gold_plus: None,
                card_settlement_zoom_silver_plus: None,
                card_settlement_zoom_bronze_plus: None,
                card_settlement_zoom_copper_plus: None,
                card_settlement_zoom_iron_plus: None,
                card_settlement_zoom_steel_plus: None,
                card_settlement_zoom_aluminum_plus: None,
                card_settlement_zoom_titanium_plus: None,
                card_settlement_zoom_platinum_pro: None,
                card_settlement_zoom_gold_pro: None,
                card_settlement_zoom_silver_pro: None,
                card_settlement_zoom_bronze_pro: None,
                card_settlement_zoom_copper_pro: None,
                card_settlement_zoom_iron_pro: None,
                card_settlement_zoom_steel_pro: None,
                card_settlement_zoom_aluminum_pro: None,
                card_settlement_zoom_titanium_pro: None,
                card_settlement_zoom_platinum_max: None,
                card_settlement_zoom_gold_max: None,
                card_settlement_zoom_silver_max: None,
                card_settlement_zoom_bronze_max: None,
                card_settlement_zoom_copper_max: None,
                card_settlement_zoom_iron_max: None,
                card_settlement_zoom_steel_max: None,
                card_settlement_zoom_aluminum_max: None,
                card_settlement_zoom_titanium_max: None,
                card_settlement_zoom_platinum_ultra: None,
                card_settlement_zoom_gold_ultra: None,
                card_settlement_zoom_silver_ultra: None,
                card_settlement_zoom_bronze_ultra: None,
                card_settlement_zoom_copper_ultra: None,
                card_settlement_zoom_iron_ultra: None,
                card_settlement_zoom_steel_ultra: None,
                card_settlement_zoom_aluminum_ultra: None,
                card_settlement_zoom_titanium_ultra: None,
                card_settlement_zoom_platinum_ultimate: None,
                card_settlement_zoom_gold_ultimate: None,
                card_settlement_zoom_silver_ultimate: None,
                card_settlement_zoom_bronze_ultimate: None,
                card_settlement_zoom_copper_ultimate: None,
                card_settlement_zoom_iron_ultimate: None,
                card_settlement_zoom_steel_ultimate: None,
                card_settlement_zoom_aluminum_ultimate: None,
                card_settlement_zoom_titanium_ultimate: None,
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only UPI payment method is supported".to_string(),
            )
            .into()),
        }
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
    TryFrom<
        EaseBuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            txnid: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: item.connector.amount_converter.convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            ).change_context(ConnectorError::RequestEncodingFailed)?,
            email: None, // TODO: Extract from router_data when available
            phone: None, // TODO: Extract from router_data when available
            key: "easebuzz_key".to_string(), // Extract from auth
            hash: Secret::new("generated_hash".to_string()), // In production, generate proper hash
        })
    }
}

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let (status, response) = match response {
            EaseBuzzPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.status.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_desc.clone().unwrap_or_default(),
                    reason: error_data.error_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EaseBuzzPaymentsResponse::Success(response_data) => {
                let redirection_data = get_redirect_form_data(response_data)?;
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: Some(Box::new(redirection_data)),
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl<
    F,
> TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = if response.status {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.txnid),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data.router_data
        })
    }
}

fn get_redirect_form_data(
    response_data: EaseBuzzPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    // For UPI payments, EaseBuzz typically returns a redirect URL
    Ok(RedirectForm::Form {
        endpoint: response_data.data,
        method: Method::Get,
        form_fields: Default::default(),
    })
}