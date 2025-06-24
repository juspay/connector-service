use crate::connector_flow::{
    Accept, Authorize, Capture, DefendDispute, PSync, RSync, Refund, SetupMandate, SubmitEvidence,
    Void,
};
use crate::connector_types::{
    AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
    DisputeWebhookDetailsResponse, MultipleCaptureRequestData, PaymentFlowData, PaymentVoidData,
    PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
    RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData,
    ResponseId, SetupMandateRequestData, SubmitEvidenceData, WebhookDetailsResponse,
};
use crate::errors::{ApiError, ApplicationErrorResponse};
use crate::utils::{ForeignFrom, ForeignTryFrom};
use error_stack::{report, ResultExt};
use grpc_api_types::payments::{
    AcceptDisputeResponse, DisputeDefendRequest, DisputeDefendResponse, DisputeResponse,
    DisputeServiceSubmitEvidenceResponse, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureResponse, PaymentServiceGetResponse,
    PaymentServiceRegisterRequest, PaymentServiceRegisterResponse, PaymentServiceVoidRequest,
    PaymentServiceVoidResponse, RefundResponse,
};
use hyperswitch_common_enums::{CaptureMethod, CardNetwork, PaymentMethod, PaymentMethodType};
use hyperswitch_common_utils::id_type::CustomerId;
use hyperswitch_common_utils::pii::Email;
use hyperswitch_masking::Secret;
// For decoding connector_meta_data and Engine trait - base64 crate no longer needed here
use hyperswitch_domain_models::mandates::MandateData;
use hyperswitch_domain_models::payment_address::PaymentAddress;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData, router_data_v2::RouterDataV2,
};
use hyperswitch_interfaces::consts::NO_ERROR_CODE;
use serde::Serialize;
use std::borrow::Cow;
use std::{collections::HashMap, str::FromStr};
use utoipa::ToSchema;
#[derive(Clone, serde::Deserialize, Debug, Default)]
pub struct Connectors {
    // Added pub
    pub adyen: ConnectorParams,
    pub razorpay: ConnectorParams,
    pub fiserv: ConnectorParams,
    pub elavon: ConnectorParams, // Add your connector params
    pub xendit: ConnectorParams,
}

#[derive(Clone, serde::Deserialize, Debug, Default)]
pub struct ConnectorParams {
    /// base url
    pub base_url: String,
    pub dispute_base_url: Option<String>,
}

#[derive(Debug, serde::Deserialize, Clone)]
pub struct Proxy {
    pub http_url: Option<String>,
    pub https_url: Option<String>,
    pub idle_pool_connection_timeout: Option<u64>,
    pub bypass_proxy_urls: Vec<String>,
}

impl ForeignTryFrom<grpc_api_types::payments::CaptureMethod>
    for hyperswitch_common_enums::CaptureMethod
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::CaptureMethod,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::CaptureMethod::Automatic => Ok(Self::Automatic),
            grpc_api_types::payments::CaptureMethod::Manual => Ok(Self::Manual),
            grpc_api_types::payments::CaptureMethod::ManualMultiple => Ok(Self::ManualMultiple),
            grpc_api_types::payments::CaptureMethod::Scheduled => Ok(Self::Scheduled),
            _ => Err(report!(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "unsupported_capture_method".to_string(),
                error_identifier: 4001,
                error_message: format!("Capture method {:?} is not supported", value),
                error_object: None,
            }))),
        }
    }
}

impl ForeignTryFrom<i32> for hyperswitch_common_enums::CardNetwork {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(connector: i32) -> Result<Self, error_stack::Report<Self::Error>> {
        match connector {
            0 => Ok(Self::Visa),
            1 => Ok(Self::Mastercard),
            2 => Ok(Self::AmericanExpress),
            3 => Ok(Self::JCB),
            4 => Ok(Self::DinersClub),
            5 => Ok(Self::Discover),
            6 => Ok(Self::CartesBancaires),
            7 => Ok(Self::UnionPay),
            8 => Ok(Self::RuPay),
            9 => Ok(Self::Maestro),
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_CARD_NETWORK".to_owned(),
                error_identifier: 401,
                error_message: format!("Invalid value for card network: {}", connector),
                error_object: None,
            })
            .into()),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentMethod> for PaymentMethodData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::PaymentMethod,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value.payment_method {
            Some(data) => match data {
                grpc_api_types::payments::payment_method::PaymentMethod::Card(card_type) => {
                    match card_type.card_type {
                        Some(grpc_api_types::payments::card_payment_method_type::CardType::Credit(card)) => Ok(
                            PaymentMethodData::Card(hyperswitch_domain_models::payment_method_data::Card {
                                card_number: hyperswitch_cards::CardNumber::from_str(&card.card_number)
                                    .change_context(ApplicationErrorResponse::BadRequest(ApiError {
                                        sub_code: "INVALID_CARD_NUMBER".to_owned(),
                                        error_identifier: 400,
                                        error_message: "Invalid card number".to_owned(),
                                        error_object: None,
                                    }))?,
                                card_exp_month: card.card_exp_month.into(),
                                card_exp_year: card.card_exp_year.into(),
                                card_cvc: card.card_cvc.into(),
                                card_issuer: card.card_issuer,
                                card_network: card
                                    .card_network
                                    .map(|network| {
                                        hyperswitch_common_enums::CardNetwork::foreign_try_from(network)
                                            .change_context(ApplicationErrorResponse::BadRequest(
                                                ApiError {
                                                    sub_code: "INVALID_CARD_NETWORK".to_owned(),
                                                    error_identifier: 400,
                                                    error_message: "Invalid card network".to_owned(),
                                                    error_object: None,
                                                },
                                            ))
                                    })
                                    .transpose()?,
                                card_type: card.card_type,
                                card_issuing_country: card.card_issuing_country_alpha2,
                                bank_code: card.bank_code,
                                nick_name: card.nick_name.map(|name| name.into()),
                            }),
                        ),
                        Some(grpc_api_types::payments::card_payment_method_type::CardType::Debit(card)) => Ok(
                            PaymentMethodData::Card(hyperswitch_domain_models::payment_method_data::Card {
                                card_number: hyperswitch_cards::CardNumber::from_str(&card.card_number)
                                    .change_context(ApplicationErrorResponse::BadRequest(ApiError {
                                        sub_code: "INVALID_CARD_NUMBER".to_owned(),
                                        error_identifier: 400,
                                        error_message: "Invalid card number".to_owned(),
                                        error_object: None,
                                    }))?,
                                card_exp_month: card.card_exp_month.into(),
                                card_exp_year: card.card_exp_year.into(),
                                card_cvc: card.card_cvc.into(),
                                card_issuer: card.card_issuer,
                                card_network: card
                                    .card_network
                                    .map(|network| {
                                        hyperswitch_common_enums::CardNetwork::foreign_try_from(network)
                                            .change_context(ApplicationErrorResponse::BadRequest(
                                                ApiError {
                                                    sub_code: "INVALID_CARD_NETWORK".to_owned(),
                                                    error_identifier: 400,
                                                    error_message: "Invalid card network".to_owned(),
                                                    error_object: None,
                                                },
                                            ))
                                    })
                                    .transpose()?,
                                card_type: card.card_type,
                                card_issuing_country: card.card_issuing_country_alpha2,
                                bank_code: card.bank_code,
                                nick_name: card.nick_name.map(|name| name.into()),
                            }),
                        ),
                        Some(grpc_api_types::payments::card_payment_method_type::CardType::CardRedirect(_card_redirect)) => {
                            Err(report!(ApplicationErrorResponse::BadRequest(ApiError {
                                sub_code: "UNSUPPORTED_PAYMENT_METHOD".to_owned(),
                                error_identifier: 400,
                                error_message: "Card redirect payments are not yet supported".to_owned(),
                                error_object: None,
                            })))
                        },
                        None => Err(report!(ApplicationErrorResponse::BadRequest(ApiError {
                            sub_code: "INVALID_PAYMENT_METHOD".to_owned(),
                            error_identifier: 400,
                            error_message: "Card type is required".to_owned(),
                            error_object: None,
                        })))
                    }
                },
                grpc_api_types::payments::payment_method::PaymentMethod::Token(_token) => Ok(
                    PaymentMethodData::CardToken(hyperswitch_domain_models::payment_method_data::CardToken {
                        card_holder_name: None,
                        card_cvc: None,
                    })
                ),
            },
            None => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_PAYMENT_METHOD_DATA".to_owned(),
                error_identifier: 400,
                error_message: "Payment method data is required".to_owned(),
                error_object: None,
            })
            .into()),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::Currency> for hyperswitch_common_enums::Currency {
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::Currency,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::Currency::Aed => Ok(Self::AED),
            grpc_api_types::payments::Currency::All => Ok(Self::ALL),
            grpc_api_types::payments::Currency::Amd => Ok(Self::AMD),
            grpc_api_types::payments::Currency::Ang => Ok(Self::ANG),
            grpc_api_types::payments::Currency::Aoa => Ok(Self::AOA),
            grpc_api_types::payments::Currency::Ars => Ok(Self::ARS),
            grpc_api_types::payments::Currency::Aud => Ok(Self::AUD),
            grpc_api_types::payments::Currency::Awg => Ok(Self::AWG),
            grpc_api_types::payments::Currency::Azn => Ok(Self::AZN),
            grpc_api_types::payments::Currency::Bam => Ok(Self::BAM),
            grpc_api_types::payments::Currency::Bbd => Ok(Self::BBD),
            grpc_api_types::payments::Currency::Bdt => Ok(Self::BDT),
            grpc_api_types::payments::Currency::Bgn => Ok(Self::BGN),
            grpc_api_types::payments::Currency::Bhd => Ok(Self::BHD),
            grpc_api_types::payments::Currency::Bif => Ok(Self::BIF),
            grpc_api_types::payments::Currency::Bmd => Ok(Self::BMD),
            grpc_api_types::payments::Currency::Bnd => Ok(Self::BND),
            grpc_api_types::payments::Currency::Bob => Ok(Self::BOB),
            grpc_api_types::payments::Currency::Brl => Ok(Self::BRL),
            grpc_api_types::payments::Currency::Bsd => Ok(Self::BSD),
            grpc_api_types::payments::Currency::Bwp => Ok(Self::BWP),
            grpc_api_types::payments::Currency::Byn => Ok(Self::BYN),
            grpc_api_types::payments::Currency::Bzd => Ok(Self::BZD),
            grpc_api_types::payments::Currency::Cad => Ok(Self::CAD),
            grpc_api_types::payments::Currency::Chf => Ok(Self::CHF),
            grpc_api_types::payments::Currency::Clp => Ok(Self::CLP),
            grpc_api_types::payments::Currency::Cny => Ok(Self::CNY),
            grpc_api_types::payments::Currency::Cop => Ok(Self::COP),
            grpc_api_types::payments::Currency::Crc => Ok(Self::CRC),
            grpc_api_types::payments::Currency::Cup => Ok(Self::CUP),
            grpc_api_types::payments::Currency::Cve => Ok(Self::CVE),
            grpc_api_types::payments::Currency::Czk => Ok(Self::CZK),
            grpc_api_types::payments::Currency::Djf => Ok(Self::DJF),
            grpc_api_types::payments::Currency::Dkk => Ok(Self::DKK),
            grpc_api_types::payments::Currency::Dop => Ok(Self::DOP),
            grpc_api_types::payments::Currency::Dzd => Ok(Self::DZD),
            grpc_api_types::payments::Currency::Egp => Ok(Self::EGP),
            grpc_api_types::payments::Currency::Etb => Ok(Self::ETB),
            grpc_api_types::payments::Currency::Eur => Ok(Self::EUR),
            grpc_api_types::payments::Currency::Fjd => Ok(Self::FJD),
            grpc_api_types::payments::Currency::Fkp => Ok(Self::FKP),
            grpc_api_types::payments::Currency::Gbp => Ok(Self::GBP),
            grpc_api_types::payments::Currency::Gel => Ok(Self::GEL),
            grpc_api_types::payments::Currency::Ghs => Ok(Self::GHS),
            grpc_api_types::payments::Currency::Gip => Ok(Self::GIP),
            grpc_api_types::payments::Currency::Gmd => Ok(Self::GMD),
            grpc_api_types::payments::Currency::Gnf => Ok(Self::GNF),
            grpc_api_types::payments::Currency::Gtq => Ok(Self::GTQ),
            grpc_api_types::payments::Currency::Gyd => Ok(Self::GYD),
            grpc_api_types::payments::Currency::Hkd => Ok(Self::HKD),
            grpc_api_types::payments::Currency::Hnl => Ok(Self::HNL),
            grpc_api_types::payments::Currency::Hrk => Ok(Self::HRK),
            grpc_api_types::payments::Currency::Htg => Ok(Self::HTG),
            grpc_api_types::payments::Currency::Huf => Ok(Self::HUF),
            grpc_api_types::payments::Currency::Idr => Ok(Self::IDR),
            grpc_api_types::payments::Currency::Ils => Ok(Self::ILS),
            grpc_api_types::payments::Currency::Inr => Ok(Self::INR),
            grpc_api_types::payments::Currency::Iqd => Ok(Self::IQD),
            grpc_api_types::payments::Currency::Jmd => Ok(Self::JMD),
            grpc_api_types::payments::Currency::Jod => Ok(Self::JOD),
            grpc_api_types::payments::Currency::Jpy => Ok(Self::JPY),
            grpc_api_types::payments::Currency::Kes => Ok(Self::KES),
            grpc_api_types::payments::Currency::Kgs => Ok(Self::KGS),
            grpc_api_types::payments::Currency::Khr => Ok(Self::KHR),
            grpc_api_types::payments::Currency::Kmf => Ok(Self::KMF),
            grpc_api_types::payments::Currency::Krw => Ok(Self::KRW),
            grpc_api_types::payments::Currency::Kwd => Ok(Self::KWD),
            grpc_api_types::payments::Currency::Kyd => Ok(Self::KYD),
            grpc_api_types::payments::Currency::Kzt => Ok(Self::KZT),
            grpc_api_types::payments::Currency::Lak => Ok(Self::LAK),
            grpc_api_types::payments::Currency::Lbp => Ok(Self::LBP),
            grpc_api_types::payments::Currency::Lkr => Ok(Self::LKR),
            grpc_api_types::payments::Currency::Lrd => Ok(Self::LRD),
            grpc_api_types::payments::Currency::Lsl => Ok(Self::LSL),
            grpc_api_types::payments::Currency::Lyd => Ok(Self::LYD),
            grpc_api_types::payments::Currency::Mad => Ok(Self::MAD),
            grpc_api_types::payments::Currency::Mdl => Ok(Self::MDL),
            grpc_api_types::payments::Currency::Mga => Ok(Self::MGA),
            grpc_api_types::payments::Currency::Mkd => Ok(Self::MKD),
            grpc_api_types::payments::Currency::Mmk => Ok(Self::MMK),
            grpc_api_types::payments::Currency::Mnt => Ok(Self::MNT),
            grpc_api_types::payments::Currency::Mop => Ok(Self::MOP),
            grpc_api_types::payments::Currency::Mru => Ok(Self::MRU),
            grpc_api_types::payments::Currency::Mur => Ok(Self::MUR),
            grpc_api_types::payments::Currency::Mvr => Ok(Self::MVR),
            grpc_api_types::payments::Currency::Mwk => Ok(Self::MWK),
            grpc_api_types::payments::Currency::Mxn => Ok(Self::MXN),
            grpc_api_types::payments::Currency::Myr => Ok(Self::MYR),
            grpc_api_types::payments::Currency::Mzn => Ok(Self::MZN),
            grpc_api_types::payments::Currency::Nad => Ok(Self::NAD),
            grpc_api_types::payments::Currency::Ngn => Ok(Self::NGN),
            grpc_api_types::payments::Currency::Nio => Ok(Self::NIO),
            grpc_api_types::payments::Currency::Nok => Ok(Self::NOK),
            grpc_api_types::payments::Currency::Npr => Ok(Self::NPR),
            grpc_api_types::payments::Currency::Nzd => Ok(Self::NZD),
            grpc_api_types::payments::Currency::Omr => Ok(Self::OMR),
            grpc_api_types::payments::Currency::Pab => Ok(Self::PAB),
            grpc_api_types::payments::Currency::Pen => Ok(Self::PEN),
            grpc_api_types::payments::Currency::Pgk => Ok(Self::PGK),
            grpc_api_types::payments::Currency::Php => Ok(Self::PHP),
            grpc_api_types::payments::Currency::Pkr => Ok(Self::PKR),
            grpc_api_types::payments::Currency::Pln => Ok(Self::PLN),
            grpc_api_types::payments::Currency::Pyg => Ok(Self::PYG),
            grpc_api_types::payments::Currency::Qar => Ok(Self::QAR),
            grpc_api_types::payments::Currency::Ron => Ok(Self::RON),
            grpc_api_types::payments::Currency::Rsd => Ok(Self::RSD),
            grpc_api_types::payments::Currency::Rub => Ok(Self::RUB),
            grpc_api_types::payments::Currency::Rwf => Ok(Self::RWF),
            grpc_api_types::payments::Currency::Sar => Ok(Self::SAR),
            grpc_api_types::payments::Currency::Sbd => Ok(Self::SBD),
            grpc_api_types::payments::Currency::Scr => Ok(Self::SCR),
            grpc_api_types::payments::Currency::Sek => Ok(Self::SEK),
            grpc_api_types::payments::Currency::Sgd => Ok(Self::SGD),
            grpc_api_types::payments::Currency::Shp => Ok(Self::SHP),
            grpc_api_types::payments::Currency::Sle => Ok(Self::SLE),
            grpc_api_types::payments::Currency::Sll => Ok(Self::SLL),
            grpc_api_types::payments::Currency::Sos => Ok(Self::SOS),
            grpc_api_types::payments::Currency::Srd => Ok(Self::SRD),
            grpc_api_types::payments::Currency::Ssp => Ok(Self::SSP),
            grpc_api_types::payments::Currency::Stn => Ok(Self::STN),
            grpc_api_types::payments::Currency::Svc => Ok(Self::SVC),
            grpc_api_types::payments::Currency::Szl => Ok(Self::SZL),
            grpc_api_types::payments::Currency::Thb => Ok(Self::THB),
            grpc_api_types::payments::Currency::Tnd => Ok(Self::TND),
            grpc_api_types::payments::Currency::Top => Ok(Self::TOP),
            grpc_api_types::payments::Currency::Try => Ok(Self::TRY),
            grpc_api_types::payments::Currency::Ttd => Ok(Self::TTD),
            grpc_api_types::payments::Currency::Twd => Ok(Self::TWD),
            grpc_api_types::payments::Currency::Tzs => Ok(Self::TZS),
            grpc_api_types::payments::Currency::Uah => Ok(Self::UAH),
            grpc_api_types::payments::Currency::Ugx => Ok(Self::UGX),
            grpc_api_types::payments::Currency::Usd => Ok(Self::USD),
            grpc_api_types::payments::Currency::Uyu => Ok(Self::UYU),
            grpc_api_types::payments::Currency::Uzs => Ok(Self::UZS),
            grpc_api_types::payments::Currency::Ves => Ok(Self::VES),
            grpc_api_types::payments::Currency::Vnd => Ok(Self::VND),
            grpc_api_types::payments::Currency::Vuv => Ok(Self::VUV),
            grpc_api_types::payments::Currency::Wst => Ok(Self::WST),
            grpc_api_types::payments::Currency::Xaf => Ok(Self::XAF),
            grpc_api_types::payments::Currency::Xcd => Ok(Self::XCD),
            grpc_api_types::payments::Currency::Xof => Ok(Self::XOF),
            grpc_api_types::payments::Currency::Xpf => Ok(Self::XPF),
            grpc_api_types::payments::Currency::Yer => Ok(Self::YER),
            grpc_api_types::payments::Currency::Zar => Ok(Self::ZAR),
            grpc_api_types::payments::Currency::Zmw => Ok(Self::ZMW),
            _ => Err(report!(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "unsupported_currency".to_string(),
                error_identifier: 4001,
                error_message: format!("Currency {:?} is not supported", value),
                error_object: None,
            }))),
        }
    }
}

impl ForeignTryFrom<PaymentServiceAuthorizeRequest> for PaymentsAuthorizeData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: PaymentServiceAuthorizeRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let email: Option<Email> = match value.email {
            Some(ref email_str) => Some(Email::try_from(email_str.clone()).map_err(|_| {
                error_stack::Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_EMAIL_FORMAT".to_owned(),
                    error_identifier: 400,

                    error_message: "Invalid email".to_owned(),
                    error_object: None,
                }))
            })?),
            None => None,
        };

        Ok(Self {
            capture_method: Some(hyperswitch_common_enums::CaptureMethod::foreign_try_from(
                value.capture_method(),
            )?),
            payment_method_data: PaymentMethodData::foreign_try_from(
                value.payment_method.clone().ok_or_else(|| {
                    ApplicationErrorResponse::BadRequest(ApiError {
                        sub_code: "INVALID_PAYMENT_METHOD_DATA".to_owned(),
                        error_identifier: 400,
                        error_message: "Payment method data is required".to_owned(),
                        error_object: None,
                    })
                })?,
            )?,
            amount: value.amount,
            currency: hyperswitch_common_enums::Currency::foreign_try_from(value.currency())?,
            confirm: true,
            webhook_url: value.webhook_url,
            browser_info: value.browser_info.map(|info| {
                hyperswitch_domain_models::router_request_types::BrowserInformation {
                    color_depth: None,
                    java_enabled: info.java_enabled,
                    java_script_enabled: info.java_script_enabled,
                    language: info.language,
                    screen_height: info.screen_height,
                    screen_width: info.screen_width,
                    time_zone: None,
                    ip_address: None,
                    accept_header: info.accept_header,
                    user_agent: info.user_agent,
                }
            }),
            payment_method_type: Some(hyperswitch_common_enums::PaymentMethodType::Credit), //TODO
            minor_amount: hyperswitch_common_utils::types::MinorUnit::new(value.minor_amount),
            email,
            customer_name: None,
            statement_descriptor_suffix: None,
            statement_descriptor: None,

            router_return_url: value.return_url,
            complete_authorize_url: None,
            setup_future_usage: None,
            mandate_id: None,
            off_session: None,
            order_category: None,
            session_token: None,
            enrolled_for_3ds: false,
            related_transaction_id: None,
            payment_experience: None,
            customer_id: value
                .connector_customer_id
                .clone()
                .map(|customer_id| CustomerId::try_from(Cow::from(customer_id)))
                .transpose()
                .change_context(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_CUSTOMER_ID".to_owned(),
                    error_identifier: 400,
                    error_message: "Failed to parse Customer Id".to_owned(),
                    error_object: None,
                }))?,
            request_incremental_authorization: false,
            metadata: None,
            merchant_order_reference_id: None,
            order_tax_amount: None,
            shipping_cost: None,
            merchant_account_id: None,
            merchant_config_currency: None,
            all_keys_required: None, // Field not available in new proto structure
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentAddress>
    for hyperswitch_domain_models::payment_address::PaymentAddress
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::PaymentAddress,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let shipping = match value.shipping_address {
            Some(address) => Some(hyperswitch_api_models::payments::Address::foreign_try_from(
                address,
            )?),
            None => None,
        };

        let billing = match value.billing_address.clone() {
            Some(address) => Some(hyperswitch_api_models::payments::Address::foreign_try_from(
                address,
            )?),
            None => None,
        };

        let payment_method_billing = match value.billing_address {
            Some(address) => Some(hyperswitch_api_models::payments::Address::foreign_try_from(
                address,
            )?),
            None => None,
        };

        Ok(Self::new(
            shipping,
            billing,
            payment_method_billing,
            Some(false), // should_unify_address set to false
        ))
    }
}

impl ForeignTryFrom<grpc_api_types::payments::Address>
    for hyperswitch_api_models::payments::Address
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::Address,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let email = match value.email.clone() {
            Some(email) => Some(
                hyperswitch_common_utils::pii::Email::from_str(&email).change_context(
                    ApplicationErrorResponse::BadRequest(ApiError {
                        sub_code: "INVALID_EMAIL".to_owned(),
                        error_identifier: 400,
                        error_message: "Invalid email".to_owned(),
                        error_object: None,
                    }),
                )?,
            ),
            None => None,
        };
        Ok(Self {
            address: Some(
                hyperswitch_api_models::payments::AddressDetails::foreign_try_from(value.clone())?,
            ),
            phone: value.phone_number.map(|phone_number| {
                hyperswitch_api_models::payments::PhoneDetails {
                    number: Some(phone_number.into()),
                    country_code: value.phone_country_code,
                }
            }),
            email,
        })
    }
}

impl ForeignTryFrom<i32> for hyperswitch_common_enums::CountryAlpha2 {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(value: i32) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            0 => Ok(Self::US),
            1 => Ok(Self::AF),
            2 => Ok(Self::AX),
            3 => Ok(Self::AL),
            4 => Ok(Self::DZ),
            5 => Ok(Self::AS),
            6 => Ok(Self::AD),
            7 => Ok(Self::AO),
            8 => Ok(Self::AI),
            9 => Ok(Self::AQ),
            10 => Ok(Self::AG),
            11 => Ok(Self::AR),
            12 => Ok(Self::AM),
            13 => Ok(Self::AW),
            14 => Ok(Self::AU),
            15 => Ok(Self::AT),
            16 => Ok(Self::AZ),
            17 => Ok(Self::BS),
            18 => Ok(Self::BH),
            19 => Ok(Self::BD),
            20 => Ok(Self::BB),
            21 => Ok(Self::BY),
            22 => Ok(Self::BE),
            23 => Ok(Self::BZ),
            24 => Ok(Self::BJ),
            25 => Ok(Self::BM),
            26 => Ok(Self::BT),
            27 => Ok(Self::BO),
            28 => Ok(Self::BQ),
            29 => Ok(Self::BA),
            30 => Ok(Self::BW),
            31 => Ok(Self::BV),
            32 => Ok(Self::BR),
            33 => Ok(Self::IO),
            34 => Ok(Self::BN),
            35 => Ok(Self::BG),
            36 => Ok(Self::BF),
            37 => Ok(Self::BI),
            38 => Ok(Self::KH),
            39 => Ok(Self::CM),
            40 => Ok(Self::CA),
            41 => Ok(Self::CV),
            42 => Ok(Self::KY),
            43 => Ok(Self::CF),
            44 => Ok(Self::TD),
            45 => Ok(Self::CL),
            46 => Ok(Self::CN),
            47 => Ok(Self::CX),
            48 => Ok(Self::CC),
            49 => Ok(Self::CO),
            50 => Ok(Self::KM),
            51 => Ok(Self::CG),
            52 => Ok(Self::CD),
            53 => Ok(Self::CK),
            54 => Ok(Self::CR),
            55 => Ok(Self::CI),
            56 => Ok(Self::HR),
            57 => Ok(Self::CU),
            58 => Ok(Self::CW),
            59 => Ok(Self::CY),
            60 => Ok(Self::CZ),
            61 => Ok(Self::DK),
            62 => Ok(Self::DJ),
            63 => Ok(Self::DM),
            64 => Ok(Self::DO),
            65 => Ok(Self::EC),
            66 => Ok(Self::EG),
            67 => Ok(Self::SV),
            68 => Ok(Self::GQ),
            69 => Ok(Self::ER),
            70 => Ok(Self::EE),
            71 => Ok(Self::ET),
            72 => Ok(Self::FK),
            73 => Ok(Self::FO),
            74 => Ok(Self::FJ),
            75 => Ok(Self::FI),
            76 => Ok(Self::FR),
            77 => Ok(Self::GF),
            78 => Ok(Self::PF),
            79 => Ok(Self::TF),
            80 => Ok(Self::GA),
            81 => Ok(Self::GM),
            82 => Ok(Self::GE),
            83 => Ok(Self::DE),
            84 => Ok(Self::GH),
            85 => Ok(Self::GI),
            86 => Ok(Self::GR),
            87 => Ok(Self::GL),
            88 => Ok(Self::GD),
            89 => Ok(Self::GP),
            90 => Ok(Self::GU),
            91 => Ok(Self::GT),
            92 => Ok(Self::GG),
            93 => Ok(Self::GN),
            94 => Ok(Self::GW),
            95 => Ok(Self::GY),
            96 => Ok(Self::HT),
            97 => Ok(Self::HM),
            98 => Ok(Self::VA),
            99 => Ok(Self::HN),
            100 => Ok(Self::HK),
            101 => Ok(Self::HU),
            102 => Ok(Self::IS),
            103 => Ok(Self::IN),
            104 => Ok(Self::ID),
            105 => Ok(Self::IR),
            106 => Ok(Self::IQ),
            107 => Ok(Self::IE),
            108 => Ok(Self::IM),
            109 => Ok(Self::IL),
            110 => Ok(Self::IT),
            111 => Ok(Self::JM),
            112 => Ok(Self::JP),
            113 => Ok(Self::JE),
            114 => Ok(Self::JO),
            115 => Ok(Self::KZ),
            116 => Ok(Self::KE),
            117 => Ok(Self::KI),
            118 => Ok(Self::KP),
            119 => Ok(Self::KR),
            120 => Ok(Self::KW),
            121 => Ok(Self::KG),
            122 => Ok(Self::LA),
            123 => Ok(Self::LV),
            124 => Ok(Self::LB),
            125 => Ok(Self::LS),
            126 => Ok(Self::LR),
            127 => Ok(Self::LY),
            128 => Ok(Self::LI),
            129 => Ok(Self::LT),
            130 => Ok(Self::LU),
            131 => Ok(Self::MO),
            132 => Ok(Self::MK),
            133 => Ok(Self::MG),
            134 => Ok(Self::MW),
            135 => Ok(Self::MY),
            136 => Ok(Self::MV),
            137 => Ok(Self::ML),
            138 => Ok(Self::MT),
            139 => Ok(Self::MH),
            140 => Ok(Self::MQ),
            141 => Ok(Self::MR),
            142 => Ok(Self::MU),
            143 => Ok(Self::YT),
            144 => Ok(Self::MX),
            145 => Ok(Self::FM),
            146 => Ok(Self::MD),
            147 => Ok(Self::MC),
            148 => Ok(Self::MN),
            149 => Ok(Self::ME),
            150 => Ok(Self::MS),
            151 => Ok(Self::MA),
            152 => Ok(Self::MZ),
            153 => Ok(Self::MM),
            154 => Ok(Self::NA),
            155 => Ok(Self::NR),
            156 => Ok(Self::NP),
            157 => Ok(Self::NL),
            158 => Ok(Self::NC),
            159 => Ok(Self::NZ),
            160 => Ok(Self::NI),
            161 => Ok(Self::NE),
            162 => Ok(Self::NG),
            163 => Ok(Self::NU),
            164 => Ok(Self::NF),
            165 => Ok(Self::MP),
            166 => Ok(Self::NO),
            167 => Ok(Self::OM),
            168 => Ok(Self::PK),
            169 => Ok(Self::PW),
            170 => Ok(Self::PS),
            171 => Ok(Self::PA),
            172 => Ok(Self::PG),
            173 => Ok(Self::PY),
            174 => Ok(Self::PE),
            175 => Ok(Self::PH),
            176 => Ok(Self::PN),
            177 => Ok(Self::PL),
            178 => Ok(Self::PT),
            179 => Ok(Self::PR),
            180 => Ok(Self::QA),
            181 => Ok(Self::RE),
            182 => Ok(Self::RO),
            183 => Ok(Self::RU),
            184 => Ok(Self::RW),
            185 => Ok(Self::BL),
            186 => Ok(Self::SH),
            187 => Ok(Self::KN),
            188 => Ok(Self::LC),
            189 => Ok(Self::MF),
            190 => Ok(Self::PM),
            191 => Ok(Self::VC),
            192 => Ok(Self::WS),
            193 => Ok(Self::SM),
            194 => Ok(Self::ST),
            195 => Ok(Self::SA),
            196 => Ok(Self::SN),
            197 => Ok(Self::RS),
            198 => Ok(Self::SC),
            199 => Ok(Self::SL),
            200 => Ok(Self::SG),
            201 => Ok(Self::SX),
            202 => Ok(Self::SK),
            203 => Ok(Self::SI),
            204 => Ok(Self::SB),
            205 => Ok(Self::SO),
            206 => Ok(Self::ZA),
            207 => Ok(Self::GS),
            208 => Ok(Self::SS),
            209 => Ok(Self::ES),
            210 => Ok(Self::LK),
            211 => Ok(Self::SD),
            212 => Ok(Self::SR),
            213 => Ok(Self::SJ),
            214 => Ok(Self::SZ),
            215 => Ok(Self::SE),
            216 => Ok(Self::CH),
            217 => Ok(Self::SY),
            218 => Ok(Self::TW),
            219 => Ok(Self::TJ),
            220 => Ok(Self::TZ),
            221 => Ok(Self::TH),
            222 => Ok(Self::TL),
            223 => Ok(Self::TG),
            224 => Ok(Self::TK),
            225 => Ok(Self::TO),
            226 => Ok(Self::TT),
            227 => Ok(Self::TN),
            228 => Ok(Self::TR),
            229 => Ok(Self::TM),
            230 => Ok(Self::TC),
            231 => Ok(Self::TV),
            232 => Ok(Self::UG),
            233 => Ok(Self::UA),
            234 => Ok(Self::AE),
            235 => Ok(Self::GB),
            236 => Ok(Self::UM),
            237 => Ok(Self::UY),
            238 => Ok(Self::UZ),
            239 => Ok(Self::VU),
            240 => Ok(Self::VE),
            241 => Ok(Self::VN),
            242 => Ok(Self::VG),
            243 => Ok(Self::VI),
            244 => Ok(Self::WF),
            245 => Ok(Self::EH),
            246 => Ok(Self::YE),
            247 => Ok(Self::ZM),
            248 => Ok(Self::ZW),
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_ADDRESS".to_owned(),
                error_identifier: 400,
                error_message: "Address is required".to_owned(),
                error_object: None,
            }))?,
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::Address>
    for hyperswitch_api_models::payments::AddressDetails
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::Address,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            city: value.city,
            country: value
                .country_alpha2_code
                .map(hyperswitch_common_enums::CountryAlpha2::foreign_try_from)
                .transpose()?,
            line1: value.line1.map(|val| val.into()),
            line2: value.line2.map(|val| val.into()),
            line3: value.line3.map(|val| val.into()),
            zip: value.zip_code.map(|val| val.into()),
            state: value.state.map(|val| val.into()),
            first_name: value.first_name.map(|val| val.into()),
            last_name: value.last_name.map(|val| val.into()),
        })
    }
}

// PhoneDetails conversion removed - phone info is now embedded in Address

impl ForeignTryFrom<(PaymentServiceAuthorizeRequest, Connectors)> for PaymentFlowData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (PaymentServiceAuthorizeRequest, Connectors),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let address = match &value.address {
            // Borrow value.address
            Some(address_value) => {
                // address_value is &grpc_api_types::payments::PaymentAddress
                hyperswitch_domain_models::payment_address::PaymentAddress::foreign_try_from(
                    (*address_value).clone(), // Clone the grpc_api_types::payments::PaymentAddress
                )?
            }
            None => {
                return Err(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_ADDRESS".to_owned(),
                    error_identifier: 400,
                    error_message: "Address is required".to_owned(),
                    error_object: None,
                }))?
            }
        };
        Ok(Self {
            merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
            payment_id: "IRRELEVANT_PAYMENT_ID".to_string(),
            attempt_id: "IRRELEVANT_ATTEMPT_ID".to_string(),
            status: hyperswitch_common_enums::AttemptStatus::Pending,
            payment_method: hyperswitch_common_enums::PaymentMethod::foreign_try_from(
                value.payment_method.unwrap_or_default(),
            )?, // Use direct enum
            address,
            auth_type: hyperswitch_common_enums::AuthenticationType::foreign_try_from(
                grpc_api_types::payments::AuthenticationType::try_from(value.auth_type)
                    .unwrap_or_default(),
            )?, // Use direct enum
            connector_request_reference_id: value
                .request_ref_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
            customer_id: None,
            connector_customer: value.connector_customer_id,
            description: None,
            return_url: value.return_url.clone(),
            connector_meta_data: {
                value.metadata.get("connector_meta_data").map(|json_string| {
                    Ok::<Secret<serde_json::Value>, error_stack::Report<ApplicationErrorResponse>>(Secret::new(serde_json::Value::String(json_string.clone())))
                }).transpose()? // Converts Option<Result<T, E>> to Result<Option<T>, E> and propagates E if it's an Err
            },
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            preprocessing_id: None,
            connector_api_version: None,
            test_mode: None,
            connector_http_status_code: None,
            external_latency: None,
            connectors,
            raw_connector_response: None,
        })
    }
}
impl ForeignTryFrom<(PaymentServiceVoidRequest, Connectors)> for PaymentFlowData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (PaymentServiceVoidRequest, Connectors),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let address: PaymentAddress = {
            hyperswitch_domain_models::payment_address::PaymentAddress::new(
                None,
                None,
                None,
                Some(false),
            )
        };
        Ok(Self {
            merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
            payment_id: "IRRELEVANT_PAYMENT_ID".to_string(),
            attempt_id: "IRRELEVANT_ATTEMPT_ID".to_string(),
            status: hyperswitch_common_enums::AttemptStatus::Pending,
            payment_method: hyperswitch_common_enums::PaymentMethod::Card, //TODO
            address,
            auth_type: hyperswitch_common_enums::AuthenticationType::default(),
            connector_request_reference_id: value
                .request_ref_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
            customer_id: None,
            connector_customer: None,
            description: None,
            return_url: None,
            connector_meta_data: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            preprocessing_id: None,
            connector_api_version: None,
            test_mode: None,
            connector_http_status_code: None,
            external_latency: None,
            connectors,
            raw_connector_response: None,
        })
    }
}

impl ForeignTryFrom<ResponseId> for grpc_api_types::payments::Identifier {
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(value: ResponseId) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(match value {
            ResponseId::ConnectorTransactionId(id) => Self {
                id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
            },
            ResponseId::EncodedData(data) => Self {
                id_type: Some(grpc_api_types::payments::identifier::IdType::EncodedData(
                    data,
                )),
            },
            ResponseId::NoResponseId => Self {
                id_type: Some(grpc_api_types::payments::identifier::IdType::NoResponseIdMarker(())),
            },
        })
    }
}

pub fn generate_payment_authorize_response(
    router_data_v2: RouterDataV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    >,
) -> Result<PaymentServiceAuthorizeResponse, error_stack::Report<ApplicationErrorResponse>> {
    let transaction_response = router_data_v2.response;
    let status = router_data_v2.resource_common_data.status;
    let grpc_status = grpc_api_types::payments::PaymentStatus::foreign_from(status);
    let response = match transaction_response {
        Ok(response) => match response {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data,
                connector_metadata: _,
                network_txn_id,
                connector_response_reference_id,
                incremental_authorization_allowed,
                mandate_reference: _,
                raw_connector_response: _,
            } => {
                PaymentServiceAuthorizeResponse {
                    transaction_id: Some(grpc_api_types::payments::Identifier::foreign_try_from(resource_id)?),
                    redirection_data: redirection_data.map(
                        |form| {
                            match form {
                                hyperswitch_domain_models::router_response_types::RedirectForm::Form { endpoint, method: _, form_fields: _ } => {
                                    Ok::<grpc_api_types::payments::RedirectForm, ApplicationErrorResponse>(grpc_api_types::payments::RedirectForm {
                                        form_type: Some(grpc_api_types::payments::redirect_form::FormType::Form(
                                            grpc_api_types::payments::FormData {
                                                endpoint,
                                                method: 0,
                                                form_fields: HashMap::default(), //TODO
                                            }
                                        ))
                                    })
                                },
                                hyperswitch_domain_models::router_response_types::RedirectForm::Html { html_data } => {
                                    Ok(grpc_api_types::payments::RedirectForm {
                                        form_type: Some(grpc_api_types::payments::redirect_form::FormType::Html(
                                            grpc_api_types::payments::HtmlData {
                                                html_data,
                                            }
                                        ))
                                    })
                                },
                                _ => Err(
                                    ApplicationErrorResponse::BadRequest(ApiError {
                                        sub_code: "INVALID_RESPONSE".to_owned(),
                                        error_identifier: 400,
                                        error_message: "Invalid response from connector".to_owned(),
                                        error_object: None,
                                    }))?,
                            }
                        }
                    ).transpose()?,
                    network_txn_id,
                    response_ref_id: connector_response_reference_id.map(|id| grpc_api_types::payments::Identifier {
                        id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                    }),
                    incremental_authorization_allowed,
                    status: grpc_status as i32,
                    error_message: None,
                    error_code: None,
                }
            }
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_RESPONSE".to_owned(),
                error_identifier: 400,
                error_message: "Invalid response from connector".to_owned(),
                error_object: None,
            }))?,
        },
        Err(err) => {
            let status = err
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();
            PaymentServiceAuthorizeResponse {
                transaction_id: Some(grpc_api_types::payments::Identifier {
                    id_type: Some(
                        grpc_api_types::payments::identifier::IdType::NoResponseIdMarker(()),
                    ),
                }),
                redirection_data: None,
                network_txn_id: None,
                response_ref_id: err.connector_transaction_id.map(|id| {
                    grpc_api_types::payments::Identifier {
                        id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                    }
                }),
                incremental_authorization_allowed: None,
                status: status as i32,
                error_message: Some(err.message),
                error_code: Some(err.code),
            }
        }
    };
    Ok(response)
}

// ForeignTryFrom for PaymentMethod gRPC enum to internal enum
impl ForeignTryFrom<grpc_api_types::payments::PaymentMethod>
    for hyperswitch_common_enums::PaymentMethod
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        item: grpc_api_types::payments::PaymentMethod,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match item {
            grpc_api_types::payments::PaymentMethod {
                payment_method:
                    Some(grpc_api_types::payments::payment_method::PaymentMethod::Card(_)),
            } => Ok(Self::Card),
            grpc_api_types::payments::PaymentMethod {
                payment_method:
                    Some(grpc_api_types::payments::payment_method::PaymentMethod::Token(_)),
            } => Ok(Self::Wallet),
            _ => Ok(Self::Card), // Default fallback
        }
    }
}

// ForeignTryFrom for AuthenticationType gRPC enum to internal enum
impl ForeignTryFrom<grpc_api_types::payments::AuthenticationType>
    for hyperswitch_common_enums::AuthenticationType
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        item: grpc_api_types::payments::AuthenticationType,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match item {
            grpc_api_types::payments::AuthenticationType::Unspecified => Ok(Self::NoThreeDs), // Default to NoThreeDs for unspecified
            grpc_api_types::payments::AuthenticationType::ThreeDs => Ok(Self::ThreeDs),
            grpc_api_types::payments::AuthenticationType::NoThreeDs => Ok(Self::NoThreeDs),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentServiceGetRequest> for PaymentsSyncData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::PaymentServiceGetRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        // Create ResponseId from resource_id
        let connector_transaction_id = ResponseId::ConnectorTransactionId(
            value
                .transaction_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
        );

        // Default currency to USD for now (you might want to get this from somewhere else)
        let currency = hyperswitch_common_enums::Currency::USD;

        // Default amount to 0
        let amount = hyperswitch_common_utils::types::MinorUnit::new(0);

        Ok(Self {
            connector_transaction_id,
            encoded_data: None,
            capture_method: None,
            connector_meta: None,
            sync_type:
                hyperswitch_domain_models::router_request_types::SyncRequestType::SinglePaymentSync,
            mandate_id: None,
            payment_method_type: None,
            currency,
            payment_experience: None,
            amount,
            all_keys_required: None, // Field not available in new proto structure
        })
    }
}

impl
    ForeignTryFrom<(
        grpc_api_types::payments::PaymentServiceGetRequest,
        Connectors,
    )> for PaymentFlowData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (
            grpc_api_types::payments::PaymentServiceGetRequest,
            Connectors,
        ),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
            payment_id: "PAYMENT_ID".to_string(),
            attempt_id: "ATTEMPT_ID".to_string(),
            status: hyperswitch_common_enums::AttemptStatus::Pending,
            payment_method: hyperswitch_common_enums::PaymentMethod::Card, // Default
            address: hyperswitch_domain_models::payment_address::PaymentAddress::default(),
            auth_type: hyperswitch_common_enums::AuthenticationType::default(),
            connector_request_reference_id: value
                .request_ref_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_else(|| "default_reference_id".to_string()),
            customer_id: None,
            connector_customer: None,
            description: None,
            return_url: None,
            connector_meta_data: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            preprocessing_id: None,
            connector_api_version: None,
            test_mode: None,
            connector_http_status_code: None,
            external_latency: None,
            connectors,
            raw_connector_response: None,
        })
    }
}

impl ForeignFrom<hyperswitch_common_enums::AttemptStatus>
    for grpc_api_types::payments::PaymentStatus
{
    fn foreign_from(status: hyperswitch_common_enums::AttemptStatus) -> Self {
        match status {
            hyperswitch_common_enums::AttemptStatus::Charged => Self::Charged,
            hyperswitch_common_enums::AttemptStatus::Pending => Self::Pending,
            hyperswitch_common_enums::AttemptStatus::Failure => Self::Failure,
            hyperswitch_common_enums::AttemptStatus::Authorized => Self::Authorized,
            hyperswitch_common_enums::AttemptStatus::Started => Self::Started,
            hyperswitch_common_enums::AttemptStatus::AuthenticationFailed => {
                Self::AuthenticationFailed
            }
            hyperswitch_common_enums::AttemptStatus::AuthenticationPending => {
                Self::AuthenticationPending
            }
            hyperswitch_common_enums::AttemptStatus::AuthenticationSuccessful => {
                Self::AuthenticationSuccessful
            }
            hyperswitch_common_enums::AttemptStatus::Authorizing => Self::Authorizing,
            hyperswitch_common_enums::AttemptStatus::CaptureInitiated => Self::CaptureInitiated,
            hyperswitch_common_enums::AttemptStatus::CaptureFailed => Self::CaptureFailed,
            hyperswitch_common_enums::AttemptStatus::VoidInitiated => Self::VoidInitiated,
            hyperswitch_common_enums::AttemptStatus::VoidFailed => Self::VoidFailed,
            hyperswitch_common_enums::AttemptStatus::Voided => Self::Voided,
            hyperswitch_common_enums::AttemptStatus::Unresolved => Self::Unresolved,
            hyperswitch_common_enums::AttemptStatus::PaymentMethodAwaited => {
                Self::PaymentMethodAwaited
            }
            hyperswitch_common_enums::AttemptStatus::ConfirmationAwaited => {
                Self::ConfirmationAwaited
            }
            hyperswitch_common_enums::AttemptStatus::DeviceDataCollectionPending => {
                Self::DeviceDataCollectionPending
            }
            hyperswitch_common_enums::AttemptStatus::RouterDeclined => Self::RouterDeclined,
            hyperswitch_common_enums::AttemptStatus::AuthorizationFailed => {
                Self::AuthorizationFailed
            }
            hyperswitch_common_enums::AttemptStatus::CodInitiated => Self::CodInitiated,
            hyperswitch_common_enums::AttemptStatus::AutoRefunded => Self::AutoRefunded,
            hyperswitch_common_enums::AttemptStatus::PartialCharged => Self::PartialCharged,
            hyperswitch_common_enums::AttemptStatus::PartialChargedAndChargeable => {
                Self::PartialChargedAndChargeable
            }
        }
    }
}

impl ForeignFrom<hyperswitch_common_enums::RefundStatus>
    for grpc_api_types::payments::RefundStatus
{
    fn foreign_from(status: hyperswitch_common_enums::RefundStatus) -> Self {
        match status {
            hyperswitch_common_enums::RefundStatus::Failure => Self::RefundFailure,
            hyperswitch_common_enums::RefundStatus::ManualReview => Self::RefundManualReview,
            hyperswitch_common_enums::RefundStatus::Pending => Self::RefundPending,
            hyperswitch_common_enums::RefundStatus::Success => Self::RefundSuccess,
            hyperswitch_common_enums::RefundStatus::TransactionFailure => {
                Self::RefundTransactionFailure
            }
        }
    }
}

pub fn generate_payment_void_response(
    router_data_v2: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
) -> Result<PaymentServiceVoidResponse, error_stack::Report<ApplicationErrorResponse>> {
    let transaction_response = router_data_v2.response;

    match transaction_response {
        Ok(response) => match response {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: _,
                connector_metadata: _,
                network_txn_id: _,
                connector_response_reference_id,
                incremental_authorization_allowed: _,
                mandate_reference: _,
                raw_connector_response: _,
            } => {
                let status = router_data_v2.resource_common_data.status;
                let grpc_status = grpc_api_types::payments::PaymentStatus::foreign_from(status);

                let grpc_resource_id =
                    grpc_api_types::payments::Identifier::foreign_try_from(resource_id)?;

                Ok(PaymentServiceVoidResponse {
                    transaction_id: Some(grpc_resource_id),
                    status: grpc_status.into(),
                    response_ref_id: connector_response_reference_id.map(|id| {
                        grpc_api_types::payments::Identifier {
                            id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                        }
                    }),
                    error_code: None,
                    error_message: None,
                })
            }
            _ => Err(report!(ApplicationErrorResponse::InternalServerError(
                ApiError {
                    sub_code: "INVALID_RESPONSE_TYPE".to_owned(),
                    error_identifier: 500,
                    error_message: "Invalid response type received from connector".to_owned(),
                    error_object: None,
                }
            ))),
        },
        Err(e) => {
            let status = e
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();
            Ok(PaymentServiceVoidResponse {
                transaction_id: Some(grpc_api_types::payments::Identifier {
                    id_type: Some(
                        grpc_api_types::payments::identifier::IdType::NoResponseIdMarker(()),
                    ),
                }),
                response_ref_id: e.connector_transaction_id.map(|id| {
                    grpc_api_types::payments::Identifier {
                        id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                    }
                }),
                status: status as i32,
                error_message: Some(e.message),
                error_code: Some(e.code),
            })
        }
    }
}

impl ForeignFrom<hyperswitch_common_enums::DisputeStage>
    for grpc_api_types::payments::DisputeStage
{
    fn foreign_from(status: hyperswitch_common_enums::DisputeStage) -> Self {
        match status {
            hyperswitch_common_enums::DisputeStage::PreDispute => Self::PreDispute,
            hyperswitch_common_enums::DisputeStage::Dispute => Self::ActiveDispute,
            hyperswitch_common_enums::DisputeStage::PreArbitration => Self::PreArbitration,
        }
    }
}

pub fn generate_payment_sync_response(
    router_data_v2: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
) -> Result<PaymentServiceGetResponse, error_stack::Report<ApplicationErrorResponse>> {
    let transaction_response = router_data_v2.response;

    match transaction_response {
        Ok(response) => match response {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: _,
                connector_metadata: _,
                network_txn_id: _,
                connector_response_reference_id: _,
                incremental_authorization_allowed: _,
                mandate_reference: _,
                raw_connector_response: _,
            } => {
                let status = router_data_v2.resource_common_data.status;
                let grpc_status = grpc_api_types::payments::PaymentStatus::foreign_from(status);

                let grpc_resource_id =
                    grpc_api_types::payments::Identifier::foreign_try_from(resource_id)?;

                let mandate_reference_grpc = None;

                Ok(PaymentServiceGetResponse {
                    transaction_id: Some(grpc_resource_id),
                    status: grpc_status as i32,
                    mandate_reference: mandate_reference_grpc,
                    error_code: None,
                    error_message: None,
                    network_txn_id: None,
                    response_ref_id: None,
                    amount: None,
                    minor_amount: None,
                    currency: None,
                    captured_amount: None,
                    minor_captured_amount: None,
                    payment_method_type: None,
                    capture_method: None,
                    auth_type: None,
                    created_at: None,
                    updated_at: None,
                    authorized_at: None,
                    captured_at: None,
                    customer_name: None,
                    email: None,
                    connector_customer_id: None,
                    merchant_order_reference_id: None,
                    metadata: std::collections::HashMap::new(),
                })
            }
            _ => Err(report!(ApplicationErrorResponse::InternalServerError(
                ApiError {
                    sub_code: "INVALID_RESPONSE_TYPE".to_owned(),
                    error_identifier: 500,
                    error_message: "Invalid response type received from connector".to_owned(),
                    error_object: None,
                }
            ))),
        },
        Err(e) => {
            let status = e
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();
            Ok(PaymentServiceGetResponse {
                transaction_id: Some(grpc_api_types::payments::Identifier {
                    id_type: Some(
                        grpc_api_types::payments::identifier::IdType::NoResponseIdMarker(()),
                    ),
                }),
                mandate_reference: None,
                status: status as i32,
                error_message: Some(e.message),
                error_code: Some(e.code),
                network_txn_id: None,
                response_ref_id: None,
                amount: None,
                minor_amount: None,
                currency: None,
                captured_amount: None,
                minor_captured_amount: None,
                payment_method_type: None,
                capture_method: None,
                auth_type: None,
                created_at: None,
                updated_at: None,
                authorized_at: None,
                captured_at: None,
                customer_name: None,
                email: None,
                connector_customer_id: None,
                merchant_order_reference_id: None,
                metadata: std::collections::HashMap::new(),
            })
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::RefundServiceGetRequest> for RefundSyncData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::RefundServiceGetRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        // Extract transaction_id as connector_transaction_id
        let connector_transaction_id = value
            .transaction_id
            .and_then(|id| id.id_type)
            .and_then(|id_type| match id_type {
                grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                _ => None,
            })
            .unwrap_or_default();

        Ok(RefundSyncData {
            connector_transaction_id,
            connector_refund_id: value.refund_id.clone(),
            reason: value.refund_reason.clone(),
            refund_status: hyperswitch_common_enums::RefundStatus::Pending,
            refund_connector_metadata: None,
            all_keys_required: None, // Field not available in new proto structure
        })
    }
}

impl
    ForeignTryFrom<(
        grpc_api_types::payments::RefundServiceGetRequest,
        Connectors,
    )> for RefundFlowData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (_value, connectors): (
            grpc_api_types::payments::RefundServiceGetRequest,
            Connectors,
        ),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(RefundFlowData {
            status: hyperswitch_common_enums::RefundStatus::Pending,
            refund_id: None,
            connectors,
            raw_connector_response: None,
        })
    }
}

impl
    ForeignTryFrom<(
        grpc_api_types::payments::PaymentServiceRefundRequest,
        Connectors,
    )> for RefundFlowData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (
            grpc_api_types::payments::PaymentServiceRefundRequest,
            Connectors,
        ),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(RefundFlowData {
            status: hyperswitch_common_enums::RefundStatus::Pending,
            refund_id: Some(value.refund_id),
            connectors,
            raw_connector_response: None,
        })
    }
}

impl ForeignFrom<hyperswitch_common_enums::DisputeStatus>
    for grpc_api_types::payments::DisputeStatus
{
    fn foreign_from(status: hyperswitch_common_enums::DisputeStatus) -> Self {
        match status {
            hyperswitch_common_enums::DisputeStatus::DisputeOpened => Self::DisputeOpened,
            hyperswitch_common_enums::DisputeStatus::DisputeAccepted => Self::DisputeAccepted,
            hyperswitch_common_enums::DisputeStatus::DisputeCancelled => Self::DisputeCancelled,
            hyperswitch_common_enums::DisputeStatus::DisputeChallenged => Self::DisputeChallenged,
            hyperswitch_common_enums::DisputeStatus::DisputeExpired => Self::DisputeExpired,
            hyperswitch_common_enums::DisputeStatus::DisputeLost => Self::DisputeLost,
            hyperswitch_common_enums::DisputeStatus::DisputeWon => Self::DisputeWon,
        }
    }
}

pub fn generate_accept_dispute_response(
    router_data_v2: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
) -> Result<AcceptDisputeResponse, error_stack::Report<ApplicationErrorResponse>> {
    let dispute_response = router_data_v2.response;

    match dispute_response {
        Ok(response) => {
            let grpc_status =
                grpc_api_types::payments::DisputeStatus::foreign_from(response.dispute_status);

            Ok(AcceptDisputeResponse {
                dispute_status: grpc_status.into(),
                dispute_id: response.connector_dispute_id,
                connector_status_code: None,
                error_message: None,
                error_code: None,
                response_ref_id: None,
            })
        }
        Err(e) => {
            let grpc_dispute_status = grpc_api_types::payments::DisputeStatus::default();

            Ok(AcceptDisputeResponse {
                dispute_status: grpc_dispute_status as i32,
                dispute_id: e.connector_transaction_id.unwrap_or_default(),
                connector_status_code: None,
                error_message: Some(e.message),
                error_code: Some(e.code),
                response_ref_id: None,
            })
        }
    }
}

impl ForeignTryFrom<(grpc_api_types::payments::AcceptDisputeRequest, Connectors)>
    for DisputeFlowData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (grpc_api_types::payments::AcceptDisputeRequest, Connectors),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(DisputeFlowData {
            dispute_id: None,
            connectors,
            connector_dispute_id: value.dispute_id,
            defense_reason_code: None,
            raw_connector_response: None,
        })
    }
}

pub fn generate_submit_evidence_response(
    router_data_v2: RouterDataV2<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    >,
) -> Result<DisputeServiceSubmitEvidenceResponse, error_stack::Report<ApplicationErrorResponse>> {
    let dispute_response = router_data_v2.response;

    match dispute_response {
        Ok(response) => {
            let grpc_status =
                grpc_api_types::payments::DisputeStatus::foreign_from(response.dispute_status);

            Ok(DisputeServiceSubmitEvidenceResponse {
                dispute_status: grpc_status.into(),
                dispute_id: Some(response.connector_dispute_id),
                submitted_evidence_ids: vec![],
                connector_status_code: None,
                error_message: None,
                error_code: None,
                response_ref_id: None,
            })
        }
        Err(e) => {
            let grpc_attempt_status = e
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();

            Ok(DisputeServiceSubmitEvidenceResponse {
                dispute_status: grpc_attempt_status.into(),
                dispute_id: e.connector_transaction_id,
                submitted_evidence_ids: vec![],
                connector_status_code: None,
                error_message: Some(e.message),
                error_code: Some(e.code),
                response_ref_id: None,
            })
        }
    }
}

impl
    ForeignTryFrom<(
        grpc_api_types::payments::DisputeServiceSubmitEvidenceRequest,
        Connectors,
    )> for DisputeFlowData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (
            grpc_api_types::payments::DisputeServiceSubmitEvidenceRequest,
            Connectors,
        ),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(DisputeFlowData {
            dispute_id: None,
            connectors,
            connector_dispute_id: value.dispute_id,
            defense_reason_code: None,
            raw_connector_response: None,
        })
    }
}

pub fn generate_refund_sync_response(
    router_data_v2: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
) -> Result<RefundResponse, error_stack::Report<ApplicationErrorResponse>> {
    let refunds_response = router_data_v2.response;

    match refunds_response {
        Ok(response) => {
            let status = response.refund_status;
            let grpc_status = grpc_api_types::payments::RefundStatus::foreign_from(status);

            Ok(RefundResponse {
                transaction_id: Some(grpc_api_types::payments::Identifier::default()),
                refund_id: response.connector_refund_id.clone(),
                status: grpc_status as i32,
                response_ref_id: Some(grpc_api_types::payments::Identifier {
                    id_type: Some(grpc_api_types::payments::identifier::IdType::Id(
                        response.connector_refund_id.clone(),
                    )),
                }),
                error_code: None,
                error_message: None,
                refund_amount: None,
                minor_refund_amount: None,
                refund_currency: None,
                payment_amount: None,
                minor_payment_amount: None,
                refund_reason: None,
                created_at: None,
                updated_at: None,
                processed_at: None,
                customer_name: None,
                email: None,
                merchant_order_reference_id: None,
                metadata: std::collections::HashMap::new(),
                refund_metadata: std::collections::HashMap::new(),
            })
        }
        Err(e) => {
            let status = e
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();

            Ok(RefundResponse {
                transaction_id: Some(
                    e.connector_transaction_id
                        .as_ref()
                        .map(|id| grpc_api_types::payments::Identifier {
                            id_type: Some(grpc_api_types::payments::identifier::IdType::Id(
                                id.clone(),
                            )),
                        })
                        .unwrap_or_default(),
                ),
                refund_id: String::new(),
                status: status as i32,
                response_ref_id: e.connector_transaction_id.map(|id| {
                    grpc_api_types::payments::Identifier {
                        id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                    }
                }),
                error_code: Some(e.code),
                error_message: Some(e.message),
                refund_amount: None,
                minor_refund_amount: None,
                refund_currency: None,
                payment_amount: None,
                minor_payment_amount: None,
                refund_reason: None,
                created_at: None,
                updated_at: None,
                processed_at: None,
                customer_name: None,
                email: None,
                merchant_order_reference_id: None,
                metadata: std::collections::HashMap::new(),
                refund_metadata: std::collections::HashMap::new(),
            })
        }
    }
}
impl ForeignTryFrom<WebhookDetailsResponse> for PaymentServiceGetResponse {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: WebhookDetailsResponse,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let status = grpc_api_types::payments::PaymentStatus::foreign_from(value.status);
        Ok(Self {
            transaction_id: value
                .resource_id
                .map(|resource_id| {
                    grpc_api_types::payments::Identifier::foreign_try_from(resource_id)
                })
                .transpose()?,
            status: status as i32,
            mandate_reference: None,
            error_code: value.error_code,
            error_message: value.error_message,
            network_txn_id: None,
            response_ref_id: None,
            amount: None,
            minor_amount: None,
            currency: None,
            captured_amount: None,
            minor_captured_amount: None,
            payment_method_type: None,
            capture_method: None,
            auth_type: None,
            created_at: None,
            updated_at: None,
            authorized_at: None,
            captured_at: None,
            customer_name: None,
            email: None,
            connector_customer_id: None,
            merchant_order_reference_id: None,
            metadata: std::collections::HashMap::new(),
        })
    }
}

impl ForeignTryFrom<PaymentServiceVoidRequest> for PaymentVoidData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: PaymentServiceVoidRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            connector_transaction_id: value
                .request_ref_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
            cancellation_reason: value.cancellation_reason,
            raw_connector_response: None,
        })
    }
}

impl ForeignTryFrom<RefundWebhookDetailsResponse> for RefundResponse {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: RefundWebhookDetailsResponse,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let status = grpc_api_types::payments::RefundStatus::foreign_from(value.status);

        Ok(Self {
            transaction_id: Some(grpc_api_types::payments::Identifier::default()),
            refund_id: value.connector_refund_id.unwrap_or_default(),
            status: status.into(),
            response_ref_id: value.connector_response_reference_id.map(|id| {
                grpc_api_types::payments::Identifier {
                    id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                }
            }),
            error_code: value.error_code,
            error_message: value.error_message,
            refund_amount: None,
            minor_refund_amount: None,
            refund_currency: None,
            payment_amount: None,
            minor_payment_amount: None,
            refund_reason: None,
            created_at: None,
            updated_at: None,
            processed_at: None,
            customer_name: None,
            email: None,
            merchant_order_reference_id: None,
            metadata: std::collections::HashMap::new(),
            refund_metadata: std::collections::HashMap::new(),
        })
    }
}

impl ForeignTryFrom<DisputeWebhookDetailsResponse> for DisputeResponse {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: DisputeWebhookDetailsResponse,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let grpc_status = grpc_api_types::payments::DisputeStatus::foreign_from(value.status);
        let grpc_stage = grpc_api_types::payments::DisputeStage::foreign_from(value.stage);
        Ok(Self {
            dispute_id: Some(value.dispute_id),
            transaction_id: None,
            dispute_status: grpc_status.into(),
            dispute_stage: grpc_stage.into(),
            connector_status_code: None,
            error_code: None,
            error_message: None,
            dispute_amount: None,
            dispute_currency: None,
            dispute_date: None,
            service_date: None,
            shipping_date: None,
            due_date: None,
            evidence_documents: vec![],
            dispute_reason: None,
            dispute_message: value.dispute_message,
            response_ref_id: value.connector_response_reference_id.map(|id| {
                grpc_api_types::payments::Identifier {
                    id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                }
            }),
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentServiceRefundRequest> for RefundsData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::PaymentServiceRefundRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let minor_refund_amount =
            hyperswitch_common_utils::types::MinorUnit::new(value.minor_refund_amount);

        let minor_payment_amount =
            hyperswitch_common_utils::types::MinorUnit::new(value.minor_payment_amount);

        // Extract transaction_id as connector_transaction_id
        let connector_transaction_id = value
            .transaction_id
            .clone()
            .and_then(|id| id.id_type)
            .and_then(|id_type| match id_type {
                grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                _ => None,
            })
            .unwrap_or_default();

        Ok(RefundsData {
            refund_id: value.refund_id.to_string(),
            connector_transaction_id,
            connector_refund_id: None, // refund_id field is used as refund_id, not connector_refund_id
            currency: hyperswitch_common_enums::Currency::foreign_try_from(value.currency())?,
            payment_amount: value.payment_amount,
            reason: value.reason.clone(),
            webhook_url: value.webhook_url,
            refund_amount: value.refund_amount,
            connector_metadata: {
                value
                    .metadata
                    .get("connector_metadata")
                    .map(|json_string| {
                        Ok::<serde_json::Value, error_stack::Report<ApplicationErrorResponse>>(
                            serde_json::Value::String(json_string.clone()),
                        )
                    })
                    .transpose()? // Should be Option<serde_json::Value>, not Secret
            },
            refund_connector_metadata: {
                value.refund_metadata.get("refund_connector_metadata").map(|json_string| {
                    Ok::<Secret<serde_json::Value>, error_stack::Report<ApplicationErrorResponse>>(Secret::new(serde_json::Value::String(json_string.clone())))
                }).transpose()?
            },
            minor_payment_amount,
            minor_refund_amount,
            refund_status: hyperswitch_common_enums::RefundStatus::Pending,
            merchant_account_id: value.merchant_account_id,
            capture_method: value
                .capture_method
                .map(|cm| {
                    hyperswitch_common_enums::CaptureMethod::foreign_try_from(
                        grpc_api_types::payments::CaptureMethod::try_from(cm).unwrap_or_default(),
                    )
                })
                .transpose()?,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::AcceptDisputeRequest> for AcceptDisputeData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        _value: grpc_api_types::payments::AcceptDisputeRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(AcceptDisputeData {})
    }
}

impl ForeignTryFrom<grpc_api_types::payments::DisputeServiceSubmitEvidenceRequest>
    for SubmitEvidenceData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::DisputeServiceSubmitEvidenceRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        // For now, we'll create a simplified SubmitEvidenceData using evidence_documents
        // The individual fields will be extracted from evidence_documents if needed
        Ok(SubmitEvidenceData {
            dispute_id: Some(value.dispute_id.clone()),
            connector_dispute_id: value.dispute_id, // Using dispute_id as connector_dispute_id
            access_activity_log: None,              // Extract from evidence_documents if present
            billing_address: None,
            cancellation_policy: None,
            cancellation_policy_file_type: None,
            cancellation_policy_provider_file_id: None,
            cancellation_policy_disclosure: None,
            cancellation_rebuttal: None,
            customer_communication: None,
            customer_communication_file_type: None,
            customer_communication_provider_file_id: None,
            customer_email_address: None,
            customer_name: None,
            customer_purchase_ip: None,
            customer_signature: None,
            customer_signature_file_type: None,
            customer_signature_provider_file_id: None,
            product_description: None,
            receipt: None,
            receipt_file_type: None,
            receipt_provider_file_id: None,
            refund_policy: None,
            refund_policy_file_type: None,
            refund_policy_provider_file_id: None,
            refund_policy_disclosure: None,
            refund_refusal_explanation: None,
            service_date: value.service_date.map(|date| date.to_string()),
            service_documentation: None,
            service_documentation_file_type: None,
            service_documentation_provider_file_id: None,
            shipping_address: None,
            shipping_carrier: None,
            shipping_date: value.shipping_date.map(|date| date.to_string()),
            shipping_documentation: None,
            shipping_documentation_file_type: None,
            shipping_documentation_provider_file_id: None,
            shipping_tracking_number: None,
            invoice_showing_distinct_transactions: None,
            invoice_showing_distinct_transactions_file_type: None,
            invoice_showing_distinct_transactions_provider_file_id: None,
            recurring_transaction_agreement: None,
            recurring_transaction_agreement_file_type: None,
            recurring_transaction_agreement_provider_file_id: None,
            uncategorized_file: None,
            uncategorized_file_type: None,
            uncategorized_file_provider_file_id: None,
            uncategorized_text: None,
        })
    }
}

pub fn generate_refund_response(
    router_data_v2: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
) -> Result<RefundResponse, error_stack::Report<ApplicationErrorResponse>> {
    let refund_response = router_data_v2.response;

    match refund_response {
        Ok(response) => {
            let status = response.refund_status;
            let grpc_status = grpc_api_types::payments::RefundStatus::foreign_from(status);

            Ok(RefundResponse {
                transaction_id: Some(grpc_api_types::payments::Identifier::default()),
                refund_id: response.connector_refund_id,
                status: grpc_status as i32,
                response_ref_id: None,
                error_code: None,
                error_message: None,
                refund_amount: None,
                minor_refund_amount: None,
                refund_currency: None,
                payment_amount: None,
                minor_payment_amount: None,
                refund_reason: None,
                created_at: None,
                updated_at: None,
                processed_at: None,
                customer_name: None,
                email: None,
                merchant_order_reference_id: None,
                metadata: std::collections::HashMap::new(),
                refund_metadata: std::collections::HashMap::new(),
            })
        }
        Err(e) => {
            let status = e
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();

            Ok(RefundResponse {
                transaction_id: Some(
                    e.connector_transaction_id
                        .map(|id| grpc_api_types::payments::Identifier {
                            id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                        })
                        .unwrap_or_default(),
                ),
                refund_id: String::new(),
                status: status as i32,
                response_ref_id: None,
                error_code: Some(e.code),
                error_message: Some(e.message),
                refund_amount: None,
                minor_refund_amount: None,
                refund_currency: None,
                payment_amount: None,
                minor_payment_amount: None,
                refund_reason: None,
                created_at: None,
                updated_at: None,
                processed_at: None,
                customer_name: None,
                email: None,
                merchant_order_reference_id: None,
                metadata: std::collections::HashMap::new(),
                refund_metadata: std::collections::HashMap::new(),
            })
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentServiceCaptureRequest>
    for PaymentsCaptureData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::PaymentServiceCaptureRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let connector_transaction_id = ResponseId::ConnectorTransactionId(
            value
                .transaction_id
                .clone()
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
        );

        let multiple_capture_data =
            value
                .multiple_capture_data
                .clone()
                .map(|data| MultipleCaptureRequestData {
                    capture_sequence: data.capture_sequence,
                    capture_reference: data.capture_reference,
                });

        let minor_amount = hyperswitch_common_utils::types::MinorUnit::new(value.amount_to_capture);

        Ok(Self {
            amount_to_capture: value.amount_to_capture,
            minor_amount_to_capture: minor_amount,
            currency: hyperswitch_common_enums::Currency::foreign_try_from(value.currency())?,
            connector_transaction_id,
            multiple_capture_data,
            connector_metadata: {
                value
                    .metadata
                    .get("connector_metadata")
                    .map(|json_string| {
                        Ok::<serde_json::Value, error_stack::Report<ApplicationErrorResponse>>(
                            serde_json::Value::String(json_string.clone()),
                        )
                    })
                    .transpose()? // Converts Option<Result<T, E>> to Result<Option<T>, E> and propagates E if it's an Err
            },
        })
    }
}

impl
    ForeignTryFrom<(
        grpc_api_types::payments::PaymentServiceCaptureRequest,
        Connectors,
    )> for PaymentFlowData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (
            grpc_api_types::payments::PaymentServiceCaptureRequest,
            Connectors,
        ),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
            payment_id: "PAYMENT_ID".to_string(),
            attempt_id: "ATTEMPT_ID".to_string(),
            status: hyperswitch_common_enums::AttemptStatus::Pending,
            payment_method: hyperswitch_common_enums::PaymentMethod::Card, // Default
            address: hyperswitch_domain_models::payment_address::PaymentAddress::default(),
            auth_type: hyperswitch_common_enums::AuthenticationType::default(),
            connector_request_reference_id: value
                .request_ref_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
            customer_id: None,
            connector_customer: None,
            description: None,
            return_url: None,
            connector_meta_data: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            preprocessing_id: None,
            connector_api_version: None,
            test_mode: None,
            connector_http_status_code: None,
            external_latency: None,
            connectors,
            raw_connector_response: None,
        })
    }
}

pub fn generate_payment_capture_response(
    router_data_v2: RouterDataV2<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    >,
) -> Result<PaymentServiceCaptureResponse, error_stack::Report<ApplicationErrorResponse>> {
    let transaction_response = router_data_v2.response;

    match transaction_response {
        Ok(response) => match response {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: _,
                connector_metadata: _,
                network_txn_id: _,
                connector_response_reference_id,
                incremental_authorization_allowed: _,
                mandate_reference: _,
                raw_connector_response: _,
            } => {
                let status = router_data_v2.resource_common_data.status;
                let grpc_status = grpc_api_types::payments::PaymentStatus::foreign_from(status);
                let grpc_resource_id =
                    grpc_api_types::payments::Identifier::foreign_try_from(resource_id)?;

                Ok(PaymentServiceCaptureResponse {
                    transaction_id: Some(grpc_resource_id),
                    response_ref_id: connector_response_reference_id.map(|id| {
                        grpc_api_types::payments::Identifier {
                            id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                        }
                    }),
                    error_code: None,
                    error_message: None,
                    status: grpc_status.into(),
                })
            }
            _ => Err(report!(ApplicationErrorResponse::InternalServerError(
                ApiError {
                    sub_code: "INVALID_RESPONSE_TYPE".to_owned(),
                    error_identifier: 500,
                    error_message: "Invalid response type received from connector".to_owned(),
                    error_object: None,
                }
            ))),
        },
        Err(e) => {
            let status = e
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();
            Ok(PaymentServiceCaptureResponse {
                transaction_id: Some(grpc_api_types::payments::Identifier {
                    id_type: Some(
                        grpc_api_types::payments::identifier::IdType::NoResponseIdMarker(()),
                    ),
                }),
                response_ref_id: e.connector_transaction_id.map(|id| {
                    grpc_api_types::payments::Identifier {
                        id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                    }
                }),
                status: status.into(),
                error_message: Some(e.message),
                error_code: Some(e.code),
            })
        }
    }
}

impl ForeignTryFrom<(PaymentServiceRegisterRequest, Connectors)> for PaymentFlowData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (PaymentServiceRegisterRequest, Connectors),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let address = match value.address {
            Some(address) => {
                hyperswitch_domain_models::payment_address::PaymentAddress::foreign_try_from(
                    address,
                )?
            }
            None => {
                return Err(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_ADDRESS".to_owned(),
                    error_identifier: 400,
                    error_message: "Address is required".to_owned(),
                    error_object: None,
                }))?
            }
        };
        Ok(Self {
            merchant_id: hyperswitch_common_utils::id_type::MerchantId::default(),
            payment_id: "IRRELEVANT_PAYMENT_ID".to_string(),
            attempt_id: "IRRELEVANT_ATTEMPT_ID".to_string(),
            status: hyperswitch_common_enums::AttemptStatus::Pending,
            payment_method: hyperswitch_common_enums::PaymentMethod::Card, //TODO
            address,
            auth_type: hyperswitch_common_enums::AuthenticationType::default(),
            connector_request_reference_id: value
                .request_ref_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
            customer_id: None,
            connector_customer: None,
            description: None,
            return_url: None,
            connector_meta_data: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            preprocessing_id: None,
            connector_api_version: None,
            test_mode: None,
            connector_http_status_code: None,
            external_latency: None,
            connectors,
            raw_connector_response: None,
        })
    }
}

impl ForeignTryFrom<PaymentServiceRegisterRequest> for SetupMandateRequestData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: PaymentServiceRegisterRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let email: Option<Email> = match value.email {
            Some(ref email_str) => Some(Email::try_from(email_str.clone()).map_err(|_| {
                error_stack::Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_EMAIL_FORMAT".to_owned(),
                    error_identifier: 400,

                    error_message: "Invalid email".to_owned(),
                    error_object: None,
                }))
            })?),
            None => None,
        };

        let customer_acceptance = value.customer_acceptance.clone().ok_or_else(|| {
            error_stack::Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "MISSING_CUSTOMER_ACCEPTANCE".to_owned(),
                error_identifier: 400,
                error_message: "Customer acceptance is missing".to_owned(),
                error_object: None,
            }))
        })?;

        let setup_future_usage = value.setup_future_usage.ok_or_else(|| {
            error_stack::Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "MISSING_SETUP_FUTURE_USAGE".to_owned(),
                error_identifier: 400,
                error_message: "Setup future usage is missing".to_owned(),
                error_object: None,
            }))
        })?;

        let setup_mandate_details = MandateData {
            update_mandate_id: None,
            customer_acceptance: Some(
                hyperswitch_domain_models::mandates::CustomerAcceptance::foreign_try_from(
                    customer_acceptance.clone(),
                )?,
            ),
            mandate_type: None,
        };

        Ok(Self {
            currency: hyperswitch_common_enums::Currency::foreign_try_from(value.currency())?,
            payment_method_data: PaymentMethodData::foreign_try_from(
                value.payment_method.ok_or_else(|| {
                    ApplicationErrorResponse::BadRequest(ApiError {
                        sub_code: "INVALID_PAYMENT_METHOD_DATA".to_owned(),
                        error_identifier: 400,
                        error_message: "Payment method data is required".to_owned(),
                        error_object: None,
                    })
                })?,
            )?,
            amount: Some(0),
            confirm: true,
            statement_descriptor_suffix: None,
            customer_acceptance: Some(
                hyperswitch_domain_models::mandates::CustomerAcceptance::foreign_try_from(
                    customer_acceptance.clone(),
                )?,
            ),
            mandate_id: None,
            setup_future_usage: Some(hyperswitch_common_enums::FutureUsage::foreign_try_from(
                setup_future_usage,
            )?),
            off_session: Some(false),
            setup_mandate_details: Some(setup_mandate_details),
            router_return_url: value.return_url.clone(),
            webhook_url: None,
            browser_info: value.browser_info.map(|info| {
                hyperswitch_domain_models::router_request_types::BrowserInformation {
                    color_depth: None,
                    java_enabled: info.java_enabled,
                    java_script_enabled: info.java_script_enabled,
                    language: info.language,
                    screen_height: info.screen_height,
                    screen_width: info.screen_width,
                    time_zone: None,
                    ip_address: None,
                    accept_header: info.accept_header,
                    user_agent: info.user_agent,
                }
            }),
            email,
            customer_name: None,
            return_url: value.return_url.clone(),
            payment_method_type: None,
            request_incremental_authorization: false,
            metadata: None,
            complete_authorize_url: None,
            capture_method: None,
            minor_amount: Some(hyperswitch_common_utils::types::MinorUnit::new(0)),
            shipping_cost: None,
            customer_id: value
                .connector_customer_id
                .clone()
                .map(|customer_id| CustomerId::try_from(Cow::from(customer_id)))
                .transpose()
                .change_context(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_CUSTOMER_ID".to_owned(),
                    error_identifier: 400,
                    error_message: "Failed to parse Customer Id".to_owned(),
                    error_object: None,
                }))?,
            statement_descriptor: None,
            merchant_order_reference_id: None,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::CustomerAcceptance>
    for hyperswitch_domain_models::mandates::CustomerAcceptance
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        _value: grpc_api_types::payments::CustomerAcceptance,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(hyperswitch_domain_models::mandates::CustomerAcceptance {
            acceptance_type: hyperswitch_domain_models::mandates::AcceptanceType::Offline,
            accepted_at: None,
            online: None,
        })
    }
}

impl ForeignTryFrom<i32> for hyperswitch_common_enums::FutureUsage {
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(value: i32) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            0 => Ok(hyperswitch_common_enums::FutureUsage::OffSession),
            1 => Ok(hyperswitch_common_enums::FutureUsage::OnSession),
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_FUTURE_USAGE".to_owned(),
                error_identifier: 401,
                error_message: format!("Invalid value for future_usage: {}", value),
                error_object: None,
            })
            .into()),
        }
    }
}

pub fn generate_setup_mandate_response(
    router_data_v2: RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    >,
) -> Result<PaymentServiceRegisterResponse, error_stack::Report<ApplicationErrorResponse>> {
    let transaction_response = router_data_v2.response;
    let status = router_data_v2.resource_common_data.status;
    let grpc_status = grpc_api_types::payments::PaymentStatus::foreign_from(status);
    let response = match transaction_response {
        Ok(response) => match response {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data,
                connector_metadata: _,
                network_txn_id,
                connector_response_reference_id,
                incremental_authorization_allowed,
                mandate_reference,
                raw_connector_response: _,
            } => {
                PaymentServiceRegisterResponse {
                    registration_id: Some(grpc_api_types::payments::Identifier::foreign_try_from(resource_id)?),
                    redirection_data: redirection_data.map(
                        |form| {
                            match form {
                                hyperswitch_domain_models::router_response_types::RedirectForm::Form { endpoint, method: _, form_fields: _ } => {
                                    Ok::<grpc_api_types::payments::RedirectForm, ApplicationErrorResponse>(grpc_api_types::payments::RedirectForm {
                                        form_type: Some(grpc_api_types::payments::redirect_form::FormType::Form(
                                            grpc_api_types::payments::FormData {
                                                endpoint,
                                                method: 0,
                                                form_fields: HashMap::default(), //TODO
                                            }
                                        ))
                                    })
                                },
                                hyperswitch_domain_models::router_response_types::RedirectForm::Html { html_data } => {
                                    Ok(grpc_api_types::payments::RedirectForm {
                                        form_type: Some(grpc_api_types::payments::redirect_form::FormType::Html(
                                            grpc_api_types::payments::HtmlData {
                                                html_data,
                                            }
                                        ))
                                    })
                                },
                                _ => Err(
                                    ApplicationErrorResponse::BadRequest(ApiError {
                                        sub_code: "INVALID_RESPONSE".to_owned(),
                                        error_identifier: 400,
                                        error_message: "Invalid response from connector".to_owned(),
                                        error_object: None,
                                    }))?,
                            }
                        }
                    ).transpose()?,
                    network_txn_id,
                    response_ref_id: connector_response_reference_id.map(|id| grpc_api_types::payments::Identifier {
                        id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                    }),
                    status: grpc_status as i32,
                    mandate_reference: Some(grpc_api_types::payments::MandateReference {
                        mandate_id: mandate_reference.and_then(|m| m.connector_mandate_id),
                    }),
                    incremental_authorization_allowed,
                    error_message: None,
                    error_code: None,
                }
            }
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_RESPONSE".to_owned(),
                error_identifier: 400,
                error_message: "Invalid response from connector".to_owned(),
                error_object: None,
            }))?,
        },
        Err(err) => {
            let status = err
                .attempt_status
                .map(grpc_api_types::payments::PaymentStatus::foreign_from)
                .unwrap_or_default();
            PaymentServiceRegisterResponse {
                registration_id: Some(grpc_api_types::payments::Identifier {
                    id_type: Some(
                        grpc_api_types::payments::identifier::IdType::NoResponseIdMarker(()),
                    ),
                }),
                redirection_data: None,
                network_txn_id: None,
                response_ref_id: err.connector_transaction_id.map(|id| {
                    grpc_api_types::payments::Identifier {
                        id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id)),
                    }
                }),
                status: status as i32,
                mandate_reference: None,
                incremental_authorization_allowed: None,
                error_message: Some(err.message),
                error_code: Some(err.code),
            }
        }
    };
    Ok(response)
}

impl ForeignTryFrom<(DisputeDefendRequest, Connectors)> for DisputeFlowData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        (value, connectors): (DisputeDefendRequest, Connectors),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(DisputeFlowData {
            dispute_id: Some(value.dispute_id.clone()),
            connectors,
            connector_dispute_id: value.dispute_id,
            defense_reason_code: Some(value.reason_code.unwrap_or_default()),
            raw_connector_response: None,
        })
    }
}

impl ForeignTryFrom<DisputeDefendRequest> for DisputeDefendData {
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: DisputeDefendRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let connector_dispute_id = value.dispute_id;
        Ok(Self {
            dispute_id: connector_dispute_id.clone(),
            connector_dispute_id,
            defense_reason_code: value.reason_code.unwrap_or_default(),
        })
    }
}

pub fn generate_defend_dispute_response(
    router_data_v2: RouterDataV2<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    >,
) -> Result<DisputeDefendResponse, error_stack::Report<ApplicationErrorResponse>> {
    let defend_dispute_response = router_data_v2.response;

    match defend_dispute_response {
        Ok(response) => Ok(DisputeDefendResponse {
            dispute_id: response.connector_dispute_id,
            dispute_status: response.dispute_status as i32,
            connector_status_code: None,
            error_message: None,
            error_code: None,
            response_ref_id: None,
        }),
        Err(e) => Ok(DisputeDefendResponse {
            dispute_id: e
                .connector_transaction_id
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            dispute_status: hyperswitch_common_enums::DisputeStatus::DisputeLost as i32,
            connector_status_code: None,
            error_message: Some(e.message),
            error_code: Some(e.code),
            response_ref_id: None,
        }),
    }
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct CardSpecificFeatures {
    /// Indicates whether three_ds card payments are supported
    // #[schema(value_type = FeatureStatus)]
    pub three_ds: FeatureStatus,
    /// Indicates whether non three_ds card payments are supported
    // #[schema(value_type = FeatureStatus)]
    pub no_three_ds: FeatureStatus,
    /// List of supported card networks
    // #[schema(value_type = Vec<CardNetwork>)]
    pub supported_card_networks: Vec<CardNetwork>,
}

#[derive(Debug, Clone, ToSchema, Serialize)]
#[serde(untagged)]
pub enum PaymentMethodSpecificFeatures {
    /// Card specific features
    Card(CardSpecificFeatures),
}
/// Represents details of a payment method.
#[derive(Debug, Clone)]
pub struct PaymentMethodDetails {
    /// Indicates whether mandates are supported by this payment method.
    pub mandates: FeatureStatus,
    /// Indicates whether refund is supported by this payment method.
    pub refunds: FeatureStatus,
    /// List of supported capture methods
    pub supported_capture_methods: Vec<CaptureMethod>,
    /// Payment method specific features
    pub specific_features: Option<PaymentMethodSpecificFeatures>,
}
/// The status of the feature
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    ToSchema,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum FeatureStatus {
    NotSupported,
    Supported,
}
pub type PaymentMethodTypeMetadata = HashMap<PaymentMethodType, PaymentMethodDetails>;
pub type SupportedPaymentMethods = HashMap<PaymentMethod, PaymentMethodTypeMetadata>;

#[derive(Debug, Clone)]
pub struct ConnectorInfo {
    /// Display name of the Connector
    pub display_name: &'static str,
    /// Description of the connector.
    pub description: &'static str,
    /// Connector Type
    pub connector_type: PaymentConnectorCategory,
}

/// Connector Access Method
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    ToSchema,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PaymentConnectorCategory {
    PaymentGateway,
    AlternativePaymentMethod,
    BankAcquirer,
}

#[derive(Debug, strum::Display, Eq, PartialEq, Hash)]
pub enum PaymentMethodDataType {
    Card,
    Knet,
    Benefit,
    MomoAtm,
    CardRedirect,
    AliPayQr,
    AliPayRedirect,
    AliPayHkRedirect,
    AmazonPayRedirect,
    MomoRedirect,
    KakaoPayRedirect,
    GoPayRedirect,
    GcashRedirect,
    ApplePay,
    ApplePayRedirect,
    ApplePayThirdPartySdk,
    DanaRedirect,
    DuitNow,
    GooglePay,
    GooglePayRedirect,
    GooglePayThirdPartySdk,
    MbWayRedirect,
    MobilePayRedirect,
    PaypalRedirect,
    PaypalSdk,
    Paze,
    SamsungPay,
    TwintRedirect,
    VippsRedirect,
    TouchNGoRedirect,
    WeChatPayRedirect,
    WeChatPayQr,
    CashappQr,
    SwishQr,
    KlarnaRedirect,
    KlarnaSdk,
    AffirmRedirect,
    AfterpayClearpayRedirect,
    PayBrightRedirect,
    WalleyRedirect,
    AlmaRedirect,
    AtomeRedirect,
    BancontactCard,
    Bizum,
    Blik,
    Eft,
    Eps,
    Giropay,
    Ideal,
    Interac,
    LocalBankRedirect,
    OnlineBankingCzechRepublic,
    OnlineBankingFinland,
    OnlineBankingPoland,
    OnlineBankingSlovakia,
    OpenBankingUk,
    Przelewy24,
    Sofort,
    Trustly,
    OnlineBankingFpx,
    OnlineBankingThailand,
    AchBankDebit,
    SepaBankDebit,
    BecsBankDebit,
    BacsBankDebit,
    AchBankTransfer,
    SepaBankTransfer,
    BacsBankTransfer,
    MultibancoBankTransfer,
    PermataBankTransfer,
    BcaBankTransfer,
    BniVaBankTransfer,
    BriVaBankTransfer,
    CimbVaBankTransfer,
    DanamonVaBankTransfer,
    MandiriVaBankTransfer,
    Pix,
    Pse,
    Crypto,
    MandatePayment,
    Reward,
    Upi,
    Boleto,
    Efecty,
    PagoEfectivo,
    RedCompra,
    RedPagos,
    Alfamart,
    Indomaret,
    Oxxo,
    SevenEleven,
    Lawson,
    MiniStop,
    FamilyMart,
    Seicomart,
    PayEasy,
    Givex,
    PaySafeCar,
    CardToken,
    LocalBankTransfer,
    Mifinity,
    Fps,
    PromptPay,
    VietQr,
    OpenBanking,
    NetworkToken,
    NetworkTransactionIdAndCardDetails,
    DirectCarrierBilling,
    InstantBankTransfer,
}
