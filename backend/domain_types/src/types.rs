use core::result::Result;
use std::{borrow::Cow, collections::HashMap, str::FromStr};

use common_enums::{CaptureMethod, CardNetwork, PaymentMethod, PaymentMethodType};
use common_utils::{consts::NO_ERROR_CODE, id_type::CustomerId, pii::Email};
use error_stack::{report, ResultExt};
use grpc_api_types::payments::{
    AcceptDisputeResponse, DisputeDefendRequest, DisputeDefendResponse, DisputeResponse,
    DisputeServiceSubmitEvidenceResponse, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureResponse, PaymentServiceGetResponse,
    PaymentServiceRegisterRequest, PaymentServiceRegisterResponse, PaymentServiceVoidRequest,
    PaymentServiceVoidResponse, RefundResponse,
};
use hyperswitch_masking::Secret;
use serde::Serialize;
use utoipa::ToSchema;

// For decoding connector_meta_data and Engine trait - base64 crate no longer needed here
use crate::mandates::MandateData;
use crate::{
    connector_flow::{
        Accept, Authorize, Capture, DefendDispute, PSync, RSync, Refund, SetupMandate,
        SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        DisputeWebhookDetailsResponse, MultipleCaptureRequestData, PaymentFlowData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse,
        RefundsData, RefundsResponseData, ResponseId, SetupMandateRequestData, SubmitEvidenceData,
        WebhookDetailsResponse,
    },
    errors::{ApiError, ApplicationErrorResponse},
    payment_address::{Address, AddressDetails, PaymentAddress, PhoneDetails},
    payment_method_data::PaymentMethodData,
    router_data_v2::RouterDataV2,
    utils::{ForeignFrom, ForeignTryFrom},
};
#[derive(Clone, serde::Deserialize, Debug, Default)]
pub struct Connectors {
    // Added pub
    pub adyen: ConnectorParams,
    pub razorpay: ConnectorParams,
    pub razorpayv2: ConnectorParams,
    pub fiserv: ConnectorParams,
    pub elavon: ConnectorParams, // Add your connector params
    pub xendit: ConnectorParams,
    pub checkout: ConnectorParams,
    pub authorizedotnet: ConnectorParams, // Add your connector params
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

impl ForeignTryFrom<grpc_api_types::payments::CaptureMethod> for common_enums::CaptureMethod {
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
                error_message: format!("Capture method {value:?} is not supported"),
                error_object: None,
            }))),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::CardNetwork> for common_enums::CardNetwork {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        network: grpc_api_types::payments::CardNetwork,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match network {
            grpc_api_types::payments::CardNetwork::Visa => Ok(Self::Visa),
            grpc_api_types::payments::CardNetwork::Mastercard => Ok(Self::Mastercard),
            grpc_api_types::payments::CardNetwork::Amex => Ok(Self::AmericanExpress),
            grpc_api_types::payments::CardNetwork::Jcb => Ok(Self::JCB),
            grpc_api_types::payments::CardNetwork::Diners => Ok(Self::DinersClub),
            grpc_api_types::payments::CardNetwork::Discover => Ok(Self::Discover),
            grpc_api_types::payments::CardNetwork::CartesBancaires => Ok(Self::CartesBancaires),
            grpc_api_types::payments::CardNetwork::Unionpay => Ok(Self::UnionPay),
            grpc_api_types::payments::CardNetwork::Rupay => Ok(Self::RuPay),
            grpc_api_types::payments::CardNetwork::Maestro => Ok(Self::Maestro),
            grpc_api_types::payments::CardNetwork::Unspecified => {
                Err(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "UNSPECIFIED_CARD_NETWORK".to_owned(),
                    error_identifier: 401,
                    error_message: "Card network must be specified".to_owned(),
                    error_object: None,
                })
                .into())
            }
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentMethod> for PaymentMethodData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::PaymentMethod,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        tracing::info!("PaymentMethod data received: {:?}", value);
        match value.payment_method {
            Some(data) => match data {
                grpc_api_types::payments::payment_method::PaymentMethod::Card(card_type) => {
                    match card_type.card_type {
                        Some(grpc_api_types::payments::card_payment_method_type::CardType::Credit(card)) => {
                            let card_network = Some(common_enums::CardNetwork::foreign_try_from(card.card_network())?);
                            Ok(PaymentMethodData::Card(crate::payment_method_data::Card {
                                card_number: cards::CardNumber::from_str(&card.card_number)
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
                                card_network,
                                card_type: card.card_type,
                                card_issuing_country: card.card_issuing_country_alpha2,
                                bank_code: card.bank_code,
                                nick_name: card.nick_name.map(|name| name.into()),
                                card_holder_name: card.card_holder_name.map(Secret::new),
                                co_badged_card_data: None, // TODO: Handle co-badged card data
                            }))
                        },
                        Some(grpc_api_types::payments::card_payment_method_type::CardType::Debit(card)) => {
                            let card_network = Some(common_enums::CardNetwork::foreign_try_from(card.card_network())?);
                            Ok(PaymentMethodData::Card(crate::payment_method_data::Card {
                                card_number: cards::CardNumber::from_str(&card.card_number)
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
                                card_network,
                                card_type: card.card_type,
                                card_issuing_country: card.card_issuing_country_alpha2,
                                bank_code: card.bank_code,
                                nick_name: card.nick_name.map(|name| name.into()),
                                card_holder_name: card.card_holder_name.map(Secret::new),
                                co_badged_card_data: None, // TODO: Handle co-badged card data
                            }))
                        },
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
                }
                grpc_api_types::payments::payment_method::PaymentMethod::Token(_token) => Ok(
                    PaymentMethodData::CardToken(crate::payment_method_data::CardToken {
                        card_holder_name: None,
                        card_cvc: None,
                    }),
                ),
                grpc_api_types::payments::payment_method::PaymentMethod::UpiCollect(
                    upi_collect,
                ) => Ok(PaymentMethodData::Upi(
                    crate::payment_method_data::UpiData::UpiCollect(
                        crate::payment_method_data::UpiCollectData {
                            vpa_id: upi_collect.vpa_id.map(|vpa| vpa.into()),
                        },
                    ),
                )),
                grpc_api_types::payments::payment_method::PaymentMethod::UpiIntent(_upi_intent) => {
                    Ok(PaymentMethodData::Upi(
                        crate::payment_method_data::UpiData::UpiIntent(
                            crate::payment_method_data::UpiIntentData {},
                        ),
                    ))
                }
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

impl ForeignTryFrom<grpc_api_types::payments::Currency> for common_enums::Currency {
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
                error_message: format!("Currency {value:?} is not supported"),
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
            capture_method: Some(common_enums::CaptureMethod::foreign_try_from(
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
            currency: common_enums::Currency::foreign_try_from(value.currency())?,
            confirm: true,
            webhook_url: value.webhook_url,
            browser_info: value
                .browser_info
                .map(crate::router_request_types::BrowserInformation::foreign_try_from)
                .transpose()?,
            payment_method_type: Some(common_enums::PaymentMethodType::Credit), //TODO
            minor_amount: common_utils::types::MinorUnit::new(value.minor_amount),
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
            metadata: if value.metadata.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(
                    value
                        .metadata
                        .into_iter()
                        .map(|(k, v)| (k, serde_json::Value::String(v)))
                        .collect(),
                ))
            },
            merchant_order_reference_id: None,
            order_tax_amount: None,
            shipping_cost: None,
            merchant_account_id: None,
            integrity_object: None,
            merchant_config_currency: None,
            all_keys_required: None, // Field not available in new proto structure
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentAddress>
    for crate::payment_address::PaymentAddress
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::PaymentAddress,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let shipping = match value.shipping_address {
            Some(address) => Some(Address::foreign_try_from(address)?),
            None => None,
        };

        let billing = match value.billing_address.clone() {
            Some(address) => Some(Address::foreign_try_from(address)?),
            None => None,
        };

        let payment_method_billing = match value.billing_address {
            Some(address) => Some(Address::foreign_try_from(address)?),
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

impl ForeignTryFrom<grpc_api_types::payments::Address> for Address {
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::Address,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let email = match value.email.clone() {
            Some(email) => Some(common_utils::pii::Email::from_str(&email).change_context(
                ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_EMAIL".to_owned(),
                    error_identifier: 400,
                    error_message: "Invalid email".to_owned(),
                    error_object: None,
                }),
            )?),
            None => None,
        };
        Ok(Self {
            address: Some(AddressDetails::foreign_try_from(value.clone())?),
            phone: value.phone_number.map(|phone_number| PhoneDetails {
                number: Some(phone_number.into()),
                country_code: value.phone_country_code,
            }),
            email,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::CountryAlpha2> for common_enums::CountryAlpha2 {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::CountryAlpha2,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::CountryAlpha2::Us => Ok(Self::US),
            grpc_api_types::payments::CountryAlpha2::Af => Ok(Self::AF),
            grpc_api_types::payments::CountryAlpha2::Ax => Ok(Self::AX),
            grpc_api_types::payments::CountryAlpha2::Al => Ok(Self::AL),
            grpc_api_types::payments::CountryAlpha2::Dz => Ok(Self::DZ),
            grpc_api_types::payments::CountryAlpha2::As => Ok(Self::AS),
            grpc_api_types::payments::CountryAlpha2::Ad => Ok(Self::AD),
            grpc_api_types::payments::CountryAlpha2::Ao => Ok(Self::AO),
            grpc_api_types::payments::CountryAlpha2::Ai => Ok(Self::AI),
            grpc_api_types::payments::CountryAlpha2::Aq => Ok(Self::AQ),
            grpc_api_types::payments::CountryAlpha2::Ag => Ok(Self::AG),
            grpc_api_types::payments::CountryAlpha2::Ar => Ok(Self::AR),
            grpc_api_types::payments::CountryAlpha2::Am => Ok(Self::AM),
            grpc_api_types::payments::CountryAlpha2::Aw => Ok(Self::AW),
            grpc_api_types::payments::CountryAlpha2::Au => Ok(Self::AU),
            grpc_api_types::payments::CountryAlpha2::At => Ok(Self::AT),
            grpc_api_types::payments::CountryAlpha2::Az => Ok(Self::AZ),
            grpc_api_types::payments::CountryAlpha2::Bs => Ok(Self::BS),
            grpc_api_types::payments::CountryAlpha2::Bh => Ok(Self::BH),
            grpc_api_types::payments::CountryAlpha2::Bd => Ok(Self::BD),
            grpc_api_types::payments::CountryAlpha2::Bb => Ok(Self::BB),
            grpc_api_types::payments::CountryAlpha2::By => Ok(Self::BY),
            grpc_api_types::payments::CountryAlpha2::Be => Ok(Self::BE),
            grpc_api_types::payments::CountryAlpha2::Bz => Ok(Self::BZ),
            grpc_api_types::payments::CountryAlpha2::Bj => Ok(Self::BJ),
            grpc_api_types::payments::CountryAlpha2::Bm => Ok(Self::BM),
            grpc_api_types::payments::CountryAlpha2::Bt => Ok(Self::BT),
            grpc_api_types::payments::CountryAlpha2::Bo => Ok(Self::BO),
            grpc_api_types::payments::CountryAlpha2::Bq => Ok(Self::BQ),
            grpc_api_types::payments::CountryAlpha2::Ba => Ok(Self::BA),
            grpc_api_types::payments::CountryAlpha2::Bw => Ok(Self::BW),
            grpc_api_types::payments::CountryAlpha2::Bv => Ok(Self::BV),
            grpc_api_types::payments::CountryAlpha2::Br => Ok(Self::BR),
            grpc_api_types::payments::CountryAlpha2::Io => Ok(Self::IO),
            grpc_api_types::payments::CountryAlpha2::Bn => Ok(Self::BN),
            grpc_api_types::payments::CountryAlpha2::Bg => Ok(Self::BG),
            grpc_api_types::payments::CountryAlpha2::Bf => Ok(Self::BF),
            grpc_api_types::payments::CountryAlpha2::Bi => Ok(Self::BI),
            grpc_api_types::payments::CountryAlpha2::Kh => Ok(Self::KH),
            grpc_api_types::payments::CountryAlpha2::Cm => Ok(Self::CM),
            grpc_api_types::payments::CountryAlpha2::Ca => Ok(Self::CA),
            grpc_api_types::payments::CountryAlpha2::Cv => Ok(Self::CV),
            grpc_api_types::payments::CountryAlpha2::Ky => Ok(Self::KY),
            grpc_api_types::payments::CountryAlpha2::Cf => Ok(Self::CF),
            grpc_api_types::payments::CountryAlpha2::Td => Ok(Self::TD),
            grpc_api_types::payments::CountryAlpha2::Cl => Ok(Self::CL),
            grpc_api_types::payments::CountryAlpha2::Cn => Ok(Self::CN),
            grpc_api_types::payments::CountryAlpha2::Cx => Ok(Self::CX),
            grpc_api_types::payments::CountryAlpha2::Cc => Ok(Self::CC),
            grpc_api_types::payments::CountryAlpha2::Co => Ok(Self::CO),
            grpc_api_types::payments::CountryAlpha2::Km => Ok(Self::KM),
            grpc_api_types::payments::CountryAlpha2::Cg => Ok(Self::CG),
            grpc_api_types::payments::CountryAlpha2::Cd => Ok(Self::CD),
            grpc_api_types::payments::CountryAlpha2::Ck => Ok(Self::CK),
            grpc_api_types::payments::CountryAlpha2::Cr => Ok(Self::CR),
            grpc_api_types::payments::CountryAlpha2::Ci => Ok(Self::CI),
            grpc_api_types::payments::CountryAlpha2::Hr => Ok(Self::HR),
            grpc_api_types::payments::CountryAlpha2::Cu => Ok(Self::CU),
            grpc_api_types::payments::CountryAlpha2::Cw => Ok(Self::CW),
            grpc_api_types::payments::CountryAlpha2::Cy => Ok(Self::CY),
            grpc_api_types::payments::CountryAlpha2::Cz => Ok(Self::CZ),
            grpc_api_types::payments::CountryAlpha2::Dk => Ok(Self::DK),
            grpc_api_types::payments::CountryAlpha2::Dj => Ok(Self::DJ),
            grpc_api_types::payments::CountryAlpha2::Dm => Ok(Self::DM),
            grpc_api_types::payments::CountryAlpha2::Do => Ok(Self::DO),
            grpc_api_types::payments::CountryAlpha2::Ec => Ok(Self::EC),
            grpc_api_types::payments::CountryAlpha2::Eg => Ok(Self::EG),
            grpc_api_types::payments::CountryAlpha2::Sv => Ok(Self::SV),
            grpc_api_types::payments::CountryAlpha2::Gq => Ok(Self::GQ),
            grpc_api_types::payments::CountryAlpha2::Er => Ok(Self::ER),
            grpc_api_types::payments::CountryAlpha2::Ee => Ok(Self::EE),
            grpc_api_types::payments::CountryAlpha2::Et => Ok(Self::ET),
            grpc_api_types::payments::CountryAlpha2::Fk => Ok(Self::FK),
            grpc_api_types::payments::CountryAlpha2::Fo => Ok(Self::FO),
            grpc_api_types::payments::CountryAlpha2::Fj => Ok(Self::FJ),
            grpc_api_types::payments::CountryAlpha2::Fi => Ok(Self::FI),
            grpc_api_types::payments::CountryAlpha2::Fr => Ok(Self::FR),
            grpc_api_types::payments::CountryAlpha2::Gf => Ok(Self::GF),
            grpc_api_types::payments::CountryAlpha2::Pf => Ok(Self::PF),
            grpc_api_types::payments::CountryAlpha2::Tf => Ok(Self::TF),
            grpc_api_types::payments::CountryAlpha2::Ga => Ok(Self::GA),
            grpc_api_types::payments::CountryAlpha2::Gm => Ok(Self::GM),
            grpc_api_types::payments::CountryAlpha2::Ge => Ok(Self::GE),
            grpc_api_types::payments::CountryAlpha2::De => Ok(Self::DE),
            grpc_api_types::payments::CountryAlpha2::Gh => Ok(Self::GH),
            grpc_api_types::payments::CountryAlpha2::Gi => Ok(Self::GI),
            grpc_api_types::payments::CountryAlpha2::Gr => Ok(Self::GR),
            grpc_api_types::payments::CountryAlpha2::Gl => Ok(Self::GL),
            grpc_api_types::payments::CountryAlpha2::Gd => Ok(Self::GD),
            grpc_api_types::payments::CountryAlpha2::Gp => Ok(Self::GP),
            grpc_api_types::payments::CountryAlpha2::Gu => Ok(Self::GU),
            grpc_api_types::payments::CountryAlpha2::Gt => Ok(Self::GT),
            grpc_api_types::payments::CountryAlpha2::Gg => Ok(Self::GG),
            grpc_api_types::payments::CountryAlpha2::Gn => Ok(Self::GN),
            grpc_api_types::payments::CountryAlpha2::Gw => Ok(Self::GW),
            grpc_api_types::payments::CountryAlpha2::Gy => Ok(Self::GY),
            grpc_api_types::payments::CountryAlpha2::Ht => Ok(Self::HT),
            grpc_api_types::payments::CountryAlpha2::Hm => Ok(Self::HM),
            grpc_api_types::payments::CountryAlpha2::Va => Ok(Self::VA),
            grpc_api_types::payments::CountryAlpha2::Hn => Ok(Self::HN),
            grpc_api_types::payments::CountryAlpha2::Hk => Ok(Self::HK),
            grpc_api_types::payments::CountryAlpha2::Hu => Ok(Self::HU),
            grpc_api_types::payments::CountryAlpha2::Is => Ok(Self::IS),
            grpc_api_types::payments::CountryAlpha2::In => Ok(Self::IN),
            grpc_api_types::payments::CountryAlpha2::Id => Ok(Self::ID),
            grpc_api_types::payments::CountryAlpha2::Ir => Ok(Self::IR),
            grpc_api_types::payments::CountryAlpha2::Iq => Ok(Self::IQ),
            grpc_api_types::payments::CountryAlpha2::Ie => Ok(Self::IE),
            grpc_api_types::payments::CountryAlpha2::Im => Ok(Self::IM),
            grpc_api_types::payments::CountryAlpha2::Il => Ok(Self::IL),
            grpc_api_types::payments::CountryAlpha2::It => Ok(Self::IT),
            grpc_api_types::payments::CountryAlpha2::Jm => Ok(Self::JM),
            grpc_api_types::payments::CountryAlpha2::Jp => Ok(Self::JP),
            grpc_api_types::payments::CountryAlpha2::Je => Ok(Self::JE),
            grpc_api_types::payments::CountryAlpha2::Jo => Ok(Self::JO),
            grpc_api_types::payments::CountryAlpha2::Kz => Ok(Self::KZ),
            grpc_api_types::payments::CountryAlpha2::Ke => Ok(Self::KE),
            grpc_api_types::payments::CountryAlpha2::Ki => Ok(Self::KI),
            grpc_api_types::payments::CountryAlpha2::Kp => Ok(Self::KP),
            grpc_api_types::payments::CountryAlpha2::Kr => Ok(Self::KR),
            grpc_api_types::payments::CountryAlpha2::Kw => Ok(Self::KW),
            grpc_api_types::payments::CountryAlpha2::Kg => Ok(Self::KG),
            grpc_api_types::payments::CountryAlpha2::La => Ok(Self::LA),
            grpc_api_types::payments::CountryAlpha2::Lv => Ok(Self::LV),
            grpc_api_types::payments::CountryAlpha2::Lb => Ok(Self::LB),
            grpc_api_types::payments::CountryAlpha2::Ls => Ok(Self::LS),
            grpc_api_types::payments::CountryAlpha2::Lr => Ok(Self::LR),
            grpc_api_types::payments::CountryAlpha2::Ly => Ok(Self::LY),
            grpc_api_types::payments::CountryAlpha2::Li => Ok(Self::LI),
            grpc_api_types::payments::CountryAlpha2::Lt => Ok(Self::LT),
            grpc_api_types::payments::CountryAlpha2::Lu => Ok(Self::LU),
            grpc_api_types::payments::CountryAlpha2::Mo => Ok(Self::MO),
            grpc_api_types::payments::CountryAlpha2::Mk => Ok(Self::MK),
            grpc_api_types::payments::CountryAlpha2::Mg => Ok(Self::MG),
            grpc_api_types::payments::CountryAlpha2::Mw => Ok(Self::MW),
            grpc_api_types::payments::CountryAlpha2::My => Ok(Self::MY),
            grpc_api_types::payments::CountryAlpha2::Mv => Ok(Self::MV),
            grpc_api_types::payments::CountryAlpha2::Ml => Ok(Self::ML),
            grpc_api_types::payments::CountryAlpha2::Mt => Ok(Self::MT),
            grpc_api_types::payments::CountryAlpha2::Mh => Ok(Self::MH),
            grpc_api_types::payments::CountryAlpha2::Mq => Ok(Self::MQ),
            grpc_api_types::payments::CountryAlpha2::Mr => Ok(Self::MR),
            grpc_api_types::payments::CountryAlpha2::Mu => Ok(Self::MU),
            grpc_api_types::payments::CountryAlpha2::Yt => Ok(Self::YT),
            grpc_api_types::payments::CountryAlpha2::Mx => Ok(Self::MX),
            grpc_api_types::payments::CountryAlpha2::Fm => Ok(Self::FM),
            grpc_api_types::payments::CountryAlpha2::Md => Ok(Self::MD),
            grpc_api_types::payments::CountryAlpha2::Mc => Ok(Self::MC),
            grpc_api_types::payments::CountryAlpha2::Mn => Ok(Self::MN),
            grpc_api_types::payments::CountryAlpha2::Me => Ok(Self::ME),
            grpc_api_types::payments::CountryAlpha2::Ms => Ok(Self::MS),
            grpc_api_types::payments::CountryAlpha2::Ma => Ok(Self::MA),
            grpc_api_types::payments::CountryAlpha2::Mz => Ok(Self::MZ),
            grpc_api_types::payments::CountryAlpha2::Mm => Ok(Self::MM),
            grpc_api_types::payments::CountryAlpha2::Na => Ok(Self::NA),
            grpc_api_types::payments::CountryAlpha2::Nr => Ok(Self::NR),
            grpc_api_types::payments::CountryAlpha2::Np => Ok(Self::NP),
            grpc_api_types::payments::CountryAlpha2::Nl => Ok(Self::NL),
            grpc_api_types::payments::CountryAlpha2::Nc => Ok(Self::NC),
            grpc_api_types::payments::CountryAlpha2::Nz => Ok(Self::NZ),
            grpc_api_types::payments::CountryAlpha2::Ni => Ok(Self::NI),
            grpc_api_types::payments::CountryAlpha2::Ne => Ok(Self::NE),
            grpc_api_types::payments::CountryAlpha2::Ng => Ok(Self::NG),
            grpc_api_types::payments::CountryAlpha2::Nu => Ok(Self::NU),
            grpc_api_types::payments::CountryAlpha2::Nf => Ok(Self::NF),
            grpc_api_types::payments::CountryAlpha2::Mp => Ok(Self::MP),
            grpc_api_types::payments::CountryAlpha2::No => Ok(Self::NO),
            grpc_api_types::payments::CountryAlpha2::Om => Ok(Self::OM),
            grpc_api_types::payments::CountryAlpha2::Pk => Ok(Self::PK),
            grpc_api_types::payments::CountryAlpha2::Pw => Ok(Self::PW),
            grpc_api_types::payments::CountryAlpha2::Ps => Ok(Self::PS),
            grpc_api_types::payments::CountryAlpha2::Pa => Ok(Self::PA),
            grpc_api_types::payments::CountryAlpha2::Pg => Ok(Self::PG),
            grpc_api_types::payments::CountryAlpha2::Py => Ok(Self::PY),
            grpc_api_types::payments::CountryAlpha2::Pe => Ok(Self::PE),
            grpc_api_types::payments::CountryAlpha2::Ph => Ok(Self::PH),
            grpc_api_types::payments::CountryAlpha2::Pn => Ok(Self::PN),
            grpc_api_types::payments::CountryAlpha2::Pl => Ok(Self::PL),
            grpc_api_types::payments::CountryAlpha2::Pt => Ok(Self::PT),
            grpc_api_types::payments::CountryAlpha2::Pr => Ok(Self::PR),
            grpc_api_types::payments::CountryAlpha2::Qa => Ok(Self::QA),
            grpc_api_types::payments::CountryAlpha2::Re => Ok(Self::RE),
            grpc_api_types::payments::CountryAlpha2::Ro => Ok(Self::RO),
            grpc_api_types::payments::CountryAlpha2::Ru => Ok(Self::RU),
            grpc_api_types::payments::CountryAlpha2::Rw => Ok(Self::RW),
            grpc_api_types::payments::CountryAlpha2::Bl => Ok(Self::BL),
            grpc_api_types::payments::CountryAlpha2::Sh => Ok(Self::SH),
            grpc_api_types::payments::CountryAlpha2::Kn => Ok(Self::KN),
            grpc_api_types::payments::CountryAlpha2::Lc => Ok(Self::LC),
            grpc_api_types::payments::CountryAlpha2::Mf => Ok(Self::MF),
            grpc_api_types::payments::CountryAlpha2::Pm => Ok(Self::PM),
            grpc_api_types::payments::CountryAlpha2::Vc => Ok(Self::VC),
            grpc_api_types::payments::CountryAlpha2::Ws => Ok(Self::WS),
            grpc_api_types::payments::CountryAlpha2::Sm => Ok(Self::SM),
            grpc_api_types::payments::CountryAlpha2::St => Ok(Self::ST),
            grpc_api_types::payments::CountryAlpha2::Sa => Ok(Self::SA),
            grpc_api_types::payments::CountryAlpha2::Sn => Ok(Self::SN),
            grpc_api_types::payments::CountryAlpha2::Rs => Ok(Self::RS),
            grpc_api_types::payments::CountryAlpha2::Sc => Ok(Self::SC),
            grpc_api_types::payments::CountryAlpha2::Sl => Ok(Self::SL),
            grpc_api_types::payments::CountryAlpha2::Sg => Ok(Self::SG),
            grpc_api_types::payments::CountryAlpha2::Sx => Ok(Self::SX),
            grpc_api_types::payments::CountryAlpha2::Sk => Ok(Self::SK),
            grpc_api_types::payments::CountryAlpha2::Si => Ok(Self::SI),
            grpc_api_types::payments::CountryAlpha2::Sb => Ok(Self::SB),
            grpc_api_types::payments::CountryAlpha2::So => Ok(Self::SO),
            grpc_api_types::payments::CountryAlpha2::Za => Ok(Self::ZA),
            grpc_api_types::payments::CountryAlpha2::Gs => Ok(Self::GS),
            grpc_api_types::payments::CountryAlpha2::Ss => Ok(Self::SS),
            grpc_api_types::payments::CountryAlpha2::Es => Ok(Self::ES),
            grpc_api_types::payments::CountryAlpha2::Lk => Ok(Self::LK),
            grpc_api_types::payments::CountryAlpha2::Sd => Ok(Self::SD),
            grpc_api_types::payments::CountryAlpha2::Sr => Ok(Self::SR),
            grpc_api_types::payments::CountryAlpha2::Sj => Ok(Self::SJ),
            grpc_api_types::payments::CountryAlpha2::Sz => Ok(Self::SZ),
            grpc_api_types::payments::CountryAlpha2::Se => Ok(Self::SE),
            grpc_api_types::payments::CountryAlpha2::Ch => Ok(Self::CH),
            grpc_api_types::payments::CountryAlpha2::Sy => Ok(Self::SY),
            grpc_api_types::payments::CountryAlpha2::Tw => Ok(Self::TW),
            grpc_api_types::payments::CountryAlpha2::Tj => Ok(Self::TJ),
            grpc_api_types::payments::CountryAlpha2::Tz => Ok(Self::TZ),
            grpc_api_types::payments::CountryAlpha2::Th => Ok(Self::TH),
            grpc_api_types::payments::CountryAlpha2::Tl => Ok(Self::TL),
            grpc_api_types::payments::CountryAlpha2::Tg => Ok(Self::TG),
            grpc_api_types::payments::CountryAlpha2::Tk => Ok(Self::TK),
            grpc_api_types::payments::CountryAlpha2::To => Ok(Self::TO),
            grpc_api_types::payments::CountryAlpha2::Tt => Ok(Self::TT),
            grpc_api_types::payments::CountryAlpha2::Tn => Ok(Self::TN),
            grpc_api_types::payments::CountryAlpha2::Tr => Ok(Self::TR),
            grpc_api_types::payments::CountryAlpha2::Tm => Ok(Self::TM),
            grpc_api_types::payments::CountryAlpha2::Tc => Ok(Self::TC),
            grpc_api_types::payments::CountryAlpha2::Tv => Ok(Self::TV),
            grpc_api_types::payments::CountryAlpha2::Ug => Ok(Self::UG),
            grpc_api_types::payments::CountryAlpha2::Ua => Ok(Self::UA),
            grpc_api_types::payments::CountryAlpha2::Ae => Ok(Self::AE),
            grpc_api_types::payments::CountryAlpha2::Gb => Ok(Self::GB),
            grpc_api_types::payments::CountryAlpha2::Um => Ok(Self::UM),
            grpc_api_types::payments::CountryAlpha2::Uy => Ok(Self::UY),
            grpc_api_types::payments::CountryAlpha2::Uz => Ok(Self::UZ),
            grpc_api_types::payments::CountryAlpha2::Vu => Ok(Self::VU),
            grpc_api_types::payments::CountryAlpha2::Ve => Ok(Self::VE),
            grpc_api_types::payments::CountryAlpha2::Vn => Ok(Self::VN),
            grpc_api_types::payments::CountryAlpha2::Vg => Ok(Self::VG),
            grpc_api_types::payments::CountryAlpha2::Vi => Ok(Self::VI),
            grpc_api_types::payments::CountryAlpha2::Wf => Ok(Self::WF),
            grpc_api_types::payments::CountryAlpha2::Eh => Ok(Self::EH),
            grpc_api_types::payments::CountryAlpha2::Ye => Ok(Self::YE),
            grpc_api_types::payments::CountryAlpha2::Zm => Ok(Self::ZM),
            grpc_api_types::payments::CountryAlpha2::Zw => Ok(Self::ZW),
            grpc_api_types::payments::CountryAlpha2::Unspecified => Ok(Self::US), // Default to US if unspecified
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::Address> for AddressDetails {
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::Address,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            city: value.city.clone(),
            country: Some(common_enums::CountryAlpha2::foreign_try_from(
                value.country_alpha2_code(),
            )?),
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
                crate::payment_address::PaymentAddress::foreign_try_from(
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
            merchant_id: common_utils::id_type::MerchantId::default(),
            payment_id: "IRRELEVANT_PAYMENT_ID".to_string(),
            attempt_id: "IRRELEVANT_ATTEMPT_ID".to_string(),
            status: common_enums::AttemptStatus::Pending,
            payment_method: common_enums::PaymentMethod::foreign_try_from(
                value.payment_method.unwrap_or_default(),
            )?, // Use direct enum
            address,
            auth_type: common_enums::AuthenticationType::foreign_try_from(
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
        let address: PaymentAddress =
            { crate::payment_address::PaymentAddress::new(None, None, None, Some(false)) };
        Ok(Self {
            merchant_id: common_utils::id_type::MerchantId::default(),
            payment_id: "IRRELEVANT_PAYMENT_ID".to_string(),
            attempt_id: "IRRELEVANT_ATTEMPT_ID".to_string(),
            status: common_enums::AttemptStatus::Pending,
            payment_method: common_enums::PaymentMethod::Card, //TODO
            address,
            auth_type: common_enums::AuthenticationType::default(),
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
                raw_connector_response,
            } => {
                PaymentServiceAuthorizeResponse {
                    transaction_id: Some(grpc_api_types::payments::Identifier::foreign_try_from(resource_id)?),
                    redirection_data: redirection_data.map(
                        |form| {
                            match form {
                                crate::router_response_types::RedirectForm::Form { endpoint, method: _, form_fields: _ } => {
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
                                crate::router_response_types::RedirectForm::Html { html_data } => {
                                    Ok(grpc_api_types::payments::RedirectForm {
                                        form_type: Some(grpc_api_types::payments::redirect_form::FormType::Html(
                                            grpc_api_types::payments::HtmlData {
                                                html_data,
                                            }
                                        ))
                                    })
                                },
                                crate::router_response_types::RedirectForm::Uri { uri } => {
                                    Ok(grpc_api_types::payments::RedirectForm {
                                        form_type: Some(grpc_api_types::payments::redirect_form::FormType::Uri(
                                            grpc_api_types::payments::UriData {
                                                uri,
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
                    raw_connector_response,
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
                raw_connector_response: err.raw_connector_response,
            }
        }
    };
    Ok(response)
}

// ForeignTryFrom for PaymentMethod gRPC enum to internal enum
impl ForeignTryFrom<grpc_api_types::payments::PaymentMethod> for common_enums::PaymentMethod {
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
            grpc_api_types::payments::PaymentMethod {
                payment_method:
                    Some(grpc_api_types::payments::payment_method::PaymentMethod::UpiCollect(_)),
            } => Ok(Self::Upi),
            grpc_api_types::payments::PaymentMethod {
                payment_method:
                    Some(grpc_api_types::payments::payment_method::PaymentMethod::UpiIntent(_)),
            } => Ok(Self::Upi),
            _ => Ok(Self::Card), // Default fallback
        }
    }
}

// ForeignTryFrom for AuthenticationType gRPC enum to internal enum
impl ForeignTryFrom<grpc_api_types::payments::AuthenticationType>
    for common_enums::AuthenticationType
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
        let currency = common_enums::Currency::USD;

        // Default amount to 0
        let amount = common_utils::types::MinorUnit::new(0);

        Ok(Self {
            connector_transaction_id,
            encoded_data: None,
            capture_method: None,
            connector_meta: None,
            sync_type: crate::router_request_types::SyncRequestType::SinglePaymentSync,
            mandate_id: None,
            payment_method_type: None,
            currency,
            payment_experience: None,
            amount,
            integrity_object: None,
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
            merchant_id: common_utils::id_type::MerchantId::default(),
            payment_id: "PAYMENT_ID".to_string(),
            attempt_id: "ATTEMPT_ID".to_string(),
            status: common_enums::AttemptStatus::Pending,
            payment_method: common_enums::PaymentMethod::Card, // Default
            address: crate::payment_address::PaymentAddress::default(),
            auth_type: common_enums::AuthenticationType::default(),
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

impl ForeignFrom<common_enums::AttemptStatus> for grpc_api_types::payments::PaymentStatus {
    fn foreign_from(status: common_enums::AttemptStatus) -> Self {
        match status {
            common_enums::AttemptStatus::Charged => Self::Charged,
            common_enums::AttemptStatus::Pending => Self::Pending,
            common_enums::AttemptStatus::Failure => Self::Failure,
            common_enums::AttemptStatus::Authorized => Self::Authorized,
            common_enums::AttemptStatus::Started => Self::Started,
            common_enums::AttemptStatus::AuthenticationFailed => Self::AuthenticationFailed,
            common_enums::AttemptStatus::AuthenticationPending => Self::AuthenticationPending,
            common_enums::AttemptStatus::AuthenticationSuccessful => Self::AuthenticationSuccessful,
            common_enums::AttemptStatus::Authorizing => Self::Authorizing,
            common_enums::AttemptStatus::CaptureInitiated => Self::CaptureInitiated,
            common_enums::AttemptStatus::CaptureFailed => Self::CaptureFailed,
            common_enums::AttemptStatus::VoidInitiated => Self::VoidInitiated,
            common_enums::AttemptStatus::VoidFailed => Self::VoidFailed,
            common_enums::AttemptStatus::Voided => Self::Voided,
            common_enums::AttemptStatus::Unresolved => Self::Unresolved,
            common_enums::AttemptStatus::PaymentMethodAwaited => Self::PaymentMethodAwaited,
            common_enums::AttemptStatus::ConfirmationAwaited => Self::ConfirmationAwaited,
            common_enums::AttemptStatus::DeviceDataCollectionPending => {
                Self::DeviceDataCollectionPending
            }
            common_enums::AttemptStatus::RouterDeclined => Self::RouterDeclined,
            common_enums::AttemptStatus::AuthorizationFailed => Self::AuthorizationFailed,
            common_enums::AttemptStatus::CodInitiated => Self::CodInitiated,
            common_enums::AttemptStatus::AutoRefunded => Self::AutoRefunded,
            common_enums::AttemptStatus::PartialCharged => Self::PartialCharged,
            common_enums::AttemptStatus::PartialChargedAndChargeable => {
                Self::PartialChargedAndChargeable
            }
            common_enums::AttemptStatus::IntegrityFailure => Self::Failure,
            common_enums::AttemptStatus::Unknown => Self::AttemptStatusUnspecified,
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::PaymentStatus> for common_enums::AttemptStatus {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        status: grpc_api_types::payments::PaymentStatus,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match status {
            grpc_api_types::payments::PaymentStatus::Charged => Ok(Self::Charged),
            grpc_api_types::payments::PaymentStatus::Pending => Ok(Self::Pending),
            grpc_api_types::payments::PaymentStatus::Failure => Ok(Self::Failure),
            grpc_api_types::payments::PaymentStatus::Authorized => Ok(Self::Authorized),
            grpc_api_types::payments::PaymentStatus::Started => Ok(Self::Started),
            grpc_api_types::payments::PaymentStatus::AuthenticationFailed => {
                Ok(Self::AuthenticationFailed)
            }
            grpc_api_types::payments::PaymentStatus::AuthenticationPending => {
                Ok(Self::AuthenticationPending)
            }
            grpc_api_types::payments::PaymentStatus::AuthenticationSuccessful => {
                Ok(Self::AuthenticationSuccessful)
            }
            grpc_api_types::payments::PaymentStatus::Authorizing => Ok(Self::Authorizing),
            grpc_api_types::payments::PaymentStatus::CaptureInitiated => Ok(Self::CaptureInitiated),
            grpc_api_types::payments::PaymentStatus::CaptureFailed => Ok(Self::CaptureFailed),
            grpc_api_types::payments::PaymentStatus::VoidInitiated => Ok(Self::VoidInitiated),
            grpc_api_types::payments::PaymentStatus::VoidFailed => Ok(Self::VoidFailed),
            grpc_api_types::payments::PaymentStatus::Voided => Ok(Self::Voided),
            grpc_api_types::payments::PaymentStatus::Unresolved => Ok(Self::Unresolved),
            grpc_api_types::payments::PaymentStatus::PaymentMethodAwaited => {
                Ok(Self::PaymentMethodAwaited)
            }
            grpc_api_types::payments::PaymentStatus::ConfirmationAwaited => {
                Ok(Self::ConfirmationAwaited)
            }
            grpc_api_types::payments::PaymentStatus::DeviceDataCollectionPending => {
                Ok(Self::DeviceDataCollectionPending)
            }
            grpc_api_types::payments::PaymentStatus::RouterDeclined => Ok(Self::RouterDeclined),
            grpc_api_types::payments::PaymentStatus::AuthorizationFailed => {
                Ok(Self::AuthorizationFailed)
            }
            grpc_api_types::payments::PaymentStatus::CodInitiated => Ok(Self::CodInitiated),
            grpc_api_types::payments::PaymentStatus::AutoRefunded => Ok(Self::AutoRefunded),
            grpc_api_types::payments::PaymentStatus::PartialCharged => Ok(Self::PartialCharged),
            grpc_api_types::payments::PaymentStatus::PartialChargedAndChargeable => {
                Ok(Self::PartialChargedAndChargeable)
            }
            grpc_api_types::payments::PaymentStatus::AttemptStatusUnspecified => Ok(Self::Unknown),
        }
    }
}

impl ForeignFrom<common_enums::RefundStatus> for grpc_api_types::payments::RefundStatus {
    fn foreign_from(status: common_enums::RefundStatus) -> Self {
        match status {
            common_enums::RefundStatus::Failure => Self::RefundFailure,
            common_enums::RefundStatus::ManualReview => Self::RefundManualReview,
            common_enums::RefundStatus::Pending => Self::RefundPending,
            common_enums::RefundStatus::Success => Self::RefundSuccess,
            common_enums::RefundStatus::TransactionFailure => Self::RefundTransactionFailure,
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

impl ForeignFrom<common_enums::DisputeStage> for grpc_api_types::payments::DisputeStage {
    fn foreign_from(status: common_enums::DisputeStage) -> Self {
        match status {
            common_enums::DisputeStage::PreDispute => Self::PreDispute,
            common_enums::DisputeStage::Dispute => Self::ActiveDispute,
            common_enums::DisputeStage::PreArbitration => Self::PreArbitration,
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
                raw_connector_response,
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
                    raw_connector_response,
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
                raw_connector_response: None,
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
            refund_status: common_enums::RefundStatus::Pending,
            refund_connector_metadata: None,
            all_keys_required: None, // Field not available in new proto structure
            integrity_object: None,
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
            status: common_enums::RefundStatus::Pending,
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
            status: common_enums::RefundStatus::Pending,
            refund_id: Some(value.refund_id),
            connectors,
            raw_connector_response: None,
        })
    }
}

impl ForeignFrom<common_enums::DisputeStatus> for grpc_api_types::payments::DisputeStatus {
    fn foreign_from(status: common_enums::DisputeStatus) -> Self {
        match status {
            common_enums::DisputeStatus::DisputeOpened => Self::DisputeOpened,
            common_enums::DisputeStatus::DisputeAccepted => Self::DisputeAccepted,
            common_enums::DisputeStatus::DisputeCancelled => Self::DisputeCancelled,
            common_enums::DisputeStatus::DisputeChallenged => Self::DisputeChallenged,
            common_enums::DisputeStatus::DisputeExpired => Self::DisputeExpired,
            common_enums::DisputeStatus::DisputeLost => Self::DisputeLost,
            common_enums::DisputeStatus::DisputeWon => Self::DisputeWon,
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
                raw_connector_response: response.raw_connector_response,
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
                raw_connector_response: e.raw_connector_response,
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
            raw_connector_response: value.raw_connector_response,
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
                .transaction_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    grpc_api_types::payments::identifier::IdType::Id(id) => Some(id),
                    _ => None,
                })
                .unwrap_or_default(),
            cancellation_reason: value.cancellation_reason,
            integrity_object: None,
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
            raw_connector_response: value.raw_connector_response,
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
        let minor_refund_amount = common_utils::types::MinorUnit::new(value.minor_refund_amount);

        let minor_payment_amount = common_utils::types::MinorUnit::new(value.minor_payment_amount);

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
            currency: common_enums::Currency::foreign_try_from(value.currency())?,
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
                value.refund_metadata.get("refund_metadata").map(|json_string| {
                    Ok::<Secret<serde_json::Value>, error_stack::Report<ApplicationErrorResponse>>(Secret::new(serde_json::Value::String(json_string.clone())))
                }).transpose()?
            },
            minor_payment_amount,
            minor_refund_amount,
            refund_status: common_enums::RefundStatus::Pending,
            merchant_account_id: value.merchant_account_id,
            capture_method: value
                .capture_method
                .map(|cm| {
                    common_enums::CaptureMethod::foreign_try_from(
                        grpc_api_types::payments::CaptureMethod::try_from(cm).unwrap_or_default(),
                    )
                })
                .transpose()?,
            integrity_object: None,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::AcceptDisputeRequest> for AcceptDisputeData {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::AcceptDisputeRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(AcceptDisputeData {
            connector_dispute_id: value.dispute_id,
            integrity_object: None,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::DisputeServiceSubmitEvidenceRequest>
    for SubmitEvidenceData
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::DisputeServiceSubmitEvidenceRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        // Initialize all fields to None
        let mut result = SubmitEvidenceData {
            dispute_id: Some(value.dispute_id.clone()),
            connector_dispute_id: value.dispute_id,
            integrity_object: None,
            access_activity_log: None,
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
        };

        // Extract evidence from evidence_documents array
        for document in value.evidence_documents {
            let evidence_type =
                grpc_api_types::payments::EvidenceType::try_from(document.evidence_type)
                    .unwrap_or(grpc_api_types::payments::EvidenceType::Unspecified);

            match evidence_type {
                grpc_api_types::payments::EvidenceType::CancellationPolicy => {
                    result.cancellation_policy = document.file_content;
                    result.cancellation_policy_file_type = document.file_mime_type;
                    result.cancellation_policy_provider_file_id = document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::CustomerCommunication => {
                    result.customer_communication = document.file_content;
                    result.customer_communication_file_type = document.file_mime_type;
                    result.customer_communication_provider_file_id = document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::CustomerSignature => {
                    result.customer_signature = document.file_content;
                    result.customer_signature_file_type = document.file_mime_type;
                    result.customer_signature_provider_file_id = document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::Receipt => {
                    result.receipt = document.file_content;
                    result.receipt_file_type = document.file_mime_type;
                    result.receipt_provider_file_id = document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::RefundPolicy => {
                    result.refund_policy = document.file_content;
                    result.refund_policy_file_type = document.file_mime_type;
                    result.refund_policy_provider_file_id = document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::ServiceDocumentation => {
                    result.service_documentation = document.file_content;
                    result.service_documentation_file_type = document.file_mime_type;
                    result.service_documentation_provider_file_id = document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::ShippingDocumentation => {
                    result.shipping_documentation = document.file_content;
                    result.shipping_documentation_file_type = document.file_mime_type;
                    result.shipping_documentation_provider_file_id = document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::InvoiceShowingDistinctTransactions => {
                    result.invoice_showing_distinct_transactions = document.file_content;
                    result.invoice_showing_distinct_transactions_file_type =
                        document.file_mime_type;
                    result.invoice_showing_distinct_transactions_provider_file_id =
                        document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::RecurringTransactionAgreement => {
                    result.recurring_transaction_agreement = document.file_content;
                    result.recurring_transaction_agreement_file_type = document.file_mime_type;
                    result.recurring_transaction_agreement_provider_file_id =
                        document.provider_file_id;
                }
                grpc_api_types::payments::EvidenceType::UncategorizedFile => {
                    result.uncategorized_file = document.file_content;
                    result.uncategorized_file_type = document.file_mime_type;
                    result.uncategorized_file_provider_file_id = document.provider_file_id;
                    result.uncategorized_text = document.text_content;
                }
                grpc_api_types::payments::EvidenceType::Unspecified => {
                    // Skip unspecified evidence types
                }
            }
        }

        Ok(result)
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
                raw_connector_response: response.raw_connector_response,
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
                raw_connector_response: e.raw_connector_response,
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

        let minor_amount = common_utils::types::MinorUnit::new(value.amount_to_capture);

        Ok(Self {
            amount_to_capture: value.amount_to_capture,
            minor_amount_to_capture: minor_amount,
            currency: common_enums::Currency::foreign_try_from(value.currency())?,
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
            integrity_object: None,
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
            merchant_id: common_utils::id_type::MerchantId::default(),
            payment_id: "PAYMENT_ID".to_string(),
            attempt_id: "ATTEMPT_ID".to_string(),
            status: common_enums::AttemptStatus::Pending,
            payment_method: common_enums::PaymentMethod::Card, // Default
            address: crate::payment_address::PaymentAddress::default(),
            auth_type: common_enums::AuthenticationType::default(),
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
            Some(address) => crate::payment_address::PaymentAddress::foreign_try_from(address)?,
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
            merchant_id: common_utils::id_type::MerchantId::default(),
            payment_id: "IRRELEVANT_PAYMENT_ID".to_string(),
            attempt_id: "IRRELEVANT_ATTEMPT_ID".to_string(),
            status: common_enums::AttemptStatus::Pending,
            payment_method: common_enums::PaymentMethod::Card, //TODO
            address,
            auth_type: common_enums::AuthenticationType::default(),
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

        let setup_future_usage = value.setup_future_usage();

        let setup_mandate_details = MandateData {
            update_mandate_id: None,
            customer_acceptance: Some(crate::mandates::CustomerAcceptance::foreign_try_from(
                customer_acceptance.clone(),
            )?),
            mandate_type: None,
        };

        Ok(Self {
            currency: common_enums::Currency::foreign_try_from(value.currency())?,
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
            customer_acceptance: Some(crate::mandates::CustomerAcceptance::foreign_try_from(
                customer_acceptance.clone(),
            )?),
            mandate_id: None,
            setup_future_usage: Some(common_enums::FutureUsage::foreign_try_from(
                setup_future_usage,
            )?),
            off_session: Some(false),
            setup_mandate_details: Some(setup_mandate_details),
            router_return_url: value.return_url.clone(),
            webhook_url: None,
            browser_info: value.browser_info.map(|info| {
                crate::router_request_types::BrowserInformation {
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
                    os_type: info.os_type,
                    os_version: info.os_version,
                    device_model: info.device_model,
                    accept_language: info.accept_language,
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
            integrity_object: None,
            minor_amount: Some(common_utils::types::MinorUnit::new(0)),
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
    for crate::mandates::CustomerAcceptance
{
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        _value: grpc_api_types::payments::CustomerAcceptance,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(crate::mandates::CustomerAcceptance {
            acceptance_type: crate::mandates::AcceptanceType::Offline,
            accepted_at: None,
            online: None,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::FutureUsage> for common_enums::FutureUsage {
    type Error = ApplicationErrorResponse;
    fn foreign_try_from(
        value: grpc_api_types::payments::FutureUsage,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::FutureUsage::OffSession => {
                Ok(common_enums::FutureUsage::OffSession)
            }
            grpc_api_types::payments::FutureUsage::OnSession => {
                Ok(common_enums::FutureUsage::OnSession)
            }
            grpc_api_types::payments::FutureUsage::Unspecified => {
                Err(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "UNSPECIFIED_FUTURE_USAGE".to_owned(),
                    error_identifier: 401,
                    error_message: "Future usage must be specified".to_owned(),
                    error_object: None,
                })
                .into())
            }
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
                                crate::router_response_types::RedirectForm::Form { endpoint, method: _, form_fields: _ } => {
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
                                crate::router_response_types::RedirectForm::Html { html_data } => {
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
            integrity_object: None,
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
            dispute_status: common_enums::DisputeStatus::DisputeLost as i32,
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
    InstantBankTransferPoland,
    InstantBankTransferFinland,
    CardDetailsForNetworkTransactionId,
    RevolutPay,
}

impl ForeignTryFrom<grpc_api_types::payments::BrowserInformation>
    for crate::router_request_types::BrowserInformation
{
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::BrowserInformation,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            color_depth: value.color_depth.map(|cd| cd as u8),
            java_enabled: value.java_enabled,
            java_script_enabled: value.java_script_enabled,
            language: value.language,
            screen_height: value.screen_height,
            screen_width: value.screen_width,
            time_zone: value.time_zone_offset_minutes,
            ip_address: value.ip_address.and_then(|ip| ip.parse().ok()),
            accept_header: value.accept_header,
            user_agent: value.user_agent,
            os_type: value.os_type,
            os_version: value.os_version,
            device_model: value.device_model,
            accept_language: value.accept_language,
        })
    }
}
