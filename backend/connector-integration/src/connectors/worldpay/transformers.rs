use std::collections::HashMap;

use common_enums as enums;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    types::MinorUnit,
    CustomResult,
};
use domain_types::{
    connector_flow::{Authorize, Void, Capture},
    connector_types::{
        MandateIds, MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber, DefaultPCIHolder,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret, PeekInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::worldpay::WorldpayRouterData, types::ResponseRouterData};

// Define ForeignTryFrom trait locally
pub trait ForeignTryFrom<T>: Sized {
    type Error;
    fn foreign_try_from(value: T) -> Result<Self, Self::Error>;
}

use super::requests::*;
use super::response::*;


#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WorldpayConnectorMetadataObject {
    pub merchant_name: Option<Secret<String>>,
}

impl TryFrom<Option<&pii::SecretSerdeValue>> for WorldpayConnectorMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: Option<&pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let metadata: Self = crate::utils::to_connector_meta_from_secret::<Self>(meta_data.cloned())
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata",
            })?;
        Ok(metadata)
    }
}

fn fetch_payment_instrument<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    payment_method: PaymentMethodData<T>,
    billing_address: Option<&domain_types::payment_address::Address>,
    mandate_ids: Option<MandateIds>,
) -> CustomResult<PaymentInstrument<T>, errors::ConnectorError> {
    match payment_method {
        PaymentMethodData::Card(card) => {
            // Extract expiry month and year directly from the card fields
            let expiry_month: i32 = card.card_exp_month.peek().parse::<i32>()
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            let mut expiry_year: String = card.card_exp_year.peek().clone();
            if expiry_year.len() == 2 {
                expiry_year = format!("20{expiry_year}");
            }
            let expiry_year: i32 = expiry_year.parse::<i32>()
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                
            Ok(PaymentInstrument::Card(CardPayment {
            raw_card_details: RawCardDetails {
                payment_type: PaymentType::Plain,
                expiry_date: ExpiryDate {
                    month: Secret::new(expiry_month as i8),
                    year: Secret::new(expiry_year),
                },
                card_number: card.card_number,
            },
                cvc: card.card_cvc,
                card_holder_name: billing_address.and_then(|address| address.get_optional_full_name()),
                billing_address: billing_address
                .and_then(|addr| addr.address.clone())
                .and_then(|address| {
                    match (address.line1, address.city, address.zip, address.country) {
                        (Some(address1), Some(city), Some(postal_code), Some(country_code)) => {
                            Some(BillingAddress {
                                address1,
                                address2: address.line2,
                                address3: address.line3,
                                city,
                                state: address.state,
                                postal_code,
                                country_code,
                            })
                        }
                        _ => None,
                    }
                }),
            }))
        }
        PaymentMethodData::CardDetailsForNetworkTransactionId(raw_card_details) => {
            // For NTI flow, we know this is only used with DefaultPCIHolder
            // Since CardDetailsForNetworkTransactionId always uses cards::CardNumber,
            // we can only accept this when T = DefaultPCIHolder
            if std::any::TypeId::of::<T>() != std::any::TypeId::of::<DefaultPCIHolder>() {
                return Err(errors::ConnectorError::NotImplemented(
                    "NTI flow only supported with DefaultPCIHolder type".to_string(),
                ).into());
            }
            
            // Extract expiry month and year directly from the card fields
            let expiry_month: i32 = raw_card_details.card_exp_month.peek().parse::<i32>()
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            let mut expiry_year: String = raw_card_details.card_exp_year.peek().clone();
            if expiry_year.len() == 2 {
                expiry_year = format!("20{expiry_year}");
            }
            let expiry_year: i32 = expiry_year.parse::<i32>()
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            // Create a new RawCardDetails for DefaultPCIHolder type and cast to T
            // This is safe because we've already checked that T = DefaultPCIHolder above
            let default_raw_card_details = RawCardDetails::<DefaultPCIHolder> {
                payment_type: PaymentType::Plain,
                expiry_date: ExpiryDate {
                    month: Secret::new(expiry_month as i8),
                    year: Secret::new(expiry_year),
                },
                card_number: RawCardNumber(raw_card_details.card_number),
            };

            // Since we know T = DefaultPCIHolder, we can use a safer cast approach
            // by reinterpreting the memory layout
            let raw_card_details_inner: RawCardDetails<T> = unsafe {
                std::ptr::read(&default_raw_card_details as *const RawCardDetails<DefaultPCIHolder> as *const RawCardDetails<T>)
            };
            
            // Prevent double-drop by forgetting the original
            std::mem::forget(default_raw_card_details);
                
            Ok(PaymentInstrument::RawCardForNTI(raw_card_details_inner))
        }
        PaymentMethodData::MandatePayment => mandate_ids
            .and_then(|mandate_ids| {
                mandate_ids
                    .mandate_reference_id
                    .and_then(|mandate_id| match mandate_id {
                        MandateReferenceId::ConnectorMandateId(connector_mandate_id) => {
                            connector_mandate_id.get_connector_mandate_id().map(|href| {
                                PaymentInstrument::CardToken(CardToken {
                                    payment_type: PaymentType::Token,
                                    href,
                                    cvc: None,
                                })
                            })
                        }
                        _ => None,
                    })
            })
            .ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_mandate_id",
                }
                .into(),
            ),
        PaymentMethodData::Wallet(wallet) => match wallet {
            WalletDataPaymentMethod::GooglePay(data) => Ok(PaymentInstrument::Googlepay(WalletPayment {
                payment_type: PaymentType::Encrypted,
                wallet_token: Secret::new(
                    data.tokenization_data
                        .get_encrypted_google_pay_token()
                        .change_context(errors::ConnectorError::MissingRequiredField {
                            field_name: "gpay wallet_token",
                        })?,
                ),
                ..WalletPayment::default()
            })),
            WalletDataPaymentMethod::ApplePay(data) => Ok(PaymentInstrument::Applepay(WalletPayment {
                payment_type: PaymentType::Encrypted,
                wallet_token: data.get_applepay_decoded_payment_data()?,
                ..WalletPayment::default()
            })),
            WalletDataPaymentMethod::AliPayQr(_)
            | WalletDataPaymentMethod::AliPayRedirect(_)
            | WalletDataPaymentMethod::AliPayHkRedirect(_)
            | WalletDataPaymentMethod::AmazonPayRedirect(_)
            | WalletDataPaymentMethod::MomoRedirect(_)
            | WalletDataPaymentMethod::KakaoPayRedirect(_)
            | WalletDataPaymentMethod::GoPayRedirect(_)
            | WalletDataPaymentMethod::GcashRedirect(_)
            | WalletDataPaymentMethod::ApplePayRedirect(_)
            | WalletDataPaymentMethod::ApplePayThirdPartySdk(_)
            | WalletDataPaymentMethod::DanaRedirect {}
            | WalletDataPaymentMethod::GooglePayRedirect(_)
            | WalletDataPaymentMethod::GooglePayThirdPartySdk(_)
            | WalletDataPaymentMethod::MbWayRedirect(_)
            | WalletDataPaymentMethod::MobilePayRedirect(_)
            | WalletDataPaymentMethod::PaypalRedirect(_)
            | WalletDataPaymentMethod::PaypalSdk(_)
            | WalletDataPaymentMethod::Paze(_)
            | WalletDataPaymentMethod::SamsungPay(_)
            | WalletDataPaymentMethod::TwintRedirect {}
            | WalletDataPaymentMethod::VippsRedirect {}
            | WalletDataPaymentMethod::TouchNGoRedirect(_)
            | WalletDataPaymentMethod::WeChatPayRedirect(_)
            | WalletDataPaymentMethod::CashappQr(_)
            | WalletDataPaymentMethod::SwishQr(_)
            | WalletDataPaymentMethod::WeChatPayQr(_)
            | WalletDataPaymentMethod::Mifinity(_)
            | WalletDataPaymentMethod::RevolutPay(_)
            | WalletDataPaymentMethod::BluecodeRedirect {} => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("worldpay"),
            )
            .into()),
        },
        PaymentMethodData::PayLater(_)
        | PaymentMethodData::BankRedirect(_)
        | PaymentMethodData::BankDebit(_)
        | PaymentMethodData::BankTransfer(_)
        | PaymentMethodData::Crypto(_)
        | PaymentMethodData::Reward
        | PaymentMethodData::RealTimePayment(_)
        | PaymentMethodData::MobilePayment(_)
        | PaymentMethodData::Upi(_)
        | PaymentMethodData::Voucher(_)
        | PaymentMethodData::CardRedirect(_)
        | PaymentMethodData::GiftCard(_)
        | PaymentMethodData::OpenBanking(_)
        | PaymentMethodData::CardToken(_)
        | PaymentMethodData::NetworkToken(_) => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("worldpay"),
        )
        .into()),
    }
}

impl TryFrom<(enums::PaymentMethod, Option<enums::PaymentMethodType>)> for PaymentMethod {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        src: (enums::PaymentMethod, Option<enums::PaymentMethodType>),
    ) -> Result<Self, Self::Error> {
        match (src.0, src.1) {
            (enums::PaymentMethod::Card, _) => Ok(Self::Card),
            (enums::PaymentMethod::Wallet, pmt) => {
                let pm = pmt.ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_method_type",
                })?;
                match pm {
                    enums::PaymentMethodType::ApplePay => Ok(Self::ApplePay),
                    enums::PaymentMethodType::GooglePay => Ok(Self::GooglePay),
                    _ => Err(errors::ConnectorError::NotImplemented(
                        utils::get_unimplemented_payment_method_error_message("worldpay"),
                    )
                    .into()),
                }
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("worldpay"),
            )
            .into()),
        }
    }
}

// Helper constants for 3DS
const THREE_DS_TYPE: &str = "integrated";
const THREE_DS_MODE: &str = "always";

// Helper function to create ThreeDS request for RouterDataV2
fn create_three_ds_request<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    is_mandate_payment: bool,
) -> Result<Option<ThreeDSRequest>, error_stack::Report<errors::ConnectorError>> {
    match (
        &router_data.resource_common_data.auth_type,
        &router_data.request.payment_method_data,
    ) {
        // 3DS for NTI flow
        (_, PaymentMethodData::CardDetailsForNetworkTransactionId(_)) => Ok(None),
        // 3DS for regular payments
        (enums::AuthenticationType::ThreeDs, _) => {
            let browser_info = router_data.request.browser_info.as_ref().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "browser_info",
                },
            )?;

            let accept_header = browser_info
                .accept_header
                .clone()
                .get_required_value("accept_header")
                .change_context(errors::ConnectorError::MissingRequiredField {
                    field_name: "accept_header",
                })?;

            let user_agent_header = browser_info
                .user_agent
                .clone()
                .get_required_value("user_agent")
                .change_context(errors::ConnectorError::MissingRequiredField {
                    field_name: "user_agent",
                })?;

            Ok(Some(ThreeDSRequest {
                three_ds_type: THREE_DS_TYPE.to_string(),
                mode: THREE_DS_MODE.to_string(),
                device_data: ThreeDSRequestDeviceData {
                    accept_header,
                    user_agent_header,
                    browser_language: browser_info.language.clone(),
                    browser_screen_width: browser_info.screen_width,
                    browser_screen_height: browser_info.screen_height,
                    browser_color_depth: browser_info.color_depth.map(|depth| depth.to_string()),
                    time_zone: browser_info.time_zone.map(|tz| tz.to_string()),
                    browser_java_enabled: browser_info.java_enabled,
                    browser_javascript_enabled: browser_info.java_script_enabled,
                    channel: Some(ThreeDSRequestChannel::Browser),
                },
                challenge: ThreeDSRequestChallenge {
                    return_url: router_data.request.get_complete_authorize_url()?,
                    preference: if is_mandate_payment {
                        Some(ThreeDsPreference::ChallengeMandated)
                    } else {
                        None
                    },
                },
            }))
        }
        // Non 3DS
        _ => Ok(None),
    }
}

// Helper function to get settlement info for RouterDataV2
fn get_settlement_info<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    amount: i64,
) -> Option<AutoSettlement> {
    match (router_data.request.capture_method.unwrap_or_default(), amount) {
        (_, 0) => None,
        (enums::CaptureMethod::Automatic, _)
        | (enums::CaptureMethod::SequentialAutomatic, _) => Some(AutoSettlement { auto: true }),
        (enums::CaptureMethod::Manual, _) | (enums::CaptureMethod::ManualMultiple, _) => {
            Some(AutoSettlement { auto: false })
        }
        _ => None,
    }
}

// Dangling helper function to determine token and agreement settings
fn get_token_and_agreement<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    payment_method_data: &PaymentMethodData<T>,
    setup_future_usage: Option<enums::FutureUsage>,
    off_session: Option<bool>,
    mandate_ids: Option<MandateIds>,
) -> (Option<TokenCreation>, Option<CustomerAgreement>) {
    match (payment_method_data, setup_future_usage, off_session) {
        // CIT
        (PaymentMethodData::Card(_), Some(enums::FutureUsage::OffSession), _) => (
            Some(TokenCreation {
                token_type: TokenCreationType::Worldpay,
            }),
            Some(CustomerAgreement {
                agreement_type: CustomerAgreementType::Subscription,
                stored_card_usage: Some(StoredCardUsageType::First),
                scheme_reference: None,
            }),
        ),
        // MIT
        (PaymentMethodData::Card(_), _, Some(true)) => (
            None,
            Some(CustomerAgreement {
                agreement_type: CustomerAgreementType::Subscription,
                stored_card_usage: Some(StoredCardUsageType::Subsequent),
                scheme_reference: None,
            }),
        ),
        // NTI with raw card data
        (PaymentMethodData::CardDetailsForNetworkTransactionId(_), _, _) => (
            None,
            mandate_ids.and_then(|mandate_ids| {
                mandate_ids
                    .mandate_reference_id
                    .and_then(|mandate_id| match mandate_id {
                        MandateReferenceId::NetworkMandateId(network_transaction_id) => {
                            Some(CustomerAgreement {
                                agreement_type: CustomerAgreementType::Unscheduled,
                                scheme_reference: Some(network_transaction_id.into()),
                                stored_card_usage: None,
                            })
                        }
                        _ => None,
                    })
            }),
        ),
        _ => (None, None),
    }
}

// Implementation for WorldpayPaymentsRequest using abstracted request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        WorldpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for WorldpayPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let worldpay_connector_metadata_object: WorldpayConnectorMetadataObject =
            WorldpayConnectorMetadataObject::try_from(item.router_data.resource_common_data.connector_meta_data.as_ref())?;

        let merchant_name = worldpay_connector_metadata_object.merchant_name.ok_or(
            errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata.merchant_name",
            },
        )?;

        let is_mandate_payment = item.router_data.request.is_mandate_payment();
        let three_ds = create_three_ds_request(&item.router_data, is_mandate_payment)?;

        let (token_creation, customer_agreement) = get_token_and_agreement(
            &item.router_data.request.payment_method_data,
            item.router_data.request.setup_future_usage,
            item.router_data.request.off_session,
            item.router_data.request.mandate_id.clone(),
        );

        Ok(Self {
            instruction: Instruction {
                settlement: get_settlement_info(&item.router_data, item.router_data.request.minor_amount.get_amount_as_i64()),
                method: PaymentMethod::try_from((
                    item.router_data.resource_common_data.payment_method,
                    item.router_data.request.payment_method_type,
                ))?,
                payment_instrument: fetch_payment_instrument(
                    item.router_data.request.payment_method_data.clone(),
                    item.router_data.resource_common_data.get_optional_billing(),
                    item.router_data.request.mandate_id.clone(),
                )?,
                narrative: InstructionNarrative {
                    line1: merchant_name.expose(),
                },
                value: PaymentValue {
                    amount: item.router_data.request.minor_amount.get_amount_as_i64(),
                    currency: item.router_data.request.currency,
                },
                debt_repayment: None,
                three_ds,
                token_creation,
                customer_agreement,
            },
            merchant: Merchant {
                entity: WorldpayAuthType::try_from(&item.router_data.connector_auth_type)?.entity_id,
                ..Default::default()
            },
            transaction_reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            customer: None,
        })
    }
}

pub struct WorldpayAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) entity_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            // TODO: Remove this later, kept purely for backwards compatibility
            ConnectorAuthType::BodyKey { api_key, key1 } => {
                let auth_key = format!("{}:{}", key1.peek(), api_key.peek());
                let auth_header = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth_key));
                Ok(Self {
                    api_key: Secret::new(auth_header),
                    entity_id: Secret::new("default".to_string()),
                })
            }
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => {
                let auth_key = format!("{}:{}", key1.peek(), api_key.peek());
                let auth_header = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth_key));
                Ok(Self {
                    api_key: Secret::new(auth_header),
                    entity_id: api_secret.clone(),
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType)?,
        }
    }
}

impl From<PaymentOutcome> for enums::AttemptStatus {
    fn from(item: PaymentOutcome) -> Self {
        match item {
            PaymentOutcome::Authorized => Self::Authorized,
            PaymentOutcome::SentForSettlement => Self::Charged,
            PaymentOutcome::ThreeDsDeviceDataRequired => Self::DeviceDataCollectionPending,
            PaymentOutcome::ThreeDsAuthenticationFailed => Self::AuthenticationFailed,
            PaymentOutcome::ThreeDsChallenged => Self::AuthenticationPending,
            PaymentOutcome::SentForCancellation => Self::VoidInitiated,
            PaymentOutcome::SentForPartialRefund | PaymentOutcome::SentForRefund => {
                Self::AutoRefunded
            }
            PaymentOutcome::Refused | PaymentOutcome::FraudHighRisk => Self::Failure,
            PaymentOutcome::ThreeDsUnavailable => Self::AuthenticationFailed,
        }
    }
}

impl From<PaymentOutcome> for enums::RefundStatus {
    fn from(item: PaymentOutcome) -> Self {
        match item {
            PaymentOutcome::SentForPartialRefund | PaymentOutcome::SentForRefund => Self::Success,
            PaymentOutcome::Refused
            | PaymentOutcome::FraudHighRisk
            | PaymentOutcome::Authorized
            | PaymentOutcome::SentForSettlement
            | PaymentOutcome::ThreeDsDeviceDataRequired
            | PaymentOutcome::ThreeDsAuthenticationFailed
            | PaymentOutcome::ThreeDsChallenged
            | PaymentOutcome::SentForCancellation
            | PaymentOutcome::ThreeDsUnavailable => Self::Failure,
        }
    }
}

impl From<&EventType> for enums::AttemptStatus {
    fn from(value: &EventType) -> Self {
        match value {
            EventType::SentForAuthorization => Self::Authorizing,
            EventType::SentForSettlement => Self::Charged,
            EventType::Settled => Self::Charged,
            EventType::Authorized => Self::Authorized,
            EventType::Refused
            | EventType::SettlementFailed
            | EventType::Expired
            | EventType::Cancelled
            | EventType::Error => Self::Failure,
            EventType::SentForRefund
            | EventType::RefundFailed
            | EventType::Refunded
            | EventType::Unknown => Self::Pending,
        }
    }
}

impl From<EventType> for enums::RefundStatus {
    fn from(value: EventType) -> Self {
        match value {
            EventType::Refunded | EventType::SentForRefund => Self::Success,
            EventType::RefundFailed => Self::Failure,
            EventType::Authorized
            | EventType::Cancelled
            | EventType::Settled
            | EventType::Refused
            | EventType::Error
            | EventType::SentForSettlement
            | EventType::SentForAuthorization
            | EventType::SettlementFailed
            | EventType::Expired
            | EventType::Unknown => Self::Pending,
        }
    }
}

// Add the TryFrom implementation that the macro system expects
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
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
        // Use the existing ForeignTryFrom implementation
        Self::foreign_try_from((item, None, 0))
    }
}

impl<F, T>
    ForeignTryFrom<(
        ResponseRouterData<WorldpayPaymentsResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>,
        Option<String>,
        i64,
    )> for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn foreign_try_from(
        item: (
            ResponseRouterData<WorldpayPaymentsResponse, RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>>,
            Option<String>,
            i64,
        ),
    ) -> Result<Self, Self::Error> {
        let (router_data, optional_correlation_id, amount) = item;
        let (description, redirection_data, mandate_reference, network_txn_id, error) = router_data
            .response
            .other_fields
            .as_ref()
            .map(|other_fields| match other_fields {
                WorldpayPaymentResponseFields::AuthorizedResponse(res) => (
                    res.description.clone(),
                    None,
                    res.token.as_ref().map(|mandate_token| MandateReference {
                        connector_mandate_id: Some(mandate_token.href.clone().expose()),
                        payment_method_id: Some(mandate_token.token_id.clone()),
                    }),
                    res.scheme_reference.clone(),
                    None,
                ),
                WorldpayPaymentResponseFields::DDCResponse(res) => (
                    None,
                    Some(RedirectForm::WorldpayDDCForm {
                        endpoint: res.device_data_collection.url.clone(),
                        method: common_utils::request::Method::Post,
                        collection_id: Some("SessionId".to_string()),
                        form_fields: HashMap::from([
                            (
                                "Bin".to_string(),
                                res.device_data_collection.bin.clone().expose(),
                            ),
                            (
                                "JWT".to_string(),
                                res.device_data_collection.jwt.clone().expose(),
                            ),
                        ]),
                    }),
                    None,
                    None,
                    None,
                ),
                WorldpayPaymentResponseFields::ThreeDsChallenged(res) => (
                    None,
                    Some(RedirectForm::Form {
                        endpoint: res.challenge.url.to_string(),
                        method: common_utils::request::Method::Post,
                        form_fields: HashMap::from([(
                            "JWT".to_string(),
                            res.challenge.jwt.clone().expose(),
                        )]),
                    }),
                    None,
                    None,
                    None,
                ),
                WorldpayPaymentResponseFields::RefusedResponse(res) => (
                    None,
                    None,
                    None,
                    None,
                    Some((
                        res.refusal_code.clone(),
                        res.refusal_description.clone(),
                        res.advice
                            .as_ref()
                            .and_then(|advice_code| advice_code.code.clone()),
                    )),
                ),
                WorldpayPaymentResponseFields::FraudHighRisk(_) => (None, None, None, None, None),
            })
            .unwrap_or((None, None, None, None, None));
        let worldpay_status = router_data.response.outcome.clone();
        let optional_error_message = match worldpay_status {
            PaymentOutcome::ThreeDsAuthenticationFailed => {
                Some("3DS authentication failed from issuer".to_string())
            }
            PaymentOutcome::ThreeDsUnavailable => {
                Some("3DS authentication unavailable from issuer".to_string())
            }
            PaymentOutcome::FraudHighRisk => Some("Transaction marked as high risk".to_string()),
            _ => None,
        };
        let status = if amount == 0 && worldpay_status == PaymentOutcome::Authorized {
            enums::AttemptStatus::Charged
        } else {
            enums::AttemptStatus::from(worldpay_status.clone())
        };
        let response = match (optional_error_message, error) {
            (None, None) => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::foreign_try_from((
                    router_data.response,
                    optional_correlation_id.clone(),
                ))?,
                redirection_data: redirection_data.map(Box::new),
                mandate_reference: mandate_reference.map(Box::new),
                connector_metadata: None,
                network_txn_id: network_txn_id.map(|id| id.expose()),
                connector_response_reference_id: optional_correlation_id.clone(),
                incremental_authorization_allowed: None,
                status_code: router_data.http_code,
            }),
            (Some(reason), _) => Err(ErrorResponse {
                code: worldpay_status.to_string(),
                message: reason.clone(),
                reason: Some(reason),
                status_code: router_data.http_code,
                attempt_status: Some(status),
                connector_transaction_id: optional_correlation_id,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            }),
            (_, Some((code, message, advice_code))) => Err(ErrorResponse {
                code: code.clone(),
                message: message.clone(),
                reason: Some(message.clone()),
                status_code: router_data.http_code,
                attempt_status: Some(status),
                connector_transaction_id: optional_correlation_id,
                network_advice_code: advice_code,
                // Access Worldpay returns a raw response code in the refusalCode field (if enabled) containing the unmodified response code received either directly from the card scheme for Worldpay-acquired transactions, or from third party acquirers.
                // You can use raw response codes to inform your retry logic. A rawCode is only returned if specifically requested.
                network_decline_code: Some(code),
                network_error_message: Some(message),
            }),
        };
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                description,
                ..router_data.router_data.resource_common_data
            },
            response,
            ..router_data.router_data
        })
    }
}

// Helper function to get resource ID from payment response
pub fn get_resource_id<T, F>(
    response: WorldpayPaymentsResponse,
    connector_transaction_id: Option<String>,
    transform_fn: F,
) -> Result<T, error_stack::Report<errors::ConnectorError>>
where
    F: Fn(String) -> T,
{
    // First check top-level _links (for capture, authorize, etc.)
    let optional_reference_id = response
        .links
        .as_ref()
        .and_then(|link| link.self_link.href.rsplit_once('/').map(|(_, h)| h))
        .or_else(|| {
            // Fallback to variant-specific logic for DDC and 3DS challenges
            response.other_fields.as_ref().and_then(|other_fields| match other_fields {
                WorldpayPaymentResponseFields::DDCResponse(res) => {
                    res.actions.supply_ddc_data.href.split('/').nth_back(1)
                }
                WorldpayPaymentResponseFields::ThreeDsChallenged(res) => res
                    .actions
                    .complete_three_ds_challenge
                    .href
                    .split('/')
                    .nth_back(1),
                _ => None,
            })
        })
        .map(|href| {
            urlencoding::decode(href)
                .map(|s| transform_fn(s.into_owned()))
                .change_context(errors::ConnectorError::ResponseHandlingFailed)
        })
        .transpose()?;
    optional_reference_id
        .or_else(|| connector_transaction_id.map(transform_fn))
        .ok_or_else(|| {
            errors::ConnectorError::MissingRequiredField {
                field_name: "_links.self.href",
            }
            .into()
        })
}

// Response ID string wrapper
#[derive(Debug, Clone)]
pub struct ResponseIdStr {
    pub id: String,
}

// Note: Old RouterData TryFrom implementations removed as we're using RouterDataV2
// The following implementations are kept for compatibility with existing response processing
// Steps 100-109: TryFrom implementations for Capture flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        WorldpayRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    > for WorldpayPartialRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: WorldpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            reference: item.router_data.resource_common_data.connector_request_reference_id.clone().replace("_", "-"),
            value: PaymentValue {
                amount: item.router_data.request.minor_amount_to_capture.get_amount_as_i64(),
                currency: item.router_data.request.currency,
            },
        })
    }
}

impl TryFrom<ResponseRouterData<WorldpayPaymentsResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayPaymentsResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = enums::AttemptStatus::from(item.response.outcome.clone());
        let response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::foreign_try_from((
                item.response.clone(),
                None,
            ))?,
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });
        
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

impl<F> TryFrom<(&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, MinorUnit)> for WorldpayPartialRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(req: (&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, MinorUnit)) -> Result<Self, Self::Error> {
        let (item, amount) = req;
        Ok(Self {
            reference: item.request.refund_id.clone().replace("_", "-"),
            value: PaymentValue {
                amount: amount.get_amount_as_i64(),
                currency: item.request.currency,
            },
        })
    }
}

impl TryFrom<WorldpayWebhookEventType> for WorldpayEventResponse {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(event: WorldpayWebhookEventType) -> Result<Self, Self::Error> {
        Ok(Self {
            last_event: event.event_details.event_type,
            links: None,
        })
    }
}

// Step 80-84: TryFrom implementations for PSync flow
impl<F> TryFrom<ResponseRouterData<WorldpayEventResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayEventResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = enums::AttemptStatus::from(&item.response.last_event);
        let response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                item.router_data.resource_common_data.connector_request_reference_id.clone()
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });
        
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

// Steps 85-94: TryFrom implementations for Refund flow
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        WorldpayRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for WorldpayPartialRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: WorldpayRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            reference: item.router_data.request.refund_id.clone().replace("_", "-"),
            value: PaymentValue {
                amount: item.router_data.request.minor_refund_amount.get_amount_as_i64(),
                currency: item.router_data.request.currency,
            },
        })
    }
}

impl<F> TryFrom<ResponseRouterData<WorldpayPaymentsResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = enums::RefundStatus::from(item.response.outcome.clone());
        let response = Ok(RefundsResponseData {
            connector_refund_id: item.router_data.request.refund_id.clone(),
            refund_status,
            status_code: item.http_code,
        });
        
        Ok(Self {
            resource_common_data: RefundFlowData {
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

// Steps 95-99: TryFrom implementations for RSync flow
impl<F> TryFrom<ResponseRouterData<WorldpayEventResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayEventResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = enums::RefundStatus::from(item.response.last_event);
        let response = Ok(RefundsResponseData {
            connector_refund_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            refund_status,
            status_code: item.http_code,
        });
        
        Ok(Self {
            resource_common_data: RefundFlowData {
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

// Steps 110-119: TryFrom implementations for Void flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        WorldpayRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    > for ()
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        _item: WorldpayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Void request has empty body
        Ok(())
    }
}

impl TryFrom<ResponseRouterData<WorldpayPaymentsResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = enums::AttemptStatus::from(item.response.outcome.clone());
        let response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::foreign_try_from((
                item.response.clone(),
                None,
            ))?,
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });
        
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

impl ForeignTryFrom<(WorldpayPaymentsResponse, Option<String>)> for ResponseIdStr {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn foreign_try_from(
        item: (WorldpayPaymentsResponse, Option<String>),
    ) -> Result<Self, Self::Error> {
        get_resource_id(item.0, item.1, |id| Self { id })
    }
}

impl ForeignTryFrom<(WorldpayPaymentsResponse, Option<String>)> for ResponseId {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn foreign_try_from(
        item: (WorldpayPaymentsResponse, Option<String>),
    ) -> Result<Self, Self::Error> {
        get_resource_id(item.0, item.1, Self::ConnectorTransactionId)
    }
}
