use base64::Engine;
use jsonwebtoken as jwt;
use serde_json::Value;

use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    ext_traits::OptionExt,
    pii,
    types::{SemanticVersion, StringMajorUnit},
};

use crate::unimplemented_payment_method;
use crate::{connectors::cybersource::CybersourceRouterData, types::ResponseRouterData, utils};
use cards;
use domain_types::{
    connector_flow::{
        Authenticate, Authorize, Capture, PostAuthenticate, PreAuthenticate, SetupMandate, Void,
    },
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsPostAuthenticateData, PaymentsPreAuthenticateData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_address::Address,
    payment_method_data::{
        self, ApplePayWalletData, GPayPredecryptData, GooglePayWalletData, NetworkTokenData,
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber, SamsungPayWalletData, WalletData,
    },
    router_data::{
        AdditionalPaymentMethodConnectorResponse, ApplePayPredecryptData, ConnectorAuthType,
        ErrorResponse, GooglePayDecryptedData, NetworkTokenNumber, PaymentMethodToken,
        PazeDecryptedData,
    },
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils::CardIssuer,
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
pub const REFUND_VOIDED: &str = "Refund request has been voided.";

fn get_card_number_string<T: PaymentMethodDataTypes + 'static>(
    card_number: &RawCardNumber<T>,
) -> String {
    use std::any::{Any, TypeId};

    let any_ref: &dyn Any = card_number;

    match TypeId::of::<T>() {
        id if id == TypeId::of::<payment_method_data::DefaultPCIHolder>() => any_ref
            .downcast_ref::<RawCardNumber<payment_method_data::DefaultPCIHolder>>()
            .map(|c| c.peek().to_string())
            .unwrap_or_default(),
        _ => any_ref
            .downcast_ref::<RawCardNumber<payment_method_data::VaultTokenHolder>>()
            .map(|c| c.peek().to_string())
            .unwrap_or_default(),
    }
}

fn card_issuer_to_string(card_issuer: CardIssuer) -> String {
    let card_type = match card_issuer {
        CardIssuer::AmericanExpress => "003",
        CardIssuer::Master => "002",
        //"042" is the type code for Masetro Cards(International). For Maestro Cards(UK-Domestic) the mapping should be "024"
        CardIssuer::Maestro => "042",
        CardIssuer::Visa => "001",
        CardIssuer::Discover => "004",
        CardIssuer::DinersClub => "005",
        CardIssuer::CarteBlanche => "006",
        CardIssuer::JCB => "007",
        CardIssuer::CartesBancaires => "036",
    };
    card_type.to_string()
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CybersourceConnectorMetadataObject {
    pub disable_avs: Option<bool>,
    pub disable_cvn: Option<bool>,
}

impl TryFrom<&Option<pii::SecretSerdeValue>> for CybersourceConnectorMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let metadata = utils::to_connector_meta_from_secret::<Self>(meta_data.clone())
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata",
            })?;
        Ok(metadata)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceZeroMandateRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    processing_information: ProcessingInformation,
    payment_information: PaymentInformation<T>,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
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
        CybersourceRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for CybersourceZeroMandateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;

        let order_information = OrderInformationWithBill {
            amount_details: Amount {
                total_amount: StringMajorUnit::zero(),
                currency: item.router_data.request.currency,
            },
            bill_to: Some(bill_to),
        };
        let connector_merchant_config = CybersourceConnectorMetadataObject::try_from(
            &item
                .router_data
                .request
                .metadata
                .clone()
                .map(pii::SecretSerdeValue::new),
        )?;

        let (action_list, action_token_types, authorization_options) = (
            Some(vec![CybersourceActionsList::TokenCreate]),
            Some(vec![
                CybersourceActionsTokenType::PaymentInstrument,
                CybersourceActionsTokenType::Customer,
            ]),
            Some(CybersourceAuthorizationOptions {
                initiator: Some(CybersourcePaymentInitiator {
                    initiator_type: Some(CybersourcePaymentInitiatorTypes::Customer),
                    credential_stored_on_file: Some(true),
                    stored_credential_used: None,
                }),
                merchant_initiated_transaction: None,
                ignore_avs_result: connector_merchant_config.disable_avs,
                ignore_cv_result: connector_merchant_config.disable_cvn,
            }),
        );

        let client_reference_information = ClientReferenceInformation {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        };

        let (payment_information, solution) = match item
            .router_data
            .request
            .payment_method_data
            .clone()
        {
            PaymentMethodData::Card(ccard) => {
                let card_type = match ccard
                    .card_network
                    .clone()
                    .and_then(get_cybersource_card_type)
                {
                    Some(card_network) => Some(card_network.to_string()),
                    None => domain_types::utils::get_card_issuer(&get_card_number_string(
                        &ccard.card_number,
                    ))
                    .ok()
                    .map(card_issuer_to_string),
                };

                (
                    PaymentInformation::Cards(Box::new(CardPaymentInformation {
                        card: Card {
                            number: ccard.card_number,
                            expiration_month: ccard.card_exp_month,
                            expiration_year: ccard.card_exp_year,
                            security_code: Some(ccard.card_cvc),
                            card_type,
                            type_selection_indicator: Some("1".to_owned()),
                        },
                    })),
                    None,
                )
            }

            PaymentMethodData::Wallet(wallet_data) => {
                match wallet_data {
                    WalletData::ApplePay(apple_pay_data) => match item
                        .router_data
                        .resource_common_data
                        .payment_method_token
                        .clone()
                    {
                        Some(payment_method_token) => {
                            match payment_method_token {
                                PaymentMethodToken::ApplePayDecrypt(decrypt_data) => {
                                    let expiration_month =
                                        decrypt_data.get_expiry_month().change_context(
                                            errors::ConnectorError::InvalidDataFormat {
                                                field_name: "expiration_month",
                                            },
                                        )?;
                                    let expiration_year =
                                        decrypt_data.get_four_digit_expiry_year()?;
                                    (
                                PaymentInformation::ApplePay(Box::new(
                                    ApplePayPaymentInformation {
                                        tokenized_card: TokenizedCard {
                                            number: cards::CardNumber::try_from(decrypt_data.application_primary_account_number.expose().to_string())
                                                .change_context(errors::ConnectorError::InvalidDataFormat {
                                                    field_name: "application_primary_account_number",
                                                })?,
                                            cryptogram: Some(
                                                decrypt_data.payment_data.online_payment_cryptogram,
                                            ),
                                            transaction_type: TransactionType::InApp,
                                            expiration_year,
                                            expiration_month,
                                        },
                                    },
                                )),
                                Some(PaymentSolution::ApplePay),
                            )
                                }
                                PaymentMethodToken::Token(_) => {
                                    Err(unimplemented_payment_method!(
                                        "Apple Pay",
                                        "Manual",
                                        "Cybersource"
                                    ))?
                                }
                                PaymentMethodToken::PazeDecrypt(_) => {
                                    Err(unimplemented_payment_method!("Paze", "Cybersource"))?
                                }
                                PaymentMethodToken::GooglePayDecrypt(_) => {
                                    Err(unimplemented_payment_method!("Google Pay", "Cybersource"))?
                                }
                            }
                        }
                        None => {
                            let apple_pay_encrypted_data = apple_pay_data
                                .payment_data
                                .get_encrypted_apple_pay_payment_data_mandatory()
                                .change_context(errors::ConnectorError::MissingRequiredField {
                                    field_name: "Apple pay encrypted data",
                                })?;
                            (
                                PaymentInformation::ApplePayToken(Box::new(
                                    ApplePayTokenPaymentInformation {
                                        fluid_data: FluidData {
                                            value: Secret::from(apple_pay_encrypted_data.clone()),
                                            descriptor: Some(FLUID_DATA_DESCRIPTOR.to_string()),
                                        },
                                        tokenized_card: ApplePayTokenizedCard {
                                            transaction_type: TransactionType::InApp,
                                        },
                                    },
                                )),
                                Some(PaymentSolution::ApplePay),
                            )
                        }
                    },
                    WalletData::GooglePay(google_pay_data) => (
                        PaymentInformation::GooglePayToken(Box::new(
                            GooglePayTokenPaymentInformation {
                                fluid_data: FluidData {
                                    value: Secret::from(
                                        BASE64_ENGINE.encode(
                                            google_pay_data
                                                .tokenization_data
                                                .get_encrypted_google_pay_token()
                                                .change_context(
                                                    errors::ConnectorError::MissingRequiredField {
                                                        field_name: "gpay wallet_token",
                                                    },
                                                )?,
                                        ),
                                    ),
                                    descriptor: None,
                                },
                                tokenized_card: GooglePayTokenizedCard {
                                    transaction_type: TransactionType::InApp,
                                },
                            },
                        )),
                        Some(PaymentSolution::GooglePay),
                    ),
                    WalletData::SamsungPay(samsung_pay_data) => (
                        (get_samsung_pay_payment_information(&samsung_pay_data)
                            .attach_printable("Failed to get samsung pay payment information")?),
                        Some(PaymentSolution::SamsungPay),
                    ),
                    WalletData::AliPayQr(_)
                    | WalletData::AliPayRedirect(_)
                    | WalletData::AliPayHkRedirect(_)
                    | WalletData::AmazonPayRedirect(_)
                    | WalletData::BluecodeRedirect {}
                    | WalletData::MomoRedirect(_)
                    | WalletData::KakaoPayRedirect(_)
                    | WalletData::GoPayRedirect(_)
                    | WalletData::GcashRedirect(_)
                    | WalletData::ApplePayRedirect(_)
                    | WalletData::ApplePayThirdPartySdk(_)
                    | WalletData::DanaRedirect {}
                    | WalletData::GooglePayRedirect(_)
                    | WalletData::GooglePayThirdPartySdk(_)
                    | WalletData::MbWayRedirect(_)
                    | WalletData::MobilePayRedirect(_)
                    | WalletData::PaypalRedirect(_)
                    | WalletData::PaypalSdk(_)
                    | WalletData::Paze(_)
                    | WalletData::TwintRedirect {}
                    | WalletData::VippsRedirect {}
                    | WalletData::TouchNGoRedirect(_)
                    | WalletData::WeChatPayRedirect(_)
                    | WalletData::WeChatPayQr(_)
                    | WalletData::CashappQr(_)
                    | WalletData::SwishQr(_)
                    | WalletData::Mifinity(_)
                    | WalletData::RevolutPay(_) => Err(errors::ConnectorError::NotImplemented(
                        domain_types::utils::get_unimplemented_payment_method_error_message(
                            "Cybersource",
                        ),
                    ))?,
                }
            }
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    domain_types::utils::get_unimplemented_payment_method_error_message(
                        "Cybersource",
                    ),
                ))?
            }
        };

        let processing_information = ProcessingInformation {
            capture: Some(false),
            capture_options: None,
            action_list,
            action_token_types,
            authorization_options,
            commerce_indicator: String::from("internet"),
            payment_solution: solution.map(String::from),
        };
        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourcePaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    processing_information: ProcessingInformation,
    payment_information: PaymentInformation<T>,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_authentication_information: Option<CybersourceConsumerAuthInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceRepeatPaymentRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    processing_information: ProcessingInformation,
    payment_information: PaymentInformation<T>,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_authentication_information: Option<CybersourceConsumerAuthInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInformation {
    action_list: Option<Vec<CybersourceActionsList>>,
    action_token_types: Option<Vec<CybersourceActionsTokenType>>,
    authorization_options: Option<CybersourceAuthorizationOptions>,
    commerce_indicator: String,
    capture: Option<bool>,
    capture_options: Option<CaptureOptions>,
    payment_solution: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum CybersourceParesStatus {
    #[serde(rename = "Y")]
    AuthenticationSuccessful,
    #[serde(rename = "A")]
    AuthenticationAttempted,
    #[serde(rename = "N")]
    AuthenticationFailed,
    #[serde(rename = "U")]
    AuthenticationNotCompleted,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceConsumerAuthInformation {
    ucaf_collection_indicator: Option<String>,
    cavv: Option<Secret<String>>,
    ucaf_authentication_data: Option<Secret<String>>,
    xid: Option<String>,
    directory_server_transaction_id: Option<Secret<String>>,
    specification_version: Option<SemanticVersion>,
    /// This field specifies the 3ds version
    pa_specification_version: Option<SemanticVersion>,
    /// Verification response enrollment status.
    ///
    /// This field is supported only on Asia, Middle East, and Africa Gateway.
    ///
    /// For external authentication, this field will always be "Y"
    veres_enrolled: Option<String>,
    /// Raw electronic commerce indicator (ECI)
    eci_raw: Option<String>,
    /// This field is supported only on Asia, Middle East, and Africa Gateway
    /// Also needed for Credit Mutuel-CIC in France and Mastercard Identity Check transactions
    /// This field is only applicable for Mastercard and Visa Transactions
    pares_status: Option<CybersourceParesStatus>,
    //This field is used to send the authentication date in yyyyMMDDHHMMSS format
    authentication_date: Option<String>,
    /// This field indicates the 3D Secure transaction flow. It is only supported for secure transactions in France.
    /// The possible values are - CH (Challenge), FD (Frictionless with delegation), FR (Frictionless)
    effective_authentication_type: Option<EffectiveAuthenticationType>,
    /// This field indicates the authentication type or challenge presented to the cardholder at checkout.
    challenge_code: Option<String>,
    /// This field indicates the reason for payer authentication response status. It is only supported for secure transactions in France.
    signed_pares_status_reason: Option<String>,
    /// This field indicates the reason why strong authentication was cancelled. It is only supported for secure transactions in France.
    challenge_cancel_code: Option<String>,
    /// This field indicates the score calculated by the 3D Securing platform. It is only supported for secure transactions in France.
    network_score: Option<u32>,
    /// This is the transaction ID generated by the access control server. This field is supported only for secure transactions in France.
    acs_transaction_id: Option<String>,
    /// This is the algorithm for generating a cardholder authentication verification value (CAVV) or universal cardholder authentication field (UCAF) data.
    cavv_algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum EffectiveAuthenticationType {
    CH,
    FR,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantDefinedInformation {
    key: u8,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CybersourceActionsList {
    TokenCreate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CybersourceActionsTokenType {
    Customer,
    PaymentInstrument,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceAuthorizationOptions {
    initiator: Option<CybersourcePaymentInitiator>,
    merchant_initiated_transaction: Option<MerchantInitiatedTransaction>,
    ignore_avs_result: Option<bool>,
    ignore_cv_result: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantInitiatedTransaction {
    reason: Option<String>,
    previous_transaction_id: Option<Secret<String>>,
    //Required for recurring mandates payment
    original_authorized_amount: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourcePaymentInitiator {
    #[serde(rename = "type")]
    initiator_type: Option<CybersourcePaymentInitiatorTypes>,
    credential_stored_on_file: Option<bool>,
    stored_credential_used: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CybersourcePaymentInitiatorTypes {
    Customer,
    Merchant,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureOptions {
    capture_sequence_number: u32,
    total_capture_count: u32,
    is_final: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTokenizedCard {
    number: NetworkTokenNumber,
    expiration_month: Secret<String>,
    expiration_year: Secret<String>,
    cryptogram: Option<Secret<String>>,
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTokenPaymentInformation {
    tokenized_card: NetworkTokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardPaymentInformation<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    card: Card<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenizedCard {
    number: cards::CardNumber,
    expiration_month: Secret<String>,
    expiration_year: Secret<String>,
    cryptogram: Option<Secret<String>>,
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayTokenizedCard {
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayTokenPaymentInformation {
    fluid_data: FluidData,
    tokenized_card: ApplePayTokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayPaymentInformation {
    tokenized_card: TokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MandatePaymentTokenizedCard {
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MandatePaymentInformation {
    payment_instrument: CybersoucrePaymentInstrument,
    tokenized_card: MandatePaymentTokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FluidData {
    value: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor: Option<String>,
}

pub const FLUID_DATA_DESCRIPTOR: &str = "RklEPUNPTU1PTi5BUFBMRS5JTkFQUC5QQVlNRU5U";

pub const FLUID_DATA_DESCRIPTOR_FOR_SAMSUNG_PAY: &str = "FID=COMMON.SAMSUNG.INAPP.PAYMENT";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayTokenPaymentInformation {
    fluid_data: FluidData,
    tokenized_card: GooglePayTokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayTokenizedCard {
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayPaymentInformation {
    tokenized_card: TokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamsungPayTokenizedCard {
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamsungPayPaymentInformation {
    fluid_data: FluidData,
    tokenized_card: SamsungPayTokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamsungPayFluidDataValue {
    public_key_hash: Secret<String>,
    version: String,
    data: Secret<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MessageExtensionAttribute {
    pub id: String,
    pub name: String,
    pub criticality_indicator: bool,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaymentInformation<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    Cards(Box<CardPaymentInformation<T>>),
    GooglePayToken(Box<GooglePayTokenPaymentInformation>),
    GooglePay(Box<GooglePayPaymentInformation>),
    ApplePay(Box<ApplePayPaymentInformation>),
    ApplePayToken(Box<ApplePayTokenPaymentInformation>),
    MandatePayment(Box<MandatePaymentInformation>),
    SamsungPay(Box<SamsungPayPaymentInformation>),
    NetworkToken(Box<NetworkTokenPaymentInformation>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CybersoucrePaymentInstrument {
    id: Secret<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    number: RawCardNumber<T>,
    expiration_month: Secret<String>,
    expiration_year: Secret<String>,
    security_code: Option<Secret<String>>,
    #[serde(rename = "type")]
    card_type: Option<String>,
    type_selection_indicator: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformationWithBill {
    amount_details: Amount,
    bill_to: Option<BillTo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformationIncrementalAuthorization {
    amount_details: AdditionalAmount,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformation {
    amount_details: Amount,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Amount {
    total_amount: StringMajorUnit,
    currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalAmount {
    additional_amount: StringMajorUnit,
    currency: String,
}

#[derive(Debug, Serialize)]
pub enum PaymentSolution {
    ApplePay,
    GooglePay,
    SamsungPay,
}

#[derive(Debug, Serialize)]
pub enum TransactionType {
    #[serde(rename = "1")]
    InApp,
    #[serde(rename = "2")]
    ContactlessNFC,
    #[serde(rename = "3")]
    StoredCredentials,
}

impl From<PaymentSolution> for String {
    fn from(solution: PaymentSolution) -> Self {
        let payment_solution = match solution {
            PaymentSolution::ApplePay => "001",
            PaymentSolution::GooglePay => "012",
            PaymentSolution::SamsungPay => "008",
        };
        payment_solution.to_string()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillTo {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    address1: Option<Secret<String>>,
    locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    administrative_area: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<Secret<String>>,
    country: Option<common_enums::CountryAlpha2>,
    email: pii::Email,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    From<
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ClientReferenceInformation
{
    fn from(
        item: &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Self {
        Self {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
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
    From<
        &CybersourceRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ClientReferenceInformation
{
    fn from(
        item: &CybersourceRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Self {
        Self {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Option<PaymentSolution>,
        Option<String>,
    )> for ProcessingInformation
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, solution, network): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Option<PaymentSolution>,
            Option<String>,
        ),
    ) -> Result<Self, Self::Error> {
        let commerce_indicator = solution
            .as_ref()
            .map(|pm_solution| match pm_solution {
                PaymentSolution::ApplePay | PaymentSolution::SamsungPay => network
                    .as_ref()
                    .map(|card_network| match card_network.to_lowercase().as_str() {
                        "mastercard" => "spa",
                        _ => "internet",
                    })
                    .unwrap_or("internet"),
                PaymentSolution::GooglePay => "internet",
            })
            .unwrap_or("internet")
            .to_string();

        let connector_merchant_config = CybersourceConnectorMetadataObject::try_from(
            &item.router_data.resource_common_data.connector_meta_data,
        )?;

        let (action_list, action_token_types, authorization_options) =
            if item.router_data.request.setup_future_usage
                == Some(common_enums::FutureUsage::OffSession)
                && (item.router_data.request.customer_acceptance.is_some())
            {
                (
                    Some(vec![CybersourceActionsList::TokenCreate]),
                    Some(vec![
                        CybersourceActionsTokenType::PaymentInstrument,
                        CybersourceActionsTokenType::Customer,
                    ]),
                    Some(CybersourceAuthorizationOptions {
                        initiator: Some(CybersourcePaymentInitiator {
                            initiator_type: Some(CybersourcePaymentInitiatorTypes::Customer),
                            credential_stored_on_file: Some(true),
                            stored_credential_used: None,
                        }),
                        ignore_avs_result: connector_merchant_config.disable_avs,
                        ignore_cv_result: connector_merchant_config.disable_cvn,
                        merchant_initiated_transaction: None,
                    }),
                )
            } else {
                (
                    None,
                    None,
                    Some(CybersourceAuthorizationOptions {
                        initiator: None,
                        merchant_initiated_transaction: None,
                        ignore_avs_result: connector_merchant_config.disable_avs,
                        ignore_cv_result: connector_merchant_config.disable_cvn,
                    }),
                )
            };
        // this logic is for external authenticated card
        let commerce_indicator_for_external_authentication = item
            .router_data
            .request
            .metadata
            .as_ref()
            .and_then(|authn_data| {
                authn_data
                    .get("eci")
                    .and_then(|eci| eci.as_str())
                    .map(|eci| {
                        get_commerce_indicator_for_external_authentication(network, eci.to_string())
                    })
            });

        Ok(Self {
            capture: Some(matches!(
                item.router_data.request.capture_method,
                Some(common_enums::CaptureMethod::Automatic) | None
            )),
            payment_solution: solution.map(String::from),
            action_list,
            action_token_types,
            authorization_options,
            capture_options: None,
            commerce_indicator: commerce_indicator_for_external_authentication
                .unwrap_or(commerce_indicator),
        })
    }
}

fn get_commerce_indicator_for_external_authentication(
    card_network: Option<String>,
    eci: String,
) -> String {
    let card_network_lower_case = card_network
        .as_ref()
        .map(|card_network| card_network.to_lowercase());
    match eci.as_str() {
        "00" | "01" | "02" => {
            if matches!(
                card_network_lower_case.as_deref(),
                Some("mastercard") | Some("maestro")
            ) {
                "spa"
            } else {
                "internet"
            }
        }
        "05" => match card_network_lower_case.as_deref() {
            Some("amex") => "aesk",
            Some("discover") => "dipb",
            Some("mastercard") => "spa",
            Some("visa") => "vbv",
            Some("diners") => "pb",
            Some("upi") => "up3ds",
            _ => "internet",
        },
        "06" => match card_network_lower_case.as_deref() {
            Some("amex") => "aesk_attempted",
            Some("discover") => "dipb_attempted",
            Some("mastercard") => "spa",
            Some("visa") => "vbv_attempted",
            Some("diners") => "pb_attempted",
            Some("upi") => "up3ds_attempted",
            _ => "internet",
        },
        "07" => match card_network_lower_case.as_deref() {
            Some("amex") => "internet",
            Some("discover") => "internet",
            Some("diners") => "internet",
            Some("mastercard") => "spa",
            Some("visa") => "vbv_failure",
            Some("upi") => "up3ds_failure",
            _ => "internet",
        },
        _ => "vbv_failure",
    }
    .to_string()
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    From<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Option<BillTo>,
    )> for OrderInformationWithBill
{
    fn from(
        (item, bill_to): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Option<BillTo>,
        ),
    ) -> Self {
        let total_amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount.to_owned(),
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)
            .expect("Failed to convert amount");
        Self {
            amount_details: Amount {
                total_amount,
                currency: item.router_data.request.currency,
            },
            bill_to,
        }
    }
}

fn truncate_string(state: &Secret<String>, max_len: usize) -> Secret<String> {
    let exposed = state.clone().expose();
    let truncated = exposed.get(..max_len).unwrap_or(&exposed);
    Secret::new(truncated.to_string())
}

fn build_bill_to(
    address_details: Option<&Address>,
    email: pii::Email,
) -> Result<BillTo, error_stack::Report<errors::ConnectorError>> {
    let default_address = BillTo {
        first_name: None,
        last_name: None,
        address1: None,
        locality: None,
        administrative_area: None,
        postal_code: None,
        country: None,
        email: email.clone(),
    };
    Ok(address_details
        .and_then(|addr| {
            addr.address.as_ref().map(|addr| BillTo {
                first_name: addr.first_name.remove_new_line(),
                last_name: addr.last_name.remove_new_line(),
                address1: addr.line1.remove_new_line(),
                locality: addr.city.remove_new_line(),
                administrative_area: addr.to_state_code_as_optional().unwrap_or_else(|_| {
                    addr.state
                        .remove_new_line()
                        .as_ref()
                        .map(|state| truncate_string(state, 20)) //NOTE: Cybersource connector throws error if billing state exceeds 20 characters, so truncation is done to avoid payment failure
                }),
                postal_code: addr.zip.remove_new_line(),
                country: addr.country,
                email,
            })
        })
        .unwrap_or(default_address))
}

fn convert_metadata_to_merchant_defined_info(metadata: Value) -> Vec<MerchantDefinedInformation> {
    let hashmap: std::collections::BTreeMap<String, Value> =
        serde_json::from_str(&metadata.to_string()).unwrap_or(std::collections::BTreeMap::new());
    let mut vector = Vec::new();
    let mut iter = 1;
    for (key, value) in hashmap {
        vector.push(MerchantDefinedInformation {
            key: iter,
            value: format!("{key}={value}"),
        });
        iter += 1;
    }
    vector
}

impl From<common_enums::DecoupledAuthenticationType> for EffectiveAuthenticationType {
    fn from(auth_type: common_enums::DecoupledAuthenticationType) -> Self {
        match auth_type {
            common_enums::DecoupledAuthenticationType::Challenge => Self::CH,
            common_enums::DecoupledAuthenticationType::Frictionless => Self::FR,
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        payment_method_data::Card<T>,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, ccard): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            payment_method_data::Card<T>,
        ),
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));

        let raw_card_type = ccard.card_network.clone();

        let card_type = match raw_card_type.clone().and_then(get_cybersource_card_type) {
            Some(card_network) => Some(card_network.to_string()),
            None => {
                domain_types::utils::get_card_issuer(&get_card_number_string(&ccard.card_number))
                    .ok()
                    .map(card_issuer_to_string)
            }
        };

        let payment_information = PaymentInformation::Cards(Box::new(CardPaymentInformation {
            card: Card {
                number: ccard.card_number,
                expiration_month: ccard.card_exp_month,
                expiration_year: ccard.card_exp_year,
                security_code: None,
                card_type: card_type.clone(),
                type_selection_indicator: Some("1".to_owned()),
            },
        }));

        let processing_information = ProcessingInformation::try_from((
            item,
            None,
            raw_card_type.map(|network| network.to_string()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: None,
            merchant_defined_information,
        })
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        NetworkTokenData,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, token_data): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            NetworkTokenData,
        ),
    ) -> Result<Self, Self::Error> {
        let transaction_type = if item.router_data.request.off_session == Some(true) {
            TransactionType::StoredCredentials
        } else {
            TransactionType::InApp
        };

        let email = item.router_data.request.get_email()?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));

        let card_issuer =
            domain_types::utils::get_card_issuer(token_data.get_network_token().peek());
        let card_type = match card_issuer {
            Ok(issuer) => Some(card_issuer_to_string(issuer)),
            Err(_) => None,
        };

        let payment_information =
            PaymentInformation::NetworkToken(Box::new(NetworkTokenPaymentInformation {
                tokenized_card: NetworkTokenizedCard {
                    number: token_data.get_network_token(),
                    expiration_month: token_data.get_network_token_expiry_month(),
                    expiration_year: token_data.get_network_token_expiry_year(),
                    cryptogram: token_data.get_cryptogram().clone(),
                    transaction_type,
                },
            }));

        let processing_information = ProcessingInformation::try_from((item, None, card_type))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: None,
            merchant_defined_information,
        })
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Box<PazeDecryptedData>,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, paze_data): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Box<PazeDecryptedData>,
        ),
    ) -> Result<Self, Self::Error> {
        let transaction_type = if item.router_data.request.off_session == Some(true) {
            TransactionType::StoredCredentials
        } else {
            TransactionType::InApp
        };

        let email = item.router_data.request.get_email()?;
        let (first_name, last_name) = match paze_data.billing_address.name {
            Some(name) => {
                let (first_name, last_name) = name
                    .peek()
                    .split_once(' ')
                    .map(|(first, last)| (first.to_string(), last.to_string()))
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "billing_address.name",
                    })?;
                (Secret::from(first_name), Secret::from(last_name))
            }
            None => (
                item.router_data
                    .resource_common_data
                    .get_billing_first_name()?,
                item.router_data
                    .resource_common_data
                    .get_billing_last_name()?,
            ),
        };
        let bill_to = BillTo {
            first_name: Some(first_name),
            last_name: Some(last_name),
            address1: paze_data.billing_address.line1,
            locality: paze_data.billing_address.city.map(|city| city.expose()),
            administrative_area: Some(Secret::from(
                //Paze wallet is currently supported in US only
                domain_types::utils::convert_us_state_to_code(
                    paze_data
                        .billing_address
                        .state
                        .ok_or(errors::ConnectorError::MissingRequiredField {
                            field_name: "billing_address.state",
                        })?
                        .peek(),
                ),
            )),
            postal_code: paze_data.billing_address.zip,
            country: paze_data.billing_address.country_code,
            email,
        };
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));

        let payment_information =
            PaymentInformation::NetworkToken(Box::new(NetworkTokenPaymentInformation {
                tokenized_card: NetworkTokenizedCard {
                    number: paze_data.token.payment_token,
                    expiration_month: paze_data.token.token_expiration_month,
                    expiration_year: paze_data.token.token_expiration_year,
                    cryptogram: Some(paze_data.token.payment_account_reference),
                    transaction_type,
                },
            }));

        let processing_information = ProcessingInformation::try_from((item, None, None))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: None,
            merchant_defined_information,
        })
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Box<ApplePayPredecryptData>,
        ApplePayWalletData,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        input: (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Box<ApplePayPredecryptData>,
            ApplePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let (item, apple_pay_data, apple_pay_wallet_data) = input;
        let transaction_type = if item.router_data.request.off_session == Some(true) {
            TransactionType::StoredCredentials
        } else {
            TransactionType::InApp
        };

        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));
        let processing_information = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::ApplePay),
            Some(apple_pay_wallet_data.payment_method.network.clone()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let expiration_month = apple_pay_data.get_expiry_month()?;

        if let Err(parse_err) = expiration_month.peek().parse::<u8>() {
            tracing::warn!(
                "Invalid expiration month format in Apple Pay data: {}. Error: {}",
                expiration_month.peek(),
                parse_err
            );
        }
        let expiration_year = apple_pay_data.get_four_digit_expiry_year()?;
        let payment_information =
            PaymentInformation::ApplePay(Box::new(ApplePayPaymentInformation {
                tokenized_card: TokenizedCard {
                    number: apple_pay_data
                        .application_primary_account_number
                        .expose()
                        .parse::<cards::CardNumber>()
                        .map_err(|err| {
                            tracing::error!(
                                "Failed to parse Apple Pay account number as CardNumber: {:?}",
                                err
                            );
                            report!(ConnectorError::RequestEncodingFailed)
                        })?,
                    cryptogram: Some(apple_pay_data.payment_data.online_payment_cryptogram),
                    transaction_type,
                    expiration_year,
                    expiration_month,
                },
            }));
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        let ucaf_collection_indicator = match apple_pay_wallet_data
            .payment_method
            .network
            .to_lowercase()
            .as_str()
        {
            "mastercard" => Some("2".to_string()),
            _ => None,
        };
        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: Some(CybersourceConsumerAuthInformation {
                pares_status: None,
                ucaf_collection_indicator,
                cavv: None,
                ucaf_authentication_data: None,
                xid: None,
                directory_server_transaction_id: None,
                specification_version: None,
                pa_specification_version: None,
                veres_enrolled: None,
                eci_raw: None,
                authentication_date: None,
                effective_authentication_type: None,
                challenge_code: None,
                signed_pares_status_reason: None,
                challenge_cancel_code: None,
                network_score: None,
                acs_transaction_id: None,
                cavv_algorithm: None,
            }),
            merchant_defined_information,
        })
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        GooglePayWalletData,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, google_pay_data): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            GooglePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));

        let payment_information =
            PaymentInformation::GooglePayToken(Box::new(GooglePayTokenPaymentInformation {
                fluid_data: FluidData {
                    value: Secret::from(
                        BASE64_ENGINE.encode(
                            google_pay_data
                                .tokenization_data
                                .get_encrypted_google_pay_token()
                                .change_context(errors::ConnectorError::MissingRequiredField {
                                    field_name: "gpay wallet_token",
                                })?,
                        ),
                    ),
                    descriptor: None,
                },
                tokenized_card: GooglePayTokenizedCard {
                    transaction_type: TransactionType::InApp,
                },
            }));
        let processing_information =
            ProcessingInformation::try_from((item, Some(PaymentSolution::GooglePay), None))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: None,
            merchant_defined_information,
        })
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Box<GPayPredecryptData>,
        GooglePayWalletData,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, google_pay_decrypted_data, google_pay_data): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Box<GPayPredecryptData>,
            GooglePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let transaction_type = if item.router_data.request.off_session == Some(true) {
            TransactionType::StoredCredentials
        } else {
            TransactionType::InApp
        };
        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));

        let payment_information =
            PaymentInformation::GooglePay(Box::new(GooglePayPaymentInformation {
                tokenized_card: TokenizedCard {
                    number: google_pay_decrypted_data
                        .application_primary_account_number
                        .clone(),
                    cryptogram: google_pay_decrypted_data.cryptogram.clone(),
                    transaction_type,
                    expiration_year: google_pay_decrypted_data
                        .get_four_digit_expiry_year()
                        .change_context(errors::ConnectorError::InvalidDataFormat {
                            field_name: "expiration_year",
                        })?,
                    expiration_month: google_pay_decrypted_data
                        .get_expiry_month()
                        .change_context(errors::ConnectorError::InvalidDataFormat {
                            field_name: "expiration_month",
                        })?,
                },
            }));
        let processing_information = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::GooglePay),
            Some(google_pay_data.info.card_network.clone()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        let ucaf_collection_indicator =
            match google_pay_data.info.card_network.to_lowercase().as_str() {
                "mastercard" => Some("2".to_string()),
                _ => None,
            };

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: Some(CybersourceConsumerAuthInformation {
                pares_status: None,
                ucaf_collection_indicator,
                cavv: None,
                ucaf_authentication_data: None,
                xid: None,
                directory_server_transaction_id: None,
                specification_version: None,
                pa_specification_version: None,
                veres_enrolled: None,
                eci_raw: None,
                authentication_date: None,
                effective_authentication_type: None,
                challenge_code: None,
                signed_pares_status_reason: None,
                challenge_cancel_code: None,
                network_score: None,
                acs_transaction_id: None,
                cavv_algorithm: None,
            }),
            merchant_defined_information,
        })
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Box<GooglePayDecryptedData>,
        GooglePayWalletData,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, google_pay_decrypted_data, google_pay_data): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Box<GooglePayDecryptedData>,
            GooglePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let transaction_type = if item.router_data.request.off_session == Some(true) {
            TransactionType::StoredCredentials
        } else {
            TransactionType::InApp
        };
        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));

        let payment_information =
            PaymentInformation::GooglePay(Box::new(GooglePayPaymentInformation {
                tokenized_card: TokenizedCard {
                    number: google_pay_decrypted_data.payment_method_details.pan.clone(),
                    cryptogram: google_pay_decrypted_data
                        .payment_method_details
                        .cryptogram
                        .clone(),
                    transaction_type,
                    expiration_year: Secret::new(
                        google_pay_decrypted_data
                            .payment_method_details
                            .expiration_year
                            .get_year()
                            .to_string(),
                    ),
                    expiration_month: Secret::new(
                        google_pay_decrypted_data
                            .payment_method_details
                            .expiration_month
                            .two_digits(),
                    ),
                },
            }));
        let processing_information = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::GooglePay),
            Some(google_pay_data.info.card_network.clone()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        let ucaf_collection_indicator =
            match google_pay_data.info.card_network.to_lowercase().as_str() {
                "mastercard" => Some("2".to_string()),
                _ => None,
            };

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: Some(CybersourceConsumerAuthInformation {
                pares_status: None,
                ucaf_collection_indicator,
                cavv: None,
                ucaf_authentication_data: None,
                xid: None,
                directory_server_transaction_id: None,
                specification_version: None,
                pa_specification_version: None,
                veres_enrolled: None,
                eci_raw: None,
                authentication_date: None,
                effective_authentication_type: None,
                challenge_code: None,
                signed_pares_status_reason: None,
                challenge_cancel_code: None,
                network_score: None,
                acs_transaction_id: None,
                cavv_algorithm: None,
            }),
            merchant_defined_information,
        })
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
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Box<SamsungPayWalletData>,
    )> for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, samsung_pay_data): (
            &CybersourceRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Box<SamsungPayWalletData>,
        ),
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item.router_data.request.get_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::from((item, Some(bill_to)));

        let payment_information = get_samsung_pay_payment_information(&samsung_pay_data)
            .attach_printable("Failed to get samsung pay payment information")?;

        let processing_information = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::SamsungPay),
            Some(samsung_pay_data.payment_credential.card_brand.to_string()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: None,
            merchant_defined_information,
        })
    }
}

fn get_samsung_pay_payment_information<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    samsung_pay_data: &payment_method_data::SamsungPayWalletData,
) -> Result<PaymentInformation<T>, error_stack::Report<errors::ConnectorError>> {
    let samsung_pay_fluid_data_value =
        get_samsung_pay_fluid_data_value(&samsung_pay_data.payment_credential.token_data)?;

    let samsung_pay_fluid_data_str = serde_json::to_string(&samsung_pay_fluid_data_value)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Failed to serialize samsung pay fluid data")?;

    let payment_information =
        PaymentInformation::SamsungPay(Box::new(SamsungPayPaymentInformation {
            fluid_data: FluidData {
                value: Secret::new(BASE64_ENGINE.encode(samsung_pay_fluid_data_str)),
                descriptor: Some(BASE64_ENGINE.encode(FLUID_DATA_DESCRIPTOR_FOR_SAMSUNG_PAY)),
            },
            tokenized_card: SamsungPayTokenizedCard {
                transaction_type: TransactionType::InApp,
            },
        }));

    Ok(payment_information)
}

fn get_samsung_pay_fluid_data_value(
    samsung_pay_token_data: &payment_method_data::SamsungPayTokenData,
) -> Result<SamsungPayFluidDataValue, error_stack::Report<errors::ConnectorError>> {
    let samsung_pay_header = jwt::decode_header(samsung_pay_token_data.data.clone().peek())
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Failed to decode samsung pay header")?;

    let samsung_pay_kid_optional = samsung_pay_header.kid;

    let samsung_pay_fluid_data_value = SamsungPayFluidDataValue {
        public_key_hash: Secret::new(
            samsung_pay_kid_optional
                .get_required_value("samsung pay public_key_hash")
                .change_context(errors::ConnectorError::RequestEncodingFailed)?
                .to_string(),
        ),
        version: samsung_pay_token_data.version.clone(),
        data: Secret::new(BASE64_ENGINE.encode(samsung_pay_token_data.data.peek())),
    };
    Ok(samsung_pay_fluid_data_value)
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
        CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for CybersourcePaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(ccard) => Self::try_from((&item, ccard)),
            PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                WalletData::ApplePay(apple_pay_data) => {
                    match item
                        .router_data
                        .resource_common_data
                        .payment_method_token
                        .clone()
                    {
                        Some(payment_method_token) => match payment_method_token {
                            PaymentMethodToken::ApplePayDecrypt(decrypt_data) => {
                                Self::try_from((&item, decrypt_data, apple_pay_data))
                            }
                            PaymentMethodToken::Token(_) => Err(unimplemented_payment_method!(
                                "Apple Pay",
                                "Manual",
                                "Cybersource"
                            ))?,
                            PaymentMethodToken::PazeDecrypt(_) => {
                                Err(unimplemented_payment_method!("Paze", "Cybersource"))?
                            }
                            PaymentMethodToken::GooglePayDecrypt(_) => {
                                Err(unimplemented_payment_method!("Google Pay", "Cybersource"))?
                            }
                        },
                        None => {
                            let transaction_type =
                                if item.router_data.request.off_session == Some(true) {
                                    TransactionType::StoredCredentials
                                } else {
                                    TransactionType::InApp
                                };
                            let email = item
                                .router_data
                                .resource_common_data
                                .get_billing_email()
                                .or(item.router_data.request.get_email())?;
                            let bill_to = build_bill_to(
                                item.router_data.resource_common_data.get_optional_billing(),
                                email,
                            )?;
                            let order_information =
                                OrderInformationWithBill::from((&item, Some(bill_to)));
                            let processing_information = ProcessingInformation::try_from((
                                &item,
                                Some(PaymentSolution::ApplePay),
                                Some(apple_pay_data.payment_method.network.clone()),
                            ))?;
                            let client_reference_information =
                                ClientReferenceInformation::from(&item);

                            let apple_pay_encrypted_data = apple_pay_data
                                .payment_data
                                .get_encrypted_apple_pay_payment_data_mandatory()
                                .change_context(errors::ConnectorError::MissingRequiredField {
                                    field_name: "Apple pay encrypted data",
                                })?;
                            let payment_information = PaymentInformation::ApplePayToken(Box::new(
                                ApplePayTokenPaymentInformation {
                                    fluid_data: FluidData {
                                        value: Secret::from(apple_pay_encrypted_data.clone()),
                                        descriptor: Some(FLUID_DATA_DESCRIPTOR.to_string()),
                                    },
                                    tokenized_card: ApplePayTokenizedCard { transaction_type },
                                },
                            ));
                            let merchant_defined_information =
                                item.router_data.request.metadata.clone().map(|metadata| {
                                    convert_metadata_to_merchant_defined_info(metadata)
                                });
                            let ucaf_collection_indicator = match apple_pay_data
                                .payment_method
                                .network
                                .to_lowercase()
                                .as_str()
                            {
                                "mastercard" => Some("2".to_string()),
                                _ => None,
                            };
                            Ok(Self {
                                processing_information,
                                payment_information,
                                order_information,
                                client_reference_information,
                                merchant_defined_information,
                                consumer_authentication_information: Some(
                                    CybersourceConsumerAuthInformation {
                                        pares_status: None,
                                        ucaf_collection_indicator,
                                        cavv: None,
                                        ucaf_authentication_data: None,
                                        xid: None,
                                        directory_server_transaction_id: None,
                                        specification_version: None,
                                        pa_specification_version: None,
                                        veres_enrolled: None,
                                        eci_raw: None,
                                        authentication_date: None,
                                        effective_authentication_type: None,
                                        challenge_code: None,
                                        signed_pares_status_reason: None,
                                        challenge_cancel_code: None,
                                        network_score: None,
                                        acs_transaction_id: None,
                                        cavv_algorithm: None,
                                    },
                                ),
                            })
                        }
                    }
                }
                WalletData::GooglePay(google_pay_data) => {
                    match item
                        .router_data
                        .resource_common_data
                        .payment_method_token
                        .clone()
                    {
                        Some(payment_method_token) => match payment_method_token {
                            PaymentMethodToken::GooglePayDecrypt(decrypt_data) => {
                                Self::try_from((&item, decrypt_data, google_pay_data))
                            }
                            PaymentMethodToken::Token(_) => Err(unimplemented_payment_method!(
                                "Apple Pay",
                                "Manual",
                                "Cybersource"
                            ))?,
                            PaymentMethodToken::PazeDecrypt(_) => {
                                Err(unimplemented_payment_method!("Paze", "Cybersource"))?
                            }
                            PaymentMethodToken::ApplePayDecrypt(_) => {
                                Err(unimplemented_payment_method!(
                                    "Apple Pay",
                                    "Simplified",
                                    "Cybersource"
                                ))?
                            }
                        },
                        None => Self::try_from((&item, google_pay_data)),
                    }
                }
                WalletData::SamsungPay(samsung_pay_data) => {
                    Self::try_from((&item, samsung_pay_data))
                }
                WalletData::Paze(_) => {
                    match item
                        .router_data
                        .resource_common_data
                        .payment_method_token
                        .clone()
                    {
                        Some(PaymentMethodToken::PazeDecrypt(paze_decrypted_data)) => {
                            Self::try_from((&item, paze_decrypted_data))
                        }
                        _ => Err(errors::ConnectorError::NotImplemented(
                            domain_types::utils::get_unimplemented_payment_method_error_message(
                                "Cybersource",
                            ),
                        )
                        .into()),
                    }
                }
                WalletData::AliPayQr(_)
                | WalletData::AliPayRedirect(_)
                | WalletData::AliPayHkRedirect(_)
                | WalletData::AmazonPayRedirect(_)
                | WalletData::BluecodeRedirect {}
                | WalletData::MomoRedirect(_)
                | WalletData::KakaoPayRedirect(_)
                | WalletData::GoPayRedirect(_)
                | WalletData::GcashRedirect(_)
                | WalletData::ApplePayRedirect(_)
                | WalletData::ApplePayThirdPartySdk(_)
                | WalletData::DanaRedirect {}
                | WalletData::GooglePayRedirect(_)
                | WalletData::GooglePayThirdPartySdk(_)
                | WalletData::MbWayRedirect(_)
                | WalletData::MobilePayRedirect(_)
                | WalletData::PaypalRedirect(_)
                | WalletData::PaypalSdk(_)
                | WalletData::TwintRedirect {}
                | WalletData::VippsRedirect {}
                | WalletData::TouchNGoRedirect(_)
                | WalletData::WeChatPayRedirect(_)
                | WalletData::WeChatPayQr(_)
                | WalletData::CashappQr(_)
                | WalletData::SwishQr(_)
                | WalletData::Mifinity(_)
                | WalletData::RevolutPay(_) => Err(errors::ConnectorError::NotImplemented(
                    domain_types::utils::get_unimplemented_payment_method_error_message(
                        "Cybersource",
                    ),
                )
                .into()),
            },
            PaymentMethodData::NetworkToken(token_data) => Self::try_from((&item, token_data)),
            PaymentMethodData::MandatePayment
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_) => Err(errors::ConnectorError::NotImplemented(
                domain_types::utils::get_unimplemented_payment_method_error_message("Cybersource"),
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
        CybersourceRouterData<
            RouterDataV2<
                domain_types::connector_flow::RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for CybersourceRepeatPaymentRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<
                domain_types::connector_flow::RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_merchant_config = CybersourceConnectorMetadataObject::try_from(
            &item.router_data.resource_common_data.connector_meta_data,
        )?;

        let (payment_instrument, authorization_options, commerce_indicator) = match &item
            .router_data
            .request
            .mandate_reference
        {
            MandateReferenceId::ConnectorMandateId(connector_mandate_data) => {
                let connector_mandate_id = connector_mandate_data
                    .get_connector_mandate_id()
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                    })?;

                let original_amount = item
                    .router_data
                    .request
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("original_payment_authorized_amount"))
                    .and_then(|val| val.parse::<i64>().ok());

                let original_currency = item
                    .router_data
                    .request
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("original_payment_authorized_currency"))
                    .and_then(|currency_str| common_enums::Currency::from_str(currency_str).ok());

                let original_authorized_amount = match original_amount.zip(original_currency) {
                    Some((original_amount, original_currency)) => {
                        Some(domain_types::utils::get_amount_as_string(
                            &common_enums::CurrencyUnit::Base,
                            original_amount,
                            original_currency,
                        )?)
                    }
                    None => None,
                };

                let payment_instrument = CybersoucrePaymentInstrument {
                    id: connector_mandate_id.into(),
                };

                let authorization_options = CybersourceAuthorizationOptions {
                    initiator: None,
                    merchant_initiated_transaction: Some(MerchantInitiatedTransaction {
                        reason: None,
                        original_authorized_amount,
                        previous_transaction_id: None,
                    }),
                    ignore_avs_result: connector_merchant_config.disable_avs,
                    ignore_cv_result: connector_merchant_config.disable_cvn,
                };

                (
                    payment_instrument,
                    Some(authorization_options),
                    "recurring".to_string(),
                )
            }
            MandateReferenceId::NetworkMandateId(network_transaction_id) => {
                let original_amount = item.router_data.request.minor_amount.get_amount_as_i64();
                let original_currency = item.router_data.request.currency;
                let original_authorized_amount = Some(
                    domain_types::utils::to_currency_base_unit_with_zero_decimal_check(
                        original_amount,
                        original_currency,
                    )?,
                );

                // For NetworkMandateId, we don't use payment_instrument, instead we use the network transaction id
                let payment_instrument = CybersoucrePaymentInstrument {
                    id: Secret::new("dummy".to_string()), // This won't be used for NetworkMandateId
                };

                let authorization_options = CybersourceAuthorizationOptions {
                    initiator: Some(CybersourcePaymentInitiator {
                        initiator_type: Some(CybersourcePaymentInitiatorTypes::Merchant),
                        credential_stored_on_file: None,
                        stored_credential_used: Some(true),
                    }),
                    merchant_initiated_transaction: Some(MerchantInitiatedTransaction {
                        reason: Some("7".to_string()),
                        original_authorized_amount,
                        previous_transaction_id: Some(Secret::new(network_transaction_id.clone())),
                    }),
                    ignore_avs_result: connector_merchant_config.disable_avs,
                    ignore_cv_result: connector_merchant_config.disable_cvn,
                };

                (
                    payment_instrument,
                    Some(authorization_options),
                    "recurring".to_string(),
                )
            }
            MandateReferenceId::NetworkTokenWithNTI(mandate_data) => {
                let original_amount = item.router_data.request.minor_amount.get_amount_as_i64();
                let original_currency = item.router_data.request.currency;
                let original_authorized_amount = Some(
                    domain_types::utils::to_currency_base_unit_with_zero_decimal_check(
                        original_amount,
                        original_currency,
                    )?,
                );

                // For NetworkTokenWithNTI, we don't use payment_instrument, instead we use the network transaction id
                let payment_instrument = CybersoucrePaymentInstrument {
                    id: Secret::new("dummy".to_string()), // This won't be used for NetworkTokenWithNTI
                };

                let authorization_options = CybersourceAuthorizationOptions {
                    initiator: Some(CybersourcePaymentInitiator {
                        initiator_type: Some(CybersourcePaymentInitiatorTypes::Merchant),
                        credential_stored_on_file: None,
                        stored_credential_used: Some(true),
                    }),
                    merchant_initiated_transaction: Some(MerchantInitiatedTransaction {
                        reason: Some("7".to_string()), // 7 is for MIT using NTI
                        original_authorized_amount,
                        previous_transaction_id: Some(Secret::new(
                            mandate_data.network_transaction_id.clone(),
                        )),
                    }),
                    ignore_avs_result: connector_merchant_config.disable_avs,
                    ignore_cv_result: connector_merchant_config.disable_cvn,
                };

                (
                    payment_instrument,
                    Some(authorization_options),
                    "recurring".to_string(),
                )
            }
        };

        // Create ProcessingInformation for repeat payments with proper merchant_initiated_transaction
        let processing_information = ProcessingInformation {
            capture: Some(matches!(
                item.router_data.request.capture_method,
                Some(common_enums::CaptureMethod::Automatic) | None
            )),
            payment_solution: None,
            action_list: None,
            action_token_types: None,
            authorization_options,
            capture_options: None,
            commerce_indicator,
        };

        let bill_to = item
            .router_data
            .resource_common_data
            .get_optional_billing_email()
            .or(item.router_data.request.email.clone())
            .and_then(|email| {
                build_bill_to(
                    item.router_data.resource_common_data.get_optional_billing(),
                    email,
                )
                .ok()
            });

        let total_amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount.to_owned(),
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let order_information = OrderInformationWithBill {
            amount_details: Amount {
                total_amount,
                currency: item.router_data.request.currency,
            },
            bill_to,
        };

        let payment_information =
            PaymentInformation::MandatePayment(Box::new(MandatePaymentInformation {
                payment_instrument,
                tokenized_card: MandatePaymentTokenizedCard {
                    transaction_type: TransactionType::StoredCredentials,
                },
            }));

        let client_reference_information = ClientReferenceInformation {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        };

        let merchant_defined_information =
            item.router_data
                .request
                .metadata
                .clone()
                .and_then(|metadata| {
                    serde_json::to_value(metadata)
                        .ok()
                        .map(convert_metadata_to_merchant_defined_info)
                });

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: None,
        })
    }
}

// TryFrom implementation for CybersourceRepeatPaymentRequest with connector_mandate_id
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<(
        &CybersourceRouterData<
            RouterDataV2<
                domain_types::connector_flow::RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData,
                PaymentsResponseData,
            >,
            T,
        >,
        String,
    )> for CybersourceRepeatPaymentRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, connector_mandate_id): (
            &CybersourceRouterData<
                RouterDataV2<
                    domain_types::connector_flow::RepeatPayment,
                    PaymentFlowData,
                    RepeatPaymentData,
                    PaymentsResponseData,
                >,
                T,
            >,
            String,
        ),
    ) -> Result<Self, Self::Error> {
        let processing_information = ProcessingInformation {
            capture: Some(matches!(
                item.router_data.request.capture_method,
                Some(common_enums::CaptureMethod::Automatic) | None
            )),
            payment_solution: None,
            action_list: None,
            action_token_types: None,
            authorization_options: Some(CybersourceAuthorizationOptions {
                initiator: Some(CybersourcePaymentInitiator {
                    initiator_type: Some(CybersourcePaymentInitiatorTypes::Merchant),
                    credential_stored_on_file: None,
                    stored_credential_used: Some(true),
                }),
                merchant_initiated_transaction: None,
                ignore_avs_result: None,
                ignore_cv_result: None,
            }),
            capture_options: None,
            commerce_indicator: "recurring".to_string(),
        };

        let payment_instrument = CybersoucrePaymentInstrument {
            id: connector_mandate_id.into(),
        };

        let bill_to = item
            .router_data
            .resource_common_data
            .get_optional_billing_email()
            .or(item.router_data.request.email.clone())
            .and_then(|email| {
                build_bill_to(
                    item.router_data.resource_common_data.get_optional_billing(),
                    email,
                )
                .ok()
            });

        let total_amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount.to_owned(),
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let order_information = OrderInformationWithBill {
            amount_details: Amount {
                total_amount,
                currency: item.router_data.request.currency,
            },
            bill_to,
        };

        let payment_information =
            PaymentInformation::MandatePayment(Box::new(MandatePaymentInformation {
                payment_instrument,
                tokenized_card: MandatePaymentTokenizedCard {
                    transaction_type: TransactionType::StoredCredentials,
                },
            }));

        let client_reference_information = ClientReferenceInformation {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        };

        let merchant_defined_information =
            item.router_data
                .request
                .metadata
                .clone()
                .and_then(|metadata| {
                    serde_json::to_value(metadata)
                        .ok()
                        .map(convert_metadata_to_merchant_defined_info)
                });

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: None,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceAuthSetupRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    payment_information: PaymentInformation<T>,
    client_reference_information: ClientReferenceInformation,
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
        CybersourceRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for CybersourceAuthSetupRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsPreAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method_data = item
            .router_data
            .request
            .payment_method_data
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            })?;

        match payment_method_data.clone() {
            PaymentMethodData::Card(ccard) => {
                let card_type = match ccard
                    .card_network
                    .clone()
                    .and_then(get_cybersource_card_type)
                {
                    Some(card_network) => Some(card_network.to_string()),
                    None => domain_types::utils::get_card_issuer(&get_card_number_string(
                        &ccard.card_number,
                    ))
                    .ok()
                    .map(card_issuer_to_string),
                };

                let payment_information =
                    PaymentInformation::Cards(Box::new(CardPaymentInformation {
                        card: Card {
                            number: ccard.card_number,
                            expiration_month: ccard.card_exp_month,
                            expiration_year: ccard.card_exp_year,
                            security_code: Some(ccard.card_cvc),
                            card_type,
                            type_selection_indicator: Some("1".to_owned()),
                        },
                    }));
                let client_reference_information = ClientReferenceInformation::from(&item);
                Ok(Self {
                    payment_information,
                    client_reference_information,
                })
            }
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Cybersource"),
                )
                .into())
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourcePaymentsCaptureRequest {
    processing_information: ProcessingInformation,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourcePaymentsIncrementalAuthorizationRequest {
    processing_information: ProcessingInformation,
    order_information: OrderInformationIncrementalAuthorization,
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
        CybersourceRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for CybersourcePaymentsCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_defined_information = item
            .router_data
            .request
            .connector_metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        let is_final = matches!(
            item.router_data.request.capture_method,
            Some(common_enums::CaptureMethod::Manual)
        )
        .then_some(true);
        let total_amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount_to_capture,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            processing_information: ProcessingInformation {
                capture_options: Some(CaptureOptions {
                    capture_sequence_number: 1,
                    total_capture_count: 1,
                    is_final,
                }),
                action_list: None,
                action_token_types: None,
                authorization_options: None,
                capture: None,
                commerce_indicator: String::from("internet"),
                payment_solution: None,
            },
            order_information: OrderInformationWithBill {
                amount_details: Amount {
                    total_amount,
                    currency: item.router_data.request.currency,
                },
                bill_to: None,
            },
            client_reference_information: ClientReferenceInformation {
                code: Some(
                    item.router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
            },
            merchant_defined_information,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceVoidRequest {
    client_reference_information: ClientReferenceInformation,
    reversal_information: ReversalInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
    // The connector documentation does not mention the merchantDefinedInformation field for Void requests. But this has been still added because it works!
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversalInformation {
    amount_details: Amount,
    reason: String,
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
        CybersourceRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for CybersourceVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        value: CybersourceRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_defined_information = value
            .router_data
            .resource_common_data
            .connector_meta_data
            .clone()
            .map(|secret_value: Secret<serde_json::Value>| {
                convert_metadata_to_merchant_defined_info(secret_value.expose())
            });
        let currency = value.router_data.request.currency.unwrap();
        let total_amount = value
            .connector
            .amount_converter
            .convert(value.router_data.request.amount.unwrap(), currency)
            .change_context(ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            client_reference_information: ClientReferenceInformation {
                code: Some(
                    value
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
            },
            reversal_information: ReversalInformation {
                amount_details: Amount {
                    total_amount,
                    currency,
                },
                reason: value
                    .router_data
                    .request
                    .cancellation_reason
                    .clone()
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "Cancellation Reason",
                    })?,
            },
            merchant_defined_information,
        })
    }
}

pub struct CybersourceAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) merchant_account: Secret<String>,
    pub(super) api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for CybersourceAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } = auth_type
        {
            Ok(Self {
                api_key: api_key.to_owned(),
                merchant_account: key1.to_owned(),
                api_secret: api_secret.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationStatus {
    Success,
    Failure,
    Processing,
    Unresolved,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CybersourcePaymentStatus {
    Authorized,
    Succeeded,
    Failed,
    Voided,
    Reversed,
    Pending,
    Declined,
    Rejected,
    Challenge,
    AuthorizedPendingReview,
    AuthorizedRiskDeclined,
    Transmitted,
    InvalidRequest,
    ServerError,
    PendingAuthentication,
    PendingReview,
    Accepted,
    Cancelled,
    StatusNotReceived,
    //PartialAuthorized, not being consumed yet.
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CybersourceIncrementalAuthorizationStatus {
    Authorized,
    Declined,
    AuthorizedPendingReview,
}

pub fn map_cybersource_attempt_status(
    status: CybersourcePaymentStatus,
    capture: bool,
) -> common_enums::AttemptStatus {
    match status {
        CybersourcePaymentStatus::Authorized => {
            if capture {
                // Because Cybersource will return Payment Status as Authorized even in AutoCapture Payment
                common_enums::AttemptStatus::Charged
            } else {
                common_enums::AttemptStatus::Authorized
            }
        }
        CybersourcePaymentStatus::Succeeded | CybersourcePaymentStatus::Transmitted => {
            common_enums::AttemptStatus::Charged
        }
        CybersourcePaymentStatus::Voided
        | CybersourcePaymentStatus::Reversed
        | CybersourcePaymentStatus::Cancelled => common_enums::AttemptStatus::Voided,
        CybersourcePaymentStatus::Failed
        | CybersourcePaymentStatus::Declined
        | CybersourcePaymentStatus::AuthorizedRiskDeclined
        | CybersourcePaymentStatus::Rejected
        | CybersourcePaymentStatus::InvalidRequest
        | CybersourcePaymentStatus::ServerError => common_enums::AttemptStatus::Failure,
        CybersourcePaymentStatus::PendingAuthentication => {
            common_enums::AttemptStatus::AuthenticationPending
        }
        CybersourcePaymentStatus::PendingReview
        | CybersourcePaymentStatus::StatusNotReceived
        | CybersourcePaymentStatus::Challenge
        | CybersourcePaymentStatus::Accepted
        | CybersourcePaymentStatus::Pending
        | CybersourcePaymentStatus::AuthorizedPendingReview => common_enums::AttemptStatus::Pending,
    }
}
impl From<CybersourceIncrementalAuthorizationStatus> for AuthorizationStatus {
    fn from(item: CybersourceIncrementalAuthorizationStatus) -> Self {
        match item {
            CybersourceIncrementalAuthorizationStatus::Authorized => Self::Success,
            CybersourceIncrementalAuthorizationStatus::AuthorizedPendingReview => Self::Processing,
            CybersourceIncrementalAuthorizationStatus::Declined => Self::Failure,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourcePaymentsResponse {
    id: String,
    status: Option<CybersourcePaymentStatus>,
    client_reference_information: Option<ClientReferenceInformation>,
    processor_information: Option<ClientProcessorInformation>,
    risk_information: Option<ClientRiskInformation>,
    token_information: Option<CybersourceTokenInformation>,
    error_information: Option<CybersourceErrorInformation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceErrorInformationResponse {
    id: String,
    error_information: CybersourceErrorInformation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceConsumerAuthInformationResponse {
    access_token: String,
    device_data_collection_url: String,
    reference_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAuthSetupInfoResponse {
    id: String,
    client_reference_information: ClientReferenceInformation,
    consumer_authentication_information: CybersourceConsumerAuthInformationResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CybersourceAuthSetupResponse {
    ClientAuthSetupInfo(Box<ClientAuthSetupInfoResponse>),
    ErrorInformation(Box<CybersourceErrorInformationResponse>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourcePaymentsIncrementalAuthorizationResponse {
    status: CybersourceIncrementalAuthorizationStatus,
    error_information: Option<CybersourceErrorInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientReferenceInformation {
    code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientProcessorInformation {
    network_transaction_id: Option<String>,
    avs: Option<Avs>,
    card_verification: Option<CardVerification>,
    merchant_advice: Option<MerchantAdvice>,
    response_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantAdvice {
    code: Option<String>,
    code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardVerification {
    result_code: Option<String>,
    result_code_raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Avs {
    code: Option<String>,
    code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRiskInformation {
    rules: Option<Vec<ClientRiskInformationRules>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientRiskInformationRules {
    name: Option<Secret<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceTokenInformation {
    payment_instrument: Option<CybersoucrePaymentInstrument>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CybersourceErrorInformation {
    reason: Option<String>,
    message: Option<String>,
    details: Option<Vec<Details>>,
}

fn get_error_response_if_failure(
    (info_response, status, http_code): (
        &CybersourcePaymentsResponse,
        common_enums::AttemptStatus,
        u16,
    ),
) -> Option<ErrorResponse> {
    if domain_types::utils::is_payment_failure(status) {
        Some(get_error_response(
            &info_response.error_information,
            &info_response.processor_information,
            &info_response.risk_information,
            Some(status),
            http_code,
            info_response.id.clone(),
        ))
    } else {
        None
    }
}

fn get_payment_response(
    (info_response, status, http_code): (
        &CybersourcePaymentsResponse,
        common_enums::AttemptStatus,
        u16,
    ),
) -> Result<PaymentsResponseData, Box<ErrorResponse>> {
    let error_response = get_error_response_if_failure((info_response, status, http_code));
    match error_response {
        Some(error) => Err(Box::new(error)),
        None => {
            let incremental_authorization_allowed =
                Some(status == common_enums::AttemptStatus::Authorized);
            let mandate_reference =
                info_response
                    .token_information
                    .clone()
                    .map(|token_info| MandateReference {
                        connector_mandate_id: token_info
                            .payment_instrument
                            .map(|payment_instrument| payment_instrument.id.expose()),
                        payment_method_id: None,
                    });

            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(info_response.id.clone()),
                redirection_data: None,
                mandate_reference: mandate_reference.map(Box::new),
                connector_metadata: None,
                network_txn_id: info_response.processor_information.as_ref().and_then(
                    |processor_information| processor_information.network_transaction_id.clone(),
                ),
                connector_response_reference_id: Some(
                    info_response
                        .client_reference_information
                        .clone()
                        .and_then(|client_reference_information| client_reference_information.code)
                        .unwrap_or(info_response.id.clone()),
                ),
                incremental_authorization_allowed,
                status_code: http_code,
            })
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
        ResponseRouterData<
            CybersourcePaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            CybersourcePaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = map_cybersource_attempt_status(
            item.response
                .status
                .clone()
                .unwrap_or(CybersourcePaymentStatus::StatusNotReceived),
            item.router_data.request.is_auto_capture()?,
        );
        let response =
            get_payment_response((&item.response, status, item.http_code)).map_err(|err| *err);
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

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<CybersourceAuthSetupResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourceAuthSetupResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            CybersourceAuthSetupResponse::ClientAuthSetupInfo(info_response) => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::AuthenticationPending,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::PreAuthenticateResponse {
                    resource_id: ResponseId::NoResponseId,
                    redirection_data: Some(Box::new(RedirectForm::CybersourceAuthSetup {
                        access_token: info_response
                            .consumer_authentication_information
                            .access_token,
                        ddc_url: info_response
                            .consumer_authentication_information
                            .device_data_collection_url,
                        reference_id: info_response
                            .consumer_authentication_information
                            .reference_id,
                    })),
                    connector_metadata: None,
                    connector_response_reference_id: Some(
                        info_response
                            .client_reference_information
                            .code
                            .unwrap_or(info_response.id.clone()),
                    ),
                    status_code: item.http_code,
                }),
                ..item.router_data
            }),
            CybersourceAuthSetupResponse::ErrorInformation(error_response) => {
                let detailed_error_info =
                    error_response
                        .error_information
                        .details
                        .to_owned()
                        .map(|details| {
                            details
                                .iter()
                                .map(|details| format!("{} : {}", details.field, details.reason))
                                .collect::<Vec<_>>()
                                .join(", ")
                        });

                let reason = get_error_reason(
                    error_response.error_information.message,
                    detailed_error_info,
                    None,
                );
                let error_message = error_response.error_information.reason;
                Ok(Self {
                    response: Err(ErrorResponse {
                        code: error_message.clone().unwrap_or(NO_ERROR_CODE.to_string()),
                        message: error_message.unwrap_or(NO_ERROR_MESSAGE.to_string()),
                        reason,
                        status_code: item.http_code,
                        attempt_status: None,
                        connector_transaction_id: Some(error_response.id.clone()),
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::AuthenticationFailed,
                        ..item.router_data.resource_common_data
                    },
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceConsumerAuthInformationRequest {
    return_url: String,
    reference_id: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceAuthEnrollmentRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    payment_information: PaymentInformation<T>,
    client_reference_information: ClientReferenceInformation,
    consumer_authentication_information: CybersourceConsumerAuthInformationRequest,
    order_information: OrderInformationWithBill,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CybersourceRedirectionAuthResponse {
    pub transaction_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceConsumerAuthInformationValidateRequest {
    authentication_transaction_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceAuthValidateRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    payment_information: PaymentInformation<T>,
    client_reference_information: ClientReferenceInformation,
    consumer_authentication_information: CybersourceConsumerAuthInformationValidateRequest,
    order_information: OrderInformation,
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
        CybersourceRouterData<
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for CybersourceAuthValidateRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsPostAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let client_reference_information = ClientReferenceInformation {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        };
        let payment_method_data = item.router_data.request.payment_method_data.clone().ok_or(
            errors::ConnectorError::MissingConnectorRedirectionPayload {
                field_name: "payment_method_data",
            },
        )?;
        let payment_information = match payment_method_data {
            PaymentMethodData::Card(ccard) => {
                let card_type = match ccard
                    .card_network
                    .clone()
                    .and_then(get_cybersource_card_type)
                {
                    Some(card_network) => Some(card_network.to_string()),
                    None => domain_types::utils::get_card_issuer(&get_card_number_string(
                        &ccard.card_number,
                    ))
                    .ok()
                    .map(card_issuer_to_string),
                };

                Ok(PaymentInformation::Cards(Box::new(
                    CardPaymentInformation {
                        card: Card {
                            number: ccard.card_number,
                            expiration_month: ccard.card_exp_month,
                            expiration_year: ccard.card_exp_year,
                            security_code: Some(ccard.card_cvc),
                            card_type,
                            type_selection_indicator: Some("1".to_owned()),
                        },
                    },
                )))
            }
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Cybersource"),
                ))
            }
        }?;

        let redirect_response = item.router_data.request.redirect_response.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "redirect_response",
            },
        )?;
        let total_amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency.unwrap(),
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let amount_details = Amount {
            total_amount,
            currency: item.router_data.request.currency.ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                },
            )?,
        };

        let transaction_id = redirect_response
            .params
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "params.transaction_id",
            })?
            .expose();
        let order_information = OrderInformation { amount_details };

        Ok(Self {
            payment_information,
            client_reference_information,
            consumer_authentication_information:
                CybersourceConsumerAuthInformationValidateRequest {
                    authentication_transaction_id: transaction_id,
                },
            order_information,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CybersourceAuthenticateResponse {
    ClientAuthCheckInfo(Box<ClientAuthCheckInfoResponse>),
    ErrorInformation(Box<CybersourceErrorInformationResponse>),
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<CybersourceAuthenticateResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourceAuthenticateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            CybersourceAuthenticateResponse::ClientAuthCheckInfo(info_response) => {
                let status = common_enums::AttemptStatus::from(info_response.status);
                let risk_info: Option<ClientRiskInformation> = None;
                if domain_types::utils::is_payment_failure(status) {
                    let response = Err(get_error_response(
                        &info_response.error_information,
                        &None,
                        &risk_info,
                        Some(status),
                        item.http_code,
                        info_response.id.clone(),
                    ));

                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response,
                        ..item.router_data
                    })
                } else {
                    let connector_response_reference_id = Some(
                        info_response
                            .client_reference_information
                            .code
                            .unwrap_or(info_response.id.clone()),
                    );

                    let redirection_data = match (
                        info_response
                            .consumer_authentication_information
                            .access_token,
                        info_response
                            .consumer_authentication_information
                            .step_up_url,
                    ) {
                        (Some(token), Some(step_up_url)) => {
                            Some(RedirectForm::CybersourceConsumerAuth {
                                access_token: token.expose(),
                                step_up_url,
                            })
                        }
                        _ => None,
                    };
                    let three_ds_data = serde_json::to_value(
                        info_response
                            .consumer_authentication_information
                            .validate_response,
                    )
                    .change_context(errors::ConnectorError::ResponseHandlingFailed)?;

                    let resource_id = info_response
                        .consumer_authentication_information
                        .authentication_transaction_id
                        .map(ResponseId::ConnectorTransactionId)
                        .unwrap_or(ResponseId::NoResponseId);

                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response: Ok(PaymentsResponseData::AuthenticateResponse {
                            resource_id,
                            redirection_data: redirection_data.map(Box::new),
                            connector_metadata: Some(serde_json::json!({
                                "three_ds_data": three_ds_data
                            })),
                            connector_response_reference_id,
                            status_code: item.http_code,
                        }),
                        ..item.router_data
                    })
                }
            }
            CybersourceAuthenticateResponse::ErrorInformation(error_response) => {
                let detailed_error_info =
                    error_response
                        .error_information
                        .details
                        .to_owned()
                        .map(|details| {
                            details
                                .iter()
                                .map(|details| format!("{} : {}", details.field, details.reason))
                                .collect::<Vec<_>>()
                                .join(", ")
                        });

                let reason = get_error_reason(
                    error_response.error_information.message,
                    detailed_error_info,
                    None,
                );
                let error_message = error_response.error_information.reason.to_owned();
                let response = Err(ErrorResponse {
                    code: error_message.clone().unwrap_or(NO_ERROR_CODE.to_string()),
                    message: error_message.unwrap_or(NO_ERROR_MESSAGE.to_string()),
                    reason,
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: Some(error_response.id.clone()),
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                });
                Ok(Self {
                    response,
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::AuthenticationFailed,
                        ..item.router_data.resource_common_data
                    },
                    ..item.router_data
                })
            }
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
        CybersourceRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for CybersourceAuthEnrollmentRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthenticateData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let client_reference_information = ClientReferenceInformation {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        };
        let payment_method_data = item.router_data.request.payment_method_data.clone().ok_or(
            errors::ConnectorError::MissingConnectorRedirectionPayload {
                field_name: "payment_method_data",
            },
        )?;
        let payment_information = match payment_method_data {
            PaymentMethodData::Card(ccard) => {
                let card_type = match ccard
                    .card_network
                    .clone()
                    .and_then(get_cybersource_card_type)
                {
                    Some(card_network) => Some(card_network.to_string()),
                    None => domain_types::utils::get_card_issuer(&get_card_number_string(
                        &ccard.card_number,
                    ))
                    .ok()
                    .map(card_issuer_to_string),
                };

                Ok(PaymentInformation::Cards(Box::new(
                    CardPaymentInformation {
                        card: Card {
                            number: ccard.card_number,
                            expiration_month: ccard.card_exp_month,
                            expiration_year: ccard.card_exp_year,
                            security_code: Some(ccard.card_cvc),
                            card_type,
                            type_selection_indicator: Some("1".to_owned()),
                        },
                    },
                )))
            }
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Cybersource"),
                ))
            }
        }?;

        let redirect_response = item.router_data.request.redirect_response.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "redirect_response",
            },
        )?;
        let total_amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency.unwrap(),
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let amount_details = Amount {
            total_amount,
            currency: item.router_data.request.currency.ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "currency",
                },
            )?,
        };

        let param = redirect_response.params.ok_or(
            errors::ConnectorError::MissingConnectorRedirectionPayload {
                field_name: "request.redirect_response.params",
            },
        )?;

        let reference_id = param
            .clone()
            .peek()
            .split('=')
            .next_back()
            .ok_or(errors::ConnectorError::MissingConnectorRedirectionPayload {
                field_name: "request.redirect_response.params.reference_id",
            })?
            .to_string();
        let email = item
            .router_data
            .resource_common_data
            .get_billing_email()
            .or(item
                .router_data
                .request
                .email
                .clone()
                .ok_or_else(utils::missing_field_err("email")))?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill {
            amount_details,
            bill_to: Some(bill_to),
        };

        Ok(Self {
            payment_information,
            client_reference_information,
            consumer_authentication_information: CybersourceConsumerAuthInformationRequest {
                return_url: item
                    .router_data
                    .request
                    .continue_redirection_url
                    .clone()
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "continue_redirection_url",
                    })?
                    .to_string(),
                reference_id,
            },
            order_information,
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
    > TryFrom<ResponseRouterData<CybersourceAuthenticateResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourceAuthenticateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            CybersourceAuthenticateResponse::ClientAuthCheckInfo(info_response) => {
                let status = common_enums::AttemptStatus::from(info_response.status);
                let risk_info: Option<ClientRiskInformation> = None;
                if domain_types::utils::is_payment_failure(status) {
                    let response = Err(get_error_response(
                        &info_response.error_information,
                        &None,
                        &risk_info,
                        Some(status),
                        item.http_code,
                        info_response.id.clone(),
                    ));

                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response,
                        ..item.router_data
                    })
                } else {
                    let connector_response_reference_id = Some(
                        info_response
                            .client_reference_information
                            .code
                            .unwrap_or(info_response.id.clone()),
                    );

                    let redirection_data = match (
                        info_response
                            .consumer_authentication_information
                            .access_token,
                        info_response
                            .consumer_authentication_information
                            .step_up_url,
                    ) {
                        (Some(token), Some(step_up_url)) => {
                            Some(RedirectForm::CybersourceConsumerAuth {
                                access_token: token.expose(),
                                step_up_url,
                            })
                        }
                        _ => None,
                    };
                    let three_ds_data = serde_json::to_value(
                        info_response
                            .consumer_authentication_information
                            .validate_response,
                    )
                    .change_context(errors::ConnectorError::ResponseHandlingFailed)?;
                    let resource_id = info_response
                        .consumer_authentication_information
                        .authentication_transaction_id
                        .map(ResponseId::ConnectorTransactionId)
                        .unwrap_or(ResponseId::NoResponseId);

                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response: Ok(PaymentsResponseData::PostAuthenticateResponse {
                            resource_id,
                            redirection_data: redirection_data.map(Box::new),
                            connector_metadata: Some(serde_json::json!({
                                "three_ds_data": three_ds_data
                            })),
                            connector_response_reference_id,
                            status_code: item.http_code,
                        }),
                        ..item.router_data
                    })
                }
            }
            CybersourceAuthenticateResponse::ErrorInformation(error_response) => {
                let detailed_error_info =
                    error_response
                        .error_information
                        .details
                        .to_owned()
                        .map(|details| {
                            details
                                .iter()
                                .map(|details| format!("{} : {}", details.field, details.reason))
                                .collect::<Vec<_>>()
                                .join(", ")
                        });

                let reason = get_error_reason(
                    error_response.error_information.message,
                    detailed_error_info,
                    None,
                );
                let error_message = error_response.error_information.reason.to_owned();
                let response = Err(ErrorResponse {
                    code: error_message.clone().unwrap_or(NO_ERROR_CODE.to_string()),
                    message: error_message.unwrap_or(NO_ERROR_MESSAGE.to_string()),
                    reason,
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: Some(error_response.id.clone()),
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                });
                Ok(Self {
                    response,
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::AuthenticationFailed,
                        ..item.router_data.resource_common_data
                    },
                    ..item.router_data
                })
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CybersourceAuthEnrollmentStatus {
    PendingAuthentication,
    AuthenticationSuccessful,
    AuthenticationFailed,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceConsumerAuthValidateResponse {
    ucaf_collection_indicator: Option<String>,
    cavv: Option<Secret<String>>,
    ucaf_authentication_data: Option<Secret<String>>,
    xid: Option<String>,
    specification_version: Option<SemanticVersion>,
    directory_server_transaction_id: Option<Secret<String>>,
    indicator: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CybersourceThreeDSMetadata {
    three_ds_data: CybersourceConsumerAuthValidateResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceConsumerAuthInformationEnrollmentResponse {
    access_token: Option<Secret<String>>,
    step_up_url: Option<String>,
    authentication_transaction_id: Option<String>,
    //Added to segregate the three_ds_data in a separate struct
    #[serde(flatten)]
    validate_response: CybersourceConsumerAuthValidateResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAuthCheckInfoResponse {
    id: String,
    client_reference_information: ClientReferenceInformation,
    consumer_authentication_information: CybersourceConsumerAuthInformationEnrollmentResponse,
    status: CybersourceAuthEnrollmentStatus,
    error_information: Option<CybersourceErrorInformation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CybersourcePreProcessingResponse {
    ClientAuthCheckInfo(Box<ClientAuthCheckInfoResponse>),
    ErrorInformation(Box<CybersourceErrorInformationResponse>),
}

impl From<CybersourceAuthEnrollmentStatus> for common_enums::AttemptStatus {
    fn from(item: CybersourceAuthEnrollmentStatus) -> Self {
        match item {
            CybersourceAuthEnrollmentStatus::PendingAuthentication => Self::AuthenticationPending,
            CybersourceAuthEnrollmentStatus::AuthenticationSuccessful => {
                Self::AuthenticationSuccessful
            }
            CybersourceAuthEnrollmentStatus::AuthenticationFailed => Self::AuthenticationFailed,
        }
    }
}

impl From<&ClientProcessorInformation> for AdditionalPaymentMethodConnectorResponse {
    fn from(processor_information: &ClientProcessorInformation) -> Self {
        let payment_checks = Some(
            serde_json::json!({"avs_response": processor_information.avs, "card_verification": processor_information.card_verification}),
        );

        Self::Card {
            authentication_data: None,
            payment_checks,
            card_network: None,
            domestic_network: None,
        }
    }
}

impl<F> TryFrom<ResponseRouterData<CybersourcePaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourcePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_cybersource_attempt_status(
            item.response
                .status
                .clone()
                .unwrap_or(CybersourcePaymentStatus::StatusNotReceived),
            true,
        );
        let response =
            get_payment_response((&item.response, status, item.http_code)).map_err(|err| *err);
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

impl<F> TryFrom<ResponseRouterData<CybersourcePaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourcePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_cybersource_attempt_status(
            item.response
                .status
                .clone()
                .unwrap_or(CybersourcePaymentStatus::StatusNotReceived),
            false,
        );
        let response =
            get_payment_response((&item.response, status, item.http_code)).map_err(|err| *err);
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

impl<F> TryFrom<ResponseRouterData<CybersourcePaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourcePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_cybersource_attempt_status(
            item.response
                .status
                .clone()
                .unwrap_or(CybersourcePaymentStatus::StatusNotReceived),
            true,
        );
        let response =
            get_payment_response((&item.response, status, item.http_code)).map_err(|err| *err);
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

// zero dollar response
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<CybersourcePaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourcePaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let mandate_reference =
            item.response
                .token_information
                .clone()
                .map(|token_info| MandateReference {
                    connector_mandate_id: token_info
                        .payment_instrument
                        .map(|payment_instrument| payment_instrument.id.expose()),
                    payment_method_id: None,
                });
        let mut mandate_status = map_cybersource_attempt_status(
            item.response
                .status
                .clone()
                .unwrap_or(CybersourcePaymentStatus::StatusNotReceived),
            false,
        );
        if matches!(mandate_status, common_enums::AttemptStatus::Authorized) {
            //In case of zero auth mandates we want to make the payment reach the terminal status so we are converting the authorized status to charged as well.
            mandate_status = common_enums::AttemptStatus::Charged
        }
        let error_response =
            get_error_response_if_failure((&item.response, mandate_status, item.http_code));

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: mandate_status,
                ..item.router_data.resource_common_data
            },
            response: match error_response {
                Some(error) => Err(error),
                None => Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                    redirection_data: None,
                    mandate_reference: mandate_reference.map(Box::new),
                    connector_metadata: None,
                    network_txn_id: item.response.processor_information.as_ref().and_then(
                        |processor_information| {
                            processor_information.network_transaction_id.clone()
                        },
                    ),
                    connector_response_reference_id: Some(
                        item.response
                            .client_reference_information
                            .and_then(|client_reference_information| {
                                client_reference_information.code.clone()
                            })
                            .unwrap_or(item.response.id),
                    ),
                    incremental_authorization_allowed: Some(
                        mandate_status == common_enums::AttemptStatus::Authorized,
                    ),
                    status_code: item.http_code,
                }),
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceTransactionResponse {
    id: String,
    application_information: ApplicationInformation,
    processor_information: Option<ClientProcessorInformation>,
    client_reference_information: Option<ClientReferenceInformation>,
    error_information: Option<CybersourceErrorInformation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationInformation {
    status: Option<CybersourcePaymentStatus>,
}

impl<F> TryFrom<ResponseRouterData<CybersourceTransactionResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourceTransactionResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.application_information.status {
            Some(status) => {
                let status = map_cybersource_attempt_status(
                    status,
                    item.router_data.request.is_auto_capture()?,
                );
                let incremental_authorization_allowed =
                    Some(status == common_enums::AttemptStatus::Authorized);
                let risk_info: Option<ClientRiskInformation> = None;
                if domain_types::utils::is_payment_failure(status) {
                    Ok(Self {
                        response: Err(get_error_response(
                            &item.response.error_information,
                            &item.response.processor_information,
                            &risk_info,
                            Some(status),
                            item.http_code,
                            item.response.id.clone(),
                        )),
                        resource_common_data: PaymentFlowData {
                            status: common_enums::AttemptStatus::Failure,
                            ..item.router_data.resource_common_data
                        },
                        ..item.router_data
                    })
                } else {
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                item.response.id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: item
                                .response
                                .client_reference_information
                                .map(|cref| cref.code)
                                .unwrap_or(Some(item.response.id)),
                            incremental_authorization_allowed,
                            status_code: item.http_code,
                        }),
                        ..item.router_data
                    })
                }
            }
            None => Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: item.router_data.resource_common_data.status,
                    ..item.router_data.resource_common_data
                },
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(item.response.id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                ..item.router_data
            }),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceRefundRequest {
    order_information: OrderInformation,
    client_reference_information: ClientReferenceInformation,
}

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
        CybersourceRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for CybersourceRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: CybersourceRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let total_amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_payment_amount.to_owned(),
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            order_information: OrderInformation {
                amount_details: Amount {
                    total_amount,
                    currency: item.router_data.request.currency,
                },
            },
            client_reference_information: ClientReferenceInformation {
                code: Some(item.router_data.request.refund_id.clone()),
            },
        })
    }
}

impl From<CybersourceRefundStatus> for common_enums::RefundStatus {
    fn from(item: CybersourceRefundStatus) -> Self {
        match item {
            CybersourceRefundStatus::Succeeded | CybersourceRefundStatus::Transmitted => {
                Self::Success
            }
            CybersourceRefundStatus::Cancelled
            | CybersourceRefundStatus::Failed
            | CybersourceRefundStatus::Voided => Self::Failure,
            CybersourceRefundStatus::Pending => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CybersourceRefundStatus {
    Succeeded,
    Transmitted,
    Failed,
    Pending,
    Voided,
    Cancelled,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceRefundResponse {
    id: String,
    status: CybersourceRefundStatus,
    error_information: Option<CybersourceErrorInformation>,
}

impl<F> TryFrom<ResponseRouterData<CybersourceRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourceRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = common_enums::RefundStatus::from(item.response.status.clone());
        let response = if utils::is_refund_failure(refund_status) {
            Err(get_error_response(
                &item.response.error_information,
                &None,
                &None,
                None,
                item.http_code,
                item.response.id.clone(),
            ))
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: common_enums::RefundStatus::from(item.response.status),
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RsyncApplicationInformation {
    status: Option<CybersourceRefundStatus>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceRsyncResponse {
    id: String,
    application_information: Option<RsyncApplicationInformation>,
    error_information: Option<CybersourceErrorInformation>,
}

impl<F> TryFrom<ResponseRouterData<CybersourceRsyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CybersourceRsyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = match item
            .response
            .application_information
            .and_then(|application_information| application_information.status)
        {
            Some(status) => {
                let refund_status = common_enums::RefundStatus::from(status.clone());
                if utils::is_refund_failure(refund_status) {
                    if status == CybersourceRefundStatus::Voided {
                        Err(get_error_response(
                            &Some(CybersourceErrorInformation {
                                message: Some(REFUND_VOIDED.to_string()),
                                reason: Some(REFUND_VOIDED.to_string()),
                                details: None,
                            }),
                            &None,
                            &None,
                            None,
                            item.http_code,
                            item.response.id.clone(),
                        ))
                    } else {
                        Err(get_error_response(
                            &item.response.error_information,
                            &None,
                            &None,
                            None,
                            item.http_code,
                            item.response.id.clone(),
                        ))
                    }
                } else {
                    Ok(RefundsResponseData {
                        connector_refund_id: item.response.id,
                        refund_status,
                        status_code: item.http_code,
                    })
                }
            }

            None => Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status: match item.router_data.response {
                    Ok(response) => response.refund_status,
                    Err(_) => common_enums::RefundStatus::Pending,
                },
                status_code: item.http_code,
            }),
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceStandardErrorResponse {
    pub error_information: Option<ErrorInformation>,
    pub status: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
    pub details: Option<Vec<Details>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceNotAvailableErrorResponse {
    pub errors: Vec<CybersourceNotAvailableErrorObject>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceNotAvailableErrorObject {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CybersourceServerErrorResponse {
    pub status: Option<String>,
    pub message: Option<String>,
    pub reason: Option<Reason>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reason {
    SystemError,
    ServerTimeout,
    ServiceTimeout,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CybersourceAuthenticationErrorResponse {
    pub response: AuthenticationErrorInformation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CybersourceErrorResponse {
    AuthenticationError(Box<CybersourceAuthenticationErrorResponse>),
    //If the request resource is not available/exists in cybersource
    NotAvailableError(Box<CybersourceNotAvailableErrorResponse>),
    StandardError(Box<CybersourceStandardErrorResponse>),
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Details {
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ErrorInformation {
    pub message: String,
    pub reason: String,
    pub details: Option<Vec<Details>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct AuthenticationErrorInformation {
    pub rmsg: String,
}

pub fn get_error_response(
    error_data: &Option<CybersourceErrorInformation>,
    processor_information: &Option<ClientProcessorInformation>,
    risk_information: &Option<ClientRiskInformation>,
    attempt_status: Option<common_enums::AttemptStatus>,
    status_code: u16,
    transaction_id: String,
) -> ErrorResponse {
    let avs_message = risk_information
        .clone()
        .map(|client_risk_information| {
            client_risk_information.rules.map(|rules| {
                rules
                    .iter()
                    .map(|risk_info| {
                        risk_info.name.clone().map_or("".to_string(), |name| {
                            format!(" , {}", name.clone().expose())
                        })
                    })
                    .collect::<Vec<String>>()
                    .join("")
            })
        })
        .unwrap_or(Some("".to_string()));

    let detailed_error_info = error_data.as_ref().and_then(|error_data| {
        error_data.details.as_ref().map(|details| {
            details
                .iter()
                .map(|detail| format!("{} : {}", detail.field, detail.reason))
                .collect::<Vec<_>>()
                .join(", ")
        })
    });
    let network_decline_code = processor_information
        .as_ref()
        .and_then(|info| info.response_code.clone());
    let network_advice_code = processor_information.as_ref().and_then(|info| {
        info.merchant_advice
            .as_ref()
            .and_then(|merchant_advice| merchant_advice.code_raw.clone())
    });

    let reason = get_error_reason(
        error_data
            .as_ref()
            .and_then(|error_info| error_info.message.clone()),
        detailed_error_info,
        avs_message,
    );

    let error_message = error_data
        .as_ref()
        .and_then(|error_info| error_info.reason.clone());

    ErrorResponse {
        code: error_message
            .clone()
            .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
        message: error_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
        reason,
        status_code,
        attempt_status,
        connector_transaction_id: Some(transaction_id),
        network_advice_code,
        network_decline_code,
        network_error_message: None,
    }
}

pub fn get_error_reason(
    error_info: Option<String>,
    detailed_error_info: Option<String>,
    avs_error_info: Option<String>,
) -> Option<String> {
    match (error_info, detailed_error_info, avs_error_info) {
        (Some(message), Some(details), Some(avs_message)) => Some(format!(
            "{message}, detailed_error_information: {details}, avs_message: {avs_message}",
        )),
        (Some(message), Some(details), None) => {
            Some(format!("{message}, detailed_error_information: {details}"))
        }
        (Some(message), None, Some(avs_message)) => {
            Some(format!("{message}, avs_message: {avs_message}"))
        }
        (None, Some(details), Some(avs_message)) => {
            Some(format!("{details}, avs_message: {avs_message}"))
        }
        (Some(message), None, None) => Some(message),
        (None, Some(details), None) => Some(details),
        (None, None, Some(avs_message)) => Some(avs_message),
        (None, None, None) => None,
    }
}

fn get_cybersource_card_type(card_network: common_enums::CardNetwork) -> Option<&'static str> {
    match card_network {
        common_enums::CardNetwork::Visa => Some("001"),
        common_enums::CardNetwork::Mastercard => Some("002"),
        common_enums::CardNetwork::AmericanExpress => Some("003"),
        common_enums::CardNetwork::JCB => Some("007"),
        common_enums::CardNetwork::DinersClub => Some("005"),
        common_enums::CardNetwork::Discover => Some("004"),
        common_enums::CardNetwork::CartesBancaires => Some("036"),
        common_enums::CardNetwork::UnionPay => Some("062"),
        //"042" is the type code for Masetro Cards(International). For Maestro Cards(UK-Domestic) the mapping should be "024"
        common_enums::CardNetwork::Maestro => Some("042"),
        common_enums::CardNetwork::Interac
        | common_enums::CardNetwork::RuPay
        | common_enums::CardNetwork::Star
        | common_enums::CardNetwork::Accel
        | common_enums::CardNetwork::Pulse
        | common_enums::CardNetwork::Nyce => None,
    }
}

pub trait RemoveNewLine {
    fn remove_new_line(&self) -> Self;
}

impl RemoveNewLine for Option<Secret<String>> {
    fn remove_new_line(&self) -> Self {
        self.clone().map(|masked_value| {
            let new_string = masked_value.expose().replace("\n", " ");
            Secret::new(new_string)
        })
    }
}

impl RemoveNewLine for Option<String> {
    fn remove_new_line(&self) -> Self {
        self.clone().map(|value| value.replace("\n", " "))
    }
}
