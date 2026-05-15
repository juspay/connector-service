use std::fmt::Debug;

use common_enums::{AttemptStatus, CaptureMethod, CardNetwork, FutureUsage, PaymentChannel, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, CreateConnectorCustomer, PSync, RSync, Refund, SetupMandate, Void},
    connector_types::{
        ConnectorCustomerData, ConnectorCustomerResponse, MandateReference, MandateReferenceId,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId, SetupMandateRequestData,
    },
    errors::{ConnectorError, IntegrationError},
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::{
    requests::{
        TsysXmlAddCustomerCardDetails, TsysXmlAddCustomerRequest,
        TsysXmlAddCustomerWalletDetails, TsysXmlAuthorizationIndicator, TsysXmlAuthorizeBody,
        TsysXmlAuthorizeRequest, TsysXmlCaptureRequest, TsysXmlCardAuthenticationRequest,
        TsysXmlCardDataInputMode, TsysXmlCardDataOutputCapability, TsysXmlCardDataSource,
        TsysXmlCardOnFile, TsysXmlCardPresentDetail, TsysXmlCardholderAuthenticationEntity,
        TsysXmlCardholderAuthenticationMethod, TsysXmlCardholderPresentDetail, TsysXmlMaxPinLength,
        TsysXmlMit, TsysXmlMitIndicator, TsysXmlPersonalDetails, TsysXmlRegisteredUserIndicator,
        TsysXmlReturnRequest, TsysXmlTerminalAuthenticationCapability, TsysXmlTerminalCapability,
        TsysXmlTerminalCardCaptureCapability, TsysXmlTerminalOperatingEnvironment,
        TsysXmlTerminalOutputCapability, TsysXmlTransactionInquiryRequest, TsysXmlVoidRequest,
        TsysXmlWalletDetailsRef,
    },
    responses::{
        TsysXmlAddCustomerResponse, TsysXmlAuthorizeResponse, TsysXmlCaptureResponse,
        TsysXmlCardAuthenticationResponse, TsysXmlReturnResponse, TsysXmlStatus,
        TsysXmlTransactionInquiryResponse, TsysXmlTransactionState, TsysXmlVoidResponse,
    },
    TsysXmlRouterData,
};
use crate::types::ResponseRouterData;

// =============================================================================
// Connector metadata schema (parsed from `PaymentsAuthorizeData.metadata`)
// =============================================================================

/// Top-level wrapper — the merchant supplies `connector_metadata.tsys_xml.{...}`.
#[derive(Debug, Default, Deserialize)]
struct TsysXmlMerchantMetadata {
    #[serde(default)]
    tsys_xml: Option<TsysXmlMerchantMetadataInner>,
}

#[derive(Debug, Default, Deserialize)]
struct TsysXmlMerchantMetadataInner {
    #[serde(default)]
    acceptor: Option<TsysXmlAcceptorMetadata>,
    #[serde(default)]
    terminal_data: Option<TsysXmlTerminalDataOverrides>,
}

#[derive(Debug, Default, Deserialize)]
struct TsysXmlAcceptorMetadata {
    street_address: Option<String>,
    customer_service_phone: Option<String>,
    phone: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TsysXmlTerminalDataOverrides {
    terminal_capability: Option<TsysXmlTerminalCapability>,
    terminal_operating_environment: Option<TsysXmlTerminalOperatingEnvironment>,
    cardholder_authentication_method: Option<TsysXmlCardholderAuthenticationMethod>,
    terminal_authentication_capability: Option<TsysXmlTerminalAuthenticationCapability>,
    terminal_output_capability: Option<TsysXmlTerminalOutputCapability>,
    max_pin_length: Option<TsysXmlMaxPinLength>,
    terminal_card_capture_capability: Option<TsysXmlTerminalCardCaptureCapability>,
    cardholder_present_detail: Option<TsysXmlCardholderPresentDetail>,
    card_present_detail: Option<TsysXmlCardPresentDetail>,
    card_data_input_mode: Option<TsysXmlCardDataInputMode>,
    cardholder_authentication_entity: Option<TsysXmlCardholderAuthenticationEntity>,
    card_data_output_capability: Option<TsysXmlCardDataOutputCapability>,
}

/// Auth bundle for TsysXml (TransIT) — flattened into the XML request body.
///
/// TransIT does not use HTTP auth headers; instead each request carries the
/// `deviceID`, `transactionKey`, and `developerID` inline in the XML payload.
#[derive(Debug, Clone)]
pub struct TsysXmlAuthType {
    pub device_id: Secret<String>,
    pub transaction_key: Secret<String>,
    pub developer_id: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for TsysXmlAuthType {
    type Error = Report<IntegrationError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::TsysXml {
                device_id,
                transaction_key,
                developer_id,
                ..
            } => Ok(Self {
                device_id: device_id.to_owned(),
                transaction_key: transaction_key.to_owned(),
                developer_id: developer_id.to_owned(),
            }),
            _ => Err(IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            }
            .into()),
        }
    }
}

/// Minimal error envelope for TsysXml.
///
/// TransIT signals failure with `<status>FAIL</status>` and supplies a
/// `<responseCode>` / `<responseMessage>` pair. The exact element layout will be
/// hardened further per-flow; this scaffold provides only what
/// `build_error_response` needs.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TsysXmlErrorResponse {
    #[serde(rename = "status", default, alias = "Status")]
    pub status: Option<String>,
    #[serde(rename = "responseCode", default, alias = "ResponseCode")]
    pub response_code: Option<String>,
    #[serde(rename = "responseMessage", default, alias = "ResponseMessage")]
    pub response_message: Option<String>,
}

// =============================================================================
// AUTHORIZE — request transformer
// =============================================================================

fn format_expiration_date(card: &Card<impl PaymentMethodDataTypes>) -> Secret<String> {
    // TransIT documents `MM/YY` (tech spec § Sale/Auth Field Reference). Normalize
    // 4-digit years down to 2 digits.
    let month = card.card_exp_month.peek().clone();
    let year_full = card.card_exp_year.peek().clone();
    let year_short = if year_full.len() == 4 {
        year_full[2..].to_string()
    } else {
        year_full
    };
    Secret::new(format!("{}/{}", month, year_short))
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlAuthorizeRequest<T>
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        // Mandate-driven dispatch: when the upstream HS request supplies a
        // `connector_mandate_id` we recognize one of:
        //   - `cust:CCC:WWW`  → Path B (vault token MIT). Omit PAN/expiry/cvv2;
        //                       emit customerCode + walletDetails.
        //   - `ntid:XXX`      → Path A (network-token MIT). Keep PAN, emit
        //                       previousNetworkTransactionID + cardOnFile + mit.
        //   - everything else → fall through to CIT / one-shot logic (PAN-bearing).
        // We split on the FIRST ':' to find the prefix so that walletIDs / NTIDs
        // containing colons still round-trip correctly.
        let mandate_dispatch = decode_mandate_dispatch(
            router_data.request.mandate_id.as_ref(),
        );

        // CIT signal (no prior mandate but caller intends to store creds).
        let is_cit_setup = matches!(mandate_dispatch, MandateDispatch::None)
            && (router_data.request.setup_future_usage == Some(FutureUsage::OffSession)
                || router_data.request.off_session == Some(true));

        // Path B (vault) does NOT need card data — we emit customerCode + walletID
        // instead. Every other branch (Path A / CIT / one-shot) requires a Card.
        let card_opt = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => Some(card),
            _ => None,
        };
        let card = match (&mandate_dispatch, card_opt) {
            (MandateDispatch::Vault { .. }, _) => None,
            (_, Some(card)) => Some(card),
            (_, None) => {
                return Err(IntegrationError::NotSupported {
                    message: "Selected payment method".to_string(),
                    connector: "tsys_xml",
                    context: Default::default(),
                }
                .into());
            }
        };

        let transaction_amount = super::TsysXmlAmountConvertor::convert(
            router_data.request.minor_amount,
            router_data.request.currency,
        )?;

        // Billing address fields used by AVS (addressLine1 + zip). Both REQUIRED
        // by the e-commerce certification script.
        let billing = router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|b| b.address.as_ref());
        let address_line1 = billing.and_then(|a| a.line1.clone()).ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "billing.address.line1",
                context: Default::default(),
            })
        })?;
        let zip = billing.and_then(|a| a.zip.clone()).ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "billing.address.zip",
                context: Default::default(),
            })
        })?;

        // Channel-driven cardDataSource selection — replaces the previous
        // hardcoded Internet default.
        let channel = router_data.request.payment_channel.clone();
        let card_data_source = match channel {
            Some(PaymentChannel::TelephoneOrder) => TsysXmlCardDataSource::Phone,
            Some(PaymentChannel::MailOrder) => TsysXmlCardDataSource::Mail,
            Some(PaymentChannel::Ecommerce) | None => TsysXmlCardDataSource::Internet,
        };

        // Capture method drives MC/AMEX authorizationIndicator.
        let is_manual_capture = matches!(
            router_data.request.capture_method,
            Some(CaptureMethod::Manual) | Some(CaptureMethod::ManualMultiple)
        );

        // Card network drives several MC/AMEX/Discover-only fields. On Path B
        // (vault MIT) no card object is available — we skip the network-driven
        // optional fields entirely.
        let card_network = card.and_then(|c| c.card_network.clone());

        let authorization_indicator = match card_network {
            Some(CardNetwork::Mastercard) | Some(CardNetwork::AmericanExpress) => Some(
                if is_manual_capture {
                    TsysXmlAuthorizationIndicator::Preauth
                } else {
                    TsysXmlAuthorizationIndicator::Final
                },
            ),
            _ => None,
        };

        // Parse connector metadata once. Failure to deserialize surfaces as
        // InvalidDataFormat so merchants see a precise error.
        let merchant_metadata = match router_data.request.metadata.as_ref() {
            Some(meta) => serde_json::from_value::<TsysXmlMerchantMetadata>(
                meta.clone().expose(),
            )
            .change_context(IntegrationError::InvalidDataFormat {
                field_name: "connector_metadata.tsys_xml",
                context: Default::default(),
            })?,
            None => TsysXmlMerchantMetadata::default(),
        };
        let merchant_inner = merchant_metadata.tsys_xml.unwrap_or_default();
        let acceptor_meta = merchant_inner.acceptor;
        let terminal_overrides = merchant_inner.terminal_data.unwrap_or_default();

        // Acceptor fields — MC only, all four required together.
        let (
            acceptor_street_address,
            acceptor_customer_service_phone_number,
            acceptor_phone_number,
            acceptor_url_address,
        ) = if matches!(card_network, Some(CardNetwork::Mastercard)) {
            let a = acceptor_meta.ok_or_else(|| {
                error_stack::report!(IntegrationError::MissingRequiredField {
                    field_name:
                        "connector_metadata.tsys_xml.acceptor.* required for MasterCard",
                    context: Default::default(),
                })
            })?;
            match (a.street_address, a.customer_service_phone, a.phone, a.url) {
                (Some(s), Some(cs), Some(p), Some(u)) => {
                    (Some(s), Some(cs), Some(p), Some(u))
                }
                _ => {
                    return Err(IntegrationError::MissingRequiredField {
                        field_name:
                            "connector_metadata.tsys_xml.acceptor.* required for MasterCard",
                        context: Default::default(),
                    }
                    .into());
                }
            }
        } else {
            (None, None, None, None)
        };

        // registeredUserIndicator / lastRegisteredChangeDate — Discover/JCB/Diners/CUP only.
        let (registered_user_indicator, last_registered_change_date) = match card_network {
            Some(CardNetwork::Discover)
            | Some(CardNetwork::JCB)
            | Some(CardNetwork::DinersClub)
            | Some(CardNetwork::UnionPay) => (
                Some(TsysXmlRegisteredUserIndicator::No),
                Some("00/00/0000".to_string()),
            ),
            _ => (None, None),
        };

        // terminalData fields — flat in the XSD; defaults driven by payment_channel,
        // each field individually override-able via `connector_metadata.tsys_xml.terminal_data`.
        let terminal_capability = terminal_overrides
            .terminal_capability
            .unwrap_or(TsysXmlTerminalCapability::KeyedEntryOnly);
        let terminal_operating_environment = terminal_overrides
            .terminal_operating_environment
            .unwrap_or(TsysXmlTerminalOperatingEnvironment::NoTerminal);
        let cardholder_authentication_method = terminal_overrides
            .cardholder_authentication_method
            .unwrap_or(TsysXmlCardholderAuthenticationMethod::NotAuthenticated);
        let terminal_authentication_capability = terminal_overrides
            .terminal_authentication_capability
            .unwrap_or(TsysXmlTerminalAuthenticationCapability::NoCapability);
        let terminal_output_capability = terminal_overrides
            .terminal_output_capability
            .unwrap_or(TsysXmlTerminalOutputCapability::None);
        let max_pin_length = terminal_overrides
            .max_pin_length
            .unwrap_or(TsysXmlMaxPinLength::NotSupported);
        let terminal_card_capture_capability = terminal_overrides
            .terminal_card_capture_capability
            .unwrap_or(TsysXmlTerminalCardCaptureCapability::NoCapability);
        let cardholder_present_detail =
            terminal_overrides
                .cardholder_present_detail
                .unwrap_or_else(|| match channel {
                    Some(PaymentChannel::TelephoneOrder) => {
                        TsysXmlCardholderPresentDetail::CardholderNotPresentPhoneTransaction
                    }
                    Some(PaymentChannel::MailOrder) => {
                        TsysXmlCardholderPresentDetail::CardholderNotPresentMailTransaction
                    }
                    _ => TsysXmlCardholderPresentDetail::CardholderNotPresentElectronicCommerce,
                });
        let card_present_detail = terminal_overrides
            .card_present_detail
            .unwrap_or(TsysXmlCardPresentDetail::CardNotPresent);
        let card_data_input_mode =
            terminal_overrides
                .card_data_input_mode
                .unwrap_or_else(|| match channel {
                    Some(PaymentChannel::Ecommerce) | None => {
                        TsysXmlCardDataInputMode::PanEntryElectronicCommerceIncludingRemoteChip
                    }
                    _ => TsysXmlCardDataInputMode::KeyEnteredInput,
                });
        let cardholder_authentication_entity = terminal_overrides
            .cardholder_authentication_entity
            .unwrap_or(TsysXmlCardholderAuthenticationEntity::NotAuthenticated);
        let card_data_output_capability = terminal_overrides
            .card_data_output_capability
            .unwrap_or(TsysXmlCardDataOutputCapability::None);

        // Path-specific card-source fields: Path A / CIT / one-shot carry PAN;
        // Path B carries customerCode + walletDetails instead.
        let (
            card_number,
            expiration_date,
            cvv2_opt,
            customer_code_opt,
            wallet_details_opt,
        ) = match (&mandate_dispatch, card) {
            (MandateDispatch::Vault { customer_code, wallet_id }, _) => (
                None,
                None,
                None,
                Some(Secret::new(customer_code.clone())),
                Some(TsysXmlWalletDetailsRef {
                    wallet_id: Secret::new(wallet_id.clone()),
                }),
            ),
            (_, Some(card)) => {
                let cvv = if card.card_cvc.peek().is_empty() {
                    None
                } else {
                    Some(card.card_cvc.clone())
                };
                (
                    Some(Secret::new(card.card_number.peek().to_string())),
                    Some(format_expiration_date(card)),
                    cvv,
                    None,
                    None,
                )
            }
            // Unreachable — guarded above; fail closed if reached.
            (_, None) => {
                return Err(IntegrationError::NotSupported {
                    message: "Selected payment method".to_string(),
                    connector: "tsys_xml",
                    context: Default::default(),
                }
                .into());
            }
        };

        // cardOnFile + MIT + previousNetworkTransactionID — driven by dispatch.
        let (card_on_file, mit_block, previous_network_transaction_id) =
            match &mandate_dispatch {
                MandateDispatch::Ntid { ntid } => (
                    Some(TsysXmlCardOnFile::Y),
                    Some(TsysXmlMit {
                        // Default Recurring indicator for MIT — overridable via
                        // metadata in a follow-up TODO.
                        mit_indicator: TsysXmlMitIndicator::R,
                    }),
                    Some(ntid.clone()),
                ),
                MandateDispatch::Vault { .. } => (
                    Some(TsysXmlCardOnFile::Y),
                    Some(TsysXmlMit {
                        mit_indicator: TsysXmlMitIndicator::R,
                    }),
                    None,
                ),
                MandateDispatch::None if is_cit_setup => (
                    // CIT (storing the credential for future MIT) — flag cardOnFile=Y
                    // but no MIT indicator and no NTID.
                    Some(TsysXmlCardOnFile::Y),
                    None,
                    None,
                ),
                MandateDispatch::None => (None, None, None),
            };

        let body = TsysXmlAuthorizeBody {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            card_data_source,
            transaction_amount,
            card_number,
            expiration_date,
            // TransIT cert "Do Not Send" CVV scenario: emit no `<cvv2>` when empty
            // (cert script row 113 — AMEX with absent CVV is still approved).
            cvv2: cvv2_opt,
            customer_code: customer_code_opt,
            wallet_details: wallet_details_opt,
            address_line1,
            zip,
            external_reference_id: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            partial_auth_support: "YES".to_string(),
            terminal_capability,
            terminal_operating_environment,
            cardholder_authentication_method,
            terminal_authentication_capability,
            terminal_output_capability,
            max_pin_length,
            terminal_card_capture_capability,
            cardholder_present_detail,
            card_present_detail,
            card_data_input_mode,
            cardholder_authentication_entity,
            card_data_output_capability,
            developer_id: auth.developer_id,
            registered_user_indicator,
            last_registered_change_date,
            authorization_indicator,
            acceptor_street_address,
            acceptor_customer_service_phone_number,
            acceptor_phone_number,
            acceptor_url_address,
            card_on_file,
            previous_network_transaction_id,
            mit: mit_block,
            _marker: std::marker::PhantomData,
        };

        Ok(if is_manual_capture {
            Self::Auth(body)
        } else {
            Self::Sale(body)
        })
    }
}

// =============================================================================
// Mandate dispatch helper
// =============================================================================

/// Result of decoding an upstream `connector_mandate_id` ("cust:CCC:WWW" or
/// "ntid:XXX") into a Path A / Path B / fall-through directive.
#[derive(Debug, Clone)]
enum MandateDispatch {
    /// Path B — vault token MIT. Emit customerCode + walletDetails.
    Vault {
        customer_code: String,
        wallet_id: String,
    },
    /// Path A — network-token MIT. Emit cardOnFile + MIT + previousNetworkTransactionID.
    Ntid { ntid: String },
    /// No mandate id (or a mandate id we couldn't decode) — caller decides
    /// whether to treat the request as a CIT or a one-shot.
    None,
}

/// Decode `MandateIds.mandate_reference_id` into a `MandateDispatch`.
///
/// We look at the `ConnectorMandateId` variant first (this is where prior
/// CreateConnectorCustomer / SetupMandate responses encode the mandate id).
/// Falls back to `NetworkMandateId` so plain NTIDs surfaced by HS are still
/// treated as Path A.
fn decode_mandate_dispatch(
    mandate_id: Option<&domain_types::connector_types::MandateIds>,
) -> MandateDispatch {
    let Some(mandate_id) = mandate_id else {
        return MandateDispatch::None;
    };

    if let Some(MandateReferenceId::ConnectorMandateId(connector_mandate_ids)) =
        mandate_id.mandate_reference_id.as_ref()
    {
        if let Some(raw) = connector_mandate_ids.get_connector_mandate_id() {
            return decode_mandate_id_string(&raw);
        }
    }

    // NetworkMandateId — treat as a raw NTID (Path A) so HS-stored network
    // transaction ids still drive the MIT path.
    if let Some(MandateReferenceId::NetworkMandateId(ntid)) =
        mandate_id.mandate_reference_id.as_ref()
    {
        return MandateDispatch::Ntid { ntid: ntid.clone() };
    }

    MandateDispatch::None
}

/// Parse the prefix-encoded mandate id our CreateConnectorCustomer /
/// SetupMandate flows emit:
/// - `cust:<customerCode>:<walletID>` → Path B
/// - `ntid:<cardTransactionIdentifier>` → Path A
/// Anything else → `None` (fall through to CIT / one-shot decision).
fn decode_mandate_id_string(raw: &str) -> MandateDispatch {
    if let Some(rest) = raw.strip_prefix("cust:") {
        // splitn(2, ':') so wallet IDs containing additional colons survive.
        let mut parts = rest.splitn(2, ':');
        match (parts.next(), parts.next()) {
            (Some(customer_code), Some(wallet_id))
                if !customer_code.is_empty() && !wallet_id.is_empty() =>
            {
                return MandateDispatch::Vault {
                    customer_code: customer_code.to_string(),
                    wallet_id: wallet_id.to_string(),
                };
            }
            _ => {}
        }
    }
    if let Some(ntid) = raw.strip_prefix("ntid:") {
        if !ntid.is_empty() {
            return MandateDispatch::Ntid {
                ntid: ntid.to_string(),
            };
        }
    }
    MandateDispatch::None
}

// =============================================================================
// AUTHORIZE — response transformer
// =============================================================================

/// Successful response codes per tech spec § Status Mappings.
///
/// `A0000` = full approval, `A0002` = partial approval. Anything else combined
/// with `status=PASS` is treated as an unexpected success surface (fail closed)
/// to surface upstream.
fn map_authorize_status(
    response: &TsysXmlAuthorizeResponse,
) -> AttemptStatus {
    let body = response.body();
    match (
        body.status.as_ref(),
        body.response_code.as_deref(),
        response,
    ) {
        (Some(TsysXmlStatus::Pass), Some("A0000"), TsysXmlAuthorizeResponse::SaleResponse(_)) => {
            AttemptStatus::Charged
        }
        (Some(TsysXmlStatus::Pass), Some("A0000"), TsysXmlAuthorizeResponse::AuthResponse(_)) => {
            AttemptStatus::Authorized
        }
        (Some(TsysXmlStatus::Pass), Some("A0002"), _) => AttemptStatus::PartialCharged,
        (Some(TsysXmlStatus::Fail), _, _) => AttemptStatus::Failure,
        // Unknown / missing — fail closed.
        _ => AttemptStatus::Failure,
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TsysXmlAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;
        let body = response.body();

        let status = map_authorize_status(response);

        // Failure surface: surface code/message but keep transactionID if TransIT
        // gave us one (tech spec § Error Codes — decline envelopes still carry
        // <transactionID>).
        if matches!(status, AttemptStatus::Failure) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: body
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: body
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: body.response_message.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: body.transaction_id.clone(),
                    network_decline_code: body.host_response_code.clone(),
                    network_advice_code: None,
                    network_error_message: body.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path requires a transactionID — without one we cannot drive
        // subsequent Capture/Void/Refund flows, so reject as a deserialization
        // problem.
        let transaction_id = body.transaction_id.clone().ok_or_else(|| {
            crate::utils::response_deserialization_fail(
                item.http_code,
                "tsys_xml: success response missing <transactionID>; confirm API contract.",
            )
        })?;

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: body.auth_code.clone(),
            connector_response_reference_id: Some(transaction_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// PSYNC — request transformer
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlTransactionInquiryRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let transaction_id = router_data.request.get_connector_transaction_id()?;

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
        })
    }
}

// =============================================================================
// PSYNC — response transformer
// =============================================================================

/// Map TransIT PSync (`<status>` + `<transactionState>`) to `AttemptStatus`
/// per tech spec § Status Mappings.
fn map_sync_status(response: &TsysXmlTransactionInquiryResponse) -> AttemptStatus {
    match (response.status.as_ref(), response.transaction_state.as_ref()) {
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Authorized)) => {
            AttemptStatus::Authorized
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Captured)) => {
            AttemptStatus::Charged
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Settled)) => {
            AttemptStatus::Charged
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Voided)) => {
            AttemptStatus::Voided
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Returned)) => {
            AttemptStatus::AutoRefunded
        }
        (Some(TsysXmlStatus::Fail), _) => AttemptStatus::Failure,
        // Unknown / missing transactionState — keep Pending and log a warning
        // rather than panicking. UCS callers will retry the sync.
        _ => {
            tracing::warn!(
                "tsys_xml: PSync response missing or unrecognized transactionState; defaulting to Pending"
            );
            AttemptStatus::Pending
        }
    }
}

impl TryFrom<ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let status = map_sync_status(response);

        if matches!(status, AttemptStatus::Failure) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // For success / pending: prefer the response's transactionID when
        // present; otherwise fall back to what we asked about so the caller
        // never loses the reference.
        let connector_txn_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => router_data.request.get_connector_transaction_id().map_err(
                |_| {
                    crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: PSync response and request both missing transactionID.",
                    )
                },
            )?,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(connector_txn_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// CAPTURE — request transformer
// =============================================================================
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlCaptureRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        // The auth's <transactionID> drives the capture — it is required.
        let transaction_id = router_data.request.get_connector_transaction_id()?;

        let transaction_amount = super::TsysXmlAmountConvertor::convert(
            router_data.request.minor_amount_to_capture,
            router_data.request.currency,
        )?;

        // TODO(tsys_xml): wire seq_number / payment_count for multi-clearing
        // (split-shipment) via add-connector-flow. PR-1 ships single-capture only.
        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
            transaction_amount,
            seq_number: None,
            payment_count: None,
        })
    }
}

// =============================================================================
// CAPTURE — response transformer
// =============================================================================

/// Map TransIT Capture (`<status>` + `<responseCode>`) to `AttemptStatus` per
/// tech spec § Status Mappings.
///
/// - `PASS` + `A0000` → `Charged`
/// - `PASS` + `A0002` → `PartialCharged`
/// - `FAIL` (any code) → `CaptureFailed`
/// - Anything else → `CaptureFailed` (fail closed)
fn map_capture_status(response: &TsysXmlCaptureResponse) -> AttemptStatus {
    match (response.status.as_ref(), response.response_code.as_deref()) {
        (Some(TsysXmlStatus::Pass), Some("A0000")) => AttemptStatus::Charged,
        (Some(TsysXmlStatus::Pass), Some("A0002")) => AttemptStatus::PartialCharged,
        (Some(TsysXmlStatus::Fail), _) => AttemptStatus::CaptureFailed,
        _ => AttemptStatus::CaptureFailed,
    }
}

impl TryFrom<ResponseRouterData<TsysXmlCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let status = map_capture_status(response);

        if matches!(status, AttemptStatus::CaptureFailed) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: Some(AttemptStatus::CaptureFailed),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path: prefer response's transactionID; fall back to the auth
        // txn id we sent (TransIT's capture echoes the same id).
        let connector_txn_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => router_data.request.get_connector_transaction_id().map_err(
                |_| {
                    crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: Capture response missing <transactionID> and request had none.",
                    )
                },
            )?,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(connector_txn_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// REFUND — request transformer
// =============================================================================
//
// TransIT Return supports three modes from the same `<Return>` element shape:
//
//   1. Referenced full    — `transactionID` only (no `transactionAmount`).
//   2. Referenced partial — `transactionID` + `transactionAmount`.
//   3. Unreferenced       — NO `transactionID`; raw card data + `transactionAmount`.
//
// Mode selection happens here based on `RefundsData`:
//   * non-empty `connector_transaction_id` → referenced (we always emit
//     `transactionAmount` in PR-1; "omit for full" is a TODO follow-up so the
//     gateway recognises the partial vs. full distinction without us guessing
//     the original amount).
//   * empty `connector_transaction_id` → unreferenced; raw card data is
//     required. `RefundsData` does not surface `payment_method_data` today, so
//     this path returns `MissingRequiredField` until upstream wires card data
//     through for refunds.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for TsysXmlReturnRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let transaction_amount = super::TsysXmlAmountConvertor::convert(
            router_data.request.minor_refund_amount,
            router_data.request.currency,
        )?;

        let connector_transaction_id = router_data.request.connector_transaction_id.clone();

        if !connector_transaction_id.is_empty() {
            // Referenced mode (full or partial). PR-1 always emits
            // `transactionAmount` so the gateway sees the explicit value; a
            // follow-up TODO will compare `refund_amount` to the original
            // captured amount and omit `transactionAmount` for full refunds.
            Ok(Self {
                device_id: auth.device_id,
                transaction_key: auth.transaction_key,
                developer_id: auth.developer_id,
                transaction_id: Some(connector_transaction_id),
                card_data_source: None,
                card_number: None,
                expiration_date: None,
                cvv2: None,
                transaction_amount: Some(transaction_amount),
            })
        } else {
            // Unreferenced mode: full card data must be supplied. `RefundsData`
            // does not carry `payment_method_data` today, so PR-1 surfaces this
            // as a missing-field error rather than silently producing an
            // invalid request.
            Err(IntegrationError::MissingRequiredField {
                field_name: "payment_method_data for unreferenced refund",
                context: Default::default(),
            }
            .into())
        }
    }
}

// =============================================================================
// REFUND — response transformer
// =============================================================================

/// Map TransIT Return (`<status>` + `<responseCode>`) to `RefundStatus` per
/// tech spec § Status Mappings.
///
/// - `PASS` + `A0000` → `Success` — full referenced refund completed.
/// - `PASS` + `A0002` → `Success` — partial approval (refundedAmount in the
///   response reflects the actual amount processed).
/// - `PASS` + `A0014` → `Success` — Return requested against an unsettled
///   transaction; TSYS converts it to a pre-settlement Void. Effective refund
///   from the merchant's perspective. Verified live (`<ReturnResponse>` with
///   `responseMessage: "Return requested, Void successful"`).
/// - `FAIL` (any code) → `Failure`
/// - Anything else → `Failure` (fail closed)
fn map_refund_status(response: &TsysXmlReturnResponse) -> RefundStatus {
    match (response.status.as_ref(), response.response_code.as_deref()) {
        (Some(TsysXmlStatus::Pass), Some("A0000" | "A0002" | "A0014")) => RefundStatus::Success,
        (Some(TsysXmlStatus::Fail), _) => RefundStatus::Failure,
        _ => RefundStatus::Failure,
    }
}

impl TryFrom<ResponseRouterData<TsysXmlReturnResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlReturnResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let refund_status = map_refund_status(response);

        if matches!(refund_status, RefundStatus::Failure) {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: None,
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path: TransIT echoes the original capture's transactionID for
        // referenced returns; we treat that as the refund identifier for PR-1.
        // RSync will refine this once we know the on-wire id semantics.
        let connector_refund_id = response.transaction_id.clone().ok_or_else(|| {
            crate::utils::response_deserialization_fail(
                item.http_code,
                "tsys_xml: Return response missing <transactionID>; confirm API contract.",
            )
        })?;

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// RSYNC — request transformer (REUSES TsysXmlTransactionInquiryRequest)
// =============================================================================
//
// TransIT refunds are sync-final on `<ReturnResponse>`; there is no dedicated
// refund-status-poll endpoint. HS still dispatches RSync though, so we
// re-issue a `<TransactionInquiry>` against the original refund's
// `transactionID` (echoed back by TransIT as `connector_refund_id` in our
// Return response transformer). If upstream lacks a refund id we fall back to
// the original payment transactionID — both are valid keys for TransIT's
// inquiry endpoint.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for TsysXmlTransactionInquiryRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        // Prefer `connector_refund_id` (TransIT's echoed `<transactionID>` from
        // the original `<ReturnResponse>`); fall back to the original payment's
        // `connector_transaction_id` if the refund id wasn't recorded.
        let transaction_id = if !router_data.request.connector_refund_id.is_empty() {
            router_data.request.connector_refund_id.clone()
        } else if !router_data.request.connector_transaction_id.is_empty() {
            router_data.request.connector_transaction_id.clone()
        } else {
            return Err(IntegrationError::MissingRequiredField {
                field_name: "connector_refund_id or connector_transaction_id",
                context: Default::default(),
            }
            .into());
        };

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
        })
    }
}

// =============================================================================
// RSYNC — response transformer (REUSES TsysXmlTransactionInquiryResponse)
// =============================================================================

/// Map TransIT TransactionInquiry (`<status>` + `<transactionState>`) to
/// `RefundStatus` per tech spec § Status Mappings.
///
/// - `PASS` + `RETURNED` → `Success` (refund applied, awaiting batch settle)
/// - `PASS` + `SETTLED`  → `Success` (refund batch settled — terminal success)
/// - `PASS` + `VOIDED`   → `Failure` (the return itself was reversed; refund
///   didn't actually go through).
///   TODO(tsys_xml): VOIDED-on-RSync semantics depend on whether TransIT
///   distinguishes "return reversed before settle" vs "original auth voided";
///   confirm with TSYS whether `Failure` is the correct terminal mapping.
/// - `FAIL`              → `Failure`
/// - Unknown / missing   → `Pending` (do NOT fail; let HS poll again).
fn map_rsync_status(response: &TsysXmlTransactionInquiryResponse) -> RefundStatus {
    match (response.status.as_ref(), response.transaction_state.as_ref()) {
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Returned)) => {
            RefundStatus::Success
        }
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Settled)) => {
            RefundStatus::Success
        }
        // TODO(tsys_xml): confirm VOIDED semantics with TSYS — currently treated
        // as terminal Failure because a voided return means the refund didn't
        // settle to the cardholder.
        (Some(TsysXmlStatus::Pass), Some(TsysXmlTransactionState::Voided)) => {
            RefundStatus::Failure
        }
        (Some(TsysXmlStatus::Fail), _) => RefundStatus::Failure,
        // Unknown / missing transactionState (including Authorized/Captured
        // pre-return states) — stay Pending so HS keeps polling.
        _ => {
            tracing::warn!(
                "tsys_xml: RSync response missing or unrecognized transactionState; defaulting to Pending"
            );
            RefundStatus::Pending
        }
    }
}

impl TryFrom<ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlTransactionInquiryResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let refund_status = map_rsync_status(response);

        if matches!(refund_status, RefundStatus::Failure) {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: None,
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success / Pending: prefer the response's transactionID; fall back to
        // whichever id we sent so the caller never loses the reference.
        let connector_refund_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => {
                if !router_data.request.connector_refund_id.is_empty() {
                    router_data.request.connector_refund_id.clone()
                } else if !router_data.request.connector_transaction_id.is_empty() {
                    router_data.request.connector_transaction_id.clone()
                } else {
                    return Err(crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: RSync response and request both missing transactionID.",
                    )
                    .into());
                }
            }
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// VOID — request transformer
// =============================================================================
//
// TransIT `<Void>` accepts an optional `<transactionAmount>`:
//   * Omitted   → full void of the prior auth.
//   * Provided  → partial void (cert script Step 7) — the prior auth is reduced
//     by that amount.
//
// `PaymentVoidData` carries an `Option<MinorUnit>` `amount` field. When set
// alongside `currency`, we convert via the StringMajorUnit converter and emit
// it; otherwise we omit `<transactionAmount>` so TransIT treats this as a full
// void.
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for TsysXmlVoidRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let transaction_id = router_data.request.connector_transaction_id.clone();

        // Partial-void support: if both `amount` and `currency` are present on
        // PaymentVoidData, convert to a major-unit string and emit
        // `<transactionAmount>`; otherwise omit so TransIT performs a full
        // void.
        let transaction_amount = match (
            router_data.request.amount,
            router_data.request.currency,
        ) {
            (Some(amount), Some(currency)) => {
                Some(super::TsysXmlAmountConvertor::convert(amount, currency)?)
            }
            _ => None,
        };

        // Cert script Step 7: voidReason is required. Derive from
        // `cancellation_reason`, fall back to a sensible default, cap at 80
        // chars to stay within TSYS' field bounds.
        let void_reason = {
            let raw = router_data
                .request
                .cancellation_reason
                .clone()
                .unwrap_or_else(|| "POST_AUTH_USER_DECLINE".to_string());
            if raw.len() > 80 {
                raw.chars().take(80).collect()
            } else {
                raw
            }
        };

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            developer_id: auth.developer_id,
            transaction_id,
            transaction_amount,
            void_reason,
        })
    }
}

// =============================================================================
// VOID — response transformer
// =============================================================================

/// Map TransIT Void (`<status>` + `<responseCode>`) to `AttemptStatus` per
/// tech spec § Status Mappings.
///
/// - `PASS` + `A0000` → `Voided` (full void)
/// - `PASS` + `A0002` → `Voided` (partial void — the auth is reduced; at the
///   auth lifecycle level the state is still "voided" from UCS's perspective)
/// - `FAIL` (any code) → `VoidFailed`
/// - Anything else → `VoidFailed` (fail closed)
fn map_void_status(response: &TsysXmlVoidResponse) -> AttemptStatus {
    match (response.status.as_ref(), response.response_code.as_deref()) {
        (Some(TsysXmlStatus::Pass), Some("A0000")) => AttemptStatus::Voided,
        (Some(TsysXmlStatus::Pass), Some("A0002")) => AttemptStatus::Voided,
        (Some(TsysXmlStatus::Fail), _) => AttemptStatus::VoidFailed,
        _ => AttemptStatus::VoidFailed,
    }
}

impl TryFrom<ResponseRouterData<TsysXmlVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let status = map_void_status(response);

        if matches!(status, AttemptStatus::VoidFailed) {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: Some(AttemptStatus::VoidFailed),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success path: prefer response's transactionID; fall back to the auth
        // txn id we sent (TransIT echoes the same id).
        let connector_txn_id = match response.transaction_id.clone() {
            Some(id) => id,
            None => {
                let id = router_data.request.connector_transaction_id.clone();
                if id.is_empty() {
                    return Err(crate::utils::response_deserialization_fail(
                        item.http_code,
                        "tsys_xml: Void response missing <transactionID> and request had none.",
                    )
                    .into());
                }
                id
            }
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(connector_txn_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// CreateConnectorCustomer — request transformer (`<AddCustomer>`)
// =============================================================================
//
// Sources:
//   - first/last name: split `ConnectorCustomerData.name` on first whitespace.
//     No whitespace -> entire string goes to firstName, lastName defaults to
//     "-" (TSYS' XSD requires both fields).
//   - addressLine1 / zip: PaymentFlowData.address.billing_address.
//   - card data: `ConnectorCustomerData` does NOT carry payment_method_data in
//     this repo. PR-1 fails closed via `MissingRequiredField` so the live-test
//     phase identifies the right HS-side bridge before iterating.
//
// `expirationDate` in `<AddCustomer>` is MMYYYY (6 digits) — different from
// Sale/Auth's MMYY.

fn split_full_name(full: &str) -> (String, String) {
    let trimmed = full.trim();
    if trimmed.is_empty() {
        return ("-".to_string(), "-".to_string());
    }
    match trimmed.split_once(char::is_whitespace) {
        Some((first, rest)) => {
            let last = rest.trim();
            (
                first.to_string(),
                if last.is_empty() {
                    "-".to_string()
                } else {
                    last.to_string()
                },
            )
        }
        None => (trimmed.to_string(), "-".to_string()),
    }
}

#[allow(dead_code)]
fn format_add_customer_expiration(card: &Card<impl PaymentMethodDataTypes>) -> Secret<String> {
    // AddCustomer wants MMYYYY (6 digits). Normalize 2-digit years up to 4-digit
    // by prefixing "20" (TransIT only supports cards expiring this century).
    let month_raw = card.card_exp_month.peek().clone();
    let year_raw = card.card_exp_year.peek().clone();
    let month = if month_raw.len() == 1 {
        format!("0{month_raw}")
    } else {
        month_raw
    };
    let year_full = if year_raw.len() == 2 {
        format!("20{year_raw}")
    } else {
        year_raw
    };
    Secret::new(format!("{month}{year_full}"))
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<
                CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
            T,
        >,
    > for TsysXmlAddCustomerRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<
                CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        // Name — required by AddCustomer XSD. Split on the first whitespace; if
        // no whitespace at all, lastName defaults to "-".
        let name_secret = router_data.request.name.clone().ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "ConnectorCustomerData.name",
                context: Default::default(),
            })
        })?;
        let (first_name, last_name) = split_full_name(name_secret.peek().as_str());

        // Billing address — supplies addressLine1 + zip in both personalDetails
        // and walletDetails per the AddCustomer body shape.
        let billing = router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|b| b.address.as_ref());
        let address_line1 = billing.and_then(|a| a.line1.clone()).ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "billing.address.line1",
                context: Default::default(),
            })
        })?;
        let zip = billing.and_then(|a| a.zip.clone()).ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "billing.address.zip",
                context: Default::default(),
            })
        })?;

        // `ConnectorCustomerData` is non-generic and lacks `payment_method_data`
        // in this repo; we cannot populate the mandatory <walletDetails>
        // <cardDetails> block without it. Fail closed with the precise field
        // name so the live-test phase identifies the right HS-side bridge.
        let (card_number, expiration_date) = extract_add_customer_card::<T>(router_data)?;

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            personal_details: TsysXmlPersonalDetails {
                first_name: Secret::new(first_name),
                last_name: Secret::new(last_name),
                address_line1: address_line1.clone(),
                zip: zip.clone(),
            },
            wallet_details: TsysXmlAddCustomerWalletDetails {
                card_details: TsysXmlAddCustomerCardDetails {
                    card_number,
                    expiration_date,
                },
                address_line1,
                zip,
                payment_sequence: "1".to_string(),
            },
            developer_id: auth.developer_id,
        })
    }
}

/// Pull card data for `<AddCustomer>` from any HS-side surface we recognize.
///
/// `ConnectorCustomerData` does not carry `payment_method_data` in this repo
/// today, so we surface `MissingRequiredField` explicitly. The live-test phase
/// will identify the right HS-side bridge (likely a generic variant of
/// `ConnectorCustomerData` or a `connector_feature_data` payload).
fn extract_add_customer_card<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>(
    _router_data: &RouterDataV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    >,
) -> Result<(Secret<String>, Secret<String>), Report<IntegrationError>> {
    Err(IntegrationError::MissingRequiredField {
        field_name: "ConnectorCustomerData.payment_method_data (card)",
        context: Default::default(),
    }
    .into())
}

// =============================================================================
// CreateConnectorCustomer — response transformer
// =============================================================================

impl TryFrom<ResponseRouterData<TsysXmlAddCustomerResponse, Self>>
    for RouterDataV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    >
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlAddCustomerResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let is_success = matches!(response.status, Some(TsysXmlStatus::Pass))
            && response.response_code.as_deref() == Some("A0000");

        if !is_success {
            return Ok(Self {
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        let customer_code = response.customer_code.clone().ok_or_else(|| {
            crate::utils::response_deserialization_fail(
                item.http_code,
                "tsys_xml: AddCustomerResponse missing <customerCode>; confirm API contract.",
            )
        })?;
        let wallet_id = response
            .wallet_details
            .as_ref()
            .and_then(|w| w.wallet_id.clone())
            .ok_or_else(|| {
                crate::utils::response_deserialization_fail(
                    item.http_code,
                    "tsys_xml: AddCustomerResponse missing <walletDetails><walletID>; confirm API contract.",
                )
            })?;

        // Stash the Path B mandate id (`cust:CCC:WWW`) on
        // `PaymentFlowData.reference_id` so the next Authorize call can pick it
        // up. `ConnectorCustomerResponse` only carries `connector_customer_id`,
        // so we use the generic reference_id slot to surface walletID.
        let path_b_mandate_id = format!("cust:{customer_code}:{wallet_id}");

        Ok(Self {
            response: Ok(ConnectorCustomerResponse {
                connector_customer_id: customer_code,
            }),
            resource_common_data: PaymentFlowData {
                reference_id: Some(path_b_mandate_id),
                ..router_data.resource_common_data.clone()
            },
            ..router_data.clone()
        })
    }
}

// =============================================================================
// SetupMandate — request transformer (`<CardAuthentication>`, zero-dollar CIT)
// =============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        TsysXmlRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TsysXmlCardAuthenticationRequest
{
    type Error = Report<IntegrationError>;

    fn try_from(
        item: TsysXmlRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = TsysXmlAuthType::try_from(&router_data.connector_config)?;

        let card = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(IntegrationError::NotSupported {
                    message: "Selected payment method".to_string(),
                    connector: "tsys_xml",
                    context: Default::default(),
                }
                .into());
            }
        };

        let billing = router_data
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|b| b.address.as_ref());
        let address_line1 = billing.and_then(|a| a.line1.clone()).ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "billing.address.line1",
                context: Default::default(),
            })
        })?;
        let zip = billing.and_then(|a| a.zip.clone()).ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "billing.address.zip",
                context: Default::default(),
            })
        })?;

        let channel = router_data.request.payment_channel.clone();
        let card_data_source = match channel {
            Some(PaymentChannel::TelephoneOrder) => TsysXmlCardDataSource::Phone,
            Some(PaymentChannel::MailOrder) => TsysXmlCardDataSource::Mail,
            Some(PaymentChannel::Ecommerce) | None => TsysXmlCardDataSource::Internet,
        };

        // Reuse the Authorize metadata overrides so terminalData is consistent
        // across CIT verify and the subsequent MIT call.
        let merchant_metadata = match router_data.request.metadata.as_ref() {
            Some(meta) => serde_json::from_value::<TsysXmlMerchantMetadata>(meta.clone().expose())
                .change_context(IntegrationError::InvalidDataFormat {
                    field_name: "connector_metadata.tsys_xml",
                    context: Default::default(),
                })?,
            None => TsysXmlMerchantMetadata::default(),
        };
        let merchant_inner = merchant_metadata.tsys_xml.unwrap_or_default();
        let terminal_overrides = merchant_inner.terminal_data.unwrap_or_default();

        let terminal_capability = terminal_overrides
            .terminal_capability
            .unwrap_or(TsysXmlTerminalCapability::KeyedEntryOnly);
        let terminal_operating_environment = terminal_overrides
            .terminal_operating_environment
            .unwrap_or(TsysXmlTerminalOperatingEnvironment::NoTerminal);
        let cardholder_authentication_method = terminal_overrides
            .cardholder_authentication_method
            .unwrap_or(TsysXmlCardholderAuthenticationMethod::NotAuthenticated);
        let terminal_authentication_capability = terminal_overrides
            .terminal_authentication_capability
            .unwrap_or(TsysXmlTerminalAuthenticationCapability::NoCapability);
        let terminal_output_capability = terminal_overrides
            .terminal_output_capability
            .unwrap_or(TsysXmlTerminalOutputCapability::None);
        let max_pin_length = terminal_overrides
            .max_pin_length
            .unwrap_or(TsysXmlMaxPinLength::NotSupported);
        let terminal_card_capture_capability = terminal_overrides
            .terminal_card_capture_capability
            .unwrap_or(TsysXmlTerminalCardCaptureCapability::NoCapability);
        let cardholder_present_detail = terminal_overrides
            .cardholder_present_detail
            .unwrap_or_else(|| match channel {
                Some(PaymentChannel::TelephoneOrder) => {
                    TsysXmlCardholderPresentDetail::CardholderNotPresentPhoneTransaction
                }
                Some(PaymentChannel::MailOrder) => {
                    TsysXmlCardholderPresentDetail::CardholderNotPresentMailTransaction
                }
                _ => TsysXmlCardholderPresentDetail::CardholderNotPresentElectronicCommerce,
            });
        let card_present_detail = terminal_overrides
            .card_present_detail
            .unwrap_or(TsysXmlCardPresentDetail::CardNotPresent);
        let card_data_input_mode = terminal_overrides
            .card_data_input_mode
            .unwrap_or_else(|| match channel {
                Some(PaymentChannel::Ecommerce) | None => {
                    TsysXmlCardDataInputMode::PanEntryElectronicCommerceIncludingRemoteChip
                }
                _ => TsysXmlCardDataInputMode::KeyEnteredInput,
            });
        let cardholder_authentication_entity = terminal_overrides
            .cardholder_authentication_entity
            .unwrap_or(TsysXmlCardholderAuthenticationEntity::NotAuthenticated);
        let card_data_output_capability = terminal_overrides
            .card_data_output_capability
            .unwrap_or(TsysXmlCardDataOutputCapability::None);

        Ok(Self {
            device_id: auth.device_id,
            transaction_key: auth.transaction_key,
            card_data_source,
            card_number: Secret::new(card.card_number.peek().to_string()),
            expiration_date: format_expiration_date(card),
            address_line1,
            zip,
            external_reference_id: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            card_on_file: TsysXmlCardOnFile::Y,
            developer_id: auth.developer_id,
            terminal_capability,
            terminal_operating_environment,
            cardholder_authentication_method,
            terminal_authentication_capability,
            terminal_output_capability,
            max_pin_length,
            terminal_card_capture_capability,
            cardholder_present_detail,
            card_present_detail,
            card_data_input_mode,
            cardholder_authentication_entity,
            card_data_output_capability,
        })
    }
}

// =============================================================================
// SetupMandate — response transformer
// =============================================================================

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TsysXmlCardAuthenticationResponse, Self>>
    for RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    type Error = Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TsysXmlCardAuthenticationResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let response = &item.response;

        let is_success = matches!(response.status, Some(TsysXmlStatus::Pass))
            && response.response_code.as_deref() == Some("A0000");

        if !is_success {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .response_code
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_message
                        .clone()
                        .unwrap_or_else(|| common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: response.response_message.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: response.transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: response.response_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Prefer cardTransactionIdentifier (the actual NTID); fall back to
        // transactionID if the cert sandbox forgets to emit it.
        let ntid_source = response
            .card_transaction_identifier
            .clone()
            .or_else(|| response.transaction_id.clone())
            .ok_or_else(|| {
                crate::utils::response_deserialization_fail(
                    item.http_code,
                    "tsys_xml: CardAuthenticationResponse missing both <cardTransactionIdentifier> and <transactionID>; confirm API contract.",
                )
            })?;

        let path_a_mandate_id = format!("ntid:{ntid_source}");
        let mandate_reference = Box::new(MandateReference {
            connector_mandate_id: Some(path_a_mandate_id),
            payment_method_id: None,
            connector_mandate_request_reference_id: None,
        });

        let connector_txn_id = response
            .transaction_id
            .clone()
            .unwrap_or_else(|| ntid_source.clone());

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_txn_id.clone()),
            redirection_data: None,
            mandate_reference: Some(mandate_reference),
            connector_metadata: None,
            network_txn_id: response.auth_code.clone(),
            connector_response_reference_id: Some(connector_txn_id),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                // Card verified — Authorized is the closest non-charged status.
                status: AttemptStatus::Authorized,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}
