#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
use super::{transformers::*, Adyenplatform};
use common_enums::{CountryAlpha2, Currency, PayoutPriority, PayoutStatus};
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::PayoutTransfer,
    connector_types::*,
    payment_address::{Address, AddressDetails},
    payment_method_data::DefaultPCIHolder,
    payouts::{
        payout_method_data::{
            AchBankTransfer, Bank, CardPayout, PayoutMethodData, SepaBankTransfer,
        },
        payouts_types::*,
    },
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    types::{ConnectorParams, Connectors},
};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
    connector_types::IncomingWebhook,
};
use serde_json::{json, Value};
type Data = RouterDataV2<
    PayoutTransfer,
    PayoutFlowData,
    PayoutTransferRequest<DefaultPCIHolder>,
    PayoutTransferResponse,
>;
fn data() -> Data {
    Data {
        flow: Default::default(),
        connector_config: ConnectorSpecificConfig::Adyenplatform {
            api_key: "dummy-key".to_string().into(),
            source_balance_account: Some("BA-source".to_string().into()),
            base_url: None,
        },
        resource_common_data: PayoutFlowData {
            merchant_id: Default::default(),
            payout_id: "po_1".into(),
            connectors: Connectors {
                adyenplatform: ConnectorParams {
                    base_url: "https://balanceplatform-api-test.adyen.com/".into(),
                    ..Default::default()
                },
                ..Default::default()
            }
            .into(),
            connector_request_reference_id: "attempt-1".into(),
            raw_connector_response: None,
            typed_connector_response: None,
            connector_response_headers: None,
            raw_connector_request: None,
            typed_connector_request: None,
            access_token: None,
            test_mode: Some(true),
            description: Some("payout".into()),
            merchant_request_id: None,
            vault_headers: None,
        },
        request: PayoutTransferRequest {
            merchant_payout_id: Some("po_1".into()),
            connector_quote_id: None,
            connector_payout_id: None,
            amount: MinorUnit::new(1234),
            source_currency: Currency::EUR,
            destination_currency: Currency::EUR,
            priority: None,
            connector_payout_method_id: None,
            webhook_url: None,
            payout_method_data: Some(PayoutMethodData::Card(CardPayout {
                card_number: "4111111111111111".parse().unwrap(),
                expiry_month: "03".to_string().into(),
                expiry_year: "30".to_string().into(),
                card_holder_name: Some("Jane Mary Doe".to_string().into()),
                card_network: None,
            })),
            address: Some(PayoutAddress {
                shipping_address: None,
                billing_address: Some(Address {
                    email: Some("jane@example.com".parse().unwrap()),
                    address: Some(AddressDetails {
                        line1: Some("Main Street".to_string().into()),
                        line2: Some("10".to_string().into()),
                        city: Some("Amsterdam".to_string().into()),
                        country: Some(CountryAlpha2::NL),
                        first_name: Some(" Jane ".to_string().into()),
                        last_name: Some(" Doe ".to_string().into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            }),
            source_bank_data: None,
            customer: Some(PayoutCustomer {
                name: None,
                email: None,
                merchant_customer_id: None,
                connector_customer_id: Some("customer-1".into()),
                phone_number: None,
                phone_country_code: None,
            }),
            connector_eligibility_reference_id: None,
            payout_connector_metadata: None,
            billing_descriptor: None,
        },
        response: Err(ErrorResponse::default()),
    }
}
fn body(d: &Data) -> Value {
    serde_json::to_value(AdyenTransferRequest::try_from(d).unwrap()).unwrap()
}
#[test]
fn raw_card_matches_hyperswitch_payload() {
    assert_eq!(
        body(&data()),
        json!({"amount":{"currency":"EUR","value":1234},"balanceAccountId":"BA-source","category":"card","counterparty":{"card":{"cardHolder":{"address":{"line1":"Main Street","line2":"10","city":"Amsterdam","country":"NL"},"firstName":"Jane","lastName":"Mary Doe","fullName":null,"email":"jane@example.com","reference":"customer-1","type":"individual"},"cardIdentification":{"number":"4111111111111111","expiryMonth":"03","expiryYear":"2030","issueNumber":null,"startMonth":null,"startYear":null}}},"reference":"attempt-1","referenceForBeneficiary":"attempt-1","description":"payout"})
    );
}
#[test]
fn stored_card_precedes_raw_and_uses_billing_names() {
    let mut d = data();
    d.request.connector_payout_method_id = Some("stored-1".into());
    let b = body(&d);
    assert_eq!(
        b["counterparty"]["card"]["cardIdentification"],
        json!({"storedPaymentMethodId":"stored-1"})
    );
    assert_eq!(
        b["counterparty"]["card"]["cardHolder"]["fullName"],
        "Jane Doe"
    );
}
#[test]
fn stored_card_without_raw_data_and_name_fallback() {
    let mut d = data();
    d.request.connector_payout_method_id = Some("stored-1".into());
    d.request.payout_method_data = None;
    d.request
        .address
        .as_mut()
        .unwrap()
        .billing_address
        .as_mut()
        .unwrap()
        .address
        .as_mut()
        .unwrap()
        .last_name = None;
    d.request.payout_connector_metadata =
        Some(json!({"payout_type":"card","card_holder_name":"Jane Mary Doe"}).into());
    assert_eq!(
        body(&d)["counterparty"]["card"]["cardHolder"]["lastName"],
        "Mary Doe"
    );
    d.request.payout_connector_metadata = None;
    assert!(AdyenTransferRequest::try_from(&d).is_err());
}
#[test]
fn sepa_requires_priority_and_matches_payload() {
    let mut d = data();
    d.request.payout_method_data = Some(PayoutMethodData::Bank(Bank::Sepa(SepaBankTransfer {
        iban: "NL91ABNA0417164300".to_string().into(),
        ..Default::default()
    })));
    assert!(AdyenTransferRequest::try_from(&d).is_err());
    d.request.priority = Some(PayoutPriority::CrossBorder);
    let b = body(&d);
    assert_eq!(b["category"], "bank");
    assert_eq!(b["priority"], "crossBorder");
    assert_eq!(
        b["counterparty"]["bankAccount"]["accountIdentification"],
        json!({"type":"iban","iban":"NL91ABNA0417164300"})
    );
    let h = &b["counterparty"]["bankAccount"]["accountHolder"];
    assert_eq!(h["fullName"], " Jane   Doe ");
    assert!(h["firstName"].is_null());
}
#[test]
fn rejects_unsupported_bank_and_missing_required_data() {
    let mut d = data();
    d.request.payout_method_data = Some(PayoutMethodData::Bank(Bank::Ach(
        AchBankTransfer::default(),
    )));
    assert!(AdyenTransferRequest::try_from(&d).is_err());
    let mut d = data();
    d.request
        .address
        .as_mut()
        .unwrap()
        .billing_address
        .as_mut()
        .unwrap()
        .address
        .as_mut()
        .unwrap()
        .line2 = None;
    assert!(AdyenTransferRequest::try_from(&d).is_err());
    let mut d = data();
    d.request.customer = None;
    assert!(AdyenTransferRequest::try_from(&d).is_err());
}
#[test]
fn source_account_and_entity_metadata_adapters() {
    let mut d = data();
    d.connector_config = ConnectorSpecificConfig::Adyenplatform {
        api_key: "dummy".to_string().into(),
        source_balance_account: None,
        base_url: None,
    };
    assert!(AdyenTransferRequest::try_from(&d).is_err());
    for (entity, expected) in [
        ("Individual", "individual"),
        ("Personal", "individual"),
        ("NaturalPerson", "individual"),
        ("Company", "organization"),
        ("Business", "organization"),
        ("NonProfit", "unknown"),
        ("PublicSector", "unknown"),
    ] {
        d.request.payout_connector_metadata =
            Some(json!({"source_balance_account":"BA-meta","entity_type":entity}).into());
        let b = body(&d);
        assert_eq!(b["balanceAccountId"], "BA-meta");
        assert_eq!(b["counterparty"]["card"]["cardHolder"]["type"], expected);
    }
}
fn response(status: &str, reason: Option<&str>) -> AdyenTransferResponse {
    serde_json::from_value(json!({"id":"transfer-1","accountHolder":{"id":"AH1"},"amount":{"currency":"EUR","value":1234},"balanceAccount":{"id":"BA1"},"category":"card","direction":"outgoing","reference":"attempt-1","referenceForBeneficiary":"attempt-1","status":status,"type":"cardTransfer","reason":reason})).unwrap()
}
#[test]
fn all_transfer_statuses_match_hyperswitch() {
    for (s, expected) in [
        ("authorised", PayoutStatus::Initiated),
        ("booked", PayoutStatus::Initiated),
        ("pending", PayoutStatus::Pending),
        ("received", PayoutStatus::Pending),
        ("returned", PayoutStatus::Reversed),
    ] {
        assert_eq!(
            response(s, None)
                .into_result(Some("po_1".into()), 200)
                .unwrap()
                .payout_status,
            expected
        );
    }
    for s in ["refused", "error", "failed"] {
        let e = response(s, Some("declined"))
            .into_result(None, 200)
            .unwrap_err();
        assert_eq!(e.code, format!("{}{}", s[..1].to_uppercase(), &s[1..]));
        assert_eq!(e.message, "declined");
        assert_eq!(e.connector_transaction_id.as_deref(), Some("transfer-1"));
        assert_eq!(
            response(s, Some(""))
                .into_result(None, 200)
                .unwrap_err()
                .message,
            format!("{}{}", s[..1].to_uppercase(), &s[1..])
        );
    }
}
#[test]
fn endpoint_and_single_key_follow_adyen_documentation() {
    let connector = Adyenplatform::<DefaultPCIHolder>::new();
    let d = data();
    assert_eq!(
        connector.get_url(&d).unwrap(),
        "https://balanceplatform-api-test.adyen.com/btl/v4/transfers"
    );
    let headers = connector.get_auth_header(&d.connector_config).unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0, "X-API-Key");
    assert_eq!(headers[0].1.clone().into_inner(), "dummy-key");
}
fn webhook_request(kind: &str, status: &str, tracking: Option<&str>) -> RequestDetails {
    RequestDetails {method:HttpMethod::Post,uri:None,headers:Default::default(),query_params:None,body:serde_json::to_vec(&json!({"type":format!("balancePlatform.transfer.{kind}"),"data":{"reference":"attempt-1","status":status,"tracking":tracking.map(|s|json!({"status":s,"reason":"tracking reason"})),"reason":"data reason"}})).unwrap()}
}
#[test]
fn webhook_status_and_tracking_precedence_match_hyperswitch() {
    let c = Adyenplatform::<DefaultPCIHolder>::new();
    for (status, event) in [
        ("authorised", EventType::PayoutCreated),
        ("received", EventType::PayoutCreated),
        ("booked", EventType::PayoutProcessing),
        ("pending", EventType::PayoutProcessing),
        ("failed", EventType::PayoutFailure),
        ("returned", EventType::PayoutReversed),
    ] {
        assert_eq!(
            c.get_event_type(webhook_request("updated", status, None))
                .unwrap(),
            event
        );
        assert_eq!(
            c.get_event_type(webhook_request("created", status, Some("credited")))
                .unwrap(),
            EventType::PayoutCreated
        );
        for (tracking, event) in [
            ("accepted", EventType::PayoutSuccess),
            ("credited", EventType::PayoutSuccess),
            ("pending", EventType::PayoutProcessing),
        ] {
            assert_eq!(
                c.get_event_type(webhook_request("updated", status, Some(tracking)))
                    .unwrap(),
                event
            );
        }
    }
    let r = c
        .process_payout_webhook(webhook_request("updated", "failed", None), None, None)
        .unwrap();
    assert_eq!(r.merchant_payout_id.as_deref(), Some("attempt-1"));
    assert_eq!(r.error_message.as_deref(), Some("data reason"));
    assert!(r.connector_payout_id.is_none());
}
#[test]
fn webhook_hmac_accepts_valid_and_rejects_tampering() {
    use base64::Engine;
    let c = Adyenplatform::<DefaultPCIHolder>::new();
    let mut req = webhook_request("created", "received", None);
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-secret");
    let sig = ring::hmac::sign(&key, &req.body);
    req.headers.insert(
        "HmacSignature".into(),
        base64::engine::general_purpose::STANDARD.encode(sig.as_ref()),
    );
    let secret = Some(ConnectorWebhookSecrets {
        secret: hex::encode(b"test-secret").into_bytes(),
        additional_secret: None,
    });
    assert!(c
        .verify_webhook_source(req.clone(), secret.clone(), None)
        .unwrap());
    req.body.push(b' ');
    assert!(!c.verify_webhook_source(req, secret, None).unwrap());
}

#[test]
fn typed_configuration_and_registry_routes_to_adyenplatform() {
    use domain_types::utils::ForeignTryFrom;
    use grpc_api_types::payments::{
        connector_specific_config::Config, AdyenplatformConfig,
        ConnectorSpecificConfig as ProtoConfig,
    };
    let proto = Config::Adyenplatform(AdyenplatformConfig {
        api_key: Some("dummy-key".to_string().into()),
        source_balance_account: Some("BA-config".to_string().into()),
        base_url: Some("https://example.com/".into()),
    });
    assert_eq!(
        PayoutConnectorEnum::foreign_try_from(proto.clone()).unwrap(),
        PayoutConnectorEnum::Adyenplatform
    );
    let config = ConnectorSpecificConfig::foreign_try_from(ProtoConfig {
        config: Some(proto),
    })
    .unwrap();
    assert!(matches!(
        config,
        ConnectorSpecificConfig::Adyenplatform {
            source_balance_account: Some(_),
            ..
        }
    ));
    let payout = crate::types::PayoutConnectorData::<DefaultPCIHolder>::get_connector_by_name(
        &PayoutConnectorEnum::Adyenplatform,
    );
    assert_eq!(payout.connector.id(), "adyenplatform");
    let webhook = crate::types::ConnectorData::<DefaultPCIHolder>::get_connector_by_name(
        &ConnectorEnum::Adyenplatform,
    );
    assert_eq!(webhook.connector.id(), "adyenplatform");
}

#[test]
fn provider_error_details_match_hyperswitch() {
    let c = Adyenplatform::<DefaultPCIHolder>::new();
    let d = data();
    for (extra, message) in [
        (json!({}), "Invalid transfer"),
        (
            json!({"detail":"bad account"}),
            "Invalid transfer Detail: bad account",
        ),
        (
            json!({"detail":"bad account","invalidFields":[]}),
            "Invalid transfer Invalid fields: []",
        ),
    ] {
        let mut value = json!({"errorCode":"30_001","type":"validation","status":422,"title":"Invalid transfer","requestId":"provider-request"});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let r = domain_types::router_response_types::Response {
            status_code: 400,
            response: serde_json::to_vec(&value).unwrap().into(),
            headers: None,
        };
        let error = c
            .build_error_response(r, None, &d.connector_config)
            .unwrap();
        assert_eq!(error.code, "30_001");
        assert_eq!(error.message, message);
        assert_eq!(error.status_code, 400);
        assert!(error.connector_transaction_id.is_none());
    }
}

#[test]
fn unsupported_flows_do_not_generate_transfer_requests() {
    use domain_types::connector_flow::PayoutGet;
    let d = data();
    let req = RouterDataV2::<PayoutGet, _, _, PayoutGetResponse> {
        flow: Default::default(),
        resource_common_data: d.resource_common_data,
        connector_config: d.connector_config,
        request: PayoutGetRequest {
            merchant_payout_id: None,
            connector_payout_id: Some("transfer-1".into()),
            customer: None,
            source_bank_data: None,
            payout_method_type: None,
        },
        response: Err(ErrorResponse::default()),
    };
    assert!(Adyenplatform::<DefaultPCIHolder>::new()
        .get_url(&req)
        .is_err());
}

#[test]
fn macro_transfer_bridge_builds_request_and_maps_responses() {
    let c = crate::payout_connectors::AdyenplatformPayouts::<DefaultPCIHolder>::new();
    let d = data();
    assert!(c.get_request_body(&d).unwrap().is_some());
    for (status, expected) in [
        ("booked", PayoutStatus::Initiated),
        ("returned", PayoutStatus::Reversed),
    ] {
        let res = domain_types::router_response_types::Response {
            status_code: 200,
            headers: None,
            response: serde_json::to_vec(&response(status, None)).unwrap().into(),
        };
        let mapped = c.handle_response_v2(&d, None, res).unwrap();
        assert_eq!(mapped.response.unwrap().payout_status, expected);
        assert!(mapped
            .resource_common_data
            .typed_connector_response
            .is_some());
    }
    let res = domain_types::router_response_types::Response {
        status_code: 200,
        headers: None,
        response: serde_json::to_vec(&response("failed", Some("declined")))
            .unwrap()
            .into(),
    };
    let error = c
        .handle_response_v2(&d, None, res)
        .unwrap()
        .response
        .unwrap_err();
    assert_eq!(error.code, "Failed");
    assert_eq!(error.message, "declined");
}
