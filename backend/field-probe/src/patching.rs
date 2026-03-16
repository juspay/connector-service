// ── Probe patch functions ─────────────────────────────────────────────────────
//
// RULE: This file (together with patch-config.toml) is where connector-specific
// fields belong.  When a connector transformer returns a "Missing required
// field: X" error the probe engine calls the appropriate patch_*_request
// function here with the field name, and this function populates it with a
// suitable probe/dummy value.
//
// Do NOT pre-populate connector-specific fields in the base request builders
// (requests.rs).  Instead, add an alias + probe value here or in the
// corresponding [flow] section of patch-config.toml.
//
// If a connector returns `RequestEncodingFailed` (not a missing-field error)
// for a field it needs, that is a connector-side reporting issue — fix it there
// by returning `MissingRequiredField("field_name")` instead, which allows the
// probe to detect and patch the field automatically.
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::OnceLock;

use grpc_api_types::payments::{
    self as proto, payment_method::PaymentMethod as PmVariant,
    Address, BrowserInformation, Customer, PaymentAddress,
    PaymentServiceAuthorizeRequest, PaymentServiceCaptureRequest,
    PaymentServiceGetRequest, PaymentServiceRefundRequest,
    PaymentServiceSetupRecurringRequest, PaymentServiceVoidRequest,
    RecurringPaymentServiceChargeRequest,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    DisputeServiceAcceptRequest, DisputeServiceDefendRequest, DisputeServiceSubmitEvidenceRequest,
};
use hyperswitch_masking::Secret;

use crate::config::{get_patch_config, FlowFieldSpec, PatchAction, PatchParent, PatchValueType};
use crate::sample_data::*;
use crate::registry::mock_connector_state;

// ── ensure_* helpers: create parent on demand, return mutable ref ─────────────

pub(crate) fn ensure_billing_address(req: &mut PaymentServiceAuthorizeRequest) -> &mut Address {
    if req.address.is_none() {
        req.address = Some(PaymentAddress::default());
    }
    let addr = req.address.as_mut().unwrap();
    if addr.billing_address.is_none() {
        addr.billing_address = Some(Address::default());
    }
    addr.billing_address.as_mut().unwrap()
}

pub(crate) fn ensure_shipping_address(req: &mut PaymentServiceAuthorizeRequest) -> &mut Address {
    if req.address.is_none() {
        req.address = Some(PaymentAddress::default());
    }
    let addr = req.address.as_mut().unwrap();
    if addr.shipping_address.is_none() {
        addr.shipping_address = Some(Address::default());
    }
    addr.shipping_address.as_mut().unwrap()
}

pub(crate) fn ensure_browser_info(
    req: &mut PaymentServiceAuthorizeRequest,
) -> &mut BrowserInformation {
    if req.browser_info.is_none() {
        req.browser_info = Some(BrowserInformation::default());
    }
    req.browser_info.as_mut().unwrap()
}

pub(crate) fn ensure_customer(req: &mut PaymentServiceAuthorizeRequest) -> &mut Customer {
    if req.customer.is_none() {
        req.customer = Some(Customer::default());
    }
    req.customer.as_mut().unwrap()
}

// ── TOML-driven executor ──────────────────────────────────────────────────────

static AUTHORIZE_PATCH_MAP: OnceLock<HashMap<String, Vec<PatchAction>>> = OnceLock::new();

fn authorize_patch_map() -> &'static HashMap<String, Vec<PatchAction>> {
    AUTHORIZE_PATCH_MAP.get_or_init(|| {
        let cfg = get_patch_config();
        let mut map: HashMap<String, Vec<PatchAction>> = HashMap::new();

        // Grouped sections: parent is implicit from the section.
        let sections: &[(PatchParent, &HashMap<String, crate::config::FieldPatchSpec>)] = &[
            (PatchParent::BillingAddress,  &cfg.billing_address),
            (PatchParent::ShippingAddress, &cfg.shipping_address),
            (PatchParent::BrowserInfo,     &cfg.browser_info),
            (PatchParent::Customer,        &cfg.customer),
            (PatchParent::TopLevel,        &cfg.top_level),
        ];
        for (parent, specs) in sections {
            for (field, spec) in specs.iter() {
                let actions = vec![PatchAction {
                    parent: parent.clone(),
                    field: field.clone(),
                    value_type: spec.value_type.clone(),
                    value: spec.value.clone(),
                }];
                for alias in &spec.aliases {
                    map.insert(alias.clone(), actions.clone());
                }
            }
        }

        // Multi-field entries.
        for entry in &cfg.multi {
            for alias in &entry.aliases {
                map.insert(alias.clone(), entry.actions.clone());
            }
        }

        map
    })
}

/// Try to apply a TOML-defined patch. Returns true if the alias was found.
fn try_toml_patch(req: &mut PaymentServiceAuthorizeRequest, field_name: &str) -> bool {
    let Some(actions) = authorize_patch_map().get(field_name) else {
        return false;
    };
    for action in actions {
        apply_action(req, action);
    }
    true
}

fn apply_action(req: &mut PaymentServiceAuthorizeRequest, action: &PatchAction) {
    let value = action.value.as_deref().unwrap_or("");
    match action.parent {
        PatchParent::BillingAddress => {
            apply_address_field(ensure_billing_address(req), &action.field, &action.value_type, value);
        }
        PatchParent::ShippingAddress => {
            apply_address_field(ensure_shipping_address(req), &action.field, &action.value_type, value);
        }
        PatchParent::BrowserInfo => {
            apply_browser_info_field(ensure_browser_info(req), &action.field, &action.value_type, value);
        }
        PatchParent::Customer => {
            apply_customer_field(ensure_customer(req), &action.field, &action.value_type, value);
        }
        PatchParent::TopLevel => {
            apply_top_level_field(req, &action.field, &action.value_type, value);
        }
    }
}

fn apply_address_field(addr: &mut Address, field: &str, vtype: &PatchValueType, value: &str) {
    match field {
        "city"                => addr.city        = Some(Secret::new(value.to_string())),
        "zip_code"            => addr.zip_code    = Some(Secret::new(value.to_string())),
        "state"               => addr.state       = Some(Secret::new(value.to_string())),
        "line1"               => addr.line1       = Some(Secret::new(value.to_string())),
        "first_name"          => addr.first_name  = Some(Secret::new(value.to_string())),
        "last_name"           => addr.last_name   = Some(Secret::new(value.to_string())),
        "email"               => addr.email       = Some(Secret::new(value.to_string())),
        "phone_number"        => addr.phone_number = Some(Secret::new(value.to_string())),
        "phone_country_code"  => addr.phone_country_code = Some(value.to_string()),
        "country_alpha2_code" if *vtype == PatchValueType::CountryUs => {
            addr.country_alpha2_code = Some(proto::CountryAlpha2::Us as i32);
        }
        _ => {}
    }
}

fn apply_browser_info_field(bi: &mut BrowserInformation, field: &str, _vtype: &PatchValueType, value: &str) {
    match field {
        "accept_header"            => bi.accept_header = Some(value.to_string()),
        "user_agent"               => bi.user_agent    = Some(value.to_string()),
        "ip_address"               => bi.ip_address    = Some(value.to_string()),
        "language"                 => bi.language      = Some(value.to_string()),
        "java_script_enabled"      => bi.java_script_enabled = Some(value == "true"),
        "color_depth"              => bi.color_depth   = Some(value.parse().unwrap_or(24)),
        "screen_height"            => bi.screen_height = Some(value.parse().unwrap_or(900)),
        "screen_width"             => bi.screen_width  = Some(value.parse().unwrap_or(1440)),
        "time_zone_offset_minutes" => bi.time_zone_offset_minutes = Some(value.parse().unwrap_or(-480)),
        _ => {}
    }
}

fn apply_customer_field(c: &mut Customer, field: &str, _vtype: &PatchValueType, value: &str) {
    match field {
        "email"                  => c.email = Some(Secret::new(value.to_string())),
        "name"                   => c.name  = Some(value.to_string()),
        "connector_customer_id"  => c.connector_customer_id = Some(value.to_string()),
        "phone_number"           => c.phone_number = Some(value.to_string()),
        "phone_country_code"     => c.phone_country_code = Some(value.to_string()),
        _ => {}
    }
}

fn apply_top_level_field(
    req: &mut PaymentServiceAuthorizeRequest,
    field: &str,
    vtype: &PatchValueType,
    value: &str,
) {
    match field {
        "return_url"               => req.return_url = Some(value.to_string()),
        "webhook_url"              => req.webhook_url = Some(value.to_string()),
        "complete_authorize_url"   => req.complete_authorize_url = Some(value.to_string()),
        "merchant_order_id"        => req.merchant_order_id = Some(value.to_string()),
        "description"              => req.description = Some(value.to_string()),
        "statement_descriptor_name" => req.statement_descriptor_name = Some(value.to_string()),
        "payment_method_token"     => req.payment_method_token = Some(Secret::new(value.to_string())),
        "order_category"           => req.order_category = Some(value.to_string()),
        "setup_future_usage" if *vtype == PatchValueType::FutureUsageOffSession => {
            req.setup_future_usage = Some(proto::FutureUsage::OffSession as i32);
        }
        _ => {}
    }
}

// ── patch_authorize_request ───────────────────────────────────────────────────
//
// Patching philosophy:
//   1. Try the TOML-driven lookup first (covers all simple alias → field mappings).
//   2. Fall through to the Rust match only for cases that require logic:
//      parent-object fallbacks, type switches, multi-struct mutations that can't
//      be expressed as a flat (parent, field, value) triple.

pub(crate) fn patch_authorize_request(req: &mut PaymentServiceAuthorizeRequest, field_name: &str) {
    if try_toml_patch(req, field_name) {
        return;
    }

    match field_name {
        // ── simple scalars already handled in TOML for single-field cases ─────
        "amount" | "Amount" | "currency" => req.amount = Some(usd_money(1000)),
        "payment_method" => req.payment_method = Some(card_payment_method()),
        "capture_method" => req.capture_method = Some(proto::CaptureMethod::Automatic as i32),

        // ── billing_address: parent-object fallback ───────────────────────────
        "billing_address" | "billing.address" | "address" => {
            if let Some(ref mut addr) = req.address {
                addr.billing_address = Some(full_address());
            } else {
                req.address = Some(PaymentAddress {
                    billing_address: Some(full_address()),
                    shipping_address: None,
                });
            }
        }

        // ── shipping_address: parent-object fallback ──────────────────────────
        "shipping_address" | "shipping.address" => {
            if let Some(ref mut addr) = req.address {
                addr.shipping_address = Some(full_address());
            } else {
                req.address = Some(PaymentAddress {
                    billing_address: None,
                    shipping_address: Some(full_address()),
                });
            }
        }

        // Both billing and shipping as a unit.
        "address_full" => {
            req.address = Some(PaymentAddress {
                billing_address: Some(full_address()),
                shipping_address: Some(full_address()),
            });
        }

        // ── browser_info / customer: parent-object fallbacks ──────────────────
        "browser_info" => req.browser_info = Some(full_browser_info()),
        "customer"     => req.customer = Some(full_customer()),

        // ── payment method sub-fields (conditional on PM variant) ─────────────
        // "billing_name" and the full proto path set the card holder name field.
        "billing_name" | "payment_method_data.card.card_holder_name" => {
            if let Some(ref mut pm) = req.payment_method {
                if let Some(PmVariant::Card(ref mut card)) = pm.payment_method {
                    card.card_holder_name = Some(Secret::new("John Doe".to_string()));
                }
            }
        }
        // Switch to encrypted GPay token format (Stripe and similar).
        "gpay wallet_token" => req.payment_method = Some(google_pay_encrypted_method()),
        // Switch to encrypted Apple Pay token format (Nexinets, Novalnet, etc.).
        "Apple pay encrypted data" => req.payment_method = Some(apple_pay_encrypted_method()),
        // iDEAL bank name — needed by ACI and other bank-redirect connectors.
        "ideal.bank_name" => {
            if let Some(ref mut pm) = req.payment_method {
                if let Some(PmVariant::Ideal(ref mut ideal)) = pm.payment_method {
                    ideal.bank_name = Some(proto::BankNames::Ing as i32);
                }
            }
        }

        // ── multi-field / structured patches ─────────────────────────────────
        // Connector metadata JSON blob (reference_id, connector_request_id).
        "connector_request_id" | "connector_metadata" | "connector_meta_data" => {
            req.metadata = Some(Secret::new(
                r#"{"reference_id":"probe_ref_001","connector_request_id":"probe_req_001"}"#
                    .to_string(),
            ));
        }
        // Session-based connectors: payment_session_id maps to merchant_order_id.
        "payment_session_id" => req.merchant_order_id = Some("probe_session_id".to_string()),
        // Multi-step session / handle tokens — map to payment_method_token.
        "session_token" => {
            req.session_token = Some("probe_session_token".to_string());
        }
        "payment_handle_token" => {
            req.payment_method_token = Some(Secret::new("probe_session_token".to_string()));
        }
        // Order details struct.
        "order_details" => {
            req.order_details = vec![grpc_api_types::payments::OrderDetailsWithAmount {
                product_name: "Test Product".to_string(),
                quantity: 1,
                amount: 1000,
                ..Default::default()
            }];
        }
        // Cached access token in request state (TrustPay and similar).
        "access_token" => {
            if req.state.is_none() {
                req.state = Some(mock_connector_state());
            }
        }
        // 3DS authentication data (NexixPay and similar).
        "authentication_data"
        | "authentication_data.transaction_id"
        | "authentication_data (must be present for 3DS flow)"
        | "authentication_data.threeds_server_transaction_id" => {
            req.auth_type = proto::AuthenticationType::ThreeDs as i32;
            req.authentication_data = Some(proto::AuthenticationData {
                eci: Some("05".to_string()),
                cavv: Some("AAAAAA==".to_string()),
                threeds_server_transaction_id: Some("probe_3ds_txn_id".to_string()),
                message_version: Some("2.1.0".to_string()),
                ds_transaction_id: Some("probe_ds_txn_id".to_string()),
                acs_transaction_id: Some("probe_acs_txn_id".to_string()),
                connector_transaction_id: Some("probe_connector_txn_id".to_string()),
                ..Default::default()
            });
        }
        // Connector feature data (Cybersource and similar).
        "connector_feature_data" | "connector_feature_data.link_data" => {
            req.connector_feature_data = Some(Secret::new("{}".to_string()));
        }
        // Mandate metadata — stored in request metadata JSON.
        "mandate_metadata" => {
            req.metadata = Some(Secret::new(
                r#"{"mandate_metadata":{"mandate_type":"single_use"}}"#.to_string(),
            ));
        }

        _ => {}
    }
}

// ── Per-flow TOML-driven executors ────────────────────────────────────────────
//
// Each flow has:
//   1. A static OnceLock lookup: alias → (field, value_type, value)
//   2. try_X_patch()   — looks up alias and calls apply_X_field()
//   3. apply_X_field() — matches on field name and sets the struct field

type FlowMap = HashMap<String, (String, PatchValueType, Option<String>)>;

fn build_flow_map(specs: &HashMap<String, FlowFieldSpec>) -> FlowMap {
    let mut map = FlowMap::new();
    for spec in specs.values() {
        let entry = (spec.field.clone(), spec.value_type.clone(), spec.value.clone());
        for alias in &spec.aliases {
            map.insert(alias.clone(), entry.clone());
        }
    }
    map
}

// ── capture ───────────────────────────────────────────────────────────────────

static CAPTURE_MAP: OnceLock<FlowMap> = OnceLock::new();
fn capture_map() -> &'static FlowMap { CAPTURE_MAP.get_or_init(|| build_flow_map(&get_patch_config().capture)) }

fn apply_capture_field(req: &mut PaymentServiceCaptureRequest, field: &str, vtype: &PatchValueType, value: &str) {
    match (field, vtype) {
        ("amount_to_capture", _)      => req.amount_to_capture    = Some(usd_money(1000)),
        ("browser_info", _)           => req.browser_info          = Some(full_browser_info()),
        ("metadata", _)               => req.metadata              = Some(Secret::new(value.to_string())),
        ("connector_feature_data", _) => req.connector_feature_data = Some(Secret::new(value.to_string())),
        _ => {}
    }
}

pub(crate) fn patch_capture_request(req: &mut PaymentServiceCaptureRequest, field_name: &str) {
    if let Some((field, vtype, value)) = capture_map().get(field_name) {
        apply_capture_field(req, field, vtype, value.as_deref().unwrap_or(""));
    }
}

// ── refund ────────────────────────────────────────────────────────────────────

static REFUND_MAP: OnceLock<FlowMap> = OnceLock::new();
fn refund_map() -> &'static FlowMap { REFUND_MAP.get_or_init(|| build_flow_map(&get_patch_config().refund)) }

fn apply_refund_field(req: &mut PaymentServiceRefundRequest, field: &str, _vtype: &PatchValueType, value: &str) {
    match field {
        "refund_amount"          => req.refund_amount          = Some(usd_money(1000)),
        "webhook_url"            => req.webhook_url             = Some(value.to_string()),
        "reason"                 => req.reason                  = Some(value.to_string()),
        "customer_id"            => req.customer_id             = Some(value.to_string()),
        "metadata"               => req.metadata                = Some(Secret::new(value.to_string())),
        "connector_feature_data" => req.connector_feature_data  = Some(Secret::new(value.to_string())),
        _ => {}
    }
}

pub(crate) fn patch_refund_request(req: &mut PaymentServiceRefundRequest, field_name: &str) {
    if let Some((field, vtype, value)) = refund_map().get(field_name) {
        apply_refund_field(req, field, vtype, value.as_deref().unwrap_or(""));
    }
}

// ── get (psync) ───────────────────────────────────────────────────────────────

static GET_MAP: OnceLock<FlowMap> = OnceLock::new();
fn get_map() -> &'static FlowMap { GET_MAP.get_or_init(|| build_flow_map(&get_patch_config().get)) }

fn apply_get_field(req: &mut PaymentServiceGetRequest, field: &str, _vtype: &PatchValueType, value: &str) {
    match field {
        "connector_order_reference_id" => req.connector_order_reference_id = Some(value.to_string()),
        "metadata"                     => req.metadata                      = Some(Secret::new(value.to_string())),
        "connector_feature_data"       => req.connector_feature_data        = Some(Secret::new(value.to_string())),
        _ => {}
    }
}

pub(crate) fn patch_get_request(req: &mut PaymentServiceGetRequest, field_name: &str) {
    if let Some((field, vtype, value)) = get_map().get(field_name) {
        apply_get_field(req, field, vtype, value.as_deref().unwrap_or(""));
    }
}

// ── void ──────────────────────────────────────────────────────────────────────

static VOID_MAP: OnceLock<FlowMap> = OnceLock::new();
fn void_map() -> &'static FlowMap { VOID_MAP.get_or_init(|| build_flow_map(&get_patch_config().void_flow)) }

fn apply_void_field(req: &mut PaymentServiceVoidRequest, field: &str, _vtype: &PatchValueType, value: &str) {
    match field {
        "amount"                 => req.amount                  = Some(usd_money(1000)),
        "browser_info"           => req.browser_info             = Some(full_browser_info()),
        "cancellation_reason"    => req.cancellation_reason      = Some(value.to_string()),
        "metadata"               => req.metadata                 = Some(Secret::new(value.to_string())),
        "connector_feature_data" => req.connector_feature_data   = Some(Secret::new(value.to_string())),
        _ => {}
    }
}

pub(crate) fn patch_void_request(req: &mut PaymentServiceVoidRequest, field_name: &str) {
    if let Some((field, vtype, value)) = void_map().get(field_name) {
        apply_void_field(req, field, vtype, value.as_deref().unwrap_or(""));
    }
}

// ── setup_recurring ───────────────────────────────────────────────────────────

static SETUP_RECURRING_MAP: OnceLock<FlowMap> = OnceLock::new();
fn setup_recurring_map() -> &'static FlowMap {
    SETUP_RECURRING_MAP.get_or_init(|| build_flow_map(&get_patch_config().setup_recurring))
}

fn apply_setup_recurring_field(req: &mut PaymentServiceSetupRecurringRequest, field: &str, _vtype: &PatchValueType, value: &str) {
    match field {
        "metadata"       => { if req.metadata.is_none() { req.metadata = Some(Secret::new(value.to_string())); } }
        "webhook_url"    => req.webhook_url    = Some(value.to_string()),
        "order_category" => req.order_category = Some(value.to_string()),
        "session_token"  => req.session_token  = Some(value.to_string()),
        _ => {}
    }
}

pub(crate) fn patch_setup_recurring_request(
    req: &mut PaymentServiceSetupRecurringRequest,
    field_name: &str,
) {
    if let Some((field, vtype, value)) = setup_recurring_map().get(field_name) {
        apply_setup_recurring_field(req, field, vtype, value.as_deref().unwrap_or(""));
    }
}

// ── recurring_charge ──────────────────────────────────────────────────────────

static RECURRING_CHARGE_MAP: OnceLock<FlowMap> = OnceLock::new();
fn recurring_charge_map() -> &'static FlowMap {
    RECURRING_CHARGE_MAP.get_or_init(|| build_flow_map(&get_patch_config().recurring_charge))
}

fn apply_recurring_charge_field(req: &mut RecurringPaymentServiceChargeRequest, field: &str, _vtype: &PatchValueType, value: &str) {
    match field {
        "email"                  => req.email               = Some(Secret::new(value.to_string())),
        "description"            => req.description          = Some(value.to_string()),
        "webhook_url"            => req.webhook_url          = Some(value.to_string()),
        "return_url"             => req.return_url           = Some(value.to_string()),
        "browser_info"           => req.browser_info         = Some(full_browser_info()),
        "metadata"               => req.metadata             = Some(Secret::new(value.to_string())),
        "connector_feature_data" => req.connector_feature_data = Some(Secret::new(value.to_string())),
        _ => {}
    }
}

pub(crate) fn patch_recurring_charge_request(req: &mut RecurringPaymentServiceChargeRequest, field_name: &str) {
    if let Some((field, vtype, value)) = recurring_charge_map().get(field_name) {
        apply_recurring_charge_field(req, field, vtype, value.as_deref().unwrap_or(""));
        return;
    }
    // Billing address fields — require nested struct creation
    match field_name {
        "billing_address" | "address"
        | "payment_method_data.billing.address.first_name"
        | "payment_method_data.billing.address.country"
        | "address.first_name" | "address.city" | "address.country"
        | "address.zip" | "address.line1" | "address.state"
        | "billing_address.first_name" | "billing_address.city" | "billing_address.country"
        | "billing_address.zip" | "billing_address.line1" => {
            if req.address.is_none() {
                req.address = Some(PaymentAddress {
                    billing_address: Some(full_address()),
                    shipping_address: None,
                });
            }
        }
        _ => {}
    }
}

// ── authenticate ──────────────────────────────────────────────────────────────

pub(crate) fn patch_authenticate_request(
    req: &mut PaymentMethodAuthenticationServiceAuthenticateRequest,
    field_name: &str,
) {
    match field_name {
        "authentication_data" | "authentication_data.threeds_server_transaction_id" => {
            if req.authentication_data.is_none() {
                req.authentication_data = Some(proto::AuthenticationData {
                    eci: Some("05".to_string()),
                    cavv: Some("AAAAAA==".to_string()),
                    threeds_server_transaction_id: Some("probe_3ds_txn_id".to_string()),
                    message_version: Some("2.1.0".to_string()),
                    ds_transaction_id: Some("probe_ds_txn_id".to_string()),
                    acs_transaction_id: Some("probe_acs_txn_id".to_string()),
                    connector_transaction_id: Some("probe_connector_txn_id".to_string()),
                    ..Default::default()
                });
            }
        }
        _ => {}
    }
}

// ── post_authenticate ─────────────────────────────────────────────────────────

pub(crate) fn patch_post_authenticate_request(
    req: &mut PaymentMethodAuthenticationServicePostAuthenticateRequest,
    field_name: &str,
) {
    match field_name {
        "reference_id" | "reference_id (order_id)" | "connector_order_reference_id" => {
            req.connector_order_reference_id = Some("probe_order_ref_001".to_string());
        }
        "merchant_order_id" | "order_id" => {
            req.merchant_order_id = Some("probe_order_001".to_string());
        }
        _ => {}
    }
}

pub(crate) fn patch_accept_dispute_request(
    _req: &mut DisputeServiceAcceptRequest,
    _field_name: &str,
) {
}

pub(crate) fn patch_submit_evidence_request(
    _req: &mut DisputeServiceSubmitEvidenceRequest,
    _field_name: &str,
) {
}

pub(crate) fn patch_defend_dispute_request(
    _req: &mut DisputeServiceDefendRequest,
    _field_name: &str,
) {
}
