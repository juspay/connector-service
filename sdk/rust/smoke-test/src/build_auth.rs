// AUTO-GENERATED — do not edit manually.
// Regenerate: python3 scripts/generate-connector-docs.py --all
//
// Maps connector name (from creds.json) to ConnectorAuth proto type.

use grpc_api_types::payments::{connector_auth, ConnectorAuth, *};
use hyperswitch_masking::Secret;

fn get_val(
    creds: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    match creds.get(key) {
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(serde_json::Value::Object(obj)) => obj
            .get("value")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("field {key}: no .value")),
        _ => Err(format!("missing or invalid field: {key}")),
    }
}

fn get_opt(
    creds: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<Secret<String>> {
    get_val(creds, key).ok().map(Secret::new)
}

pub fn build_connector_auth(
    connector: &str,
    creds: &serde_json::Map<String, serde_json::Value>,
) -> Result<ConnectorAuth, String> {
    #[allow(clippy::match_single_binding)]
    match connector {
        "adyen" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Adyen(
                    AdyenAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            merchant_account: Some(Secret::new(get_val(creds, "merchant_account")?)),
            review_key: get_opt(creds, "review_key"),
                        ..Default::default()
                    },
                )),
            })
        }
        "airwallex" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Airwallex(
                    AirwallexAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            client_id: Some(Secret::new(get_val(creds, "client_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "bambora" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Bambora(
                    BamboraAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "bankofamerica" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Bankofamerica(
                    BankOfAmericaAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            merchant_account: Some(Secret::new(get_val(creds, "merchant_account")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "billwerk" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Billwerk(
                    BillwerkAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            public_api_key: Some(Secret::new(get_val(creds, "public_api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "bluesnap" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Bluesnap(
                    BluesnapAuth {
            username: Some(Secret::new(get_val(creds, "username")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "braintree" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Braintree(
                    BraintreeAuth {
            public_key: Some(Secret::new(get_val(creds, "public_key")?)),
            private_key: Some(Secret::new(get_val(creds, "private_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "cashtocode" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Cashtocode(
                    CashtocodeAuth {
                        ..Default::default()
                    },
                )),
            })
        }
        "cryptopay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Cryptopay(
                    CryptopayAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "cybersource" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Cybersource(
                    CybersourceAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            merchant_account: Some(Secret::new(get_val(creds, "merchant_account")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "datatrans" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Datatrans(
                    DatatransAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "dlocal" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Dlocal(
                    DlocalAuth {
            x_login: Some(Secret::new(get_val(creds, "x_login")?)),
            x_trans_key: Some(Secret::new(get_val(creds, "x_trans_key")?)),
            secret: Some(Secret::new(get_val(creds, "secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "elavon" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Elavon(
                    ElavonAuth {
            ssl_merchant_id: Some(Secret::new(get_val(creds, "ssl_merchant_id")?)),
            ssl_user_id: Some(Secret::new(get_val(creds, "ssl_user_id")?)),
            ssl_pin: Some(Secret::new(get_val(creds, "ssl_pin")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "fiserv" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Fiserv(
                    FiservAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            merchant_account: Some(Secret::new(get_val(creds, "merchant_account")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "fiservemea" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Fiservemea(
                    FiservemeaAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "forte" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Forte(
                    ForteAuth {
            api_access_id: Some(Secret::new(get_val(creds, "api_access_id")?)),
            organization_id: Some(Secret::new(get_val(creds, "organization_id")?)),
            location_id: Some(Secret::new(get_val(creds, "location_id")?)),
            api_secret_key: Some(Secret::new(get_val(creds, "api_secret_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "getnet" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Getnet(
                    GetnetAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
            seller_id: Some(Secret::new(get_val(creds, "seller_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "globalpay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Globalpay(
                    GlobalpayAuth {
            app_id: Some(Secret::new(get_val(creds, "app_id")?)),
            app_key: Some(Secret::new(get_val(creds, "app_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "hipay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Hipay(
                    HipayAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "helcim" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Helcim(
                    HelcimAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "iatapay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Iatapay(
                    IatapayAuth {
            client_id: Some(Secret::new(get_val(creds, "client_id")?)),
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            client_secret: Some(Secret::new(get_val(creds, "client_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "jpmorgan" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Jpmorgan(
                    JpmorganAuth {
            client_id: Some(Secret::new(get_val(creds, "client_id")?)),
            client_secret: Some(Secret::new(get_val(creds, "client_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "mifinity" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Mifinity(
                    MifinityAuth {
            key: Some(Secret::new(get_val(creds, "key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "mollie" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Mollie(
                    MollieAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            profile_token: get_opt(creds, "profile_token"),
                        ..Default::default()
                    },
                )),
            })
        }
        "multisafepay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Multisafepay(
                    MultisafepayAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "nexinets" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Nexinets(
                    NexinetsAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "nexixpay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Nexixpay(
                    NexixpayAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "nmi" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Nmi(
                    NmiAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            public_key: get_opt(creds, "public_key"),
                        ..Default::default()
                    },
                )),
            })
        }
        "noon" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Noon(
                    NoonAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            application_identifier: Some(Secret::new(get_val(creds, "application_identifier")?)),
            business_identifier: Some(Secret::new(get_val(creds, "business_identifier")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "novalnet" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Novalnet(
                    NovalnetAuth {
            product_activation_key: Some(Secret::new(get_val(creds, "product_activation_key")?)),
            payment_access_key: Some(Secret::new(get_val(creds, "payment_access_key")?)),
            tariff_id: Some(Secret::new(get_val(creds, "tariff_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "nuvei" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Nuvei(
                    NuveiAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            merchant_site_id: Some(Secret::new(get_val(creds, "merchant_site_id")?)),
            merchant_secret: Some(Secret::new(get_val(creds, "merchant_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "paybox" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Paybox(
                    PayboxAuth {
            site: Some(Secret::new(get_val(creds, "site")?)),
            rank: Some(Secret::new(get_val(creds, "rank")?)),
            key: Some(Secret::new(get_val(creds, "key")?)),
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "payme" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Payme(
                    PaymeAuth {
            seller_payme_id: Some(Secret::new(get_val(creds, "seller_payme_id")?)),
            payme_client_key: get_opt(creds, "payme_client_key"),
                        ..Default::default()
                    },
                )),
            })
        }
        "payu" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Payu(
                    PayuAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "powertranz" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Powertranz(
                    PowertranzAuth {
            power_tranz_id: Some(Secret::new(get_val(creds, "power_tranz_id")?)),
            power_tranz_password: Some(Secret::new(get_val(creds, "power_tranz_password")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "rapyd" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Rapyd(
                    RapydAuth {
            access_key: Some(Secret::new(get_val(creds, "access_key")?)),
            secret_key: Some(Secret::new(get_val(creds, "secret_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "redsys" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Redsys(
                    RedsysAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            terminal_id: Some(Secret::new(get_val(creds, "terminal_id")?)),
            sha256_pwd: Some(Secret::new(get_val(creds, "sha256_pwd")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "shift4" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Shift4(
                    Shift4Auth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "stax" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Stax(
                    StaxAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "stripe" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Stripe(
                    StripeAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "trustpay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Trustpay(
                    TrustpayAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            project_id: Some(Secret::new(get_val(creds, "project_id")?)),
            secret_key: Some(Secret::new(get_val(creds, "secret_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "tsys" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Tsys(
                    TsysAuth {
            device_id: Some(Secret::new(get_val(creds, "device_id")?)),
            transaction_key: Some(Secret::new(get_val(creds, "transaction_key")?)),
            developer_id: Some(Secret::new(get_val(creds, "developer_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "volt" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Volt(
                    VoltAuth {
            username: Some(Secret::new(get_val(creds, "username")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
            client_id: Some(Secret::new(get_val(creds, "client_id")?)),
            client_secret: Some(Secret::new(get_val(creds, "client_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "wellsfargo" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Wellsfargo(
                    WellsfargoAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            merchant_account: Some(Secret::new(get_val(creds, "merchant_account")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "worldpay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Worldpay(
                    WorldpayAuth {
            username: Some(Secret::new(get_val(creds, "username")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
            entity_id: Some(Secret::new(get_val(creds, "entity_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "worldpayvantiv" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Worldpayvantiv(
                    WorldpayvantivAuth {
            user: Some(Secret::new(get_val(creds, "user")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "xendit" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Xendit(
                    XenditAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "phonepe" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Phonepe(
                    PhonepeAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            salt_key: Some(Secret::new(get_val(creds, "salt_key")?)),
            salt_index: Some(Secret::new(get_val(creds, "salt_index")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "cashfree" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Cashfree(
                    CashfreeAuth {
            app_id: Some(Secret::new(get_val(creds, "app_id")?)),
            secret_key: Some(Secret::new(get_val(creds, "secret_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "paytm" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Paytm(
                    PaytmAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            merchant_key: Some(Secret::new(get_val(creds, "merchant_key")?)),
            website: Some(Secret::new(get_val(creds, "website")?)),
            client_id: get_opt(creds, "client_id"),
                        ..Default::default()
                    },
                )),
            })
        }
        "calida" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Calida(
                    CalidaAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "payload" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Payload(
                    PayloadAuth {
                        ..Default::default()
                    },
                )),
            })
        }
        "authipay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Authipay(
                    AuthipayAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "silverflow" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Silverflow(
                    SilverflowAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
            merchant_acceptor_key: Some(Secret::new(get_val(creds, "merchant_acceptor_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "celero" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Celero(
                    CeleroAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "trustpayments" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Trustpayments(
                    TrustpaymentsAuth {
            username: Some(Secret::new(get_val(creds, "username")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
            site_reference: Some(Secret::new(get_val(creds, "site_reference")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "paysafe" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Paysafe(
                    PaysafeAuth {
            username: Some(Secret::new(get_val(creds, "username")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "barclaycard" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Barclaycard(
                    BarclaycardAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
            merchant_account: Some(Secret::new(get_val(creds, "merchant_account")?)),
            api_secret: Some(Secret::new(get_val(creds, "api_secret")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "worldpayxml" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Worldpayxml(
                    WorldpayxmlAuth {
            api_username: Some(Secret::new(get_val(creds, "api_username")?)),
            api_password: Some(Secret::new(get_val(creds, "api_password")?)),
            merchant_code: Some(Secret::new(get_val(creds, "merchant_code")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "revolut" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Revolut(
                    RevolutAuth {
            secret_api_key: Some(Secret::new(get_val(creds, "secret_api_key")?)),
            signing_secret: get_opt(creds, "signing_secret"),
                        ..Default::default()
                    },
                )),
            })
        }
        "loonio" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Loonio(
                    LoonioAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            merchant_token: Some(Secret::new(get_val(creds, "merchant_token")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "gigadat" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Gigadat(
                    GigadatAuth {
            campaign_id: Some(Secret::new(get_val(creds, "campaign_id")?)),
            access_token: Some(Secret::new(get_val(creds, "access_token")?)),
            security_token: Some(Secret::new(get_val(creds, "security_token")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "hyperpg" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Hyperpg(
                    HyperpgAuth {
            username: Some(Secret::new(get_val(creds, "username")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "zift" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Zift(
                    ZiftAuth {
            user_name: Some(Secret::new(get_val(creds, "user_name")?)),
            password: Some(Secret::new(get_val(creds, "password")?)),
            account_id: Some(Secret::new(get_val(creds, "account_id")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "screenstream" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Screenstream(
                    ScreenstreamAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "ebanx" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Ebanx(
                    EbanxAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "fiuu" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Fiuu(
                    FiuuAuth {
            merchant_id: Some(Secret::new(get_val(creds, "merchant_id")?)),
            verify_key: Some(Secret::new(get_val(creds, "verify_key")?)),
            secret_key: Some(Secret::new(get_val(creds, "secret_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "globepay" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Globepay(
                    GlobepayAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "coinbase" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Coinbase(
                    CoinbaseAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "coingate" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Coingate(
                    CoingateAuth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "revolv3" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Revolv3(
                    Revolv3Auth {
            api_key: Some(Secret::new(get_val(creds, "api_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "authorizedotnet" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Authorizedotnet(
                    AuthorizedotnetAuth {
            name: Some(Secret::new(get_val(creds, "name")?)),
            transaction_key: Some(Secret::new(get_val(creds, "transaction_key")?)),
                        ..Default::default()
                    },
                )),
            })
        }
        "paypal" => {
            Ok(ConnectorAuth {
                auth_type: Some(connector_auth::AuthType::Paypal(
                    PaypalAuth {
            client_id: Some(Secret::new(get_val(creds, "client_id")?)),
            client_secret: Some(Secret::new(get_val(creds, "client_secret")?)),
            payer_id: get_opt(creds, "payer_id"),
                        ..Default::default()
                    },
                )),
            })
        }
        _ => Err(format!("unsupported connector for Rust smoke test: {connector}")),
    }
}
