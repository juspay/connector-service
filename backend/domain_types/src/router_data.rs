use std::collections::HashMap;

use cards::NetworkToken;
use common_utils::{
    ext_traits::{OptionExt, ValueExt},
    MinorUnit,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};

use crate::{
    payment_method_data,
    utils::{missing_field_err, ForeignTryFrom},
};

pub type Error = error_stack::Report<crate::errors::ConnectorError>;

#[derive(Default, Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "auth_type")]
pub enum ConnectorAuthType {
    TemporaryAuth,
    HeaderKey {
        api_key: Secret<String>,
    },
    BodyKey {
        api_key: Secret<String>,
        key1: Secret<String>,
    },
    SignatureKey {
        api_key: Secret<String>,
        key1: Secret<String>,
        api_secret: Secret<String>,
    },
    MultiAuthKey {
        api_key: Secret<String>,
        key1: Secret<String>,
        api_secret: Secret<String>,
        key2: Secret<String>,
    },
    CurrencyAuthKey {
        auth_key_map: HashMap<common_enums::enums::Currency, common_utils::pii::SecretSerdeValue>,
    },
    CertificateAuth {
        certificate: Secret<String>,
        private_key: Secret<String>,
    },
    #[default]
    NoKey,
}

impl ConnectorAuthType {
    pub fn from_option_secret_value(
        value: Option<common_utils::pii::SecretSerdeValue>,
    ) -> common_utils::errors::CustomResult<Self, common_utils::errors::ParsingError> {
        value
            .parse_value::<Self>("ConnectorAuthType")
            .change_context(common_utils::errors::ParsingError::StructParseFailure(
                "ConnectorAuthType",
            ))
    }

    pub fn from_secret_value(
        value: common_utils::pii::SecretSerdeValue,
    ) -> common_utils::errors::CustomResult<Self, common_utils::errors::ParsingError> {
        value
            .parse_value::<Self>("ConnectorAuthType")
            .change_context(common_utils::errors::ParsingError::StructParseFailure(
                "ConnectorAuthType",
            ))
    }

    // show only first and last two digits of the key and mask others with *
    // mask the entire key if it's length is less than or equal to 4
    fn mask_key(&self, key: String) -> Secret<String> {
        let key_len = key.len();
        let masked_key = if key_len <= 4 {
            "*".repeat(key_len)
        } else {
            // Show the first two and last two characters, mask the rest with '*'
            let mut masked_key = String::new();
            let key_len = key.len();
            // Iterate through characters by their index
            for (index, character) in key.chars().enumerate() {
                if index < 2 || index >= key_len - 2 {
                    masked_key.push(character); // Keep the first two and last two characters
                } else {
                    masked_key.push('*'); // Mask the middle characters
                }
            }
            masked_key
        };
        Secret::new(masked_key)
    }

    // Mask the keys in the auth_type
    pub fn get_masked_keys(&self) -> Self {
        match self {
            Self::TemporaryAuth => Self::TemporaryAuth,
            Self::NoKey => Self::NoKey,
            Self::HeaderKey { api_key } => Self::HeaderKey {
                api_key: self.mask_key(api_key.clone().expose()),
            },
            Self::BodyKey { api_key, key1 } => Self::BodyKey {
                api_key: self.mask_key(api_key.clone().expose()),
                key1: self.mask_key(key1.clone().expose()),
            },
            Self::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Self::SignatureKey {
                api_key: self.mask_key(api_key.clone().expose()),
                key1: self.mask_key(key1.clone().expose()),
                api_secret: self.mask_key(api_secret.clone().expose()),
            },
            Self::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Self::MultiAuthKey {
                api_key: self.mask_key(api_key.clone().expose()),
                key1: self.mask_key(key1.clone().expose()),
                api_secret: self.mask_key(api_secret.clone().expose()),
                key2: self.mask_key(key2.clone().expose()),
            },
            Self::CurrencyAuthKey { auth_key_map } => Self::CurrencyAuthKey {
                auth_key_map: auth_key_map.clone(),
            },
            Self::CertificateAuth {
                certificate,
                private_key,
            } => Self::CertificateAuth {
                certificate: self.mask_key(certificate.clone().expose()),
                private_key: self.mask_key(private_key.clone().expose()),
            },
        }
    }
}

/// Connector-specific authentication types.
///
/// Each variant holds the exact credentials a specific connector needs,
/// as opposed to the generic `ConnectorAuthType` which uses positional fields.
#[derive(Debug, Clone)]
pub enum ConnectorSpecificAuth {
    // --- Single-field (HeaderKey) connectors ---
    Stripe {
        api_key: Secret<String>,
    },
    Calida {
        api_key: Secret<String>,
    },
    Celero {
        api_key: Secret<String>,
    },
    Helcim {
        api_key: Secret<String>,
    },
    Mifinity {
        key: Secret<String>,
    },
    Multisafepay {
        api_key: Secret<String>,
    },
    Nexixpay {
        api_key: Secret<String>,
    },
    Revolut {
        api_key: Secret<String>,
    },
    Shift4 {
        api_key: Secret<String>,
    },
    Stax {
        api_key: Secret<String>,
    },
    Xendit {
        api_key: Secret<String>,
    },
    Bambora {
        merchant_id: Secret<String>,
        api_key: Secret<String>,
    },
    Nexinets {
        merchant_id: Secret<String>,
        api_key: Secret<String>,
    },

    // --- Two-field connectors ---
    Razorpay {
        api_key: Secret<String>,
        api_secret: Option<Secret<String>>,
    },
    RazorpayV2 {
        api_key: Secret<String>,
        api_secret: Option<Secret<String>>,
    },
    Aci {
        api_key: Secret<String>,
        entity_id: Secret<String>,
    },
    Airwallex {
        api_key: Secret<String>,
        client_id: Secret<String>,
    },
    Authorizedotnet {
        name: Secret<String>,
        transaction_key: Secret<String>,
    },
    Billwerk {
        api_key: Secret<String>,
        public_api_key: Secret<String>,
    },
    Bluesnap {
        username: Secret<String>,
        password: Secret<String>,
    },
    Cashfree {
        app_id: Secret<String>,
        secret_key: Secret<String>,
    },
    Cryptopay {
        api_key: Secret<String>,
        api_secret: Secret<String>,
    },
    Datatrans {
        merchant_id: Secret<String>,
        password: Secret<String>,
    },
    Globalpay {
        app_id: Secret<String>,
        app_key: Secret<String>,
    },
    Hipay {
        api_key: Secret<String>,
        api_secret: Secret<String>,
    },
    Jpmorgan {
        client_id: Secret<String>,
        client_secret: Secret<String>,
    },
    Loonio {
        merchant_id: Secret<String>,
        merchant_token: Secret<String>,
    },
    Paysafe {
        username: Secret<String>,
        password: Secret<String>,
    },
    Payu {
        api_key: Secret<String>,
        api_secret: Secret<String>,
    },
    Placetopay {
        login: Secret<String>,
        tran_key: Secret<String>,
    },
    Powertranz {
        power_tranz_id: Secret<String>,
        power_tranz_password: Secret<String>,
    },
    Rapyd {
        access_key: Secret<String>,
        secret_key: Secret<String>,
    },
    Authipay {
        api_key: Secret<String>,
        api_secret: Secret<String>,
    },
    Fiservemea {
        api_key: Secret<String>,
        api_secret: Secret<String>,
    },
    Mollie {
        api_key: Secret<String>,
        profile_token: Option<Secret<String>>,
    },
    Nmi {
        api_key: Secret<String>,
        public_key: Option<Secret<String>>,
    },
    Payme {
        seller_payme_id: Secret<String>,
        payme_client_key: Option<Secret<String>>,
    },
    Braintree {
        public_key: Secret<String>,
        private_key: Secret<String>,
    },
    Worldpay {
        username: Secret<String>,
        password: Secret<String>,
        entity_id: Secret<String>,
    },

    // --- Three-field connectors ---
    Adyen {
        api_key: Secret<String>,
        merchant_account: Secret<String>,
        review_key: Option<Secret<String>>,
    },
    BankOfAmerica {
        api_key: Secret<String>,
        merchant_account: Secret<String>,
        api_secret: Secret<String>,
    },
    Bamboraapac {
        username: Secret<String>,
        password: Secret<String>,
        account_number: Secret<String>,
    },
    Barclaycard {
        api_key: Secret<String>,
        merchant_account: Secret<String>,
        api_secret: Secret<String>,
    },
    Checkout {
        api_key: Secret<String>,
        api_secret: Secret<String>,
        processing_channel_id: Secret<String>,
    },
    Cybersource {
        api_key: Secret<String>,
        merchant_account: Secret<String>,
        api_secret: Secret<String>,
    },
    Dlocal {
        x_login: Secret<String>,
        x_trans_key: Secret<String>,
        secret: Secret<String>,
    },
    Elavon {
        ssl_merchant_id: Secret<String>,
        ssl_user_id: Secret<String>,
        ssl_pin: Secret<String>,
    },
    Fiserv {
        api_key: Secret<String>,
        merchant_account: Secret<String>,
        api_secret: Secret<String>,
    },
    Fiuu {
        merchant_id: Secret<String>,
        verify_key: Secret<String>,
        secret_key: Secret<String>,
    },
    Getnet {
        api_key: Secret<String>,
        api_secret: Secret<String>,
        seller_id: Secret<String>,
    },
    Gigadat {
        security_token: Secret<String>,
        access_token: Secret<String>,
        campaign_id: Secret<String>,
    },
    Hyperpg {
        username: Secret<String>,
        password: Secret<String>,
        merchant_id: Secret<String>,
    },
    Iatapay {
        client_id: Secret<String>,
        merchant_id: Secret<String>,
        client_secret: Secret<String>,
    },
    Noon {
        api_key: Secret<String>,
        business_identifier: Secret<String>,
        application_identifier: Secret<String>,
    },
    Novalnet {
        product_activation_key: Secret<String>,
        payment_access_key: Secret<String>,
        tariff_id: Secret<String>,
    },
    Nuvei {
        merchant_id: Secret<String>,
        merchant_site_id: Secret<String>,
        merchant_secret: Secret<String>,
    },
    Phonepe {
        merchant_id: Secret<String>,
        salt_key: Secret<String>,
        salt_index: Secret<String>,
    },
    Redsys {
        merchant_id: Secret<String>,
        terminal_id: Secret<String>,
        sha256_pwd: Secret<String>,
    },
    Silverflow {
        api_key: Secret<String>,
        api_secret: Secret<String>,
        merchant_acceptor_key: Secret<String>,
    },
    Trustpay {
        api_key: Secret<String>,
        project_id: Secret<String>,
        secret_key: Secret<String>,
    },
    Trustpayments {
        username: Secret<String>,
        password: Secret<String>,
        site_reference: Secret<String>,
    },
    Tsys {
        device_id: Secret<String>,
        transaction_key: Secret<String>,
        developer_id: Secret<String>,
    },
    Wellsfargo {
        api_key: Secret<String>,
        merchant_account: Secret<String>,
        api_secret: Secret<String>,
    },
    Worldpayvantiv {
        user: Secret<String>,
        password: Secret<String>,
        merchant_id: Secret<String>,
    },
    Worldpayxml {
        api_username: Secret<String>,
        api_password: Secret<String>,
        merchant_code: Secret<String>,
    },
    Zift {
        user_name: Secret<String>,
        password: Secret<String>,
        account_id: Secret<String>,
    },
    Paypal {
        client_id: Secret<String>,
        client_secret: Secret<String>,
        payer_id: Option<Secret<String>>,
    },

    // --- Four+ field connectors ---
    Forte {
        api_access_id: Secret<String>,
        organization_id: Secret<String>,
        location_id: Secret<String>,
        api_secret_key: Secret<String>,
    },
    Paybox {
        site: Secret<String>,
        rank: Secret<String>,
        key: Secret<String>,
        merchant_id: Secret<String>,
    },
    Paytm {
        merchant_id: Secret<String>,
        merchant_key: Secret<String>,
        website: Secret<String>,
        client_id: Option<Secret<String>>,
    },
    Volt {
        username: Secret<String>,
        password: Secret<String>,
        client_id: Secret<String>,
        client_secret: Secret<String>,
    },
    Cashtocode {
        password_classic: Option<Secret<String>>,
        password_evoucher: Option<Secret<String>>,
        username_classic: Option<Secret<String>>,
        username_evoucher: Option<Secret<String>>,
    },
    Payload {
        api_key: Secret<String>,
        processing_account_id: Option<Secret<String>>,
    },

    // --- Proto-only connectors (not in ConnectorEnum, reachable via proto auth path) ---
    Screenstream {
        api_key: Secret<String>,
    },
    Ebanx {
        api_key: Secret<String>,
    },
    Globepay {
        api_key: Secret<String>,
    },
    Coinbase {
        api_key: Secret<String>,
    },
    Coingate {
        api_key: Secret<String>,
    },
    Revolv3 {
        api_key: Secret<String>,
    },
}

impl ForeignTryFrom<grpc_api_types::payments::ConnectorAuth> for ConnectorSpecificAuth {
    type Error = crate::errors::ConnectorError;

    fn foreign_try_from(auth: grpc_api_types::payments::ConnectorAuth) -> Result<Self, Error> {
        use grpc_api_types::payments::connector_auth::AuthType;

        let err = || crate::errors::ConnectorError::FailedToObtainAuthType;
        let auth_type = auth.auth_type.ok_or_else(err)?;

        match auth_type {
            AuthType::Adyen(adyen) => Ok(Self::Adyen {
                api_key: adyen.api_key.ok_or_else(err)?,
                merchant_account: adyen.merchant_account.ok_or_else(err)?,
                review_key: adyen.review_key,
            }),
            AuthType::Airwallex(airwallex) => Ok(Self::Airwallex {
                api_key: airwallex.api_key.ok_or_else(err)?,
                client_id: airwallex.client_id.ok_or_else(err)?,
            }),
            AuthType::Bambora(bambora) => Ok(Self::Bambora {
                merchant_id: bambora.merchant_id.ok_or_else(err)?,
                api_key: bambora.api_key.ok_or_else(err)?,
            }),
            AuthType::Bankofamerica(bankofamerica) => Ok(Self::BankOfAmerica {
                api_key: bankofamerica.api_key.ok_or_else(err)?,
                merchant_account: bankofamerica.merchant_account.ok_or_else(err)?,
                api_secret: bankofamerica.api_secret.ok_or_else(err)?,
            }),
            AuthType::Billwerk(billwerk) => Ok(Self::Billwerk {
                api_key: billwerk.api_key.ok_or_else(err)?,
                public_api_key: billwerk.public_api_key.ok_or_else(err)?,
            }),
            AuthType::Bluesnap(bluesnap) => Ok(Self::Bluesnap {
                username: bluesnap.username.ok_or_else(err)?,
                password: bluesnap.password.ok_or_else(err)?,
            }),
            AuthType::Braintree(braintree) => Ok(Self::Braintree {
                public_key: braintree.public_key.ok_or_else(err)?,
                private_key: braintree.private_key.ok_or_else(err)?,
            }),
            AuthType::Cashtocode(cashtocode) => Ok(Self::Cashtocode {
                password_classic: cashtocode.password_classic,
                password_evoucher: cashtocode.password_evoucher,
                username_classic: cashtocode.username_classic,
                username_evoucher: cashtocode.username_evoucher,
            }),
            AuthType::Cryptopay(cryptopay) => Ok(Self::Cryptopay {
                api_key: cryptopay.api_key.ok_or_else(err)?,
                api_secret: cryptopay.api_secret.ok_or_else(err)?,
            }),
            AuthType::Cybersource(cybersource) => Ok(Self::Cybersource {
                api_key: cybersource.api_key.ok_or_else(err)?,
                merchant_account: cybersource.merchant_account.ok_or_else(err)?,
                api_secret: cybersource.api_secret.ok_or_else(err)?,
            }),
            AuthType::Datatrans(datatrans) => Ok(Self::Datatrans {
                merchant_id: datatrans.merchant_id.ok_or_else(err)?,
                password: datatrans.password.ok_or_else(err)?,
            }),
            AuthType::Dlocal(dlocal) => Ok(Self::Dlocal {
                x_login: dlocal.x_login.ok_or_else(err)?,
                x_trans_key: dlocal.x_trans_key.ok_or_else(err)?,
                secret: dlocal.secret.ok_or_else(err)?,
            }),
            AuthType::Elavon(elavon) => Ok(Self::Elavon {
                ssl_merchant_id: elavon.ssl_merchant_id.ok_or_else(err)?,
                ssl_user_id: elavon.ssl_user_id.ok_or_else(err)?,
                ssl_pin: elavon.ssl_pin.ok_or_else(err)?,
            }),
            AuthType::Fiserv(fiserv) => Ok(Self::Fiserv {
                api_key: fiserv.api_key.ok_or_else(err)?,
                merchant_account: fiserv.merchant_account.ok_or_else(err)?,
                api_secret: fiserv.api_secret.ok_or_else(err)?,
            }),
            AuthType::Fiservemea(fiservemea) => Ok(Self::Fiservemea {
                api_key: fiservemea.api_key.ok_or_else(err)?,
                api_secret: fiservemea.api_secret.ok_or_else(err)?,
            }),
            AuthType::Forte(forte) => Ok(Self::Forte {
                api_access_id: forte.api_access_id.ok_or_else(err)?,
                organization_id: forte.organization_id.ok_or_else(err)?,
                location_id: forte.location_id.ok_or_else(err)?,
                api_secret_key: forte.api_secret_key.ok_or_else(err)?,
            }),
            AuthType::Getnet(getnet) => Ok(Self::Getnet {
                api_key: getnet.api_key.ok_or_else(err)?,
                api_secret: getnet.api_secret.ok_or_else(err)?,
                seller_id: getnet.seller_id.ok_or_else(err)?,
            }),
            AuthType::Globalpay(globalpay) => Ok(Self::Globalpay {
                app_id: globalpay.app_id.ok_or_else(err)?,
                app_key: globalpay.app_key.ok_or_else(err)?,
            }),
            AuthType::Hipay(hipay) => Ok(Self::Hipay {
                api_key: hipay.api_key.ok_or_else(err)?,
                api_secret: hipay.api_secret.ok_or_else(err)?,
            }),
            AuthType::Helcim(helcim) => Ok(Self::Helcim {
                api_key: helcim.api_key.ok_or_else(err)?,
            }),
            AuthType::Iatapay(iatapay) => Ok(Self::Iatapay {
                client_id: iatapay.client_id.ok_or_else(err)?,
                merchant_id: iatapay.merchant_id.ok_or_else(err)?,
                client_secret: iatapay.client_secret.ok_or_else(err)?,
            }),
            AuthType::Jpmorgan(jpmorgan) => Ok(Self::Jpmorgan {
                client_id: jpmorgan.client_id.ok_or_else(err)?,
                client_secret: jpmorgan.client_secret.ok_or_else(err)?,
            }),
            AuthType::Mifinity(mifinity) => Ok(Self::Mifinity {
                key: mifinity.key.ok_or_else(err)?,
            }),
            AuthType::Mollie(mollie) => Ok(Self::Mollie {
                api_key: mollie.api_key.ok_or_else(err)?,
                profile_token: mollie.profile_token,
            }),
            AuthType::Multisafepay(multisafepay) => Ok(Self::Multisafepay {
                api_key: multisafepay.api_key.ok_or_else(err)?,
            }),
            AuthType::Nexinets(nexinets) => Ok(Self::Nexinets {
                merchant_id: nexinets.merchant_id.ok_or_else(err)?,
                api_key: nexinets.api_key.ok_or_else(err)?,
            }),
            AuthType::Nexixpay(nexixpay) => Ok(Self::Nexixpay {
                api_key: nexixpay.api_key.ok_or_else(err)?,
            }),
            AuthType::Nmi(nmi) => Ok(Self::Nmi {
                api_key: nmi.api_key.ok_or_else(err)?,
                public_key: nmi.public_key,
            }),
            AuthType::Noon(noon) => Ok(Self::Noon {
                api_key: noon.api_key.ok_or_else(err)?,
                business_identifier: noon.business_identifier.ok_or_else(err)?,
                application_identifier: noon.application_identifier.ok_or_else(err)?,
            }),
            AuthType::Novalnet(novalnet) => Ok(Self::Novalnet {
                product_activation_key: novalnet.product_activation_key.ok_or_else(err)?,
                payment_access_key: novalnet.payment_access_key.ok_or_else(err)?,
                tariff_id: novalnet.tariff_id.ok_or_else(err)?,
            }),
            AuthType::Nuvei(nuvei) => Ok(Self::Nuvei {
                merchant_id: nuvei.merchant_id.ok_or_else(err)?,
                merchant_site_id: nuvei.merchant_site_id.ok_or_else(err)?,
                merchant_secret: nuvei.merchant_secret.ok_or_else(err)?,
            }),
            AuthType::Paybox(paybox) => Ok(Self::Paybox {
                site: paybox.site.ok_or_else(err)?,
                rank: paybox.rank.ok_or_else(err)?,
                key: paybox.key.ok_or_else(err)?,
                merchant_id: paybox.merchant_id.ok_or_else(err)?,
            }),
            AuthType::Payme(payme) => Ok(Self::Payme {
                seller_payme_id: payme.seller_payme_id.ok_or_else(err)?,
                payme_client_key: payme.payme_client_key,
            }),
            AuthType::Payu(payu) => Ok(Self::Payu {
                api_key: payu.api_key.ok_or_else(err)?,
                api_secret: payu.api_secret.ok_or_else(err)?,
            }),
            AuthType::Powertranz(powertranz) => Ok(Self::Powertranz {
                power_tranz_id: powertranz.power_tranz_id.ok_or_else(err)?,
                power_tranz_password: powertranz.power_tranz_password.ok_or_else(err)?,
            }),
            AuthType::Rapyd(rapyd) => Ok(Self::Rapyd {
                access_key: rapyd.access_key.ok_or_else(err)?,
                secret_key: rapyd.secret_key.ok_or_else(err)?,
            }),
            AuthType::Redsys(redsys) => Ok(Self::Redsys {
                merchant_id: redsys.merchant_id.ok_or_else(err)?,
                terminal_id: redsys.terminal_id.ok_or_else(err)?,
                sha256_pwd: redsys.sha256_pwd.ok_or_else(err)?,
            }),
            AuthType::Shift4(shift4) => Ok(Self::Shift4 {
                api_key: shift4.api_key.ok_or_else(err)?,
            }),
            AuthType::Stax(stax) => Ok(Self::Stax {
                api_key: stax.api_key.ok_or_else(err)?,
            }),
            AuthType::Stripe(stripe) => Ok(Self::Stripe {
                api_key: stripe.api_key.ok_or_else(err)?,
            }),
            AuthType::Trustpay(trustpay) => Ok(Self::Trustpay {
                api_key: trustpay.api_key.ok_or_else(err)?,
                project_id: trustpay.project_id.ok_or_else(err)?,
                secret_key: trustpay.secret_key.ok_or_else(err)?,
            }),
            AuthType::Tsys(tsys) => Ok(Self::Tsys {
                device_id: tsys.device_id.ok_or_else(err)?,
                transaction_key: tsys.transaction_key.ok_or_else(err)?,
                developer_id: tsys.developer_id.ok_or_else(err)?,
            }),
            AuthType::Volt(volt) => Ok(Self::Volt {
                username: volt.username.ok_or_else(err)?,
                password: volt.password.ok_or_else(err)?,
                client_id: volt.client_id.ok_or_else(err)?,
                client_secret: volt.client_secret.ok_or_else(err)?,
            }),
            AuthType::Wellsfargo(wellsfargo) => Ok(Self::Wellsfargo {
                api_key: wellsfargo.api_key.ok_or_else(err)?,
                merchant_account: wellsfargo.merchant_account.ok_or_else(err)?,
                api_secret: wellsfargo.api_secret.ok_or_else(err)?,
            }),
            AuthType::Worldpay(worldpay) => Ok(Self::Worldpay {
                username: worldpay.username.ok_or_else(err)?,
                password: worldpay.password.ok_or_else(err)?,
                entity_id: worldpay.entity_id.ok_or_else(err)?,
            }),
            AuthType::Worldpayvantiv(worldpayvantiv) => Ok(Self::Worldpayvantiv {
                user: worldpayvantiv.user.ok_or_else(err)?,
                password: worldpayvantiv.password.ok_or_else(err)?,
                merchant_id: worldpayvantiv.merchant_id.ok_or_else(err)?,
            }),
            AuthType::Xendit(xendit) => Ok(Self::Xendit {
                api_key: xendit.api_key.ok_or_else(err)?,
            }),
            AuthType::Phonepe(phonepe) => Ok(Self::Phonepe {
                merchant_id: phonepe.merchant_id.ok_or_else(err)?,
                salt_key: phonepe.salt_key.ok_or_else(err)?,
                salt_index: phonepe.salt_index.ok_or_else(err)?,
            }),
            AuthType::Cashfree(cashfree) => Ok(Self::Cashfree {
                app_id: cashfree.app_id.ok_or_else(err)?,
                secret_key: cashfree.secret_key.ok_or_else(err)?,
            }),
            AuthType::Paytm(paytm) => Ok(Self::Paytm {
                merchant_id: paytm.merchant_id.ok_or_else(err)?,
                merchant_key: paytm.merchant_key.ok_or_else(err)?,
                website: paytm.website.ok_or_else(err)?,
                client_id: paytm.client_id,
            }),
            AuthType::Calida(calida) => Ok(Self::Calida {
                api_key: calida.api_key.ok_or_else(err)?,
            }),
            AuthType::Payload(payload) => Ok(Self::Payload {
                api_key: payload.api_key.ok_or_else(err)?,
                processing_account_id: payload.processing_account_id,
            }),
            AuthType::Authipay(authipay) => Ok(Self::Authipay {
                api_key: authipay.api_key.ok_or_else(err)?,
                api_secret: authipay.api_secret.ok_or_else(err)?,
            }),
            AuthType::Silverflow(silverflow) => Ok(Self::Silverflow {
                api_key: silverflow.api_key.ok_or_else(err)?,
                api_secret: silverflow.api_secret.ok_or_else(err)?,
                merchant_acceptor_key: silverflow.merchant_acceptor_key.ok_or_else(err)?,
            }),
            AuthType::Celero(celero) => Ok(Self::Celero {
                api_key: celero.api_key.ok_or_else(err)?,
            }),
            AuthType::Trustpayments(trustpayments) => Ok(Self::Trustpayments {
                username: trustpayments.username.ok_or_else(err)?,
                password: trustpayments.password.ok_or_else(err)?,
                site_reference: trustpayments.site_reference.ok_or_else(err)?,
            }),
            AuthType::Paysafe(paysafe) => Ok(Self::Paysafe {
                username: paysafe.username.ok_or_else(err)?,
                password: paysafe.password.ok_or_else(err)?,
            }),
            AuthType::Barclaycard(barclaycard) => Ok(Self::Barclaycard {
                api_key: barclaycard.api_key.ok_or_else(err)?,
                merchant_account: barclaycard.merchant_account.ok_or_else(err)?,
                api_secret: barclaycard.api_secret.ok_or_else(err)?,
            }),
            AuthType::Worldpayxml(worldpayxml) => Ok(Self::Worldpayxml {
                api_username: worldpayxml.api_username.ok_or_else(err)?,
                api_password: worldpayxml.api_password.ok_or_else(err)?,
                merchant_code: worldpayxml.merchant_code.ok_or_else(err)?,
            }),
            AuthType::Revolut(revolut) => Ok(Self::Revolut {
                api_key: revolut.api_key.ok_or_else(err)?,
            }),
            AuthType::Loonio(loonio) => Ok(Self::Loonio {
                merchant_id: loonio.merchant_id.ok_or_else(err)?,
                merchant_token: loonio.merchant_token.ok_or_else(err)?,
            }),
            AuthType::Gigadat(gigadat) => Ok(Self::Gigadat {
                security_token: gigadat.security_token.ok_or_else(err)?,
                access_token: gigadat.access_token.ok_or_else(err)?,
                campaign_id: gigadat.campaign_id.ok_or_else(err)?,
            }),
            AuthType::Hyperpg(hyperpg) => Ok(Self::Hyperpg {
                username: hyperpg.username.ok_or_else(err)?,
                password: hyperpg.password.ok_or_else(err)?,
                merchant_id: hyperpg.merchant_id.ok_or_else(err)?,
            }),
            AuthType::Zift(zift) => Ok(Self::Zift {
                user_name: zift.user_name.ok_or_else(err)?,
                password: zift.password.ok_or_else(err)?,
                account_id: zift.account_id.ok_or_else(err)?,
            }),
            AuthType::Screenstream(screenstream) => Ok(Self::Screenstream {
                api_key: screenstream.api_key.ok_or_else(err)?,
            }),
            AuthType::Ebanx(ebanx) => Ok(Self::Ebanx {
                api_key: ebanx.api_key.ok_or_else(err)?,
            }),
            AuthType::Fiuu(fiuu) => Ok(Self::Fiuu {
                merchant_id: fiuu.merchant_id.ok_or_else(err)?,
                verify_key: fiuu.verify_key.ok_or_else(err)?,
                secret_key: fiuu.secret_key.ok_or_else(err)?,
            }),
            AuthType::Globepay(globepay) => Ok(Self::Globepay {
                api_key: globepay.api_key.ok_or_else(err)?,
            }),
            AuthType::Coinbase(coinbase) => Ok(Self::Coinbase {
                api_key: coinbase.api_key.ok_or_else(err)?,
            }),
            AuthType::Coingate(coingate) => Ok(Self::Coingate {
                api_key: coingate.api_key.ok_or_else(err)?,
            }),
            AuthType::Revolv3(revolv3) => Ok(Self::Revolv3 {
                api_key: revolv3.api_key.ok_or_else(err)?,
            }),
        }
    }
}

impl ForeignTryFrom<(&ConnectorAuthType, &crate::connector_types::ConnectorEnum)>
    for ConnectorSpecificAuth
{
    type Error = crate::errors::ConnectorError;

    fn foreign_try_from(
        (auth, connector): (&ConnectorAuthType, &crate::connector_types::ConnectorEnum),
    ) -> Result<Self, Error> {
        use crate::connector_types::ConnectorEnum;

        let err = || crate::errors::ConnectorError::FailedToObtainAuthType;

        match connector {
            // --- HeaderKey connectors ---
            ConnectorEnum::Stripe => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Stripe {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Calida => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Calida {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Celero => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Celero {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Helcim => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Helcim {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Mifinity => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Mifinity {
                    key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Multisafepay => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Multisafepay {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Nexixpay => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Nexixpay {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Revolut => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Revolut {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Shift4 => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Shift4 {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Stax => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Stax {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Xendit => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Xendit {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            // Razorpay supports both HeaderKey and BodyKey
            ConnectorEnum::Razorpay => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Razorpay {
                    api_key: api_key.clone(),
                    api_secret: None,
                }),
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Razorpay {
                    api_key: api_key.clone(),
                    api_secret: Some(key1.clone()),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::RazorpayV2 => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::RazorpayV2 {
                    api_key: api_key.clone(),
                    api_secret: None,
                }),
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::RazorpayV2 {
                    api_key: api_key.clone(),
                    api_secret: Some(key1.clone()),
                }),
                _ => Err(err().into()),
            },

            // --- BodyKey connectors ---
            ConnectorEnum::Aci => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Aci {
                    api_key: api_key.clone(),
                    entity_id: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Airwallex => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Airwallex {
                    api_key: api_key.clone(),
                    client_id: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Authorizedotnet => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Authorizedotnet {
                    name: api_key.clone(),
                    transaction_key: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Bambora => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Bambora {
                    merchant_id: key1.clone(),
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Billwerk => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Billwerk {
                    api_key: api_key.clone(),
                    public_api_key: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Bluesnap => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Bluesnap {
                    username: key1.clone(),
                    password: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Cashfree => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Cashfree {
                    app_id: key1.clone(),
                    secret_key: api_key.clone(),
                }),
                ConnectorAuthType::SignatureKey {
                    api_key: _,
                    key1,
                    api_secret,
                } => Ok(Self::Cashfree {
                    app_id: key1.clone(),
                    secret_key: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Cryptopay => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Cryptopay {
                    api_key: api_key.clone(),
                    api_secret: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Datatrans => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Datatrans {
                    merchant_id: key1.clone(),
                    password: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Globalpay => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Globalpay {
                    app_id: key1.clone(),
                    app_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Hipay => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Hipay {
                    api_key: api_key.clone(),
                    api_secret: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Jpmorgan => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Jpmorgan {
                    client_id: api_key.clone(),
                    client_secret: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Loonio => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Loonio {
                    merchant_id: api_key.clone(),
                    merchant_token: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Paysafe => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Paysafe {
                    username: api_key.clone(),
                    password: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Payu => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Payu {
                    api_key: api_key.clone(),
                    api_secret: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Placetopay => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Placetopay {
                    login: api_key.clone(),
                    tran_key: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Powertranz => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Powertranz {
                    power_tranz_id: key1.clone(),
                    power_tranz_password: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Rapyd => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Rapyd {
                    access_key: api_key.clone(),
                    secret_key: key1.clone(),
                }),
                _ => Err(err().into()),
            },

            // --- Connectors supporting both BodyKey and SignatureKey ---
            ConnectorEnum::Adyen => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Adyen {
                    api_key: api_key.clone(),
                    merchant_account: key1.clone(),
                    review_key: None,
                }),
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Adyen {
                    api_key: api_key.clone(),
                    merchant_account: key1.clone(),
                    review_key: Some(api_secret.clone()),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Authipay => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Authipay {
                    api_key: api_key.clone(),
                    api_secret: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Fiservemea => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Fiservemea {
                    api_key: api_key.clone(),
                    api_secret: key1.clone(),
                }),
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1: _,
                    api_secret,
                } => Ok(Self::Fiservemea {
                    api_key: api_key.clone(),
                    api_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Mollie => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Mollie {
                    api_key: api_key.clone(),
                    profile_token: Some(key1.clone()),
                }),
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Mollie {
                    api_key: api_key.clone(),
                    profile_token: None,
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Nmi => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Nmi {
                    api_key: api_key.clone(),
                    public_key: None,
                }),
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Nmi {
                    api_key: api_key.clone(),
                    public_key: Some(key1.clone()),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Payme => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Payme {
                    seller_payme_id: api_key.clone(),
                    payme_client_key: Some(key1.clone()),
                }),
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret: _,
                } => Ok(Self::Payme {
                    seller_payme_id: api_key.clone(),
                    payme_client_key: Some(key1.clone()),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Nexinets => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Nexinets {
                    merchant_id: key1.clone(),
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },

            // --- SignatureKey connectors ---
            ConnectorEnum::Bankofamerica => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::BankOfAmerica {
                    api_key: api_key.clone(),
                    merchant_account: key1.clone(),
                    api_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Bamboraapac => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Bamboraapac {
                    username: api_key.clone(),
                    password: api_secret.clone(),
                    account_number: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Barclaycard => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Barclaycard {
                    api_key: api_key.clone(),
                    merchant_account: key1.clone(),
                    api_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Braintree => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1: _,
                    api_secret,
                } => Ok(Self::Braintree {
                    public_key: api_key.clone(),
                    private_key: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Checkout => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Checkout {
                    api_key: api_key.clone(),
                    api_secret: api_secret.clone(),
                    processing_channel_id: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Cybersource => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Cybersource {
                    api_key: api_key.clone(),
                    merchant_account: key1.clone(),
                    api_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Dlocal => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Dlocal {
                    x_login: api_key.clone(),
                    x_trans_key: key1.clone(),
                    secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Elavon => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Elavon {
                    ssl_merchant_id: api_key.clone(),
                    ssl_user_id: key1.clone(),
                    ssl_pin: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Fiserv => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Fiserv {
                    api_key: api_key.clone(),
                    merchant_account: key1.clone(),
                    api_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Fiuu => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Fiuu {
                    merchant_id: key1.clone(),
                    verify_key: api_key.clone(),
                    secret_key: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Getnet => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Getnet {
                    api_key: api_key.clone(),
                    api_secret: api_secret.clone(),
                    seller_id: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Gigadat => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Gigadat {
                    security_token: api_secret.clone(),
                    access_token: api_key.clone(),
                    campaign_id: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Hyperpg => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Hyperpg {
                    username: api_key.clone(),
                    password: key1.clone(),
                    merchant_id: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Iatapay => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Iatapay {
                    client_id: api_key.clone(),
                    merchant_id: key1.clone(),
                    client_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Noon => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Noon {
                    api_key: api_key.clone(),
                    business_identifier: key1.clone(),
                    application_identifier: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Novalnet => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Novalnet {
                    product_activation_key: api_key.clone(),
                    payment_access_key: key1.clone(),
                    tariff_id: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Nuvei => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Nuvei {
                    merchant_id: api_key.clone(),
                    merchant_site_id: key1.clone(),
                    merchant_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Phonepe => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Phonepe {
                    merchant_id: api_key.clone(),
                    salt_key: key1.clone(),
                    salt_index: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Redsys => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Redsys {
                    merchant_id: api_key.clone(),
                    terminal_id: key1.clone(),
                    sha256_pwd: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Silverflow => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Silverflow {
                    api_key: api_key.clone(),
                    api_secret: api_secret.clone(),
                    merchant_acceptor_key: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Trustpay => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Trustpay {
                    api_key: api_key.clone(),
                    project_id: key1.clone(),
                    secret_key: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Trustpayments => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Trustpayments {
                    username: api_key.clone(),
                    password: key1.clone(),
                    site_reference: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Tsys => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Tsys {
                    device_id: api_key.clone(),
                    transaction_key: key1.clone(),
                    developer_id: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Wellsfargo => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Wellsfargo {
                    api_key: api_key.clone(),
                    merchant_account: key1.clone(),
                    api_secret: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Worldpay => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Worldpay {
                    username: key1.clone(),
                    password: api_key.clone(),
                    entity_id: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Worldpayvantiv => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Worldpayvantiv {
                    user: api_key.clone(),
                    password: api_secret.clone(),
                    merchant_id: key1.clone(),
                }),
                ConnectorAuthType::MultiAuthKey {
                    api_key,
                    key1,
                    api_secret,
                    key2: _,
                } => Ok(Self::Worldpayvantiv {
                    user: api_key.clone(),
                    password: api_secret.clone(),
                    merchant_id: key1.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Worldpayxml => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Worldpayxml {
                    api_username: api_key.clone(),
                    api_password: key1.clone(),
                    merchant_code: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Zift => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Zift {
                    user_name: api_key.clone(),
                    password: api_secret.clone(),
                    account_id: key1.clone(),
                }),
                _ => Err(err().into()),
            },

            // --- Paypal (BodyKey or SignatureKey) ---
            ConnectorEnum::Paypal => match auth {
                ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::Paypal {
                    client_id: key1.clone(),
                    client_secret: api_key.clone(),
                    payer_id: None,
                }),
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Paypal {
                    client_id: key1.clone(),
                    client_secret: api_key.clone(),
                    payer_id: Some(api_secret.clone()),
                }),
                _ => Err(err().into()),
            },

            // --- MultiAuthKey connectors ---
            ConnectorEnum::Forte => match auth {
                ConnectorAuthType::MultiAuthKey {
                    api_key,
                    key1,
                    api_secret,
                    key2,
                } => Ok(Self::Forte {
                    api_access_id: api_key.clone(),
                    organization_id: key1.clone(),
                    location_id: key2.clone(),
                    api_secret_key: api_secret.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Paybox => match auth {
                ConnectorAuthType::MultiAuthKey {
                    api_key,
                    key1,
                    api_secret,
                    key2,
                } => Ok(Self::Paybox {
                    site: api_key.clone(),
                    rank: key1.clone(),
                    key: api_secret.clone(),
                    merchant_id: key2.clone(),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Paytm => match auth {
                ConnectorAuthType::SignatureKey {
                    api_key,
                    key1,
                    api_secret,
                } => Ok(Self::Paytm {
                    merchant_id: api_key.clone(),
                    merchant_key: key1.clone(),
                    website: api_secret.clone(),
                    client_id: None,
                }),
                ConnectorAuthType::MultiAuthKey {
                    api_key,
                    key1,
                    api_secret,
                    key2,
                } => Ok(Self::Paytm {
                    merchant_id: api_key.clone(),
                    merchant_key: key1.clone(),
                    website: api_secret.clone(),
                    client_id: Some(key2.clone()),
                }),
                _ => Err(err().into()),
            },
            ConnectorEnum::Volt => match auth {
                ConnectorAuthType::MultiAuthKey {
                    api_key,
                    key1,
                    api_secret,
                    key2,
                } => Ok(Self::Volt {
                    username: api_key.clone(),
                    password: api_secret.clone(),
                    client_id: key1.clone(),
                    client_secret: key2.clone(),
                }),
                _ => Err(err().into()),
            },

            // --- CurrencyAuthKey connectors ---
            ConnectorEnum::Cashtocode => Ok(Self::Cashtocode {
                password_classic: None,
                password_evoucher: None,
                username_classic: None,
                username_evoucher: None,
            }),
            ConnectorEnum::Payload => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Payload {
                    api_key: api_key.clone(),
                    processing_account_id: None,
                }),
                _ => Ok(Self::Payload {
                    api_key: Secret::new(String::new()),
                    processing_account_id: None,
                }),
            },
            ConnectorEnum::Revolv3 => match auth {
                ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Revolv3 {
                    api_key: api_key.clone(),
                }),
                _ => Err(err().into()),
            },
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub status_code: u16,
    pub attempt_status: Option<common_enums::enums::AttemptStatus>,
    pub connector_transaction_id: Option<String>,
    pub network_decline_code: Option<String>,
    pub network_advice_code: Option<String>,
    pub network_error_message: Option<String>,
}

impl Default for ErrorResponse {
    fn default() -> Self {
        Self {
            code: "HE_00".to_string(),
            message: "Something went wrong".to_string(),
            reason: None,
            status_code: http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        }
    }
}

impl ErrorResponse {
    /// Returns attempt status for gRPC response
    ///
    /// For 2xx: If attempt_status is None, use fallback (router_data.status set by connector)
    /// For 4xx/5xx: If attempt_status is None, return None
    pub fn get_attempt_status_for_grpc(
        &self,
        http_status_code: u16,
        fallback_status: common_enums::enums::AttemptStatus,
    ) -> Option<common_enums::enums::AttemptStatus> {
        self.attempt_status.or_else(|| {
            if (200..300).contains(&http_status_code) {
                Some(fallback_status)
            } else {
                None
            }
        })
    }

    pub fn get_not_implemented() -> Self {
        Self {
            code: "IR_00".to_string(),
            message: "This API is under development and will be made available soon.".to_string(),
            reason: None,
            status_code: http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayCryptogramData {
    pub online_payment_cryptogram: Secret<String>,
    pub eci_indicator: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeDecryptedData {
    pub client_id: Secret<String>,
    pub profile_id: String,
    pub token: PazeToken,
    pub payment_card_network: common_enums::enums::CardNetwork,
    pub dynamic_data: Vec<PazeDynamicData>,
    pub billing_address: PazeAddress,
    pub consumer: PazeConsumer,
    pub eci: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeToken {
    pub payment_token: cards::NetworkToken,
    pub token_expiration_month: Secret<String>,
    pub token_expiration_year: Secret<String>,
    pub payment_account_reference: Secret<String>,
}

pub type NetworkTokenNumber = NetworkToken;

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeConsumer {
    // This is consumer data not customer data.
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub full_name: Secret<String>,
    pub email_address: common_utils::pii::Email,
    pub mobile_number: Option<PazePhoneNumber>,
    pub country_code: Option<common_enums::enums::CountryAlpha2>,
    pub language_code: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PazePhoneNumber {
    pub country_code: Secret<String>,
    pub phone_number: Secret<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeAddress {
    pub name: Option<Secret<String>>,
    pub line1: Option<Secret<String>>,
    pub line2: Option<Secret<String>>,
    pub line3: Option<Secret<String>>,
    pub city: Option<Secret<String>>,
    pub state: Option<Secret<String>>,
    pub zip: Option<Secret<String>>,
    pub country_code: Option<common_enums::enums::CountryAlpha2>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PazeDynamicData {
    pub dynamic_data_value: Option<Secret<String>>,
    pub dynamic_data_type: Option<String>,
    pub dynamic_data_expiration: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub enum PaymentMethodToken {
    Token(Secret<String>),
}

#[derive(Debug, Default, Clone)]
pub struct RecurringMandatePaymentData {
    pub payment_method_type: Option<common_enums::enums::PaymentMethodType>, //required for making recurring payment using saved payment method through stripe
    pub original_payment_authorized_amount: Option<MinorUnit>,
    pub original_payment_authorized_currency: Option<common_enums::enums::Currency>,
    pub mandate_metadata: Option<common_utils::pii::SecretSerdeValue>,
}

impl RecurringMandatePaymentData {
    pub fn get_original_payment_amount(&self) -> Result<MinorUnit, Error> {
        self.original_payment_authorized_amount
            .ok_or_else(missing_field_err("original_payment_authorized_amount"))
    }
    pub fn get_original_payment_currency(&self) -> Result<common_enums::Currency, Error> {
        self.original_payment_authorized_currency
            .ok_or_else(missing_field_err("original_payment_authorized_currency"))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectorResponseData {
    pub additional_payment_method_data: Option<AdditionalPaymentMethodConnectorResponse>,
    extended_authorization_response_data: Option<ExtendedAuthorizationResponseData>,
    is_overcapture_enabled: Option<bool>,
}

impl ConnectorResponseData {
    pub fn with_auth_code(auth_code: String, pmt: common_enums::PaymentMethodType) -> Self {
        let additional_payment_method_data = match pmt {
            common_enums::PaymentMethodType::GooglePay => {
                AdditionalPaymentMethodConnectorResponse::GooglePay {
                    auth_code: Some(auth_code),
                }
            }
            common_enums::PaymentMethodType::ApplePay => {
                AdditionalPaymentMethodConnectorResponse::ApplePay {
                    auth_code: Some(auth_code),
                }
            }
            _ => AdditionalPaymentMethodConnectorResponse::Card {
                authentication_data: None,
                payment_checks: None,
                card_network: None,
                domestic_network: None,
                auth_code: Some(auth_code),
            },
        };
        Self {
            additional_payment_method_data: Some(additional_payment_method_data),
            extended_authorization_response_data: None,
            is_overcapture_enabled: None,
        }
    }
    pub fn with_additional_payment_method_data(
        additional_payment_method_data: AdditionalPaymentMethodConnectorResponse,
    ) -> Self {
        Self {
            additional_payment_method_data: Some(additional_payment_method_data),
            extended_authorization_response_data: None,
            is_overcapture_enabled: None,
        }
    }
    pub fn new(
        additional_payment_method_data: Option<AdditionalPaymentMethodConnectorResponse>,
        is_overcapture_enabled: Option<bool>,
        extended_authorization_response_data: Option<ExtendedAuthorizationResponseData>,
    ) -> Self {
        Self {
            additional_payment_method_data,
            extended_authorization_response_data,
            is_overcapture_enabled,
        }
    }

    pub fn get_extended_authorization_response_data(
        &self,
    ) -> Option<&ExtendedAuthorizationResponseData> {
        self.extended_authorization_response_data.as_ref()
    }

    pub fn is_overcapture_enabled(&self) -> Option<bool> {
        self.is_overcapture_enabled
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AdditionalPaymentMethodConnectorResponse {
    Card {
        /// Details regarding the authentication details of the connector, if this is a 3ds payment.
        authentication_data: Option<serde_json::Value>,
        /// Various payment checks that are done for a payment
        payment_checks: Option<serde_json::Value>,
        /// Card Network returned by the processor
        card_network: Option<String>,
        /// Domestic(Co-Branded) Card network returned by the processor
        domestic_network: Option<String>,
        /// auth code returned by the processor
        auth_code: Option<String>,
    },
    Upi {
        /// UPI source detected from the connector response
        upi_mode: Option<payment_method_data::UpiSource>,
    },
    GooglePay {
        auth_code: Option<String>,
    },
    ApplePay {
        auth_code: Option<String>,
    },
    BankRedirect {
        interac: Option<InteracCustomerInfo>,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtendedAuthorizationResponseData {
    pub extended_authentication_applied: Option<bool>,
    pub extended_authorization_last_applied_at: Option<time::PrimitiveDateTime>,
    pub capture_before: Option<time::PrimitiveDateTime>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InteracCustomerInfo {
    pub customer_info: Option<payment_method_data::CustomerInfoDetails>,
}
