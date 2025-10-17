pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorSpecifications, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::{AmountConverterTrait, ConnectorAuthType},
};
use error_stack::ResultExt;

use crate::{
    core::errors::{self, ConnectorError},
    services::{
        self,
        connector::ConnectorCommon,
        request as connector_request,
        ConnectorIntegrationV2, ConnectorValidation, PaymentAuthorizeV2, PaymentSyncV2,
        RefundSyncV2,
    },
    types::ResponseId,
};

// Create all prerequisites using the mandatory macro framework
macros::create_all_prerequisites!(
    connector_name: EaseBuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: transformers::EaseBuzzPaymentsRequest,
            response_body: transformers::EaseBuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: transformers::EaseBuzzPaymentsSyncRequest,
            response_body: transformers::EaseBuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: RSync,
            request_body: transformers::EaseBuzzRefundSyncRequest,
            response_body: transformers::EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        fn get_api_tag(&self) -> &'static str {
            "EaseBuzz"
        }

        fn get_content_type(&self) -> &'static str {
            "application/x-www-form-urlencoded"
        }

        fn get_error_response_v2(
            &self,
            response: &[u8],
        ) -> CustomResult<transformers::EaseBuzzErrorResponse, errors::ConnectorError> {
            self.handle_error_response(response)
        }

        fn handle_error_response(
            &self,
            response: &[u8],
        ) -> CustomResult<transformers::EaseBuzzErrorResponse, errors::ConnectorError> {
            let error_response: transformers::EaseBuzzErrorResponse = response
                .parse_struct("EaseBuzzErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            Ok(error_response)
        }
    }
);

// Implement the connector using the mandatory macro framework
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(transformers::EaseBuzzPaymentsRequest),
    curl_response: transformers::EaseBuzzPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let auth = transformers::get_auth_header(&req.connector_auth_type)?;
            let request = transformers::EaseBuzzPaymentsRequest::try_from(req)?;
            let request_body = RequestContent::Form(request);
            let request = connector_request::build_request(
                &self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
                &self.get_authorize_endpoint(),
                request_body,
                Some(auth),
                vec![],
                None,
                None,
            )?;
            Ok(Some(request))
        }

        fn get_authorize_endpoint(&self) -> &'static str {
            constants::ENDPOINT_SEAMLESS_TRANSACTION
        }

        fn get_base_url(&self, test_mode: bool) -> &'static str {
            if test_mode {
                constants::BASE_URL_TEST
            } else {
                constants::BASE_URL_PRODUCTION
            }
        }
    }
);

// Implement PSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(transformers::EaseBuzzPaymentsSyncRequest),
    curl_response: transformers::EaseBuzzPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let auth = transformers::get_auth_header(&req.connector_auth_type)?;
            let request = transformers::EaseBuzzPaymentsSyncRequest::try_from(req)?;
            let request_body = RequestContent::Form(request);
            let request = connector_request::build_request(
                &self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
                &self.get_sync_endpoint(),
                request_body,
                Some(auth),
                vec![],
                None,
                None,
            )?;
            Ok(Some(request))
        }

        fn get_sync_endpoint(&self) -> &'static str {
            constants::ENDPOINT_TXN_SYNC
        }
    }
);

// Implement RSync flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Form(transformers::EaseBuzzRefundSyncRequest),
    curl_response: transformers::EaseBuzzRefundSyncResponse,
    flow_name: RSync,
    resource_common_data: PaymentFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize],
    other_functions: {
        fn build_request_v2(
            &self,
            req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
            let auth = transformers::get_auth_header(&req.connector_auth_type)?;
            let request = transformers::EaseBuzzRefundSyncRequest::try_from(req)?;
            let request_body = RequestContent::Form(request);
            let request = connector_request::build_request(
                &self.get_base_url(req.resource_common_data.test_mode.unwrap_or(false)),
                &self.get_refund_sync_endpoint(),
                request_body,
                Some(auth),
                vec![],
                None,
                None,
            )?;
            Ok(Some(request))
        }

        fn get_refund_sync_endpoint(&self) -> &'static str {
            constants::ENDPOINT_REFUND_SYNC
        }
    }
);

// Implement ConnectorCommon trait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn get_connector_name(&self) -> &'static str {
        "EaseBuzz"
    }

    fn get_connector_version(&self) -> &'static str {
        "1.0.0"
    }

    fn get_connector_specifications(&self) -> ConnectorSpecifications {
        ConnectorSpecifications {
            connector_name: "EaseBuzz".to_string(),
            connector_type: domain_types::enums::ConnectorType::PaymentGateway,
            supported_payment_methods: vec![
                PaymentMethodType::Upi,
                PaymentMethodType::UpiCollect,
                PaymentMethodType::UpiIntent,
            ],
            supported_flows: vec![
                domain_types::enums::PaymentFlow::Authorize,
                domain_types::enums::PaymentFlow::PaymentSync,
                domain_types::enums::PaymentFlow::RefundSync,
            ],
            supported_currencies: vec![
                common_enums::Currency::INR,
            ],
            supported_countries: vec![
                common_enums::Country::IN,
            ],
            supports_three_ds: false,
            supports_webhooks: true,
            supports_refunds: true,
            supports_mandates: true,
            supports_tokenization: false,
            supports_recurring: true,
            supports_card_vaulting: false,
            supports_network_tokenization: false,
            supports_apple_pay: false,
            supports_google_pay: false,
            supports_paypal: false,
            supports_amazon_pay: false,
            supports_microsoft_pay: false,
            supports_samsung_pay: false,
            supports_alipay: false,
            supports_wechat_pay: false,
            supports_momo: false,
            supports_zalo_pay: false,
            supports_ideal: false,
            supports_sepa: false,
            supports_sofort: false,
            supports_giropay: false,
            supports_eps: false,
            supports_multibanco: false,
            supports_p24: false,
            supports_klarna: false,
            supports_afterpay: false,
            supports_affirm: false,
            supports_clearpay: false,
            supports_ratepay: false,
            supports_zip: false,
            supports_paybright: false,
            supports_payu: false,
            supports_oxxo: false,
            supports_boleto: false,
            supports_pix: false,
            supports_ach: false,
            supports_echeck: false,
            supports_interac: false,
            supports_mada: false,
            supports_meeza: false,
            supports_fawry: false,
            supports_knet: false,
            supports_naps: false,
            supports_sadad: false,
            supports_uatp: false,
            supports_diners_club: false,
            supports_discover: false,
            supports_jcb: false,
            supports_unionpay: false,
            supports_maestro: false,
            supports_mastercard: false,
            supports_visa: false,
            supports_amex: false,
            supports_cartes_bancaires: false,
            supports_elv: false,
            supports_giropay: false,
            supports_ideal: false,
            supports_interac: false,
            supports_maestro: false,
            supports_masterpass: false,
            supports_paypal: false,
            supports_sepa: false,
            supports_sofort: false,
            supports_visa_checkout: false,
            supports_visa_direct: false,
            supports_visa_verified: false,
            supports_mastercard_id_check: false,
            supports_mastercard_secure_code: false,
            supports_amex_safe_key: false,
            supports_jcb_secure: false,
            supports_diners_club_protect: false,
            supports_unionpay_quick_pass: false,
            supports_visa_token_service: false,
            supports_mastercard_token_service: false,
            supports_amex_token_service: false,
            supports_jcb_token_service: false,
            supports_diners_club_token_service: false,
            supports_unionpay_token_service: false,
            supports_maestro_token_service: false,
            supports_visa_checkout_token_service: false,
            supports_masterpass_token_service: false,
            supports_paypal_token_service: false,
            supports_sepa_token_service: false,
            supports_sofort_token_service: false,
            supports_ideal_token_service: false,
            supports_interac_token_service: false,
            supports_giropay_token_service: false,
            supports_elv_token_service: false,
            supports_cartes_bancaires_token_service: false,
            supports_mada_token_service: false,
            supports_meeza_token_service: false,
            supports_fawry_token_service: false,
            supports_knet_token_service: false,
            supports_naps_token_service: false,
            supports_sadad_token_service: false,
            supports_uatp_token_service: false,
            supports_diners_club_token_service: false,
            supports_discover_token_service: false,
            supports_jcb_token_service: false,
            supports_unionpay_token_service: false,
            supports_maestro_token_service: false,
            supports_mastercard_token_service: false,
            supports_visa_token_service: false,
            supports_amex_token_service: false,
            supports_cartes_bancaires_token_service: false,
            supports_elv_token_service: false,
            supports_giropay_token_service: false,
            supports_ideal_token_service: false,
            supports_interac_token_service: false,
            supports_maestro_token_service: false,
            supports_masterpass_token_service: false,
            supports_paypal_token_service: false,
            supports_sepa_token_service: false,
            supports_sofort_token_service: false,
            supports_visa_checkout_token_service: false,
            supports_visa_direct_token_service: false,
            supports_visa_verified_token_service: false,
            supports_mastercard_id_check_token_service: false,
            supports_mastercard_secure_code_token_service: false,
            supports_amex_safe_key_token_service: false,
            supports_jcb_secure_token_service: false,
            supports_diners_club_protect_token_service: false,
            supports_unionpay_quick_pass_token_service: false,
        }
    }

    fn get_webhook_details(&self) -> ConnectorWebhookSecrets {
        ConnectorWebhookSecrets {
            primary_key: None,
            secondary_key: None,
            webhook_url: None,
            webhook_username: None,
            webhook_password: None,
        }
    }

    fn validate_connector(&self) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

// Implement source verification stubs for all flows
impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
impl_source_verification_stub!(RSync, PaymentFlowData, RefundSyncData, RefundsResponseData);

// Implement connector types traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentAuthorize for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::PaymentSync for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    domain_types::connector_types::RefundSync for EaseBuzz<T> {}