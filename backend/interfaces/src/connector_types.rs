use std::collections::HashSet;

use crate::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, errors::ConnectorError,
};
use common_enums::{AttemptStatus, CaptureMethod, PaymentMethod, PaymentMethodType};
use common_utils::{CustomResult, SecretSerdeValue};
use domain_types::{
    connector_flow,
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, DisputeWebhookDetailsResponse, EventType,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundWebhookDetailsResponse, RefundsData,
        RefundsResponseData, RequestDetails, SetupMandateRequestData, SubmitEvidenceData,
        WebhookDetailsResponse,
    },
    payment_method_data::PaymentMethodData,
    router_data::ConnectorAuthType,
    types::{PaymentMethodDataType, PaymentMethodDetails, SupportedPaymentMethods},
};
use error_stack::ResultExt;

pub trait ConnectorServiceTrait:
    ConnectorCommon
    + ValidationTrait
    + PaymentAuthorizeV2
    + PaymentSyncV2
    + PaymentOrderCreate
    + PaymentVoidV2
    + IncomingWebhook
    + RefundV2
    + PaymentCapture
    + SetupMandateV2
    + AcceptDispute
    + RefundSyncV2
    + DisputeDefend
    + SubmitEvidenceV2
{
}

pub trait PaymentVoidV2:
    ConnectorIntegrationV2<
    domain_types::connector_flow::Void,
    PaymentFlowData,
    PaymentVoidData,
    PaymentsResponseData,
>
{
}

pub type BoxedConnector = Box<&'static (dyn ConnectorServiceTrait + Sync)>;

pub trait ValidationTrait {
    fn should_do_order_create(&self) -> bool {
        false
    }
}

pub trait PaymentOrderCreate:
    ConnectorIntegrationV2<
    connector_flow::CreateOrder,
    PaymentFlowData,
    PaymentCreateOrderData,
    PaymentCreateOrderResponse,
>
{
}

pub trait PaymentAuthorizeV2:
    ConnectorIntegrationV2<
    domain_types::connector_flow::Authorize,
    PaymentFlowData,
    PaymentsAuthorizeData,
    PaymentsResponseData,
>
{
}

pub trait PaymentSyncV2:
    ConnectorIntegrationV2<
    domain_types::connector_flow::PSync,
    PaymentFlowData,
    PaymentsSyncData,
    PaymentsResponseData,
>
{
}

pub trait RefundV2:
    ConnectorIntegrationV2<
    domain_types::connector_flow::Refund,
    RefundFlowData,
    RefundsData,
    RefundsResponseData,
>
{
}

pub trait RefundSyncV2:
    ConnectorIntegrationV2<
    domain_types::connector_flow::RSync,
    RefundFlowData,
    RefundSyncData,
    RefundsResponseData,
>
{
}

pub trait PaymentCapture:
    ConnectorIntegrationV2<
    domain_types::connector_flow::Capture,
    PaymentFlowData,
    PaymentsCaptureData,
    PaymentsResponseData,
>
{
}

pub trait SetupMandateV2:
    ConnectorIntegrationV2<
    domain_types::connector_flow::SetupMandate,
    PaymentFlowData,
    SetupMandateRequestData,
    PaymentsResponseData,
>
{
}

pub trait AcceptDispute:
    ConnectorIntegrationV2<
    domain_types::connector_flow::Accept,
    DisputeFlowData,
    AcceptDisputeData,
    DisputeResponseData,
>
{
}

pub trait SubmitEvidenceV2:
    ConnectorIntegrationV2<
    domain_types::connector_flow::SubmitEvidence,
    DisputeFlowData,
    SubmitEvidenceData,
    DisputeResponseData,
>
{
}

pub trait DisputeDefend:
    ConnectorIntegrationV2<
    domain_types::connector_flow::DefendDispute,
    DisputeFlowData,
    DisputeDefendData,
    DisputeResponseData,
>
{
}

pub trait IncomingWebhook {
    fn verify_webhook_source(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, error_stack::Report<ConnectorError>> {
        Ok(false)
    }

    fn get_event_type(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<EventType, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("get_event_type".to_string()).into())
    }

    fn process_payment_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<WebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("process_payment_webhook".to_string()).into())
    }

    fn process_refund_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<RefundWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("process_refund_webhook".to_string()).into())
    }
    fn process_dispute_webhook(
        &self,
        _request: RequestDetails,
        _connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<DisputeWebhookDetailsResponse, error_stack::Report<ConnectorError>> {
        Err(ConnectorError::NotImplemented("process_dispute_webhook".to_string()).into())
    }
}

/// trait ConnectorValidation
pub trait ConnectorValidation: ConnectorCommon + ConnectorSpecifications {
    /// Validate, the payment request against the connector supported features
    fn validate_connector_against_payment_request(
        &self,
        capture_method: Option<CaptureMethod>,
        payment_method: PaymentMethod,
        pmt: Option<common_enums::PaymentMethodType>,
    ) -> CustomResult<(), ConnectorError> {
        let capture_method = capture_method.unwrap_or_default();
        let is_default_capture_method = [CaptureMethod::Automatic].contains(&capture_method);
        let is_feature_supported = match self.get_supported_payment_methods() {
            Some(supported_payment_methods) => {
                let connector_payment_method_type_info = get_connector_payment_method_type_info(
                    supported_payment_methods,
                    payment_method,
                    pmt,
                    self.id(),
                )?;

                connector_payment_method_type_info
                    .map(|payment_method_type_info| {
                        payment_method_type_info
                            .supported_capture_methods
                            .contains(&capture_method)
                    })
                    .unwrap_or(true)
            }
            None => is_default_capture_method,
        };

        if is_feature_supported {
            Ok(())
        } else {
            Err(ConnectorError::NotSupported {
                message: capture_method.to_string(),
                connector: self.id(),
            }
            .into())
        }
    }

    /// fn validate_mandate_payment
    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        _pm_data: PaymentMethodData,
    ) -> CustomResult<(), ConnectorError> {
        let connector = self.id();
        match pm_type {
            Some(pm_type) => Err(ConnectorError::NotSupported {
                message: format!("{pm_type} mandate payment"),
                connector,
            }
            .into()),
            None => Err(ConnectorError::NotSupported {
                message: " mandate payment".to_string(),
                connector,
            }
            .into()),
        }
    }

    /// fn validate_psync_reference_id
    fn validate_psync_reference_id(
        &self,
        data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<SecretSerdeValue>,
    ) -> CustomResult<(), ConnectorError> {
        data.connector_transaction_id
            .get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)
            .map(|_| ())
    }

    /// fn is_webhook_source_verification_mandatory
    fn is_webhook_source_verification_mandatory(&self) -> bool {
        false
    }
}

fn get_connector_payment_method_type_info(
    supported_payment_method: &SupportedPaymentMethods,
    payment_method: PaymentMethod,
    payment_method_type: Option<PaymentMethodType>,
    connector: &'static str,
) -> CustomResult<Option<PaymentMethodDetails>, ConnectorError> {
    let payment_method_details =
        supported_payment_method
            .get(&payment_method)
            .ok_or_else(|| ConnectorError::NotSupported {
                message: payment_method.to_string(),
                connector,
            })?;

    payment_method_type
        .map(|pmt| {
            payment_method_details.get(&pmt).cloned().ok_or_else(|| {
                ConnectorError::NotSupported {
                    message: format!("{payment_method} {pmt}"),
                    connector,
                }
                .into()
            })
        })
        .transpose()
}

pub fn is_mandate_supported(
    selected_pmd: PaymentMethodData,
    payment_method_type: Option<PaymentMethodType>,
    mandate_implemented_pmds: HashSet<PaymentMethodDataType>,
    connector: &'static str,
) -> Result<(), error_stack::Report<ConnectorError>> {
    if mandate_implemented_pmds.contains(&PaymentMethodDataType::from(selected_pmd.clone())) {
        Ok(())
    } else {
        match payment_method_type {
            Some(pm_type) => Err(ConnectorError::NotSupported {
                message: format!("{pm_type} mandate payment"),
                connector,
            }
            .into()),
            None => Err(ConnectorError::NotSupported {
                message: "mandate payment".to_string(),
                connector,
            }
            .into()),
        }
    }
}
