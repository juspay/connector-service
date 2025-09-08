
# Enhanced UCS Connector Conversion Prompt

## Context Setup
Create NotesByXyne.md file to track conversion progress and context for future LLMs.

## Prerequisites
1. Read connector implementation guide: `connectorImplementationGuide.md`
2. Read test generation guide: `ai_generate_test.md`
3. Reference existing UCS connector: Adyen or Checkout for patterns

## Step-by-Step Conversion Process

### Phase 1: Project Setup

#### 1. Update Domain Types
**File: `backend/domain_types/src/connector_types.rs`**
- Add connector to `ConnectorEnum`:
```rust
#[derive(Clone, Copy, Debug, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    // ... existing connectors
    NewConnector, // Add your connector
}
```

- Add to `ForeignTryFrom` implementation:
```rust
grpc_api_types::payments::Connector::NewConnector => Ok(Self::NewConnector),
```

#### 2. Update Types Registration
**File: `backend/connector-integration/src/types.rs`**
- Add import: `use crate::connectors::NewConnector;`
- Add to `convert_connector` match:
```rust
ConnectorEnum::NewConnector => Box::new(NewConnector::new()),
```

#### 3. Update Configuration
**File: `config/development.toml`**
```toml
[connectors]
new_connector.base_url = "https://api.newconnector.com/"
```

### Phase 2: Connector Implementation

#### 4. Create Connector Module
**File: `backend/connector-integration/src/connectors.rs`**
```rust
pub mod new_connector;
pub use self::new_connector::NewConnector;
```

#### 5. Main Connector File Structure
**File: `backend/connector-integration/src/connectors/new_connector.rs`**

```rust
pub mod transformers;

use base64::Engine;
use common_enums::CurrencyUnit;
use common_utils::{
    errors::CustomResult, ext_traits::ByteSliceExt, types::StringMinorUnit,
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, DefendDispute, PSync, RSync, Refund,
        RepeatPayment, SetupMandate, SubmitEvidence, Void, CreateSessionToken,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SetupMandateRequestData, SubmitEvidenceData, SessionTokenRequestData, SessionTokenResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use serde::Serialize;
use std::fmt::Debug;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2, connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use transformers::{
    self as new_connector,
    // Add your request/response structs here
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use error_stack::ResultExt;

pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

// Trait implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for NewConnector<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for NewConnector<T>
{
}

macros::create_all_prerequisites!(
    connector_name: NewConnector,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: NewConnectorPaymentsRequest<T>,
            response_body: NewConnectorPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: NewConnectorSyncRequest,
            response_body: NewConnectorSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: NewConnectorCaptureRequest,
            response_body: NewConnectorCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: NewConnectorVoidRequest,
            response_body: NewConnectorVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: NewConnectorRefundRequest,
            response_body: NewConnectorRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: NewConnectorRSyncRequest,
            response_body: NewConnectorRSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        )
    ],
    amount_converters: [],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            let mut header = vec![(
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            )];
            let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
            header.append(&mut api_key);
            Ok(header)
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.new_connector.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.new_connector.base_url
        }
    }
);

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for NewConnector<T>
{
    fn id(&self) -> &'static str {
        "new_connector"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = new_connector::NewConnectorAuthType::try_from(auth_type)
            .map_err(|_| errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key.peek()).into_masked(),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.new_connector.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: new_connector::NewConnectorErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?;

        with_error_response_body!(event_builder, response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error_code.unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response.message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: response.message,
            attempt_status: None,
            connector_transaction_id: response.transaction_id,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

// Macro implementations for each flow
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: NewConnector,
    curl_request: Json(NewConnectorPaymentsRequest),
    curl_response: NewConnectorPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            self.build_headers(req)
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(format!("{}payments", self.connector_base_url_payments(req)))
        }
    }
);

// Add similar macro implementations for PSync, Capture, Void, Refund, RSync

// Stub implementations for unsupported flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
    for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
    for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
    for NewConnector<T>
{
}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for NewConnector<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for NewConnector<T>
{
}
```

### Phase 3: Transformers Implementation

#### 6. Transformers File Structure
**File: `backend/connector-integration/src/connectors/new_connector/transformers.rs`**

```rust
use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PSync, RSync, RepeatPayment, SetupMandate, Void, Capture},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
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
use strum::Display;

use crate::{connectors::new_connector::NewConnectorRouterData, types::ResponseRouterData};

// Auth Type
pub struct NewConnectorAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for NewConnectorAuthType {
    type Error = domain_types::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

// Request/Response Structs
#[derive(Debug, Serialize)]
pub struct NewConnectorPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: NewConnectorPaymentMethod<T>,
    pub reference: String,
    // Add other fields as needed
}

#[derive(Debug, Serialize)]
pub struct NewConnectorPaymentMethod<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(flatten)]
    pub method_data: NewConnectorMethodData<T>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum NewConnectorMethodData<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(rename = "card")]
    Card(NewConnectorCard<T>),
}

#[derive(Debug, Serialize)]
pub struct NewConnectorCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvc: Secret<String>,
    pub holder_name: Option<Secret<String>>,
}

#[derive(Debug, Deserialize)]
pub struct NewConnectorPaymentsResponse {
    pub id: String,
    pub status: String,
    pub amount: MinorUnit,
    // Add other fields as needed
}

#[derive(Debug, Deserialize)]
pub struct NewConnectorErrorResponse {
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub transaction_id: Option<String>,
}

// Router Data Wrapper
#[derive(Debug, Serialize)]
pub struct NewConnectorRouterData<T, U> {
    pub amount: MinorUnit,
    pub router_data: T,
    pub payment_method_data: std::marker::PhantomData<U>,
}

impl<T, U> TryFrom<(MinorUnit, T)> for NewConnectorRouterData<T, U> {
    type Error = domain_types::errors::ConnectorError;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
            payment_method_data: std::marker::PhantomData,
        })
    }
}

// TryFrom implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        NewConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for NewConnectorPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: NewConnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => NewConnectorPaymentMethod {
                method_data: NewConnectorMethodData::Card(NewConnectorCard {
                    number: card.card_number.clone(),
                    expiry_month: card.card_exp_month.clone(),
                    expiry_year: card.card_exp_year.clone(),
                    cvc: card.card_cvc.clone(),
                    holder_name: item.router_data.request.customer_name.clone().map(Secret::new),
                }),
            },
            _ => return Err(ConnectorError::NotImplemented("payment method".into()).into()),
        };

        Ok(Self {
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency.to_string(),
            payment_method,
            reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
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
    TryFrom<
        ResponseRouterData<
            NewConnectorPaymentsResponse,
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
            NewConnectorPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::AttemptStatus::Charged,
            "pending" => common_enums::AttemptStatus::Pending,
            "failed" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Add similar implementations for other flows (PSync, Capture, Void, Refund, RSync)
```

### Phase 4: Testing

#### 7. Generate Tests
Follow the `ai_generate_test.md` guide to create comprehensive tests for all implemented flows.

### Phase 5: Build and Debug

#### 8. Build Process
```bash
cargo build
```

#### 9. Common Build Fixes
- **Missing imports**: Add required use statements
- **Type mismatches**: Ensure generic constraints match
- **Macro errors**: Verify macro syntax and parameters
- **Missing implementations**: Add stub implementations for unused flows

### Phase 6: Validation

#### 10. Run Tests
```bash
cargo test --test new_connector_payment_flows_test
```

#### 11. Integration Testing
- Test all implemented flows
- Verify error handling
- Check response transformations

## Key Differences from Hyperswitch

1. **RouterData Wrapper**: UCS requires `NewConnectorRouterData<RouterData