# Connector Implementation Guide

This guide provides step-by-step instructions for adding support for a new connector in the connector service.

## Adding a NewConnectorName (NewConnectorName=the connector name which is needed to be integrated)

### File: backend/domain_types/src/connector_types.rs

1. Locate the ConnectorEnum definition and add the new connector variant
```rust
#[derive(Clone, Debug, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    Adyen,
    Razorpay,
    NewConnectorName, // Add your connector here
}
```

2. Add Match Arm in ForeignTryFrom
```rust
impl ForeignTryFrom<grpc_api_types::payments::Connector> for ConnectorEnum {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        connector: grpc_api_types::payments::Connector,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match connector {
            grpc_api_types::payments::Connector::Adyen => Ok(Self::Adyen),
            grpc_api_types::payments::Connector::Razorpay => Ok(Self::Razorpay),
            grpc_api_types::payments::Connector::NEW_CONNECTOR => Ok(Self::NEW_CONNECTOR),// Add your connectorhere 
            grpc_api_types::payments::Connector::Unspecified => {
                Err(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "UNSPECIFIED_CONNECTOR".to_owned(),
                    error_identifier: 400,
                    error_message: "Connector must be specified".to_owned(),
                    error_object: None,
                })
                .into())
            }
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_CONNECTOR".to_owned(),
                error_identifier: 400,
                error_message: format!("Connector {connector:?} is not supported"),
                error_object: None,
            })
            .into()),
        }
    }
}
```

### File: backend/domain_types/src/types.rs

3. Locate the Connectors struct and add the new connector
```rust
#[derive(Clone, serde::Deserialize, Debug)]
pub struct Connectors {
    pub adyen: ConnectorParams,
    pub razorpay: ConnectorParams,
    pub new_connector: ConnectorParams, // Add your connector params
}
```

### File: backend/connector-integration/src/types.rs

4. Add the Connector in use crate::connectors 
```rust
use crate::connectors::{Adyen, Razorpay, NewConnectorName}; // Add your connector here
```

5. Add the Connector match arm of function convert_connector
```rust
    fn convert_connector(connector_name: ConnectorEnum) -> BoxedConnector {
        match connector_name {
            ConnectorEnum::Adyen => Box::new(Adyen::new()),
            ConnectorEnum::Razorpay => Box::new(Razorpay::new()),
            ConnectorEnum::NewConnectorName => Box::new(NewConnectorName::new()), // Add your connector here
        }
    }
```

### File: backend/connector-integration/src/connectors.rs

6. Add this code block in the bottom of the file
```rust
    pub mod new_connector_name;
    pub use self::new_connector_name::NewConnectorName;
```

### File: config/development.toml

7. Take reference from hyperswitch development.toml for base_url
https://github.com/juspay/hyperswitch/blob/main/config/development.toml

### Create Connector Implementation

8. Export the connector name and run these two scripts
```sh
export CONNECTOR_NAME=new_connector
./fetch_connector_file.sh
./fetch_connector_transformers.sh
```

### File: backend/connector-integration/src/connectors/new_connector.rs

9. Remove all lines at the top of the Rust file that start with use, including any grouped imports and multiline use statements. Dont do anything else dont fix any errors
e.g:
```rust
pub mod transformers;

use std::fmt::Debug;

use common_enums::enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::{Method, Request, RequestBuilder, RequestContent},
};
use error_stack::{report, ResultExt};
```

10. Copy and paste the following code block as it is into the starting of main connector file and dont remove anything dont fix any errors

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
    self as new_connector_name,
};

use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use error_stack::ResultExt;
```

11. Remove the existing New_connector_name struct and the impl
e.g:
```rust
#[derive(Clone)]
pub struct New_connector_name {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl New_connector_name {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}
```

12. Remove all lines that starts with impl api::
e.g:
```rust
impl api::Payment for New_connector_name {}
impl api::PaymentSession for New_connector_name {}
impl api::ConnectorAccessToken for New_connector_name {}
impl api::MandateSetup for New_connector_name {}
impl api::PaymentAuthorize for New_connector_name {}
impl api::PaymentSync for New_connector_name {}
impl api::PaymentCapture for New_connector_name {}
impl api::PaymentVoid for New_connector_name {}
impl api::Refund for New_connector_name {}
impl api::RefundExecute for New_connector_name {}
impl api::RefundSync for New_connector_name {}
impl api::PaymentToken for New_connector_name {}
```

13. Copy and paste the following code block as it is in place of the impls that you removed in the previous step dont fix any errors
```rust
// Trait implementations with generic type parameters
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ConnectorServiceTrait<T> for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentAuthorizeV2<T> for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSyncV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundSyncV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RefundV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentCapture for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::ValidationTrait for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SetupMandateV2<T> for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::RepeatPaymentV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::AcceptDispute for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::SubmitEvidenceV2 for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::DisputeDefend for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::IncomingWebhook for New_connector_name<T>
{
}
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    connector_types::PaymentSessionToken for New_connector_name<T>
{
}
```

14. Copy and paste the following code block as it is below the impls that you added in the previous step, dont fix any errors and dont combine multiple steps
```rust
macros::create_all_prerequisites!(
    connector_name: New_connector_name,
    generic_type: T,
    api: [
       
    ],
    amount_converters: [],
    member_functions: {
        
    }
);
```

15. Copy and paste the following code block as it is at the bottom of the file, dont fix any errors
```rust
// Stub implementations for unsupported flows
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
    for New_connector_name<T>
{
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    ConnectorIntegrationV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for New_connector_name<T>
{
}

// SourceVerification implementations for all flows
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        PSync,
        PaymentFlowData,
        PaymentsSyncData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Capture,
        PaymentFlowData,
        PaymentsCaptureData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Void,
        PaymentFlowData,
        PaymentVoidData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RSync,
        RefundFlowData,
        RefundSyncData,
        RefundsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        Accept,
        DisputeFlowData,
        AcceptDisputeData,
        DisputeResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        SubmitEvidence,
        DisputeFlowData,
        SubmitEvidenceData,
        DisputeResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        DefendDispute,
        DisputeFlowData,
        DisputeDefendData,
        DisputeResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        RepeatPayment,
        PaymentFlowData,
        RepeatPaymentData,
        PaymentsResponseData,
    > for New_connector_name<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    interfaces::verification::SourceVerification<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    > for New_connector_name<T>
{
}
```

16. Locate the build_headers function
e.g
```rust
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        //...
        Ok(header)
    }
```

17. Copy and paste the build_headers function as it is in the member_functions block of macros::create_all_prerequisites, dont fix any errors and dont combine multiple steps
```rust
macros::create_all_prerequisites!(
    connector_name: New_connector_name,
    api: [
       
    ],
    amount_converters: [],
    member_functions: {

    }
);
```

18. Change the function parameters of the build_headers function to the following one, dont touch anything inside build_headers function, dont fix any errors
```rust
macros::create_all_prerequisites!(
    connector_name: New_connector_name,
    api: [
       
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
        }
    }
);
```

19. **VALIDATION STEP**: Verify that steps 17 and 18 are completed correctly:
   - Confirm that the `build_headers` function has been moved from its original location into the `member_functions` block of `macros::create_all_prerequisites!`
   - Verify that the function signature has been updated to use the new parameters: `req: &RouterDataV2<F, FCD, Req, Res>`
   - Ensure that the function body from the original `build_headers` function has been preserved inside the new location

20. Remove the whole ConnectorCommonExt trait
e.g:
```rust
impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for New_connector_name
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        //..
    }
}
```

21. Add pub(crate) mod headers with only the required headers above the macros::create_all_prerequisites!
```rust
pub(crate) mod headers {
    pub(crate) const ACCEPT: &str = "Accept";
    pub(crate) const API_KEY: &str = "API-KEY";
    pub(crate) const APIKEY: &str = "apikey";
    pub(crate) const API_TOKEN: &str = "Api-Token";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const DATE: &str = "Date";
    pub(crate) const IDEMPOTENCY_KEY: &str = "Idempotency-Key";
    pub(crate) const MESSAGE_SIGNATURE: &str = "Message-Signature";
    pub(crate) const MERCHANT_ID: &str = "Merchant-ID";
    pub(crate) const REQUEST_ID: &str = "request-id";
    pub(crate) const NONCE: &str = "nonce";
    pub(crate) const TIMESTAMP: &str = "Timestamp";
    pub(crate) const TOKEN: &str = "token";
    pub(crate) const X_ACCEPT_VERSION: &str = "X-Accept-Version";
    pub(crate) const X_CC_API_KEY: &str = "X-CC-Api-Key";
    pub(crate) const X_CC_VERSION: &str = "X-CC-Version";
    pub(crate) const X_DATE: &str = "X-Date";
    pub(crate) const X_LOGIN: &str = "X-Login";
    pub(crate) const X_NN_ACCESS_KEY: &str = "X-NN-Access-Key";
    pub(crate) const X_TRANS_KEY: &str = "X-Trans-Key";
    pub(crate) const X_RANDOM_VALUE: &str = "X-RandomValue";
    pub(crate) const X_REQUEST_DATE: &str = "X-RequestDate";
    pub(crate) const X_VERSION: &str = "X-Version";
    pub(crate) const X_API_KEY: &str = "X-Api-Key";
    pub(crate) const CORRELATION_ID: &str = "Correlation-Id";
    pub(crate) const WP_API_VERSION: &str = "WP-Api-Version";
    pub(crate) const STRIPE_COMPATIBLE_CONNECT_ACCOUNT: &str = "Stripe-Account";
    pub(crate) const SOURCE: &str = "Source";
    pub(crate) const USER_AGENT: &str = "User-Agent";
    pub(crate) const KEY: &str = "key";
    pub(crate) const X_SIGNATURE: &str = "X-Signature";
    pub(crate) const SOAP_ACTION: &str = "SOAPAction";
    pub(crate) const X_PROFILE_ID: &str = "X-Profile-Id";
}
```

22. Locate the ConnectorCommon trait impl
e.g
```rust
impl ConnectorCommon for New_connector_name {
```

23. Update the impl with this code block, dont fix any errors and dont combine multiple steps
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for New_connector_name<T>
{
```

24. Remove this code block inside the build_error_response function in ConnectorCommon trait
```rust
        event_builder.map(|i| i.set_error_response_body(&response));
        router_env::logger::info!(connector_response=?response);
```

25. Copy and paste the following code block in place of the code block that you removed in the previous step, dont fix any errors and dont combine multiple steps
```rust
        with_error_response_body!(event_builder, response);
```

26. Copy and paste the following code block as it is in the member_functions: block of macros::create_all_prerequisites, dont fix any errors and dont combine multiple steps
```rust
        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.new_connector_name.base_url
        }

        pub fn connector_base_url_refunds<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, RefundFlowData, Req, Res>,
        ) -> &'a str {
            &req.resource_common_data.connectors.new_connector_name.base_url
        }
```

27. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites, dont fix any errors and dont combine multiple steps
```rust
(
    flow: Authorize,
    request_body: ,
    response_body: ,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

28. Copy and paste the following code block as it is in the file under ConnectorCommon impl, dont fix any errors and dont combine multiple steps
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: New_connector_name,
    curl_request: ,
    curl_response: ,
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
        }
        fn get_url(
            &self,
            req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
        }
    }
);
```

29. Locate the following trait
```rust
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for New_connector_name
```

29.a. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: Authorize,
)
```

29.b. Locate the request struct and the response struct in the fn get_request_body and fn handle_response respectively inside the impl that you located in step no 28
```rust
fn get_request_body(
    &self,
    req: &PaymentsAuthorizeRouterData,
    //..
    let connector_req = new_connector_name::New_connector_namePaymentsRequest::try_from(&connector_router_data)?; //This one is the request struct i.e New_connector_namePaymentsRequest
    Ok(RequestContent::Json(Box::new(connector_req))) //The Request Format e.g: Json, Formdata
}
fn handle_response(
    //..
    let response: new_connector_name::New_connector_namePaymentsResponse = res //This one is the response struct i.e New_connector_namePaymentsResponse
}
```

29.c. Add the request struct name and response struct name to import from transformers
```rust
use transformers::{
    self as new_connector_name, New_connector_namePaymentsRequest, New_connector_namePaymentsResponse,
};
```

29.d. Add the request struct name and response struct name in the flow: Authorize of api: [] block in macros::create_all_prerequisites,
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>,
    response_body: New_connector_namePaymentsResponse,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

29.e. Add the request struct name and response struct name in the macros::macro_connector_implementation! for flow_name: Authorize
```rust
macros::macro_connector_implementation!(
    //..
    curl_request: Format(New_connector_namePaymentsRequest),
    curl_response: New_connector_namePaymentsResponse,
    flow_name: Authorize,
)
```

30. **VALIDATION STEP**: Verify that step 29 (all substeps) are completed correctly for the Authorize flow:
   - Confirm that the `get_headers` and `get_url` function implementations have been copied as it is from the original trait into the macro (step 29.a)
   - Verify that the request and response struct names have been identified from `get_request_body` and `handle_response` functions (step 29.b)
   - Check that the request and response struct names have been added to the transformers import statement (step 29.c)
   - Ensure that the request and response struct names have been added to the `api: []` block in `macros::create_all_prerequisites!` for the Authorize flow (step 29.d)
   - Confirm that the request and response struct names have been added to the `macros::macro_connector_implementation!` for `flow_name: Authorize` (step 29.e)

31. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for New_connector_name
```

32. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites put comma (,) after the previous one and dont fix any errors
```rust
(
    flow: PSync,
    request_body: ,
    response_body: ,
    router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
)
```

33. Copy and paste the following code block as it is in the file under ConnectorCommon impl, dont fix any errors and dont combine multiple steps
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: New_connector_name,
    curl_request: ,
    curl_response: ,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        }
        fn get_url(
            &self,
            req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
        }
    }
);
```

34. Locate the following trait
```rust
impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for New_connector_name
```

35. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: PSync,
)
```
35.b. Locate the request struct and the response struct in the fn get_request_body and fn handle_response respectively inside the impl that you located in step no 34
```rust
fn get_request_body(
    &self,
    req: &PaymentsSyncRouterData,
    //..
    let connector_req = new_connector_name::New_connector_nameSyncRequest::try_from(&connector_router_data)?; //This one is the request struct i.e New_connector_nameSyncRequest
    Ok(RequestContent::Json(Box::new(connector_req))) //The Request Format e.g: Json, Formdata
}
fn handle_response(
    //..
    let response: new_connector_name::New_connector_nameSyncResponse = res //This one is the response struct i.e New_connector_nameSyncResponse
}
```

35.c. Add the request struct name and response struct name to import from transformers
```rust
use transformers::{
    self as new_connector_name, New_connector_nameSyncRequest, New_connector_nameSyncResponse,
};
```

35.d. Add the request struct name and response struct name in the flow: PSync of api: [] block in macros::create_all_prerequisites,
```rust
(
    flow: PSync,
    request_body: New_connector_nameSyncRequest<T>,
    response_body: New_connector_nameSyncResponse,
    router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
```

35.e. Add the request struct name and response struct name in the macros::macro_connector_implementation! for flow_name: PSync
```rust
macros::macro_connector_implementation!(
    //..
    curl_request: Format(New_connector_nameSyncRequest),
    curl_response: New_connector_nameSyncResponse,
    flow_name: PSync,
)
```

35.f. **If get_request_body function is missing**: Remove the request_body and curl_request fields as they are not needed
- Remove `request_body: New_connector_nameSyncRequest<T>,` from the flow: PSync in api: [] block of macros::create_all_prerequisites
- Remove `curl_request: Format(New_connector_nameSyncRequest),` from the macros::macro_connector_implementation! for flow_name: PSync
- Keep only the response_body and curl_response fields

36. **VALIDATION STEP**: Verify that step 35 (all substeps) are completed correctly for the PSync flow:
   - Confirm that the `get_headers` and `get_url` function implementations have been copied as it is from the original trait into the macro (step 35.a)
   - Verify that the request and response struct names have been identified from `get_request_body` and `handle_response` functions (step 35.b)
   - Check that the request and response struct names have been added to the transformers import statement (step 35.c)
   - Ensure that the request and response struct names have been added to the `api: []` block in `macros::create_all_prerequisites!` for the PSync flow (step 35.d)
   - Confirm that the request and response struct names have been added to the `macros::macro_connector_implementation!` for `flow_name: PSync` (step 35.e)

37. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for New_connector_name
```

38. Remove the PSync stub implementation
e.g:
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for New_connector_name<T>
{
}
```
39. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites
```rust
(
    flow: Refund,
    request_body: ,
    response_body: ,
    router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
)
```

40. Copy and paste the following code block as it is in the file
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: New_connector_name,
    curl_request: Json(),
    curl_response: ,
    flow_name: Refund,
    resource_common_data: RefundFlowData,
    flow_request: RefundsData,
    flow_response: RefundsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {

        }
        fn get_url(
            &self,
            req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {

        }
    }
);
```

41. Locate the following trait
```rust
impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for New_connector_name
```

42.a. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: Refund,
)
```

42.b. Locate the request struct and the response struct in the fn get_request_body and fn handle_response respectively inside the impl that you located in step no 41, dont fix any errors and dont combine multiple steps
```rust
fn get_request_body(
    &self,
    req: &RefundsRouterData<Execute>,
    //..
    let connector_req = new_connector_name::New_connector_nameRefundRequest::try_from(&connector_router_data)?; //This one is the request struct i.e New_connector_nameRefundRequest
    Ok(RequestContent::Json(Box::new(connector_req))) //The Request Format e.g: Json, Formdata
}
fn handle_response(
    //..
    let response: new_connector_name::New_connector_nameRefundResponse = res //This one is the response struct i.e New_connector_nameRefundResponse
}
```

42.c. Add the request struct name and response struct name to import from transformers
```rust
use transformers::{
    self as new_connector_name, New_connector_nameRefundRequest, New_connector_nameRefundResponse,
};
```

42.d. Add the request struct name and response struct name in the flow: Refund of api: [] block in macros::create_all_prerequisites,
```rust
(
    flow: Refund,
    request_body: New_connector_nameRefundRequest,
    response_body: New_connector_nameRefundResponse,
    router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
)
```

42.e. Add the request struct name and response struct name in the macros::macro_connector_implementation! for flow_name: Refund
```rust
macros::macro_connector_implementation!(
    //..
    curl_request: Format(New_connector_nameRefundRequest),
    curl_response: New_connector_nameRefundResponse,
    flow_name: Refund,
)
```

43. **VALIDATION STEP**: Verify that step 42 (all substeps) are completed correctly for the Refund flow:
   - Confirm that the `get_headers` and `get_url` function implementations have been copied as it is from the original trait into the macro (step 42.a)
   - Verify that the request and response struct names have been identified from `get_request_body` and `handle_response` functions (step 42.b)
   - Check that the request and response struct names have been added to the transformers import statement (step 42.c)
   - Ensure that the request and response struct names have been added to the `api: []` block in `macros::create_all_prerequisites!` for the Refund flow (step 42.d)
   - Confirm that the request and response struct names have been added to the `macros::macro_connector_implementation!` for `flow_name: Refund` (step 42.e)

44. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for New_connector_name
```

45. Remove the Refund stub implementation
e.g:
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for New_connector_name<T>
{
}
```

46. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites
```rust
(
    flow: RSync,
    request_body: ,
    response_body: ,
    router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
)
```

47. Copy and paste the following code block as it is in the file
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: New_connector_name,
    curl_request: Json(),
    curl_response: ,
    flow_name: RSync,
    resource_common_data: RefundFlowData,
    flow_request: RefundSyncData,
    flow_response: RefundsResponseData,
    http_method: Get,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {

        }
        fn get_url(
            &self,
            req: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
        
        }
    }
);
```

48. Locate the following trait
```rust
impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for New_connector_name
```

49.a. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: RSync,
)
```
49.b. Locate the request struct and the response struct in the fn get_request_body and fn handle_response respectively inside the impl that you located in step no 48
```rust
fn get_request_body(
    &self,
    req: &RefundSyncRouterData,
    //..
    let connector_req = new_connector_name::New_connector_nameRSyncRequest::try_from(&connector_router_data)?; //This one is the request struct i.e New_connector_nameRSyncRequest
    Ok(RequestContent::Json(Box::new(connector_req))) //The Request Format e.g: Json, Formdata
}
fn handle_response(
    //..
    let response: new_connector_name::New_connector_nameRSyncResponse = res //This one is the response struct i.e New_connector_nameRSyncResponse
}
```

49.c. Add the request struct name and response struct name to import from transformers
```rust
use transformers::{
    self as new_connector_name, New_connector_nameRSyncRequest, New_connector_nameRSyncResponse,
};
```

49.d. Add the request struct name and response struct name in the flow: RSync of api: [] block in macros::create_all_prerequisites,
```rust
(
    flow: RSync,
    request_body: New_connector_nameRSyncRequest<T>,
    response_body: New_connector_nameRSyncResponse,
    router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
```

49.e. Add the request struct name and response struct name in the macros::macro_connector_implementation! for flow_name: RSync
```rust
macros::macro_connector_implementation!(
    //..
    curl_request: Format(New_connector_nameRSyncRequest),
    curl_response: New_connector_nameRSyncResponse,
    flow_name: RSync,
)
```

49.f. **If get_request_body function is missing**: Remove the request_body and curl_request fields as they are not needed
- Remove `request_body: New_connector_nameRSyncRequest<T>,` from the flow: RSync in api: [] block of macros::create_all_prerequisites
- Remove `curl_request: Format(New_connector_nameRSyncRequest),` from the macros::macro_connector_implementation! for flow_name: RSync
- Keep only the response_body and curl_response fields

50. **VALIDATION STEP**: Verify that step 49 (all substeps) are completed correctly for the RSync flow:
   - Confirm that the `get_headers` and `get_url` function implementations have been copied as it is from the original trait into the macro (step 49.a)
   - Verify that the request and response struct names have been identified from `get_request_body` and `handle_response` functions (step 49.b)
   - Check that the request and response struct names have been added to the transformers import statement (step 49.c)
   - Ensure that the request and response struct names have been added to the `api: []` block in `macros::create_all_prerequisites!` for the RSync flow (step 49.d)
   - Confirm that the request and response struct names have been added to the `macros::macro_connector_implementation!` for `flow_name: RSync` (step 49.e)
   - If applicable, verify that step 49.f has been completed for handling missing `get_request_body` function

51. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for New_connector_name
```

52. Remove the RSync stub implementation
e.g:
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for New_connector_name<T>
{
}
```

53. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites
```rust
(
    flow: Capture,
    request_body: ,
    response_body: ,
    router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
)
```

54. Copy and paste the following code block as it is in the file
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: New_connector_name,
    curl_request: Json(),
    curl_response: ,
    flow_name: Capture,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsCaptureData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {

        }
        fn get_url(
            &self,
            req: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {

        }
    }
);
```

55. Locate the following trait
```rust
impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData>  for New_connector_name
```

56.a. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: Capture,
)
```
56.b. Locate the request struct and the response struct in the fn get_request_body and fn handle_response respectively inside the impl that you located in step no 55
```rust
fn get_request_body(
    &self,
    req: &PaymentsCaptureRouterData,
    //..
    let connector_req = new_connector_name::New_connector_nameCaptureRequest::try_from(&connector_router_data)?; //This one is the request struct i.e New_connector_nameCaptureRequest
    Ok(RequestContent::Json(Box::new(connector_req))) //The Request Format e.g: Json, Formdata
}
fn handle_response(
    //..
    let response: new_connector_name::New_connector_nameCaptureResponse = res //This one is the response struct i.e New_connector_nameCaptureResponse
}
```

56.c. Add the request struct name and response struct name to import from transformers
```rust
use transformers::{
    self as new_connector_name, New_connector_nameCaptureRequest, New_connector_nameCaptureResponse,
};
```

56.d. Add the request struct name and response struct name in the flow: Capture of api: [] block in macros::create_all_prerequisites,
```rust
(
    flow: Capture,
    request_body: New_connector_nameCaptureRequest,
    response_body: New_connector_nameCaptureResponse,
    router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
)
```

56.e. Add the request struct name and response struct name in the macros::macro_connector_implementation! for flow_name: Capture
```rust
macros::macro_connector_implementation!(
    //..
    curl_request: Format(New_connector_nameCaptureRequest),
    curl_response: New_connector_nameCaptureResponse,
    flow_name: Capture,
)
```

57. **VALIDATION STEP**: Verify that step 56 (all substeps) are completed correctly for the Capture flow:
   - Confirm that the `get_headers` and `get_url` function implementations have been copied as it is from the original trait into the macro (step 56.a)
   - Verify that the request and response struct names have been identified from `get_request_body` and `handle_response` functions (step 56.b)
   - Check that the request and response struct names have been added to the transformers import statement (step 56.c)
   - Ensure that the request and response struct names have been added to the `api: []` block in `macros::create_all_prerequisites!` for the Capture flow (step 56.d)
   - Confirm that the request and response struct names have been added to the `macros::macro_connector_implementation!` for `flow_name: Capture` (step 56.e)

58. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData>  for New_connector_name
```

59. Remove the Capture stub implementation
e.g:
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
    for New_connector_name<T>
{
}
```

60. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites
```rust
(
    flow: Void,
    request_body: ,
    response_body: ,
    router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
)
```

61. Copy and paste the following code block as it is in the file
```rust
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: New_connector_name,
    curl_request: Json(),
    curl_response: ,
    flow_name: Void,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentVoidData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_headers(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {

        }
        fn get_url(
            &self,
            req: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {

        }
    }
);
```

62. Locate the following trait
```rust
impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData>  for New_connector_name
```

63.a. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: Void,
)
```
63.b. Locate the request struct and the response struct in the fn get_request_body and fn handle_response respectively inside the impl that you located in step no 62
```rust
fn get_request_body(
    &self,
    req: &PaymentsCancelRouterData,
    //..
    let connector_req = new_connector_name::New_connector_nameCancelRequest::try_from(&connector_router_data)?; //This one is the request struct i.e New_connector_nameCancelRequest
    Ok(RequestContent::Json(Box::new(connector_req))) //The Request Format e.g: Json, Formdata
}
fn handle_response(
    //..
    let response: new_connector_name::New_connector_nameCancelResponse = res //This one is the response struct i.e New_connector_nameCancelResponse
}
```

63.c. Add the request struct name and response struct name to import from transformers
```rust
use transformers::{
    self as new_connector_name, New_connector_nameCancelRequest, New_connector_nameCancelResponse,
};
```

63.d. Add the request struct name and response struct name in the flow: Void of api: [] block in macros::create_all_prerequisites,
```rust
(
    flow: Void,
    request_body: New_connector_nameCancelRequest,
    response_body: New_connector_nameCancelResponse,
    router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
)
```

63.e. Add the request struct name and response struct name in the macros::macro_connector_implementation! for flow_name: Void
```rust
macros::macro_connector_implementation!(
    //..
    curl_request: Format(New_connector_nameCancelRequest),
    curl_response: New_connector_nameCancelResponse,
    flow_name: Void,
)
```

63.f. **If get_request_body function is missing**: Remove the request_body and curl_request fields as they are not needed
- Remove `request_body: New_connector_nameCancelRequest,` from the flow: Void in api: [] block of macros::create_all_prerequisites
- Remove `curl_request: Format(New_connector_nameCancelRequest),` from the macros::macro_connector_implementation! for flow_name: Void
- Keep only the response_body and curl_response fields

64. **VALIDATION STEP**: Verify that step 63 (all substeps) are completed correctly for the Void flow:
   - Confirm that the `get_headers` and `get_url` function implementations have been copied as it is from the original trait into the macro (step 63.a)
   - Verify that the request and response struct names have been identified from `get_request_body` and `handle_response` functions (step 63.b)
   - Check that the request and response struct names have been added to the transformers import statement (step 63.c)
   - Ensure that the request and response struct names have been added to the `api: []` block in `macros::create_all_prerequisites!` for the Void flow (step 63.d)
   - Confirm that the request and response struct names have been added to the `macros::macro_connector_implementation!` for `flow_name: Void` (step 63.e)
   - If applicable, verify that step 63.f has been completed for handling missing `get_request_body` function

65. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData>  for New_connector_name
```

66. Remove the Void stub implementation
e.g:
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
    for New_connector_name<T>
{
}
```

### File: backend/connector-integration/src/connectors/new_connector/transformers.rs

67. Remove all lines at the top of the Rust file that start with use, including any grouped imports and multiline use statements. Dont do anything else dont fix any errors
e.g:
```rust
use common_enums::enums;
use common_utils::{
    ext_traits::ValueExt,
    pii::{Email, IpAddress},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::{
        CompleteAuthorizeData, PaymentsAuthorizeData, PaymentsCancelData, PaymentsCaptureData,
        PaymentsSyncData, ResponseId,
    },
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types,
};
```

68. Copy and paste the following code block as it is into the starting of transformers.rs file and dont remove anything else dont fix any errors
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
```

69. Copy and paste the following code block below the code block that you added in the previous step dont do anything else
```rust
use crate::{connectors::new_connector_name::New_connector_nameRouterData, types::ResponseRouterData};
```

70. Locate and remove the New_connector_nameRouterData struct and its impl
```rust
#[derive(Debug, Serialize)]
pub struct New_connector_nameRouterData<T> {
    pub amount: Unit,
    pub router_data: T,
}

impl<T> From<(Unit, T)> for New_connector_nameRouterData<T> {
    //..
}
```

71. See the name of the request struct in Authorize flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>, //This one
    response_body: New_connector_namePaymentsResponse,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

72. Locate the struct in transformers.rs file
e.g:
```rust
#[derive(Debug, Serialize)]
pub struct New_connector_namePaymentsRequest {
```

73. Update the struct you located in the previous step similar to this following code
e.g:
```rust
#[derive(Debug, Serialize)]
pub struct New_connector_namePaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
```

74. Add <T> in the struct which is used for payment method information like card
e.g:
```rust
#[derive(Debug, Serialize)]
pub struct New_connector_namePaymentsRequest<
//...
    billing_address: BillingAddress,
    card: Card<T>,
}
```

75. Now locate the struct where you added <T> in last step and do the changes similar in step 73 and 74 until a field with "CardNumber" is reached
e.g:
```rust
#[derive(Debug, Serialize)]
pub struct StructName {
    //..
    field_name: CardNumber,
    //..
}
```

76. Replace CardNumber with RawCardNumber<T>
```rust
pub struct StructName {
    //..
    field_name: RawCardNumber<T>,
    //..
}
```

77. **Validation: Verify CardNumber to RawCardNumber<T> Transformation**
   - [ ] Confirm all CardNumber fields have been replaced with RawCardNumber<T>
   - [ ] Verify that all structs containing card information now have the generic type parameter <T>
   - [ ] Ensure all card-related structs follow the pattern:
     ```rust
     #[derive(Debug, Serialize)]
     pub struct StructName<
         T: PaymentMethodDataTypes
             + std::fmt::Debug
             + std::marker::Sync
             + std::marker::Send
             + 'static
             + Serialize,
     > {
         //..
         card_field: RawCardNumber<T>,
         //..
     }
     ```
   - [ ] Validate that the transformation is consistent across all card-related data structures

78. See the name of the request struct in Authorize flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>, //This one
    response_body: New_connector_namePaymentsResponse,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

79. Locate the TryFrom impl for the request struct
e.g:
```rust
impl TryFrom<&New_connector_nameRouterData<PaymentsAuthorizeRouterData>> for New_connector_namePaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        any_name: &New_connector_nameRouterData<PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
```

80. Replace the code block you located in the previous step with the following one
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        New_connector_nameRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for New_connector_namePaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        any_name: New_connector_nameRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
```

81. Inside the try_from function all the function/fields that are coming from item should come from item.resource_common_data
e.g:
```rust
item.get_billing_address()? //previous
item.resource_common_data.get_billing_address()? //Correct
```

82. See the name of the response_body struct in Authorize flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>,
    response_body: New_connector_namePaymentsResponse, //This one
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

83. Locate the TryFrom impl for the RouterData from ResponseRouterData<* New_connector_namePaymentsResponse *>
e.g:
```rust
impl<F, T> TryFrom<ResponseRouterData<* New_connector_namePaymentsResponse, *>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<* New_connector_namePaymentsResponse *>,
    ) -> Result<Self, Self::Error> {
```

84. Replace the code block you located in the previous step with the following one
```rust
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
            New_connector_namePaymentsResponse,
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
            New_connector_namePaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
```

85. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

86. Wrap status inside resource_common_data: PaymentFlowData for response try_from for authorize
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```

87. See the name of the response_body struct in PSync flow in new_connector_name.rs file
e.g:
```rust
(
    flow: PSync,
    request_body: New_connector_nameSyncRequest,
    response_body: New_connector_namePSyncResponse, //This one
    router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
)
```

88. Locate the TryFrom impl for the RouterData from ResponseRouterData<* New_connector_namePSyncResponse *>
e.g:
```rust
impl<F, T> TryFrom<ResponseRouterData<* FortePaymentsSyncResponse *>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<* FortePaymentsSyncResponse *>,
    ) -> Result<Self, Self::Error> {
```

89. Replace the code block you located in the previous step with the following one
```rust
impl<F> TryFrom<ResponseRouterData<New_connector_namePSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<New_connector_namePSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
```

90. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

91. Wrap status inside resource_common_data: PaymentFlowData for response try_from for PSync
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```

92. See the name of the request struct in Refund flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Refund,
    request_body: New_connector_nameRefundRequest<T>, //This one
    response_body: New_connector_nameRefundResponse,
    router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
)
```

93. Locate the TryFrom impl for the request struct
e.g:
```rust
impl<F> TryFrom<&New_connector_nameRouterData<&types::RefundsRouterData<F>>> for New_connector_nameRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item_data: &New_connector_nameRouterData<&types::RefundsRouterData<F>>,
    ) -> Result<Self, Self::Error> {
```

94. Replace the code block you located in the previous step with the following one
```rust
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
        New_connector_nameRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for New_connector_nameRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: New_connector_nameRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
```

95. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

96. If status is present Wrap status inside resource_common_data: PaymentFlowData for request try_from for Refund
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```
97. See the name of the response_body struct in Refund flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Refund,
    request_body: New_connector_nameRefundRequest<T>, 
    response_body: New_connector_nameRefundResponse, //This one
    router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
)
```

98. Locate the TryFrom impl for the RouterData from RefundsResponseRouterData<* New_connector_nameRefundResponse *>
e.g:
```rust
impl TryFrom<RefundsResponseRouterData<* New_connector_nameRefundResponse, *>>
    for types::RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<* New_connector_nameRefundResponse, *>,
    ) -> Result<Self, Self::Error> {
```

99. Replace the code block you located in the previous step with the following one
```rust
impl<F> TryFrom<ResponseRouterData<New_connector_nameRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<New_connector_nameRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
```

100. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

101. If status is present Wrap status inside resource_common_data: PaymentFlowData for response try_from for Refund
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```

102. See the name of the response_body struct in RSync flow in new_connector_name.rs file
e.g:
```rust
(
    flow: RSync,
    request_body: New_connector_nameRSyncRequest<T>, 
    response_body: New_connector_nameRSyncResponse, //This one
    router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
)
```

103. Locate the TryFrom impl for the RouterData from RefundsResponseRouterData<* New_connector_nameRSyncResponse *>
e.g:
```rust
impl TryFrom<RefundsResponseRouterData<* New_connector_nameRSyncResponse, *>>
    for types::RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<* New_connector_nameRSyncResponse, *>,
    ) -> Result<Self, Self::Error> {
```

104. Replace the code block you located in the previous step with the following one
```rust
impl<F> TryFrom<ResponseRouterData<New_connector_nameRSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<New_connector_nameRSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
```

105. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

106. If status is present Wrap status inside resource_common_data: PaymentFlowData for response try_from for Rsync
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```
107. See the name of the request struct in Capture flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Capture,
    request_body: New_connector_nameCaptureRequest<T>, //This one
    response_body: New_connector_nameCaptureResponse,
    router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
)
```

108. Locate the TryFrom impl for the request struct
e.g:
```rust
impl TryFrom<&types::PaymentsCaptureRouterData> for New_connector_nameCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsCaptureRouterData) -> Result<Self, Self::Error> {
```

109. Replace the code block you located in the previous step with the following one
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        New_connector_nameRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for New_connector_nameCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: New_connector_nameRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {

    }
}
```

110. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

111. If status is present Wrap status inside resource_common_data: PaymentFlowData for request try_from for Capture
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```

112. See the name of the request struct in Capture flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Capture,
    request_body: New_connector_nameCaptureRequest<T>, 
    response_body: New_connector_nameCaptureResponse, //This one
    router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
)
```

113. Locate the TryFrom impl for the request struct
e.g:
```rust
impl TryFrom<PaymentsCaptureResponseRouterData<New_connector_nameCaptureResponse>>
    for types::PaymentsCaptureRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: PaymentsCaptureResponseRouterData<New_connector_nameCaptureResponse>,
    ) -> Result<Self, Self::Error> {
```

114. Replace the code block you located in the previous step with the following one
```rust
impl<F, T> TryFrom<ResponseRouterData<New_connector_nameCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<New_connector_nameCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
```

115. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

116. If status is present Wrap status inside resource_common_data: PaymentFlowData for response try_from for Capture
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```
117. See the name of the request struct in Void flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Void,
    request_body: New_connector_nameVoidRequest<T>, //This one
    response_body: New_connector_nameVoidResponse,
    router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
)
```

118. Locate the TryFrom impl for the request struct
e.g:
```rust
impl TryFrom<&types::PaymentsCancelRouterData> for New_connector_nameVoidRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsCancelRouterData) -> Result<Self, Self::Error> {
```

119. Replace the code block you located in the previous step with the following one
```rust
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        New_connector_nameRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for New_connector_nameVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: New_connector_nameRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
```

120. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

121. If status is present Wrap status inside resource_common_data: PaymentFlowData for request try_from for Void
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```
122. See the name of the response_body struct in RSync flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Void,
    request_body: New_connector_nameVoidRequest<T>, 
    response_body: New_connector_nameVoidResponse, //This one
    router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
)
```

123. Locate the TryFrom impl for the RouterData from ResponseRouterData<* New_connector_nameVoidResponse *>
e.g:
```rust
impl<F, T> TryFrom<ResponseRouterData<F, New_connector_nameVoidResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, New_connector_nameVoidResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {

```

124. Replace the code block you located in the previous step with the following one
```rust
impl<F, T> TryFrom<ResponseRouterData<New_connector_nameVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<New_connector_nameVoidResponse, Self>) -> Result<Self, Self::Error> {
```

125. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
e.g:
```rust
response: Ok(PaymentsResponseData::TransactionResponse {
    //..
    charges: None, //Remove
    raw_connector_response: None, // Add
    status_code: item.http_code,
}),
..item.data //wrong
....item.router_data //right
```

126. If status is present Wrap status inside resource_common_data: PaymentFlowData for response try_from for Void
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```

### File: backend/connector-integration/src/connectors/new_connector.rs

127. Remove the following unused code, dont fix any errors and dont combine multiple steps
```rust
impl ConnectorValidation
impl ConnectorIntegration
impl IncomingWebhook
impl ConnectorSpecifications
```
128. **Build using command `cargo build`**: Build the project and fix the build errors using the errorFixGuide mentioned at step number 129 also remove all the warnings

129. To resolve the common errors step by step run the instructions written in this file
``
./connectorErrorFixGuide.md
``

130. Write the Test file by following the steps present in ai_generated_test file.
``
./ai_generate_test.md
``
