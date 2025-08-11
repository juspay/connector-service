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

7. Take reference from hyperswitch development.toml for base_url in context

### 3. Create Connector Implementation

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
        RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, DisputeDefendData, DisputeFlowData, DisputeResponseData,
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        SetupMandateRequestData, SubmitEvidenceData,
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
use hyperswitch_masking::{ExposeInterface, Mask, Maskable};
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
```

14. Copy and paste the following code block as it is below the impls that you added in the previous step
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

15. Copy and paste the following code block as it is at the bottom of the file
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

17. Copy and paste the build_headers function as it is in the member_functions block of macros::create_all_prerequisites
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

19. Remove the whole ConnectorCommonExt trait
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

20. Copy and paste the following code block as it is above the macros::create_all_prerequisites!
```rust
pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}
```

21. Locate the ConnectorCommon trait impl
e.g
```rust
impl ConnectorCommon for New_connector_name {
```

22. Update the impl with this code block
```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon
    for New_connector_name<T>
{
```

23. Remove this code block inside the build_error_response function in ConnectorCommon trait
```rust
        event_builder.map(|i| i.set_error_response_body(&response));
        router_env::logger::info!(connector_response=?response);
```

24. Copy and paste the following code block in place of the code block that you removed in the previous step
```rust
        with_error_response_body!(event_builder, response);
```

25. Copy and paste the following code block as it is in the member_functions: block of macros::create_all_prerequisites
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

26. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>,
    response_body: New_connector_namePaymentsResponse,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

27. Copy and paste the following code block as it is in the file under ConnectorCommon impl
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

28. Locate the following trait
```rust
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for New_connector_name
```

29. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: Authorize,
)
```

30. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for New_connector_name
```

31. Copy and paste the following code block as it is in the api: [] block of macros::create_all_prerequisites put comma (,) after the previous one and dont fix any errors
```rust
(
    flow: PSync,
    request_body: ,
    response_body: ,
    router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
)
```

32. Copy and paste the following code block as it is in the file under ConnectorCommon impl
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

33. Locate the following trait
```rust
impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for New_connector_name
```

34. Copy and paste the code inside the get_headers and get_url functions as it is in the 
get_headers and get_url functions in the following macro, dont fix any errors
```rust
macros::macro_connector_implementation!(
    //..
    flow_name: PSync,
)
```

35. Remove the following trait
e.g:
```rust
impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for New_connector_name
```

36. Remove the PSync stub implementation
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






















### File: backend/connector-integration/src/connectors/new_connector/transformers.rs

37. Remove all lines at the top of the Rust file that start with use, including any grouped imports and multiline use statements. Dont do anything else dont fix any errors
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

38. Copy and paste the following code block as it is into the starting of transformers.rs file and dont remove anything else dont fix any errors
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
    connector_flow::{self, Authorize, PSync, RSync, RepeatPayment, SetupMandate, Void},
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

39. Copy and paste the following code block below the code block that you added in the previous step dont do anything else
```rust
use crate::{connectors::new_connector_name::New_connector_nameRouterData, types::ResponseRouterData};
```

40. Locate and remove the New_connector_nameRouterData struct and its impl
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

41. See the name of the request struct in Authorize flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>, //This one
    response_body: New_connector_namePaymentsResponse,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

42. Locate the struct in transformers.rs file
e.g:
```rust
#[derive(Debug, Serialize)]
pub struct New_connector_namePaymentsRequest {
```

43. Update the struct you located in the previous step similar to this following code
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

44. Add <T> in the struct which is used for payment method information like card
e.g:
```rust
#[derive(Debug, Serialize)]
pub struct New_connector_namePaymentsRequest<
//...
    billing_address: BillingAddress,
    card: Card<T>,
}
```

45. Now locate the struct where you added <T> in last step and do the changes similar in step 43 and 44 until a field with "CardNumber" is reached
e.g:
```rust
#[derive(Debug, Serialize)]
pub struct StructName {
    //..
    field_name: CardNumber,
    //..
}
```

46. Replace CardNumber with RawCardNumber<T>
```rust
pub struct StructName {
    //..
    field_name: RawCardNumber<T>,
    //..
}
```

47. See the name of the request struct in Authorize flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>, //This one
    response_body: New_connector_namePaymentsResponse,
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

48. Locate the TryFrom impl for the request struct
e.g:
```rust
impl TryFrom<&New_connector_nameRouterData<PaymentsAuthorizeRouterData>> for New_connector_namePaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        any_name: &New_connector_nameRouterData<PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
```

49. Replace the code block you located in the previous step with the following one
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

50. Inside the try_from function all the function/fields that are coming from item should come from item.resource_common_data
e.g:
```rust
item.get_billing_address()? //previous
item.resource_common_data.get_billing_address()? //Correct
```

51. See the name of the response_body struct in Authorize flow in new_connector_name.rs file
e.g:
```rust
(
    flow: Authorize,
    request_body: New_connector_namePaymentsRequest<T>,
    response_body: New_connector_namePaymentsResponse, //This one
    router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
)
```

52. Locate the TryFrom impl for the RouterData from ResponseRouterData<* New_connector_namePaymentsResponse *>
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

53. Replace the code block you located in the previous step with the following one
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

54. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
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

55. Wrap status inside resource_common_data: PaymentFlowData for response try_from for authorize
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```

56. See the name of the response_body struct in PSync flow in new_connector_name.rs file
e.g:
```rust
(
    flow: PSync,
    request_body: New_connector_nameSyncRequest,
    response_body: New_connector_namePSyncResponse, //This one
    router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
)
```

57. Locate the TryFrom impl for the RouterData from ResponseRouterData<* New_connector_namePSyncResponse *>
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

58. Replace the code block you located in the previous step with the following one
```rust
impl<F> TryFrom<ResponseRouterData<New_connector_namePSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<New_connector_namePSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
```

59. Remove charges field from PaymentsResponseData::TransactionResponse and add raw_connector_response inside try_from function that you modified in the last step and add status_code and change item.data to item.router_data
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

60. Wrap status inside resource_common_data: PaymentFlowData for response try_from for PSync
e.g:
```rust
Ok(Self {
    resource_common_data: PaymentFlowData {
        status: //..,
        ..item.router_data.resource_common_data
    },
    response: //..
```