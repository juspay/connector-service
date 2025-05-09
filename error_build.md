error[E0432]: unresolved import `masking`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:8:5
  |
8 | use masking::Secret;
  |     ^^^^^^^ use of unresolved module or unlinked crate `masking`
  |
  = help: if you wanted to use a crate named `masking`, use `cargo add masking`
to add it to your `Cargo.toml`

error[E0407]: method `handle_response` is not a member of trait `ConnectorIntegrationV2`
  --> backend/connector-integration/src/connectors/checkout.rs:70:5
   |
70 |       fn handle_response(
   |       ^  --------------- help: there is an associated function with a similar name: `handle_response_v2`
   |  _____|
   | |
71 | |         &self,
72 | |         data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
73 | |         _event_builder: Option<&mut ConnectorEvent>,
...  |
93 | |         )))
94 | |     }
   | |_____^ not a member of trait `ConnectorIntegrationV2`

error[E0407]: method `get_error_response` is not a member of trait `ConnectorIntegrationV2`
   --> backend/connector-integration/src/connectors/checkout.rs:96:5
    |
96  |       fn get_error_response(
    |       ^  ------------------ help: there is an associated function with a similar name: `get_error_response_v2`
                                 |  _____|
    | |
97  | |         &self,
98  | |         res: hyperswitch_interfaces::types::Response,
99  | |         _event_builder: Option<&mut ConnectorEvent>,
...   |
109 | |         })
110 | |     }
    | |_____^ not a member of trait `ConnectorIntegrationV2`

warning: unused imports: `ConnectorAuthType`, `ErrorResponse`, `RedirectForm`, `RouterData`, and `payment_method_data::PaymentMethodData`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:2:5
  |
2 |     payment_method_data::PaymentMethodData,
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
3 |     router_data::{ConnectorAuthType, ErrorResponse, RouterData},
  |                   ^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^  ^^^^^^^^^^
4 |     router_request_types::ResponseId,
5 |     router_response_types::{PaymentsResponseData, RedirectForm},
  |                                                   ^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: unused import: `consts`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:7:30
  |
7 | use hyperswitch_interfaces::{consts, errors};
  |                              ^^^^^^

warning: unused import: `hyperswitch_masking::Secret`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:8:5
  |
8 | use hyperswitch_masking::Secret;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `error_stack::ResultExt`
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:11:5
   |
11 | use error_stack::ResultExt;
   |     ^^^^^^^^^^^^^^^^^^^^^^

error[E0277]: the trait bound `checkout::Checkout: domain_types::connector_types::RefundSyncV2` is not satisfied
                               --> backend/connector-integration/src/connectors/checkout.rs:11:32
   |
11 | impl ConnectorServiceTrait for Checkout {
   |                                ^^^^^^^^ the trait `domain_types::connector_types::RefundSyncV2` is not implemented for `checkout::Checkout`
                                |
   = help: the following other types implement trait `domain_types::connector_types::RefundSyncV2`:
             adyen::Adyen
             razorpay::Razorpay
note: required by a bound in `ConnectorServiceTrait`
  --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:53:7
   |
43 | pub trait ConnectorServiceTrait:
   |           --------------------- required by a bound in this trait
...
53 |     + RefundSyncV2
   |       ^^^^^^^^^^^^ required by this bound in `ConnectorServiceTrait`

error[E0277]: the trait bound `checkout::Checkout: domain_types::connector_types::PaymentCapture` is not satisfied
                               --> backend/connector-integration/src/connectors/checkout.rs:11:32
   |
11 | impl ConnectorServiceTrait for Checkout {
   |                                ^^^^^^^^ the trait `domain_types::connector_types::PaymentCapture` is not implemented for `checkout::Checkout`
                                |
   = help: the following other types implement trait `domain_types::connector_types::PaymentCapture`:
             adyen::Adyen
             razorpay::Razorpay
note: required by a bound in `ConnectorServiceTrait`
  --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:52:7
   |
43 | pub trait ConnectorServiceTrait:
   |           --------------------- required by a bound in this trait
...
52 |     + PaymentCapture
   |       ^^^^^^^^^^^^^^ required by this bound in `ConnectorServiceTrait`

error[E0277]: the trait bound `checkout::Checkout: domain_types::connector_types::RefundV2` is not satisfied
  --> backend/connector-integration/src/connectors/checkout.rs:11:32
   |
11 | impl ConnectorServiceTrait for Checkout {
   |                                ^^^^^^^^ the trait `domain_types::connector_types::RefundV2` is not implemented for `checkout::Checkout`
                                |
   = help: the following other types implement trait `domain_types::connector_types::RefundV2`:
             adyen::Adyen
             razorpay::Razorpay
note: required by a bound in `ConnectorServiceTrait`
  --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:51:7
   |
43 | pub trait ConnectorServiceTrait:
   |           --------------------- required by a bound in this trait
...
51 |     + RefundV2
   |       ^^^^^^^^ required by this bound in `ConnectorServiceTrait`

error[E0277]: the trait bound `checkout::Checkout: domain_types::connector_types::PaymentVoidV2` is not satisfied
                               --> backend/connector-integration/src/connectors/checkout.rs:11:32
   |
11 | impl ConnectorServiceTrait for Checkout {
   |                                ^^^^^^^^ the trait `domain_types::connector_types::PaymentVoidV2` is not implemented for `checkout::Checkout`
                                |
   = help: the following other types implement trait `domain_types::connector_types::PaymentVoidV2`:
             adyen::Adyen
             razorpay::Razorpay
note: required by a bound in `ConnectorServiceTrait`
  --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:49:7
   |
43 | pub trait ConnectorServiceTrait:
   |           --------------------- required by a bound in this trait
...
49 |     + PaymentVoidV2
   |       ^^^^^^^^^^^^^ required by this bound in `ConnectorServiceTrait`

error[E0277]: the trait bound `checkout::Checkout: PaymentOrderCreate` is not satisfied
  --> backend/connector-integration/src/connectors/checkout.rs:11:32
   |
11 | impl ConnectorServiceTrait for Checkout {
   |                                ^^^^^^^^ the trait `PaymentOrderCreate` is not implemented for `checkout::Checkout`
                                |
   = help: the following other types implement trait `PaymentOrderCreate`:
             adyen::Adyen
             razorpay::Razorpay
note: required by a bound in `ConnectorServiceTrait`
  --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:48:7
   |
43 | pub trait ConnectorServiceTrait:
   |           --------------------- required by a bound in this trait
...
48 |     + PaymentOrderCreate
   |       ^^^^^^^^^^^^^^^^^^ required by this bound in `ConnectorServiceTrait`

error[E0277]: the trait bound `checkout::Checkout: domain_types::connector_types::PaymentSyncV2` is not satisfied
                               --> backend/connector-integration/src/connectors/checkout.rs:11:32
   |
11 | impl ConnectorServiceTrait for Checkout {
   |                                ^^^^^^^^ the trait `domain_types::connector_types::PaymentSyncV2` is not implemented for `checkout::Checkout`
                                |
   = help: the following other types implement trait `domain_types::connector_types::PaymentSyncV2`:
             adyen::Adyen
             razorpay::Razorpay
note: required by a bound in `ConnectorServiceTrait`
  --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:47:7
   |
43 | pub trait ConnectorServiceTrait:
   |           --------------------- required by a bound in this trait
...
47 |     + PaymentSyncV2
   |       ^^^^^^^^^^^^^ required by this bound in `ConnectorServiceTrait`

error[E0277]: the trait bound `checkout::Checkout: domain_types::connector_types::PaymentAuthorizeV2` is not satisfied
                               --> backend/connector-integration/src/connectors/checkout.rs:11:32
   |
11 | impl ConnectorServiceTrait for Checkout {
   |                                ^^^^^^^^ the trait `domain_types::connector_types::PaymentAuthorizeV2` is not implemented for `checkout::Checkout`
                                |
   = help: the following other types implement trait `domain_types::connector_types::PaymentAuthorizeV2`:
             adyen::Adyen
             razorpay::Razorpay
note: required by a bound in `ConnectorServiceTrait`
  --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:46:7
   |
43 | pub trait ConnectorServiceTrait:
   |           --------------------- required by a bound in this trait
...
46 |     + PaymentAuthorizeV2
   |       ^^^^^^^^^^^^^^^^^^ required by this bound in `ConnectorServiceTrait`

error[E0046]: not all trait items implemented, missing: `base_url`
  --> backend/connector-integration/src/connectors/checkout.rs:31:1
   |
31 | impl ConnectorCommon for Checkout {
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing `base_url` in implementation
   |
   = help: implement the missing item: `fn base_url(&self, _: &'a hyperswitch_interfaces::configs::Connectors) -> &'a str { todo!() }`

error[E0050]: method `get_headers` has 3 parameters but the declaration in trait `hyperswitch_interfaces::connector_integration_v2::ConnectorIntegrationV2::get_headers` has 2
                               --> backend/connector-integration/src/connectors/checkout.rs:47:9
   |
47 | /         &self,
48 | |         _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
49 | |         _connectors: &domain_types::types::Connectors,
   | |_____________________________________________________^ expected 2 parameters, found 3
   |
   = note: `get_headers` from trait: `fn(&Self, &RouterDataV2<Flow, ResourceCommonData, Req, Resp>) -> Result<Vec<(std::string::String, Maskable<std::string::String>)>, error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>>`

error[E0050]: method `get_url` has 3 parameters but the declaration in trait `hyperswitch_interfaces::connector_integration_v2::ConnectorIntegrationV2::get_url` has 2
                               --> backend/connector-integration/src/connectors/checkout.rs:55:9
   |
55 | /         &self,
56 | |         _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
57 | |         _connectors: &domain_types::types::Connectors,
   | |_____________________________________________________^ expected 2 parameters, found 3
   |
   = note: `get_url` from trait: `fn(&Self, &RouterDataV2<Flow, ResourceCommonData, Req, Resp>) -> Result<std::string::String, error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>>`
error[E0050]: method `get_request_body` has 3 parameters but the declaration in trait `hyperswitch_interfaces::connector_integration_v2::ConnectorIntegrationV2::get_request_body` has 2
                               --> backend/connector-integration/src/connectors/checkout.rs:63:9
   |
63 | /         &self,
64 | |         _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
65 | |         _connectors: &domain_types::types::Connectors,
   | |_____________________________________________________^ expected 2 parameters, found 3
   |
   = note: `get_request_body` from trait: `fn(&Self, &RouterDataV2<Flow, ResourceCommonData, Req, Resp>) -> Result<std::option::Option<RequestContent>, error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>>`

error[E0599]: no method named `parse_struct` found for struct `bytes::bytes::Bytes` in the current scope
   --> backend/connector-integration/src/connectors/checkout.rs:79:14
    |
77  |           let response: transformers::CheckoutPaymentsResponse = res
    |  ________________________________________________________________-
78  | |             .response
79  | |             .parse_struct("CheckoutPaymentsResponse")
    | |_____________-^^^^^^^^^^^^
    |
   ::: /Users/sweta.sharma/.cargo/git/checkouts/hyperswitch-90748e17e947b406/c26f9d6/crates/common_utils/src/ext_traits.rs:175:8
                                 |
175 |       fn parse_struct<'de, T>(
    |          ------------ the method is available for `bytes::bytes::Bytes` here
    |
    = help: items from traits can only be used if the trait is in scope
help: there is a method `parse_to` with a similar name, but with different arguments
   --> /Users/sweta.sharma/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/winnow-0.7.6/src/parser.rs:683:5
                                 |
683 | /     fn parse_to<O2>(self) -> impls::ParseTo<Self, I, O, O2, E>
684 | |     where
685 | |         Self: core::marker::Sized,
686 | |         I: Stream,
687 | |         O: ParseSlice<O2>,
688 | |         E: ParserError<I>,
    | |__________________________^
help: trait `BytesExt` which provides `parse_struct` is implemented but not in scope; perhaps you want to import it
                                 |
1   + use common_utils::ext_traits::BytesExt;
    |

error[E0599]: no method named `set_response` found for struct `RouterDataV2<Authorize, PaymentFlowData, ..., ...>` in the current scope
                               --> backend/connector-integration/src/connectors/checkout.rs:82:25
   |
82 |         Ok(data.clone().set_response(Ok(
   |            -------------^^^^^^^^^^^^ method not found in `RouterDataV2<Authorize, PaymentFlowData, ..., ...>`

error[E0308]: mismatched types
   --> backend/connector-integration/src/types.rs:24:49
    |
24  |             ConnectorEnum::Checkout => Box::new(Checkout::new()),
    |                                        -------- ^^^^^^^^^^^^^^^ expected `&dyn ConnectorServiceTrait + Sync`, found `Checkout`
                                 |                                        |
    |                                        arguments to this function are incorrect
    |
    = note: expected reference `&dyn ConnectorServiceTrait + std::marker::Sync`
                  found struct `checkout::Checkout`
note: associated function defined here
   --> /Users/sweta.sharma/.rustup/toolchains/stable-x86_64-apple-darwin/lib/rustlib/src/rust/library/alloc/src/boxed.rs:273:12
                                 |
273 |     pub fn new(x: T) -> Self {
    |            ^^^
help: consider borrowing here
    |
24  |             ConnectorEnum::Checkout => Box::new(&Checkout::new()),
    |                                                 +

error[E0186]: method `id` has a `&self` declaration in the trait, but not in the impl
  --> backend/connector-integration/src/connectors/checkout.rs:31:5
   |
31 |     fn id() -> &'static str {
   |     ^^^^^^^^^^^^^^^^^^^^^^^ expected `&self` in impl
   |
   = note: `id` from trait: `fn(&Self) -> &'static str`

error[E0186]: method `common_get_content_type` has a `&self` declaration in the trait, but not in the impl
  --> backend/connector-integration/src/connectors/checkout.rs:35:5
   |
35 |     fn common_get_content_type() -> &'static str {
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `&self` in impl
   |
   = note: `common_get_content_type` from trait: `fn(&Self) -> &'static str`

error[E0599]: no function or associated item named `foreign_try_from` found for struct `RouterDataV2<_, _, _,
 _>` in the current scope
   --> backend/connector-integration/src/connectors/checkout.rs:102:23
    |
102 |         RouterDataV2::foreign_try_from((
    |                       ^^^^^^^^^^^^^^^^ function or associated item not found in `RouterDataV2<_, _, _, 
_>`
    |
    = help: items from traits can only be used if the trait is in scope
help: the following traits which provide `foreign_try_from` are implemented but not in scope; perhaps you wan
t to import one of them
    |
1   + use common_utils::transformers::ForeignTryFrom;
    |
1   + use crate::connectors::adyen::transformers::ForeignTryFrom;
    |
1   + use crate::connectors::razorpay::transformers::ForeignTryFrom;
    |
1   + use domain_types::utils::ForeignTryFrom;
    |
help: there is an associated function `try_from` with a similar name
    |
102 -         RouterDataV2::foreign_try_from((
102 +         RouterDataV2::try_from((
    |

error[E0308]: mismatched types
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:36:31
   |
36 |             redirection_data: Box::new(None),
   |                               ^^^^^^^^^^^^^^ expected `Option<RedirectForm>`, found `Box<Option<_>>`
   |
   = note: expected enum `std::option::Option<RedirectForm>`
            found struct `Box<std::option::Option<_>>`
help: consider unboxing the value
   |
36 |             redirection_data: *Box::new(None),
   |                               +

error[E0063]: missing fields `charge_id` and `mandate_reference` in initializer of `hyperswitch_domain_models
::router_response_types::PaymentsResponseData`
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:34:12
   |
34 |         Ok(PaymentsResponseData::TransactionResponse {
   |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing `charge_id` and `mandate_reference`

warning: unused import: `domain_types::utils::ForeignTryFrom`
  --> backend/connector-integration/src/connectors/checkout.rs:29:5
   |
29 | use domain_types::utils::ForeignTryFrom;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(unused_imports)]` on by default

warning: unused imports: `ConnectorAuthType`, `ErrorResponse`, `MandateReference`, `RedirectForm`, `RouterDat
a`, and `payment_method_data::PaymentMethodData`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:2:51
  |
2 |     router_response_types::{PaymentsResponseData, RedirectForm, MandateReference},
  |                                                   ^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^
...
5 |     router_data::ErrorResponse,
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `consts`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:7:30
  |
7 | use hyperswitch_interfaces::{consts, errors};
  |                              ^^^^^^

warning: unused import: `hyperswitch_masking::Secret`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:8:5
  |
8 | use hyperswitch_masking::Secret;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `error_stack::ResultExt`
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:11:5
   |
11 | use error_stack::ResultExt;
   |     ^^^^^^^^^^^^^^^^^^^^^^

error[E0277]: the trait bound `RouterDataV2<_, _, _, _>: TryFrom<...>` is not satisfied
  --> backend/connector-integration/src/connectors/checkout.rs:99:9
   |
99 |         RouterDataV2::try_from((
   |         ^^^^^^^^^^^^ unsatisfied trait bound
   |
   = help: the trait `From<(CheckoutPaymentsResponse, RouterDataV2<domain_types::connector_flow::Authorize, d
omain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData, domain_t
ypes::connector_types::PaymentsResponseData>, u16, std::option::Option<common_enums::CaptureMethod>, bool, st
d::option::Option<common_enums::PaymentMethodType>)>` is not implemented for `RouterDataV2<_, _, _, _>`
   = note: required for `(CheckoutPaymentsResponse, ..., u16, ..., bool, ...)` to implement `Into<RouterData
V2<_, _, _, _>>`
   = note: required for `RouterDataV2<_, _, _, _>` to implement `TryFrom<(CheckoutPaymentsResponse, RouterDat
aV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::co
nnector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>, u16, std::option:
:Option<common_enums::CaptureMethod>, bool, std::option::Option<common_enums::PaymentMethodType>)>`
   = note: the full name for the type has been written to '/Users/sweta.sharma/Desktop/Juspay/connector-servi
ce/target/debug/deps/connector_integration-35821ce041388d3e.long-type-8923961608726566581.txt'
   = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the trait bound `RouterDataV2<Authorize, ..., ..., ...>: From<...>` is not satisfied
   --> backend/connector-integration/src/connectors/checkout.rs:99:9
    |
99  | /         RouterDataV2::try_from((
100 | |             response_payload,
101 | |             data.clone(),
102 | |             res.status_code,
...   |
105 | |             data.request.payment_method_type,
106 | |         ))
    | |__________^ unsatisfied trait bound
    |
    = help: the trait `From<(CheckoutPaymentsResponse, RouterDataV2<domain_types::connector_flow::Authorize, 
domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData, domain_
types::connector_types::PaymentsResponseData>, u16, std::option::Option<common_enums::CaptureMethod>, bool, s
td::option::Option<common_enums::PaymentMethodType>)>` is not implemented for `RouterDataV2<Authorize, Paymen
tFlowData, ..., ...>`
    = note: required for `(CheckoutPaymentsResponse, ..., u16, ..., bool, ...)` to implement `Into<RouterData
V2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::con
nector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>>`
    = note: required for `RouterDataV2<Authorize, PaymentFlowData, ..., ...>` to implement `TryFrom<(Checkout
PaymentsResponse, RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::Paymen
tFlowData, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsRespo
nseData>, u16, std::option::Option<common_enums::CaptureMethod>, bool, std::option::Option<common_enums::Paym
entMethodType>)>`
    = note: the full name for the type has been written to '/Users/sweta.sharma/Desktop/Juspay/connector-serv
ice/target/debug/deps/connector_integration-35821ce041388d3e.long-type-15073625949525886492.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0432]: unresolved import `common_enums`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:9:5
  |
9 | use common_enums::{AttemptStatus, CaptureMethod, PaymentMethodType};
  |     ^^^^^^^^^^^^ use of unresolved module or unlinked crate `common_enums`
  |
  = help: if you wanted to use a crate named `common_enums`, use `cargo add common_enums` to add it to your `
Cargo.toml`

warning: unused import: `hyperswitch_interfaces::types::Response`
  --> backend/connector-integration/src/connectors/checkout.rs:31:5
   |
31 | use hyperswitch_interfaces::types::Response;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(unused_imports)]` on by default

warning: unused imports: `MandateReference`, `RedirectForm`, and `router_data::ErrorResponse`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:2:51
  |
2 |     router_response_types::{PaymentsResponseData, RedirectForm, MandateReference},
  |                                                   ^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^
...
5 |     router_data::ErrorResponse,
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0308]: mismatched types
   --> backend/connector-integration/src/connectors/checkout.rs:102:13
    |
102 |             data.clone(),
    |             ^^^^^^^^^^^^ expected `RouterDataV2<_, PaymentFlowData, _, ...>`, found `RouterDataV2<Autho
rize, ..., ..., ...>`
    |
    = note: `PaymentsResponseData` and `PaymentsResponseData` have similar names, but are actually distinct t
ypes
note: `PaymentsResponseData` is defined in crate `domain_types`
   --> /Users/sweta.sharma/Desktop/Juspay/connector-service/backend/domain_types/src/connector_types.rs:200:1
    |
200 | pub enum PaymentsResponseData {
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
note: `PaymentsResponseData` is defined in crate `hyperswitch_domain_models`
   --> /Users/sweta.sharma/.cargo/git/checkouts/hyperswitch-90748e17e947b406/c26f9d6/crates/hyperswitch_domai
n_models/src/router_response_types.rs:17:1
    |
17  | pub enum PaymentsResponseData {
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = note: the full name for the type has been written to '/Users/sweta.sharma/Desktop/Juspay/connector-serv
ice/target/debug/deps/connector_integration-35821ce041388d3e.long-type-2677772149526003169.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0117]: only traits defined in the current crate can be implemented for types defined outside of the cr
ate
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:54:1
   |
54 |    impl<F, Req> ForeignTryFrom<(
   |   _^            -
   |  |______________|
55 | ||     CheckoutPaymentsResponse,
56 | ||     RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
57 | ||     u16,
...  ||
60 | ||     Option<PaymentMethodType>,
61 | || )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData> {
   | ||__-_____----------------------------------------------------------^
   | |   |     |
   | |___|     `RouterDataV2` is not defined in the current crate
   |     this is not defined in the current crate because this is a foreign trait
   |
   = note: impl doesn't have any local type before any uncovered type parameters
   = note: for more information see https://doc.rust-lang.org/reference/items/implementations.html#orphan-rul
es
   = note: define and implement a trait or new type instead

error[E0599]: no method named `change_context` found for enum `Result` in the current scope
   --> backend/connector-integration/src/connectors/checkout.rs:108:10
    |
100 | /         RouterDataV2::foreign_try_from((
101 | |             response_payload,
102 | |             data.clone(),
103 | |             res.status_code,
...   |
107 | |         ))
108 | |         .change_context(errors::ConnectorError::ResponseHandlingFailed)
    | |         -^^^^^^^^^^^^^^ method not found in `Result<RouterDataV2<Authorize, ..., ..., ...>, ...>`
    | |_________|
    |
    |
note: the method `change_context` exists on the type `error_stack::Report<error_stack::Report<hyperswitch_int
erfaces::errors::ConnectorError>>`
   --> /Users/sweta.sharma/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/error-stack-0.4.1/src/report.
rs:462:5
    |
462 | /     pub fn change_context<T>(mut self, context: T) -> Report<T>
463 | |     where
464 | |         T: Context,
    | |___________________^
help: use the `?` operator to extract the `error_stack::Report<error_stack::Report<hyperswitch_interfaces::er
rors::ConnectorError>>` value, propagating a `Result::Err` value to the caller
    |
107 |         ))?
    |           +

error[E0407]: method `build_error_response` is not a member of trait `ConnectorIntegrationV2`
   --> backend/connector-integration/src/connectors/checkout.rs:121:5
    |
121 | /     fn build_error_response(
122 | |         &self,
123 | |         res: hyperswitch_interfaces::types::Response,
124 | |         _event_builder: Option<&mut ConnectorEvent>,
...   |
138 | |         })
139 | |     }
    | |_____^ not a member of trait `ConnectorIntegrationV2`

warning: unused import: `crate::connectors::checkout::transformers::ForeignTryFrom`
 --> backend/connector-integration/src/connectors/checkout.rs:4:5
  |
4 | use crate::connectors::checkout::transformers::ForeignTryFrom; // Import the LOCAL trait
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: unused imports: `MandateReference as BaseMandateReference`, `self as router_req_types`, and `self as
 router_res_types`
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:11:28
   |
11 | ...::{self as router_req_types, ResponseId},
   |       ^^^^^^^^^^^^^^^^^^^^^^^^
12 | ...s::{self as router_res_types, RedirectForm as BaseRedirectForm, MandateReference as BaseMandateRefere
n...
   |        ^^^^^^^^^^^^^^^^^^^^^^^^                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
^^^

warning: unused import: `error_stack::ResultExt`
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:20:5
   |
20 | use error_stack::ResultExt;
   |     ^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `hyperswitch_cards::CardNumber`
  --> backend/connector-integration/src/connectors/checkout/transformers.rs:21:5
   |
21 | use hyperswitch_cards::CardNumber;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no method named `expose` found for struct `CardNumber` in the current scope
   --> backend/connector-integration/src/connectors/checkout/transformers.rs:244:58
    |
244 |                     number: Secret::new(card.card_number.expose()),
    |                                                          ^^^^^^ method not found in `CardNumber`

warning: unused import: `utils::ForeignTryFrom`
 --> backend/connector-integration/src/connectors/checkout/transformers.rs:6:5
  |
6 |     utils::ForeignTryFrom as DomainForeignTryFrom,
  |     ^^^^^^^^^^^^^^^^^^^^^

warning: unused variable: `event_builder`
  --> backend/connector-integration/src/connectors/checkout.rs:93:9
   |
93 |         event_builder: Option<&mut ConnectorEvent>,
   |         ^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_event_builder`
   |
   = note: `#[warn(unused_variables)]` on by default


</rewritten_file> 