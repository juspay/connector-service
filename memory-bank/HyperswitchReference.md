# PaymentMethodToken Flow: Technical Analysis

This document provides a detailed technical analysis of the `PaymentMethodToken` flow within the Hyperswitch application.

## 1. Core Flow Components

### Flow Marker Struct

The primary struct used to mark and identify the Payment Method Tokenization flow is `PaymentMethodToken`.

- __File Path:__ `crates/hyperswitch_domain_models/src/router_flow_types/payments.rs`
- __Definition:__
  ```rust
  pub struct PaymentMethodToken;
  ```

---

### Response Data Structure

The response for the tokenization flow is encapsulated within the `PaymentsResponseData` enum. The specific variant used is `TokenizationResponse`.

- __File Path:__ `crates/hyperswitch_domain_models/src/router_response_types.rs`
- __Definition:__
  ```rust
  #[derive(Debug, Clone)]
  pub enum PaymentsResponseData {
      // ... other variants
      TokenizationResponse {
          token: String,
      },
      // ... other variants
  }
  ```
- __Field Breakdown:__
  - `token`: The payment method token received from the connector.

---

### Type Aliases

Several type aliases are defined to simplify the use of `RouterData` for the tokenization flow.

- __File Path:__ `crates/router/src/types.rs`
- __Aliases:__
  ```rust
  pub type TokenizationRouterData = RouterData<
      router_flow_types::PaymentMethodToken,
      PaymentMethodTokenizationData,
      PaymentsResponseData,
  >;

  pub type TokenizationResponseRouterData<R> =
      ResponseRouterData<PaymentMethodToken, R, PaymentMethodTokenizationData, PaymentsResponseData>;
  ```
- __Description:__
  - `TokenizationRouterData`: A specialized `RouterData` type for the `PaymentMethodToken` flow, containing the request and response data structures.
  - `TokenizationResponseRouterData<R>`: A generic `ResponseRouterData` type used to handle connector-specific responses (`R`) within the tokenization flow.

---

## 2. Key Functions & Invocation Logic

### Main Handler Function

The core logic for the Payment Method Tokenization flow is orchestrated by the `add_payment_method_token` function. This function is responsible for deciding whether to tokenize the payment method with the connector and then executing the tokenization process.

- __File Path:__ `crates/router/src/core/payments/tokenization.rs`
- __Full Source Code:__
  ```rust
  pub async fn add_payment_method_token<F: Clone, T: types::Tokenizable + Clone>(
      state: &SessionState,
      connector: &api::ConnectorData,
      tokenization_action: &payments::TokenizationAction,
      router_data: &mut types::RouterData<F, T, types::PaymentsResponseData>,
      pm_token_request_data: types::PaymentMethodTokenizationData,
      should_continue_payment: bool,
  ) -> RouterResult<types::PaymentMethodTokenResult> {
      if should_continue_payment {
          match tokenization_action {
              payments::TokenizationAction::TokenizeInConnector => {
                  let connector_integration: services::BoxedPaymentConnectorIntegrationInterface<
                      api::PaymentMethodToken,
                      types::PaymentMethodTokenizationData,
                      types::PaymentsResponseData,
                  > = connector.connector.get_connector_integration();

                  let pm_token_response_data: Result<
                      types::PaymentsResponseData,
                      types::ErrorResponse,
                  > = Err(types::ErrorResponse::default());

                  let pm_token_router_data =
                      helpers::router_data_type_conversion::<_, api::PaymentMethodToken, _, _, _, _>(
                          router_data.clone(),
                          pm_token_request_data,
                          pm_token_response_data,
                      );

                  router_data
                      .request
                      .set_session_token(pm_token_router_data.session_token.clone());

                  let resp = services::execute_connector_processing_step(
                      state,
                      connector_integration,
                      &pm_token_router_data,
                      payments::CallConnectorAction::Trigger,
                      None,
                      None,
                  )
                  .await
                  .to_payment_failed_response()?;

                  metrics::CONNECTOR_PAYMENT_METHOD_TOKENIZATION.add(
                      1,
                      router_env::metric_attributes!(
                          ("connector", connector.connector_name.to_string()),
                          ("payment_method", router_data.payment_method.to_string()),
                      ),
                  );

                  let payment_token_resp = resp.response.map(|res| {
                      if let types::PaymentsResponseData::TokenizationResponse { token } = res {
                          Some(token)
                      } else {
                          None
                      }
                  });

                  Ok(types::PaymentMethodTokenResult {
                      payment_method_token_result: payment_token_resp,
                      is_payment_method_tokenization_performed: true,
                      connector_response: resp.connector_response.clone(),
                  })
              }
              _ => Ok(types::PaymentMethodTokenResult {
                  payment_method_token_result: Ok(None),
                  is_payment_method_tokenization_performed: false,
                  connector_response: None,
              }),
          }
      } else {
          logger::debug!("Skipping connector tokenization based on should_continue_payment flag");
          Ok(types::PaymentMethodTokenResult {
              payment_method_token_result: Ok(None),
              is_payment_method_tokenization_performed: false,
              connector_response: None,
          })
      }
  }
  ```

---

### Invocation Context & Decision Logic

The decision to trigger the `PaymentMethodToken` flow is primarily controlled by the `TokenizationAction` enum. This enum determines whether and how tokenization should occur.

- __File Path:__ `crates/router/src/core/payments.rs`
- __Controlling Enum:__ `TokenizationAction`
  ```rust
  #[derive(Clone, Debug)]
  pub enum TokenizationAction {
      TokenizeInRouter,
      TokenizeInConnector,
      TokenizeInConnectorAndRouter,
      ConnectorToken(String),
      SkipConnectorTokenization,
  }
  ```
  - `TokenizeInRouter`: Tokenize the payment method only in the Hyperswitch vault.
  - `TokenizeInConnector`: Tokenize the payment method only with the connector.
  - `TokenizeInConnectorAndRouter`: Tokenize in both the Hyperswitch vault and with the connector.
  - `ConnectorToken(String)`: Use a pre-existing connector token.
  - `SkipConnectorTokenization`: Skip tokenization with the connector entirely.

- __Decision Logic Function:__ `get_connector_tokenization_action_when_confirm_true`
  - This function determines the appropriate `TokenizationAction` based on several factors, including whether the payment is a recurring one, if a token already exists, and connector-specific tokenization settings.
  - __File Path:__ `crates/router/src/core/payments.rs`
  - __Logic Summary:__
    - If `setup_future_usage` is `OffSession`, it indicates a recurring payment. The function checks if a connector token already exists in Redis.
    - If a token exists, it returns `TokenizationAction::ConnectorToken`.
    - If no token exists, it checks if the connector is configured for tokenization (`is_connector_tokenization_enabled`).
    - Based on the connector's configuration, it returns either `TokenizeInConnectorAndRouter` or `TokenizeInRouter`.
    - For non-recurring payments or other scenarios, it might decide to `SkipConnectorTokenization`.

---

### Calling Flows

The `add_payment_method_token` function is invoked from other payment flows through the `Feature` trait. This trait defines a common interface for different payment operations, and `add_payment_method_token` is one of the steps in this interface.

The primary calling flows are:

1. __Authorize Flow:__
   - __File Path:__ `crates/router/src/core/payments/flows/authorize_flow.rs`
   - __Integration:__ The `Feature` trait is implemented for `types::PaymentsAuthorizeRouterData`. The `add_payment_method_token` function is called as part of the `decide_flows` method's execution path to tokenize the payment method before the authorization is sent to the connector.

2. __Setup Mandate Flow:__
   - __File Path:__ `crates/router/src/core/payments/flows/setup_mandate_flow.rs`
   - __Integration:__ The `Feature` trait is implemented for `types::SetupMandateRouterData`. Similar to the authorize flow, `add_payment_method_token` is called to tokenize the payment method before setting up the mandate with the connector.

---

## 3. Data Flow & Transformations

### Conversion Functions

Data from other payment flows is converted into `PaymentMethodTokenizationData` using `From` and `TryFrom` implementations. This allows the tokenization flow to be called seamlessly from various points in the application.

- __File Path:__ `crates/hyperswitch_domain_models/src/router_request_types.rs`

- __`From<PaymentsAuthorizeData>`:__
  ```rust
  impl TryFrom<PaymentsAuthorizeData> for PaymentMethodTokenizationData {
      type Error = error_stack::Report<ApiErrorResponse>;

      fn try_from(data: PaymentsAuthorizeData) -> Result<Self, Self::Error> {
          Ok(Self {
              payment_method_data: data.payment_method_data,
              browser_info: data.browser_info,
              currency: data.currency,
              amount: Some(data.amount),
              split_payments: data.split_payments.clone(),
              customer_acceptance: data.customer_acceptance,
              setup_future_usage: data.setup_future_usage,
              setup_mandate_details: data.setup_mandate_details,
              mandate_id: data.mandate_id,
          })
      }
  }
  ```

- __`From<SetupMandateRequestData>`:__
  ```rust
  impl TryFrom<SetupMandateRequestData> for PaymentMethodTokenizationData {
      type Error = error_stack::Report<ApiErrorResponse>;

      fn try_from(data: SetupMandateRequestData) -> Result<Self, Self::Error> {
          Ok(Self {
              payment_method_data: data.payment_method_data,
              browser_info: None,
              currency: data.currency,
              amount: data.amount,
              split_payments: None,
              customer_acceptance: data.customer_acceptance,
              setup_future_usage: data.setup_future_usage,
              setup_mandate_details: data.setup_mandate_details,
              mandate_id: data.mandate_id,
          })
      }
  }
  ```

- __`From<CompleteAuthorizeData>`:__
  ```rust
  impl TryFrom<CompleteAuthorizeData> for PaymentMethodTokenizationData {
      type Error = error_stack::Report<ApiErrorResponse>;

      fn try_from(data: CompleteAuthorizeData) -> Result<Self, Self::Error> {
          Ok(Self {
              payment_method_data: data
                  .payment_method_data
                  .get_required_value("payment_method_data")
                  .change_context(ApiErrorResponse::MissingRequiredField {
                      field_name: "payment_method_data",
                  })?,
              browser_info: data.browser_info,
              currency: data.currency,
              amount: Some(data.amount),
              split_payments: None,
              customer_acceptance: data.customer_acceptance,
              setup_future_usage: data.setup_future_usage,
              setup_mandate_details: data.setup_mandate_details,
              mandate_id: data.mandate_id,
          })
      }
  }
  ```

---

### Router Data Construction

The `RouterData` for the tokenization flow is constructed using the `router_data_type_conversion` helper function. This function is a generic converter that takes an existing `RouterData` object and transforms it into a new one with a different flow type, request type, and response type.

- __File Path:__ `crates/router/src/core/payments/helpers.rs`
- __Helper Function:__
  ```rust
  pub fn router_data_type_conversion<F1, F2, Req1, Req2, Res1, Res2>(
      router_data: RouterData<F1, Req1, Res1>,
      request: Req2,
      response: Result<Res2, ErrorResponse>,
  ) -> RouterData<F2, Req2, Res2> {
      RouterData {
          flow: std::marker::PhantomData,
          request,
          response,
          merchant_id: router_data.merchant_id,
          // ... other fields are copied over
      }
  }
  ```
- __Usage in `add_payment_method_token`:__
  When `add_payment_method_token` is called, it uses this helper to create a `TokenizationRouterData` instance from the calling flow's `RouterData` (e.g., `PaymentsAuthorizeRouterData`). It passes `PaymentMethodToken` as the new flow marker, `PaymentMethodTokenizationData` as the new request, and an empty `Err(types::ErrorResponse::default())` as a placeholder for the response.

---

## 4. Usage Context

### Triggering Conditions

The `PaymentMethodToken` flow is triggered under the following specific conditions:

- __`setup_future_usage` is `OffSession`:__ When a payment intends to save the payment method for future off-session use (e.g., recurring billing, subscriptions), this flow is triggered to get a reusable token from the connector.
- __Connector-Specific Tokenization:__ The flow is also triggered if the connector is configured to always tokenize payment methods, regardless of the `setup_future_usage` flag. This is controlled by the `is_connector_tokenization_enabled` flag.

### Business Scenarios

This flow is essential for a variety of business use cases that rely on stored payment methods:

- __Subscription Payments:__ For services that charge customers on a recurring basis (e.g., monthly, yearly), this flow provides the token needed to initiate subsequent payments without requiring the customer to re-enter their payment details.
- __One-Click Checkout:__ By tokenizing and storing a customer's payment method, merchants can offer a seamless one-click checkout experience for returning customers, significantly reducing friction and improving conversion rates.
- __Merchant-Initiated Transactions (MITs):__ Any transaction initiated by the merchant without the customer being present (e.g., metered billing, account top-ups) relies on a stored payment token obtained through this flow.

### Relationship with Other Flows

The `PaymentMethodToken` flow is not a standalone flow but is rather a sub-flow or a step within other major payment flows:

- __Authorize Flow:__ During an authorization, if the conditions for tokenization are met, this flow is called to get a token before the authorization request is sent to the connector.
- __Setup Mandate Flow:__ When setting up a mandate for future payments, this flow is used to tokenize the payment method that will be associated with the mandate.
- __Complete Authorize Flow:__ In some 3D Secure or redirect flows, tokenization might occur after the customer has completed the authentication step.

The token obtained from this flow is then stored in the `RouterData` and can be used in subsequent API calls to the connector, such as `Capture` or `Void`.

---

The primary request structure for this flow is `PaymentMethodTokenizationData`. This struct encapsulates all the necessary information to tokenize a payment method with a connector.

- __File Path:__ `crates/hyperswitch_domain_models/src/router_request_types.rs`
- __Definition:__
  ```rust
  #[derive(Debug, Clone)]
  pub struct PaymentMethodTokenizationData {
      pub payment_method_data: PaymentMethodData,
      pub browser_info: Option<BrowserInformation>,
      pub currency: storage_enums::Currency,
      pub amount: Option<i64>,
      pub split_payments: Option<common_types::payments::SplitPaymentsRequest>,
      pub customer_acceptance: Option<common_payments_types::CustomerAcceptance>,
      pub setup_future_usage: Option<storage_enums::FutureUsage>,
      pub setup_mandate_details: Option<mandates::MandateData>,
      pub mandate_id: Option<api_models::payments::MandateIds>,
  }
  ```
- __Field Breakdown:__
  - `payment_method_data`: Contains the raw payment method details (e.g., card number, wallet details).
  - `browser_info`: Optional browser details of the customer, used for 3D Secure authentication.
  - `currency`: The currency for the transaction.
  - `amount`: The transaction amount.
  - `split_payments`: Optional details for splitting payments.
  - `customer_acceptance`: Optional details of customer's acceptance of the mandate.
  - `setup_future_usage`: Indicates if the payment method should be saved for future use (e.g., `OffSession`).
  - `setup_mandate_details`: Optional details for setting up a mandate.
  - `mandate_id`: Optional mandate identifier if a mandate is being used.
---
