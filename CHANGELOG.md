# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


### Bug Fixes

- Add protoc installation in ci

- Fmt

- Clippy and spell checks 

- Run ci checks in merge queue 

- **core:** Fixed the rust client library and its usage 

- **connector:** [ADYEN] Fix Error Response Status 

- **config:** Add list parse key for proxy.bypass_proxy_urls environment variable 

- Proto fixes (Add Implementations for RefundService and DisputeService) 

- Revoked the ability of child to mutate payment flow data 

- Order_id is made optional 

- Changing default return status type to authorizing 

- Removed the default non deterministic fallback from amount converter 

- Status code not optional 

- Razorpay error status fix 

- Paytm naming 

- **connector-integration:** Update expand_fn_handle_response macro with preprocess_response logic 

- Sanitize the branch name with Slash for image tag creation 

- **connector:** Fix authorizedotnet payment flows with adding preprocess response bytes method 

- Raw connector response changes 

- Initialize Kafka metrics at startup and resolve Clippy warnings in common-util crate 

- Convert _DOT_ to . for audit event nested keys ENV parsing 

- Convert _DOT_ to . for audit event nested keys ENV parsing for transformation and extraction 

- Added masked_serialize for audit events 

- Razorpay reference id 

- Initliazing event publisher only if config.event is enabled 

- Improve flow mapping and make audit events fail-safe 

- Capture method optional handling 

- Customer_id for authorizedotnet 

- Email consumption from payment method billing in Razorpay 

- Docker public repo fix 

- **configs:** Add Bluecode's base url in sandbox and production configs 

- **cybersource:** Use minor_refund_amount instead of minor_payment_amount in refund transformer 

- Resolve disparity in Authorizedotnet flows (Authorize, RepeatPayment, SetupMandate) 

- **Access_token_flow:** Added proto field to accept expires_in_seconds in request 

- **cybersource:** Use security_code and state_code in authorize flow 

- **audit:** Ensure grpc audit events emit even for early request parsing failures 

- Authentication flow request and response handling fix 

- Fixed xendit tests for pending cases 

- Noon expiry year and fiuu three ds 

- **stripe:** Update error handling to use message instead of code for response errors 

- **noon:** Update error response message handling to use the correct message field 

- **cybersource:** Update error handling to use message instead of reason 

- Add optional error_reason field to payment responses 

- Diff fixes for Novalnet Authorize flow 

- **noon:** Refund diff check for connector noon 

- **razorpay:** Change payment_capture field type from boolean to integer 

- Capture body changes and baseurl changes 

- Adyen Diff Check Resolve 

- **Braintree:** Refund diff check for connector Braintree 

- Mapping wrongly done for hipay in types.rs 

- Stripe connector_response diff fix 

- Change address type for Customer Create and PaymenMethodToken Create Request 

- Sandbox url fix 

- [WORLDPAYVANTIV] sandbox url fix 

- **Trustpay:** AccessToken creation fix 

- **Rapyd:** Authorize diff check fix 

- Merchant_reference_payment_id proto change 

- Removed git from dockerignore to add build versions in health check 

- **Fiserv:** Authorize, Capture, Void, Refund diff check for connector Fiserv 

- Reverting merchant_reference_payment_id field addition 

- Populate payment method token for AuthorizeOnly request 

- Fix Customer_Acceptance conversion from proto to connector_type 

- Diff correction for multisafepay 

- **bluesnap:** Address `merchantTransactionId` being `IRRELEVANT_ATTEMPT_ID` instead of actual `attempt_id` 

- Adyen prod diff check parity 

- Diff checker changes in hipay 

- Fixed metadata to accept all values in Authorize flow 

- Checkout Diff check fixes 

- Removed extra ; in payments.proto file 

- **connector:** [paysafe] make payment method token calls work for authorizeonly flow 

- Status handling to use router_data.status during error case 2xx 

- Diff check fixes for Xendit Authorize flow 

- Adyen brand name lower case to match hyperswitch diff 

- **connector:** [bluesnap] pass `connector_request_ref_id` instead of `payment_id` 

- **connector:** Fiserv RSync flow Diff fix 

- Correct mapping of metadata 

- Capture, Void, Refund Request 

- Removed the authorization_indicator_type field from Authdotnet Req 

- **connector:** Paypal Capture & Void flow 

- [WORLPAYVANTIV] Diff Checks 

- Diff check fixes for Dlocal 

- Adyen url on non test mode for authorize,void,etc 

- Remove the parallel execution of test in Run test 

- Remove unused field 

- Added Capture Method in Cybersource Repeat Payment Response 

- CavvAlgorithm in proto missing field 

- Resolved RouterData diffs in Prod for Authorizedotnet  

- **connector:** Fix Razorpay metadata to accept all values 

- RepeatPayment Merchant configured Currency Handling 

- Adyen shoppername to none for bankredirect, repeatpayment 

- RouterData diff fix for Novalnet & Cashtocode 

- RouterData diff fix for Fiuu PSync 

- Add secondary base url for Fiuu 

- Diff fix for adyen and paypal repeat payments 

- [CYBERSOURCE] PSYNC DIFF FIX 

- Trustpay refund fix 

- Paypal missing redirect_uri logic in form_fields for 3DS flow 

- **payload:** Do not pass `content-type` header in sync calls 

- **connector:** Map `Ds_State` to status in Redsys PSync when `Ds_Response` is absent 

- **connector:** Rapyd amount type in request 

- Adyen webhook fix 

- Added missing proto to domain conversion of merchant_account_metadata for setupmandate 

- **connector:** [NOVALNET] Populating connector transaction id during 2xx failures 

- **connector:** Request diff fix for Stripe & Cybersource 

- **connector:** [NEXIXPAY] DIFF FIX 

- **connector:** [Fiuu] Fixed payment status being sent as Pending for Fiuu when the connector response is FiuuPaymentsResponse::Error 

- Handled metadata Parsing Err Gracefully in Core 

- Revert "Handled metadata Parsing Err Gracefully in Core" 

- PAYPAL Authorize 2xx error handling and connector_metadata diff in psync 

- **payment_method:** Blik and sofort bank redirect payment method type defaulting to card 

- **connector:** Paypal Router Data Fix in Authorize and RepeatPayment Flow 

- Populate connector response for Repeat Everything Flow's Err response 

- **connector:** Mifinity 5xx Error Handling 

- **connector:** Fixed Volt Default Response and PSync Response Handling 

- **connector:** Noon RSync Url & Default Status 

- Incremental_authorization_allowed and cybersource repeatpayment diff fix 

- **redsys:** Correct XML element ordering in SOAP sync requests to comply with DTD validation 

- Add dev tools via nix

- Standardize setup instructions to use 'make run' in SDK makefiles and READMEs

- Addressing comments of pr #515 

- Install libpq for macOS builds

- Make SDK Makefiles work from any directory


### Documentation

- Add memory banks for folder on interests 

- **setup.md:** Add setup instructions for local development setup 

- **setup.md:** Toml always prod.toml issue fix for docker 

- Remove example directory references from SDK READMEs


### Features

- **core:** Added macros and Adyen authorize with macros 

- **core:** Add Setup Mandate Flow 

- **core:** Added accept dispute (L2) and accept dispute for Adyen (L3) 

- **core:** Added Submit evidence (L2) and Submit evidence for Adyen (L3) 

- **core:** Implement Error Framework 

- **connector:** Added macros for adyen flows 

- Add macro implementations for granular apis in L2 layer 

- **docs:** Connector Integration With Macros Guide Doc 

- **core:** Added Defend Dispute flow (L2) and Adyen Defend Dispute(L3) 

- **core:** Added Dispute Webhooks flow (L2) and Dispute Webhooks for Adyen (L3) 

- **core:** [ADYEN, RAZORPAY] Added util functions for Connector Specifications & Validations 

- **core:** Added Google Pay and Apple Pay Wallets(L2) and Adyen (L3) flow 

- Add all_keys_required and raw_connector_response 

- **core:** Added response preprocessing in macros 

- **connector:** Added cards flow and unit tests for Fiserv 

- **connector:** Added cards flow and unit tests for elavon 

- **core:** Downgrade Resolver to Fix compatibility with Hyperswitch 

- **connector:** Added cards flow and unit tests for Xendit 

- Add HTTP health endpoint for Kubernetes probes 

- **connector:** Added Authorization flow and tests for checkout 

- Add structured logs 

- Adding integrity framework support 

- Added Metrics to the UCS 

- Adding source verification framework 

- **connector:** Added cards flow and unit tests for Authorizedotnet 

- Razorpay integration v2/v1 

- Phonepe UPI integration 

- Cashfree upi integration 

- **connector:** Added cards flow and tests for Fiuu 

- **connector:** [PAYU] Payu Connector Integration 

- Network status being passed 

- **connector:** Added authorize flow and tests for Cashtocode and Reward PaymentMethod 

- Headers Passing 

- **connector:** Added cards flow and tests for Novalnet 

- **config:** Add Coderabbit Configuration 

- Add new trait for payment method data type  

- **connector:** [NEXINETS] Connector Integration 

- Patym upi integration 

- **connector:** [NOON] Connector Integration 

- Add audit logging and direct Kafka logging with tracing-kafka 

- **connector:** [PAYU] Payu PSync flow 

- Adding sync for phone pe 

- **connector:** [MIFINITY] Connector Integration 

- **core:** Implemented CardNumber type in proto 

- **core:** Added Secret String Type in Proto 

- **core:** Renamed cards, common_enums and common_utils crate 

- **config:** Updated Coderabbit Guidelines 

- **connector:** Added wallet payments support for Novalnet 

- **core:** Added Masked Serialize for Golden Log Lines and Added SecretString type to Emails and Phone Number in Proto 

- **core:** Setup G2H to use compile_protos_with_config() function 

- Implement lineage ID tracking for distributed request tracing 

- **core:** Added SecretString type for first_name and last_name 

- **core:** Injector crate addition 

- **connector:** [BRAINTREE] Connector Integration and PaymentMethodToken flow 

- Setup automated nightly release workflows 

- **core:** Access token flow 

- **connector:** [VOLT] Connector Integration  

- **connector:** [BLUECODE] Added Bluecode Wallet in UCS 

- Introduce production/sandbox configs 

- **core:** Implement two step payment webhooks processing 

- **connector:** Added authorize, psync and tests for Cryptopay and CryptoCurrency PaymentMethod 

- Added raw_connector_request in ucs response 

- Emit event for grpc request and refactor event publisher to synchronous 

- **connector:** [HELCIM] Connector Integration  

- **core:** PreAuthenticate, Authenticate and PostAuthenticate flow 

- **connector:** [Dlocal] Connector Integration 

- **connector:** [Placetopay] Connector Integration 

- Emitting lineage id an reference id to kafka metadata in events 

- **connector:** [Rapyd] Connector Integration 

- **framework:** Run UCS in Shadow mode  

- **connector:** [Aci] Connector Integration 

- **connector:** [TRUSTPAY] Connector Integration PSync flow 

- **connector:** Added AccessToken flow for trustpay 

- **connector:** Added cards flow and tests for Stripe 

- **core:** Added SecretString type for raw_connector_request and raw_connector_response 

- **connector:** [CYBERSOURCE] Connector Integration 

- **core:** Added Create connector customer flow 

- Adding_new_field_for_Merchant_account_metadata 

- **connector:** Diff check fixes for Stripe, Cybersource & Novalnet 

- **connector:** [Worldpay] Connector Integration  

- **connector:** [Worldpayvantiv] Connector Integration and VoidPostCapture flow implemented 

- **connector:** Added SetupMandate, RepeatPayment and CreateConnectorCustomer flows for stripe 

- **connector:** Added RepeatPayment flow for cybersource 

- **connector:** [payload] implement core flows, card payment method and webhooks 

- Unmask x-shadow-mode header in logs 

- **connector:** [FISERVEMEA] Connector Integration  

- Add test mode and mock PG API integration 

- **connector:** [DATATRANS] Connector Integration  

- **connector:** [AUTHIPAY] Connector Integration 

- **connector:** Added Refund flow for Authorizedotnet 

- Add wait screen information for UPI payments 

- **connector:** [SILVERFLOW] Connector Integration  

- **connector:** [CELEROCOMMERCE] Connector Integration 

- Introduce session token create grpc function 

- Introduce access token create grpc function 

- **connector:** [Paypal] Connector Integration 

- **connector:** [STAX] Connector Integration 

- **connector:** [Stripe] Add Apple pay, Google pay & PaymentMethodtoken flow for Stripe 

- Introduce payment authorize only create grpc function 

- Client creation based on proxy 

- **trustpay:** Implement error type mapping and enhance error handling 

- Introduce connector customer create grpc function 

- Encoded data in psync separate field 

- Introduce create order grpc function 

- **connector:** [MULTISAFEPAY] Connector Integration 

- Introduce create payment method token create grpc function 

- Introduce register only grpc function 

- **connector:** [HIPAY] Connector Integration  

- **connector:** [TRUSTPAYMENTS] Connector Integration 

- **connector:** [GLOBALPAY] Connector Integration 

- **connector:** Add bluesnap -- no3ds authorize, void, capture, refund, psync, rsync and webhooks 

- **connector:** [paysafe] integrate no3ds card, refund, void, capture 

- Added Config Overrides 

- **connector:** Billwerk Connector Integration 

- **connector:** [NMI] Connector Integration 

- Enhance gRPC payment requests with order_id, payment_method_token, and access_token support 

- **connector:** Add Forte Connector 

- **connector:** [SHIFT4] Connector Integration 

- **connector:** Added bamboraapac integration 

- **connector:** [IATAPAY] Connector Integration 

- **connector:** [NEXIXPAY] Connector Integration 

- **core:** Added SdkSessionToken Flow support 

- **connector:** [NUVEI] Connector Integration  

- GooglePayThirdPartySdk, ApplePayThirdPartySdk, PaypalSdk wallet support for braintree 

- **connector:** Introduce barclaycard  

- Paypal refund rsync flow 

- **connector:** [AIRWALLEX] Connector Integration 

- **framework:** Implemented Custom HTTP Integration Layer 

- **connector:** Trustpay Refund & RSync flow 

- **connector:** Bankofamerica Connector Integration 

- **connector:** [Powertranz] Connector Integration  

- Paypal Threeds flow Added 

- **connector:** Nexinets void flow & PSync, Capture, Refund, RSyns diff check fix 

- Setupmandate and repeat payment flow for paypal 

- **connector:** [BAMBORA] Connector Integration 

- Enable clippy for connector integration crate 

- **connector:** [Checkout] Added Setupmandate & Repeatpayment flows for Checkout 

- **connector:** [PAYME] Connector Integration 

- **connector:** [TSYS] Connector Integration 

- **connector:** Refactored Volt connector and Refund & RSync flow implementation 

- **connector:** [WORLDPAYXML] Connector Integration 

- **connector:** [Stripe] Add Banktransfer, BNPL, BankRedirect PMs for stripe 

- **connector:** [SHIFT4] Bank-Redirect 

- **connector:** Jpmorgan 

- **connector:** Revolut Connector Integration  

- **connector:** Revolut pay fix 

- Added upi_source for cc/cl 

- **core:** Add support for NetworkTokenWithNTI and NetworkMandateId in RepeatPayment 

- **connector:** [AIRWALLEX] Bank-Redirect 

- **connector:** [GLOBALPAY] Bank-Redirect 

- **connector:** Refactor Calida 

- **core:** Add connector_order_reference_id for Psync 

- **connector:** [PAYPAL] Bank-Redirect 

- **connector:** Trustpay Bank Transfer & Bank Redirect Payment Method 

- Adyen bankredirect payment method 

- **connector:** [PAYBOX] Connector Integration 

- **connector:** [LOONIO] Connector Integration  

- **connector:** Braintree RepeatPayment Flow 

- **connector:** [GIGADAT] Connector Integration 

- Repeatpayment, nti flow for adyen 

- Add granular Claude rules for connector integration 

- **framework:** Added IncrementalAuthorization Flow support 

- **core:** MandateRevoke flow 

- Added  Network-level error details in proto 

- **connector:** [Fiuu] Added RepeatPayment flow 

- **connector:** [GETNETGLOBAL] Connector Integration  

- **core:** Changed Metadata Type to SecretString 

- **wellsfargo:** Connector integration 

- **connector:** Refactored Cybersource Mandate Payments 

- **connector:** [Adyen] Implement Bank debits  

- Add bank transfer support in adyen 

- **connector:** [NovalNet] Implement Bank Debits 

- **connector:** [ADYEN] card redirect Integration  

- **connector:** Braintree Card 3DS PaymentMethod 

- **connector:** [MOLLIE] Connector Integration 

- Disable gzip decompression in test mode 

- Noon repeateverything flow implementation 

- **framework:** Added redirection_data field in PSync response and test_mode field in PSync request 

- **connector:** [Hyperpg] Integrate Card flows 

- **connector:** Phonepe upi cc/cl response handling 

- Adyen gift card 

- **connector:** Razorpay - added pay mode handling in upi sync response  

- **framework:** Added VerifyRedirectResponse flow 

- **connector:** Implement incoming webhooks for trustpay 

- **framework:** Added missing CardNetwork Types 

- **connector:** Zift Connector Integration 

- **payment_method_data:** [adyen] Auth code in payment response 

- **connector:** Gigadat Macro Implementation 

- **framework:** Introduce BodyDecoding trait 

- **connector:** Added Adyen paylater paymentmethod 

- Uniffi working implementation for JS/Java/Python 

- **framework:** Changed access_token type from String to SecretString in proto and connector_types 

- **connector:** Added ConnectorResponse for Connector Loonio 

- Add flake.lock

- **ci:** Set up GitHub release workflow with multi-platform builds 

- Enable release workflow on branches

- **connector:** [trustpay] introduce wallet support - apple pay and google pay 

- Make examples work across directories


### Miscellaneous Tasks

- Address Rust 1.88.0 clippy lints 

- Wrapper for log 

- Log sanity (Updated code) 

- Added setupmandate flow to authorizedotnet 

- Added support for raw connector response for Authorizedotnet 

- Status of SetupMandate changed from authorize to charged 

- Added webhooks support in cashtocode 

- Added amount converter 

- Added webhooks support in Novalnet 

- **core:** Removing debug logging which is set manually 

- **version:** 2025.09.17.0

- Add amount conversion wrapper and integrity checks for Xendit 

- Update git tag for hyperswitch repo 

- **version:** 2025.09.18.0

- **version:** 2025.09.19.0

- **version:** 2025.09.22.0

- Added webhooks support in Fiuu 

- **version:** 2025.09.23.0

- **version:** 2025.09.24.0

- **version:** 2025.09.25.0

- Added OnlineBankingFpx, DuitNow payment methods support 

- **version:** 2025.09.25.1

- **version:** 2025.09.26.0

- Update git tag for hyperswitch repo 

- **version:** 2025.09.29.0

- **version:** 2025.09.30.0

- **version:** 2025.10.01.0

- **version:** 2025.10.02.0

- **version:** 2025.10.08.0

- Added webhooks support in Noon 

- **version:** 2025.10.09.0

- **version:** 2025.10.10.0

- **version:** 2025.10.10.1

- **version:** 2025.10.14.0

- Added webhooks support in Cryptopay 

- **version:** 2025.10.16.0

- **version:** 2025.10.17.0

- **version:** 2025.10.23.0

- **version:** 2025.10.27.0

- **version:** 2025.10.28.0

- **version:** 2025.10.29.0

- **version:** 2025.10.30.0

- **version:** 2025.10.31.0

- **version:** 2025.11.04.0

- **version:** 2025.11.04.1

- **version:** 2025.11.05.0

- **version:** 2025.11.10.0

- **version:** 2025.11.11.0

- **version:** 2025.11.12.0

- **version:** 2025.11.13.0

- Fixed Void and Capture flow as per diff checker 

- **version:** 2025.11.14.0

- **version:** 2025.11.17.0

- **version:** 2025.11.17.1

- **version:** 2025.11.18.0

- **version:** 2025.11.19.0

- **version:** 2025.11.19.1

- Added dynamic content type selection and authorize flow for Trustpay 

- **version:** 2025.11.19.2

- **version:** 2025.11.21.0

- **version:** 2025.11.24.0

- **version:** 2025.11.25.0

- **core:** Updating tokio and hyperswitch dependency 

- **version:** 2025.11.25.1

- **version:** 2025.11.26.0

- **version:** 2025.11.27.0

- **version:** 2025.11.28.0

- **version:** 2025.12.01.0

- **version:** 2025.12.02.0

- **version:** 2025.12.03.0

- Add trigger to push image to ghcr when tag is created 

- **version:** 2025.12.03.1

- **version:** 2025.12.04.0

- **version:** 2025.12.05.0

- **version:** 2025.12.08.0

- **version:** 2025.12.09.0

- **version:** 2025.12.10.0

- **version:** 2025.12.10.1

- **version:** 2025.12.11.0

- **version:** 2025.12.11.1

- **version:** 2025.12.12.0

- **version:** 2025.12.15.0

- **version:** 2025.12.16.0

- **version:** 2025.12.17.0

- **version:** 2025.12.18.0

- **version:** 2025.12.19.0

- **version:** 2025.12.23.0

- **version:** 2025.12.24.0

- **version:** 2025.12.25.0

- **version:** 2025.12.30.0

- **version:** 2025.12.31.0

- **version:** 2026.01.01.0

- **version:** 2026.01.05.0

- **version:** 2026.01.08.0

- **version:** 2026.01.09.0

- **version:** 2026.01.12.0

- **version:** 2026.01.12.1

- **version:** 2026.01.13.0

- **version:** 2026.01.13.1

- **version:** 2026.01.13.2

- **version:** 2026.01.14.0

- **version:** 2026.01.14.1

- **version:** 2026.01.15.0

- **version:** 2026.01.19.0

- **version:** 2026.01.21.0

- Proto code owners 

- **version:** 2026.01.22.0

- **version:** 2026.01.23.0

- **version:** 2026.01.26.0

- **version:** 2026.01.27.0

- **version:** 2026.01.28.0

- Populate connector response field in error response 

- **version:** 2026.01.29.0

- **version:** 2026.01.30.0

- **version:** 2026.02.02.0

- **version:** 2026.02.03.0

- [Auth.net] Response field made optional 

- **version:** 2026.02.04.0

- **version:** 2026.02.05.0

- Updated the creds file 

- **version:** 2026.02.06.0

- **version:** 2026.02.06.1

- Added Resource ID, Service Name, and Service Type for UCS Events 

- **version:** 2026.02.10.0

- Adding failure status to customer create response 

- **version:** 2026.02.11.0

- **version:** 2026.02.11.1

- **version:** 2026.02.12.0

- **version:** 2026.02.13.0

- **version:** 2026.02.13.1

- **version:** 2026.02.16.0

- Directory organization/naming

- Added Crate for Composite Flows 

- **version:** 2026.02.18.0

- **version:** 2026.02.18.1

- **version:** 2026.02.20.0

- Disable strict conventional commits requirement

- Use right toolchain action

- Use right toolchain action

- Use right toolchain action

- **fmt:** Run formatter

- Add protoc setup and use cargo build for native Linux

- Remove obsolete ci-makefiles directory


### Performance

- Optimize release workflow with parallel SDK packaging and caching


### Refactor

- **proto:** Improve consistency and conventions in payment.proto 

- Removing hyperswitch dependency 

- Adding getter function for domain types and adding some util functions 

- Remove unnecessary qualifications in interfaces crate 

- **connector:** [RAZORPAY] populate error for success response in sync 

- Added Webhook Events 

- Added proper referer handling 

- **connector:** [PHONEPE] refactor phonepe and add UPI_QR support 

- **connector:** Update phonepe sandbox endpoint 

- **connector:** [RAZORPAY] update Razorpay connector diffs 

- Use typed connector response with masking for events 

- **connector:** [PHONEPE] refactor status mapping 

- **connector:** [PAYTM] refactor UPI flows for Paytm 

- Flattened the payment method in proto 

- Use namespace imports for connectors in types.rs 

- Made mandatory fields in authorize flow optional 

- Refactor config override functionality 

- **connector:** Add url safe base64 decoding support 

- Use proper error mapping instead of hardcoded connector_errors for Authorize 

- **connector:** [redsys] skip serializing fields that are `none` and sort fields in alphabetical order 

- Event publisher to log processed event even when publisher is disabled 

- **connector:** [PHONEPE] add Phonepe specific headers and target_app for upi request 

- Rename x86 targets to x86_64 and limit to native platforms

- Consolidate SDK build and packaging into sdk/ directory

<!-- generated by git-cliff -->
