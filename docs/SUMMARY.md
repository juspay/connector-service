# Summary

## Getting Started
- [Overview](README.md)
- [Installation & Configuration](getting-started/installation.md)
- [Create Payment Order](getting-started/create-order.md)
- [First Payment](getting-started/first-payment.md)
- [Extend to More Flows](getting-started/extend-to-more-flows.md)

## Architecture
- [Architecture Overview](architecture/README.md)
- [PCI Compliance](architecture/compliance/compliance.md)
- [Versioning](architecture/versioning.md)
- [Core Components](architecture/concepts/core-components.md)
- [Connector Settings and Overrides](architecture/concepts/connector-settings-and-overrides.md)
- [Connectors Services Subservices Methods](architecture/concepts/connectors-services-subservices-methods.md)
- [Environment Settings](architecture/concepts/environment-settings.md)
- [Error Handling](architecture/concepts/error-handling.md)
- [Error Mapping](architecture/concepts/error-mapping.md)
- [ID and Object Modelling](architecture/concepts/id-and-object-modelling.md)
- [Modes of Usage](architecture/concepts/library-modes-of-usage.md)
- [Specs and DSL](architecture/concepts/specs-and-dsl.md)

### Frameworks
- [Integrity and Source Verification](architecture/frameworks/integrity-and-source-verification.md)
- [Money Struct](architecture/frameworks/money-struct.md)

### Autogeneration Frameworks
- [Code Generation](architecture/autogeneration-frameworks/code-generation.md)
- [Docs Generation](architecture/autogeneration-frameworks/docs-generation.md)
- [SDK Generation](architecture/autogeneration-frameworks/sdk-generation.md)
- [Test Generation](architecture/autogeneration-frameworks/test-generation.md)


## API Reference
- [API Reference Overview](api-reference/README.md)
- [Domain Schema](api-reference/domain-schema/README.md)

### Payment Service
- [Payment Service Overview](api-reference/services/payment-service/README.md)
- [Create Order](api-reference/services/payment-service/create-order.md)
- [Authorize](api-reference/services/payment-service/authorize.md)
- [Capture](api-reference/services/payment-service/capture.md)
- [Void](api-reference/services/payment-service/void.md)
- [Refund](api-reference/services/payment-service/refund.md)
- [Get](api-reference/services/payment-service/get.md)
- [Reverse](api-reference/services/payment-service/reverse.md)
- [Setup Recurring](api-reference/services/payment-service/setup-recurring.md)
- [Incremental Authorization](api-reference/services/payment-service/incremental-authorization.md)
- [Verify Redirect Response](api-reference/services/payment-service/verify-redirect-response.md)

### Recurring Payment Service
- [Recurring Payment Service Overview](api-reference/services/recurring-payment-service/README.md)
- [Charge](api-reference/services/recurring-payment-service/charge.md)
- [Revoke](api-reference/services/recurring-payment-service/revoke.md)

### Refund Service
- [Refund Service Overview](api-reference/services/refund-service/README.md)
- [Get](api-reference/services/refund-service/get.md)

### Dispute Service
- [Dispute Service Overview](api-reference/services/dispute-service/README.md)
- [Accept](api-reference/services/dispute-service/accept.md)
- [Defend](api-reference/services/dispute-service/defend.md)
- [Get](api-reference/services/dispute-service/get.md)
- [Submit Evidence](api-reference/services/dispute-service/submit-evidence.md)

### Event Service
- [Event Service Overview](api-reference/services/event-service/README.md)
- [Handle](api-reference/services/event-service/handle.md)

### Payment Method Service
- [Payment Method Service Overview](api-reference/services/payment-method-service/README.md)
- [Tokenize](api-reference/services/payment-method-service/tokenize.md)

### Customer Service
- [Customer Service Overview](api-reference/services/customer-service/README.md)
- [Create](api-reference/services/customer-service/create.md)

### Payment Method Authentication Service
- [Payment Method Authentication Service Overview](api-reference/services/payment-method-authentication-service/README.md)
- [Pre-authenticate](api-reference/services/payment-method-authentication-service/pre-authenticate.md)
- [Authenticate](api-reference/services/payment-method-authentication-service/authenticate.md)
- [Post-authenticate](api-reference/services/payment-method-authentication-service/post-authenticate.md)

### Merchant Authentication Service
- [Merchant Authentication Service Overview](api-reference/services/merchant-authentication-service/README.md)
- [Create Access Token](api-reference/services/merchant-authentication-service/create-access-token.md)
- [Create Session Token](api-reference/services/merchant-authentication-service/create-session-token.md)
- [Create SDK Session Token](api-reference/services/merchant-authentication-service/create-sdk-session-token.md)

## Connectors
- [All Connectors](all_connector.md)
- [Connectors Overview](connectors/README.md)
- [ACI](connectors/aci.md)
- [Adyen](connectors/adyen.md)
- [Airwallex](connectors/airwallex.md)
- [Authorize.Net](connectors/authorizedotnet.md)
- [Authipay](connectors/authipay.md)
- [Bambora](connectors/bambora.md)
- [Bambora APAC](connectors/bamboraapac.md)
- [Bank of America](connectors/bankofamerica.md)
- [Barclaycard](connectors/barclaycard.md)
- [Billwerk](connectors/billwerk.md)
- [Bluesnap](connectors/bluesnap.md)
- [Braintree](connectors/braintree.md)
- [Calida](connectors/calida.md)
- [Celero](connectors/celero.md)
- [Checkout.com](connectors/checkout.md)
- [Cryptopay](connectors/cryptopay.md)
- [Cybersource](connectors/cybersource.md)
- [Datatrans](connectors/datatrans.md)
- [Dlocal](connectors/dlocal.md)
- [Fiserv](connectors/fiserv.md)
- [Fiuu](connectors/fiuu.md)
- [Noon](connectors/noon.md)
- [PayPal](connectors/paypal.md)
- [PaySafe](connectors/paysafe.md)
- [Paytm](connectors/paytm.md)
- [PayU](connectors/payu.md)
- [Placetopay](connectors/placetopay.md)
- [Powertranz](connectors/powertranz.md)
- [Rapyd](connectors/rapyd.md)
- [Razorpay](connectors/razorpay.md)
- [Razorpay v2](connectors/razorpayv2.md)
- [Redsys](connectors/redsys.md)
- [Revolut](connectors/revolut.md)
- [Revolv3](connectors/revolv3.md)
- [Shift4](connectors/shift4.md)
- [Silverflow](connectors/silverflow.md)
- [Stax](connectors/stax.md)
- [Stripe](connectors/stripe.md)
- [Trustpay](connectors/trustpay.md)
- [TrustPayments](connectors/trustpayments.md)
- [Truelayer](connectors/truelayer.md)
- [Volt](connectors/volt.md)
- [Wells Fargo](connectors/wellsfargo.md)
- [Worldpay](connectors/worldpay.md)
- [Worldpay Vantiv](connectors/worldpayvantiv.md)
- [Worldpay XML](connectors/worldpayxml.md)
- [Xendit](connectors/xendit.md)
- [Zift](connectors/zift.md)

## SDKs
- [Node.js SDK](sdks/node/README.md)
- [Python SDK](sdks/python/README.md)

## Test Suite
- [Test Suite Overview](test-suite/README.md)
- [Architecture](test-suite/architecture.md)
- [Best Practices](test-suite/best-practices.md)
- [CI/CD](test-suite/ci-cd.md)
- [Configuration](test-suite/configuration.md)
- [Global Suites](test-suite/global-suites.md)
- [Overrides](test-suite/overrides.md)
- [Test Structure](test-suite/test-structure.md)
- [Usage](test-suite/usage.md)

## Blogs
- [Why We Built a Unified Payment Integration Library](blogs/why-we-built-a-unified-payment-integration-library.md)

## Additional Resources
- [Glossary](glossary.md)
- [LLMs.txt](llms.txt)