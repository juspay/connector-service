# UCS Connector Flow Matrix

This table shows which flows are implemented for each connector in the Unified Connector Service (UCS).

> **Note:** Connectors marked with 🚧 are in the pipeline for November 2025.

## Flow Implementations by Connector

| Connector | Authorize | PSync | Capture | Void | Refund | RSync | SetupMandate | RepeatPayment | CreateOrder | CreateSessionToken | CreateAccessToken | PaymentMethodToken | CreateConnectorCustomer | PreAuthenticate | Authenticate | PostAuthenticate |
|-----------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Aci | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | ✓ | | | | | | | | |
| Adyen | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | | | | | | | | | |
| Authorizedotnet | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | ✓ | | | |
| Bluecode | ✓ | ✓ | | | | | | | | | | | | | | |
| Braintree | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | ✓ | | | | |
| Cashfree | ✓ | | | | | | | | ✓ | | | | | | | |
| Cashtocode | ✓ | | | | | | | | | | | | | | | |
| Chase 🚧 | | | | | | | | | | | | | | | | |
| Checkout | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Cryptopay | ✓ | ✓ | | | | | | | | | | | | | | |
| Cybersource | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | ✓ | ✓ | ✓ |
| Dlocal | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Ebanx 🚧 | | | | | | | | | | | | | | | | |
| Elavon | ✓ | ✓ | ✓ | | ✓ | ✓ | | | | | | | | | | |
| Fiserv | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Fiuu | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Helcim | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Mifinity | ✓ | ✓ | | | | | | | | | | | | | | |
| Nexinets | ✓ | ✓ | ✓ | | ✓ | ✓ | | | | | | | | | | |
| Noon | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | |
| Novalnet | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | |
| Paypal 🚧 | | | | | | | | | | | | | | | | |
| Paytm | ✓ | ✓ | | | | | | | | ✓ | | | | | | |
| Payu | ✓ | ✓ | | | | | | | | | | | | | | |
| Phonepe | ✓ | ✓ | | | | | | | | | | | | | | |
| Placetopay | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Rapyd | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Razorpay | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | ✓ | ✓ | ✓ | | ✓ | | | |
| Razorpayv2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | ✓ | | | | | | | |
| Stripe | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | ✓ | | | |
| Trustpay | | ✓ | | | | | | | | | ✓ | | | | | |
| Volt | ✓ | ✓ | | | | | | | | | ✓ | | | | | |
| Worldpay | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | | | | | | ✓ | | ✓ |
| Worldpayvantiv | ✓ | ✓ | | | | | | | | | | | | | | |
| Xendit | ✓ | ✓ | ✓ | | ✓ | ✓ | | | | | | | | | | |

## Pipeline Connectors (Nov'25)

The following connectors are currently in development:

- **Chase (Orbital and other flavours)** - Highest priority
- **PayPal** - In development
- **Ebanx** - Strategic expansion

## Supported Integration Endpoints

*Flow enhancements will be done based on Stripe's base feature requirements*

| PSP | Supported Integration Endpoints |
|-----|--------------------------------|
| **Braintree** | • Global endpoint* - https://payments.braintree-api.com/graphql |
| **Adyen** | • Global endpoint* - https://{{merchant_endpoint_prefix}}-checkout-live.adyenpayments.com/checkout/ |
| **Worldpay** | • Vantiv* - https://transact.vantivcnp.com/vap/communicator/online<br>• Access* - https://access.worldpay.com/<br>• WPG - https://secure.worldpay.com/jsp/merchant/xml/paymentService.jsp |
| **Chase** | • JP Morgan Online Payments - https://api-ms.payments.jpmorgan.com/api/v2<br>• Chase orbital - *to be integrated*<br>• Chase payment tech - *to be integrated* |
| **Checkout** | • Global endpoint* - https://api.checkout.com/ |
| **Fiserv** | • Commerce hub - https://cert.api.fiservapps.com/<br>• Emea - https://prod.emea.api.fiservapps.com |
| **Paypal** | • Global endpoint* - https://api-m.paypal.com/ |
| **Ebanx** | • Global endpoint - *to be integrated* |
| **Dlocal** | • Global endpoint - https://api.dlocal.com/ |
| **Razorpay** | • Global endpoint - https://api.razorpay.com/ |

---

*Last updated: Auto-generated from codebase*