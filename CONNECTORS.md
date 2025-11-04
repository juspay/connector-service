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

## PSP Integration Status

Current status of payment service provider endpoint integrations:

| PSP | Status | Global Endpoint | Regional Coverage |
|-----|--------|----------------|-------------------|
| **Braintree** | ✅ **Complete** | `https://payments.braintree-api.com/graphql` | Global |
| **Adyen** | ✅ **Complete** | `https://{{merchant_endpoint_prefix}}-checkout-live.adyenpayments.com/checkout/` | Global with merchant prefix |
| **Worldpay** | 🔄 **Multi-endpoint** | Vantiv™, Access™, WPG™ variants | Regional variants |
| **Chase** | 🚧 **Planned** | JP Morgan Online Payments API | North America focus |
| **Checkout** | ✅ **Complete** | `https://api.checkout.com/` | Global |
| **Fiserv** | 🔄 **Multi-region** | Commerce Hub, EMEA endpoints | Regional |
| **PayPal** | 🚧 **Planned** | Global endpoint integration | Global |
| **Ebanx** | 🚧 **Planned** | LATAM-focused integration | Latin America |
| **Dlocal** | ✅ **Complete** | `https://api.dlocal.com/` | Global |
| **Razorpay** | ✅ **Complete** | `https://api.razorpay.com/` | India primary |

**Legend:**
- ✅ **Complete** - Fully integrated with standardized endpoints
- 🔄 **Multi-endpoint** - Active integration with multiple endpoint variants
- 🚧 **Planned** - Scheduled for future integration

---

*Last updated: Auto-generated from codebase*