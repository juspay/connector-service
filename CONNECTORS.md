# UCS Connector Flow Matrix

This table shows which flows are implemented for each connector in the Unified Connector Service (UCS).

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
| Checkout | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Cryptopay | ✓ | ✓ | | | | | | | | | | | | | | |
| Cybersource | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | ✓ | ✓ | ✓ |
| Dlocal | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Elavon | ✓ | ✓ | ✓ | | ✓ | ✓ | | | | | | | | | | |
| Fiserv | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Fiuu | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Helcim | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | | |
| Mifinity | ✓ | ✓ | | | | | | | | | | | | | | |
| Nexinets | ✓ | ✓ | ✓ | | ✓ | ✓ | | | | | | | | | | |
| Noon | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | | |
| Novalnet | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | | | | | | | |
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

## Roadmap

### November 2025
To include/enhance the following PSPs in UCS (with deeper flows):

- **Braintree**
- **Adyen** 
- **Worldpay Vantiv**
- **Worldpay Access**
- **Worldpay WPG**
- **JP Morgan Online Payments**
- **Checkout**
- **Fiserv Commerce Hub**
- **Fiserv EMEA**
- **PayPal**
- **Ebanx**
- **Dlocal**
- **Razorpay**

### December 2025
To move all Pay-in connectors from Hyperswitch to UCS


---

*Last updated: Auto-generated from codebase*