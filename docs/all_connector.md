# Connector Flow Coverage

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/
Regenerate: python3 scripts/generate-connector-docs.py --all-connectors-doc
-->

This document provides a comprehensive overview of payment method support
across all connectors for each payment flow. Flow names follow the gRPC
service definitions from `backend/grpc-api-types/proto/services.proto`.

## Summary

| Connector | Authorize | Capture | Get | Refund | Void |
|-----------|:---:|:---:|:---:|:---:|:---:|
| [ACI](connectors/aci.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Adyen](connectors/adyen.md) | ✓ | ✓ | ⚠ | ✓ | ✓ |
| [Airwallex](connectors/airwallex.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Authipay](connectors/authipay.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Bambora](connectors/bambora.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Bankofamerica](connectors/bankofamerica.md) | — | ⚠ | ⚠ | ⚠ | ⚠ |
| [Barclaycard](connectors/barclaycard.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Billwerk](connectors/billwerk.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Bluesnap](connectors/bluesnap.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Braintree](connectors/braintree.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Calida](connectors/calida.md) | — | ? | ✓ | ? | ? |
| [Cashfree](connectors/cashfree.md) | ✓ | ? | ? | ? | ? |
| [CashtoCode](connectors/cashtocode.md) | — | ? | ? | ? | ? |
| [Celero](connectors/celero.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Checkout.com](connectors/checkout.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [CryptoPay](connectors/cryptopay.md) | — | ? | ✓ | ? | ? |
| [CyberSource](connectors/cybersource.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Datatrans](connectors/datatrans.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [dLocal](connectors/dlocal.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Elavon](connectors/elavon.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Finix](connectors/finix.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Fiserv](connectors/fiserv.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Fiservemea](connectors/fiservemea.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Fiuu](connectors/fiuu.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Forte](connectors/forte.md) | ✓ | ⚠ | ✓ | ⚠ | ✓ |
| [Getnet](connectors/getnet.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Gigadat](connectors/gigadat.md) | — | ? | ✓ | ✓ | ? |
| [Globalpay](connectors/globalpay.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Helcim](connectors/helcim.md) | ✓ | ⚠ | ✓ | ⚠ | ⚠ |
| [Hipay](connectors/hipay.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Hyperpg](connectors/hyperpg.md) | ✓ | ? | ✓ | ✓ | ? |
| [Iatapay](connectors/iatapay.md) | ✓ | ? | ✓ | ✓ | ? |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Loonio](connectors/loonio.md) | — | ? | ✓ | ? | ? |
| [MiFinity](connectors/mifinity.md) | — | ? | ✓ | ? | ? |
| [Mollie](connectors/mollie.md) | ✓ | ⚠ | ✓ | ✓ | ✓ |
| [Multisafepay](connectors/multisafepay.md) | ✓ | ? | ✓ | ✓ | ? |
| [Nexinets](connectors/nexinets.md) | ✓ | ⚠ | ✓ | ✓ | ⚠ |
| [Nexixpay](connectors/nexixpay.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Nmi](connectors/nmi.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Noon](connectors/noon.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Novalnet](connectors/novalnet.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Nuvei](connectors/nuvei.md) | — | ✓ | ✓ | ✓ | ✓ |
| [Paybox](connectors/paybox.md) | ✓ | ⚠ | ⚠ | ✓ | ✓ |
| [Payload](connectors/payload.md) | — | ⚠ | ⚠ | ⚠ | ⚠ |
| [Payme](connectors/payme.md) | — | ✓ | ✓ | ✓ | ✓ |
| [Paypal](connectors/paypal.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Paysafe](connectors/paysafe.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Paytm](connectors/paytm.md) | — | ? | ✓ | ? | ? |
| [PayU](connectors/payu.md) | ✓ | ? | ✓ | ? | ? |
| [PhonePe](connectors/phonepe.md) | ✓ | ? | ✓ | ? | ? |
| [PlacetoPay](connectors/placetopay.md) | ✓ | ⚠ | ⚠ | ⚠ | ⚠ |
| [Powertranz](connectors/powertranz.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Rapyd](connectors/rapyd.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Razorpay](connectors/razorpay.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Razorpay V2](connectors/razorpayv2.md) | ✓ | ? | ✓ | ✓ | ? |
| [Redsys](connectors/redsys.md) | — | ⚠ | ⚠ | ⚠ | ⚠ |
| [Revolut](connectors/revolut.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Revolv3](connectors/revolv3.md) | ✓ | ✓ | ? | ✓ | ✓ |
| [Shift4](connectors/shift4.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Silverflow](connectors/silverflow.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Stax](connectors/stax.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Stripe](connectors/stripe.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Truelayer](connectors/truelayer.md) | — | ? | ✓ | ⚠ | ? |
| [TrustPay](connectors/trustpay.md) | ✓ | ? | ✓ | ✓ | ? |
| [Trustpayments](connectors/trustpayments.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Tsys](connectors/tsys.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Volt](connectors/volt.md) | — | ? | ✓ | ✓ | ? |
| [Wellsfargo](connectors/wellsfargo.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Worldpay](connectors/worldpay.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Worldpayxml](connectors/worldpayxml.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Xendit](connectors/xendit.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Zift](connectors/zift.md) | ✓ | ⚠ | ⚠ | ✓ | ⚠ |

## Flow Details

Flow names follow the gRPC service definitions. Each flow is prefixed with
its service name (e.g., `PaymentService.Authorize`, `RefundService.Get`).

### PaymentService

#### PaymentService.Authorize

Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.

| Connector | Card | Google Pay | Apple Pay | SEPA | BACS | ACH | BECS | iDEAL | PayPal | BLIK | Klarna | Afterpay | UPI | Affirm | Samsung Pay |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [ACI](connectors/aci.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Adyen](connectors/adyen.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Airwallex](connectors/airwallex.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Authipay](connectors/authipay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Authorize.net](connectors/authorizedotnet.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Bambora](connectors/bambora.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Bamboraapac](connectors/bamboraapac.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Bankofamerica](connectors/bankofamerica.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Barclaycard](connectors/barclaycard.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Billwerk](connectors/billwerk.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Bluesnap](connectors/bluesnap.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Braintree](connectors/braintree.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Calida](connectors/calida.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Cashfree](connectors/cashfree.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [CashtoCode](connectors/cashtocode.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Celero](connectors/celero.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Checkout.com](connectors/checkout.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [CryptoPay](connectors/cryptopay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [CyberSource](connectors/cybersource.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Datatrans](connectors/datatrans.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [dLocal](connectors/dlocal.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Elavon](connectors/elavon.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Finix](connectors/finix.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Fiserv](connectors/fiserv.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Fiservemea](connectors/fiservemea.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Fiuu](connectors/fiuu.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Forte](connectors/forte.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Getnet](connectors/getnet.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Gigadat](connectors/gigadat.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Globalpay](connectors/globalpay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Helcim](connectors/helcim.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Hipay](connectors/hipay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Hyperpg](connectors/hyperpg.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Iatapay](connectors/iatapay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Jpmorgan](connectors/jpmorgan.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Loonio](connectors/loonio.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [MiFinity](connectors/mifinity.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Mollie](connectors/mollie.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Multisafepay](connectors/multisafepay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Nexinets](connectors/nexinets.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Nexixpay](connectors/nexixpay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Nmi](connectors/nmi.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Noon](connectors/noon.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Novalnet](connectors/novalnet.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Nuvei](connectors/nuvei.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Paybox](connectors/paybox.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Payload](connectors/payload.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Payme](connectors/payme.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Paypal](connectors/paypal.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Paysafe](connectors/paysafe.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Paytm](connectors/paytm.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [PayU](connectors/payu.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [PhonePe](connectors/phonepe.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [PlacetoPay](connectors/placetopay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Powertranz](connectors/powertranz.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Rapyd](connectors/rapyd.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Razorpay](connectors/razorpay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Razorpay V2](connectors/razorpayv2.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Redsys](connectors/redsys.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Revolut](connectors/revolut.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Revolv3](connectors/revolv3.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Shift4](connectors/shift4.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Silverflow](connectors/silverflow.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Stax](connectors/stax.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Stripe](connectors/stripe.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Truelayer](connectors/truelayer.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [TrustPay](connectors/trustpay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Trustpayments](connectors/trustpayments.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Tsys](connectors/tsys.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Volt](connectors/volt.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Wellsfargo](connectors/wellsfargo.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Worldpay](connectors/worldpay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Worldpayxml](connectors/worldpayxml.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Xendit](connectors/xendit.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Zift](connectors/zift.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |

**Legend:** ✓ Supported | — Not Supported | ⚠ Error | ? Unknown

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ✓ |  |
| [Adyen](connectors/adyen.md) | ⚠ | Failed to encode connector request |
| [Airwallex](connectors/airwallex.md) | ✓ |  |
| [Authipay](connectors/authipay.md) | ✓ |  |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ |  |
| [Bambora](connectors/bambora.md) | ✓ |  |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ |  |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Invalid Configuration: connector_account_details.api_secret |
| [Barclaycard](connectors/barclaycard.md) | ✓ |  |
| [Billwerk](connectors/billwerk.md) | ✓ |  |
| [Bluesnap](connectors/bluesnap.md) | ✓ |  |
| [Braintree](connectors/braintree.md) | ✓ |  |
| [Calida](connectors/calida.md) | ✓ |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ✓ |  |
| [Checkout.com](connectors/checkout.md) | ✓ |  |
| [CryptoPay](connectors/cryptopay.md) | ✓ |  |
| [CyberSource](connectors/cybersource.md) | ✓ |  |
| [Datatrans](connectors/datatrans.md) | ✓ |  |
| [dLocal](connectors/dlocal.md) | ✓ |  |
| [Elavon](connectors/elavon.md) | ✓ |  |
| [Finix](connectors/finix.md) | ✓ |  |
| [Fiserv](connectors/fiserv.md) | ✓ |  |
| [Fiservemea](connectors/fiservemea.md) | ✓ |  |
| [Fiuu](connectors/fiuu.md) | ✓ |  |
| [Forte](connectors/forte.md) | ✓ |  |
| [Getnet](connectors/getnet.md) | ✓ |  |
| [Gigadat](connectors/gigadat.md) | ✓ |  |
| [Globalpay](connectors/globalpay.md) | ✓ |  |
| [Helcim](connectors/helcim.md) | ✓ |  |
| [Hipay](connectors/hipay.md) | ✓ |  |
| [Hyperpg](connectors/hyperpg.md) | ✓ |  |
| [Iatapay](connectors/iatapay.md) | ✓ |  |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ |  |
| [Loonio](connectors/loonio.md) | ✓ |  |
| [MiFinity](connectors/mifinity.md) | ✓ |  |
| [Mollie](connectors/mollie.md) | ✓ |  |
| [Multisafepay](connectors/multisafepay.md) | ✓ |  |
| [Nexinets](connectors/nexinets.md) | ✓ |  |
| [Nexixpay](connectors/nexixpay.md) | ✓ |  |
| [Nmi](connectors/nmi.md) | ✓ |  |
| [Noon](connectors/noon.md) | ✓ |  |
| [Novalnet](connectors/novalnet.md) | ✓ |  |
| [Nuvei](connectors/nuvei.md) | ✓ |  |
| [Paybox](connectors/paybox.md) | ⚠ | Stuck on field: connector_request_id — Missing required f... |
| [Payload](connectors/payload.md) | ⚠ | Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ✓ |  |
| [PayU](connectors/payu.md) | ✓ |  |
| [PhonePe](connectors/phonepe.md) | ✓ |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ✓ |  |
| [Razorpay V2](connectors/razorpayv2.md) | ✓ |  |
| [Redsys](connectors/redsys.md) | ⚠ | Failed to encode connector request |
| [Revolut](connectors/revolut.md) | ✓ |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ✓ |  |
| [Silverflow](connectors/silverflow.md) | ✓ |  |
| [Stax](connectors/stax.md) | ✓ |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ✓ |  |
| [TrustPay](connectors/trustpay.md) | ✓ |  |
| [Trustpayments](connectors/trustpayments.md) | ✓ |  |
| [Tsys](connectors/tsys.md) | ✓ |  |
| [Volt](connectors/volt.md) | ✓ |  |
| [Wellsfargo](connectors/wellsfargo.md) | ✓ |  |
| [Worldpay](connectors/worldpay.md) | ✓ |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ✓ |  |
| [Worldpayxml](connectors/worldpayxml.md) | ✓ |  |
| [Xendit](connectors/xendit.md) | ✓ |  |
| [Zift](connectors/zift.md) | ⚠ | Failed to encode connector request |

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ✓ |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ✓ |  |
| [Authipay](connectors/authipay.md) | ✓ |  |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ |  |
| [Bambora](connectors/bambora.md) | ✓ |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Invalid Configuration: connector_account_details.api_secret |
| [Barclaycard](connectors/barclaycard.md) | ✓ |  |
| [Billwerk](connectors/billwerk.md) | ✓ |  |
| [Bluesnap](connectors/bluesnap.md) | ✓ |  |
| [Braintree](connectors/braintree.md) | ✓ |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ✓ |  |
| [Checkout.com](connectors/checkout.md) | ✓ |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ✓ |  |
| [Datatrans](connectors/datatrans.md) | ✓ |  |
| [dLocal](connectors/dlocal.md) | ✓ |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ✓ |  |
| [Fiserv](connectors/fiserv.md) | ✓ |  |
| [Fiservemea](connectors/fiservemea.md) | ✓ |  |
| [Fiuu](connectors/fiuu.md) | ✓ |  |
| [Forte](connectors/forte.md) | ✓ |  |
| [Getnet](connectors/getnet.md) | ✓ |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ✓ |  |
| [Helcim](connectors/helcim.md) | ⚠ | Failed to encode connector request |
| [Hipay](connectors/hipay.md) | ✓ |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ✓ |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ⚠ | Parsing failed |
| [Nexixpay](connectors/nexixpay.md) | ✓ |  |
| [Nmi](connectors/nmi.md) | ✓ |  |
| [Noon](connectors/noon.md) | ✓ |  |
| [Novalnet](connectors/novalnet.md) | ✓ |  |
| [Nuvei](connectors/nuvei.md) | ✓ |  |
| [Paybox](connectors/paybox.md) | ✓ |  |
| [Payload](connectors/payload.md) | ⚠ | Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ⚠ | Failed to encode connector request |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ✓ |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ✓ |  |
| [Stax](connectors/stax.md) | ✓ |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ✓ |  |
| [Tsys](connectors/tsys.md) | ✓ |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ✓ |  |
| [Worldpay](connectors/worldpay.md) | ✓ |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ✓ |  |
| [Worldpayxml](connectors/worldpayxml.md) | ✓ |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ⚠ | Failed to encode connector request |

#### PaymentService.Reverse

Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ? |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ? |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ✓ |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ✓ |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ✓ |  |
| [Authipay](connectors/authipay.md) | ✓ |  |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ |  |
| [Bambora](connectors/bambora.md) | ✓ |  |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ |  |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Invalid Configuration: connector_account_details.api_secret |
| [Barclaycard](connectors/barclaycard.md) | ✓ |  |
| [Billwerk](connectors/billwerk.md) | ✓ |  |
| [Bluesnap](connectors/bluesnap.md) | ✓ |  |
| [Braintree](connectors/braintree.md) | ✓ |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ✓ |  |
| [Checkout.com](connectors/checkout.md) | ✓ |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ✓ |  |
| [Datatrans](connectors/datatrans.md) | ✓ |  |
| [dLocal](connectors/dlocal.md) | ✓ |  |
| [Elavon](connectors/elavon.md) | ✓ |  |
| [Finix](connectors/finix.md) | ✓ |  |
| [Fiserv](connectors/fiserv.md) | ✓ |  |
| [Fiservemea](connectors/fiservemea.md) | ✓ |  |
| [Fiuu](connectors/fiuu.md) | ✓ |  |
| [Forte](connectors/forte.md) | ⚠ | Stuck on field: amount — Missing required field: amount |
| [Getnet](connectors/getnet.md) | ✓ |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ✓ |  |
| [Helcim](connectors/helcim.md) | ⚠ | Failed to encode connector request |
| [Hipay](connectors/hipay.md) | ✓ |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ⚠ | Stuck on field: description — Missing required field: des... |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ⚠ | Parsing failed |
| [Nexixpay](connectors/nexixpay.md) | ✓ |  |
| [Nmi](connectors/nmi.md) | ✓ |  |
| [Noon](connectors/noon.md) | ✓ |  |
| [Novalnet](connectors/novalnet.md) | ✓ |  |
| [Nuvei](connectors/nuvei.md) | ✓ |  |
| [Paybox](connectors/paybox.md) | ⚠ | Stuck on field: connector_request_id — Missing required f... |
| [Payload](connectors/payload.md) | ⚠ | Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ✓ |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ⚠ | Failed to encode connector request |
| [Revolut](connectors/revolut.md) | ✓ |  |
| [Revolv3](connectors/revolv3.md) | ✓ |  |
| [Shift4](connectors/shift4.md) | ✓ |  |
| [Silverflow](connectors/silverflow.md) | ✓ |  |
| [Stax](connectors/stax.md) | ✓ |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ✓ |  |
| [Tsys](connectors/tsys.md) | ✓ |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ✓ |  |
| [Worldpay](connectors/worldpay.md) | ✓ |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ✓ |  |
| [Worldpayxml](connectors/worldpayxml.md) | ✓ |  |
| [Xendit](connectors/xendit.md) | ✓ |  |
| [Zift](connectors/zift.md) | ⚠ | Failed to encode connector request |

#### PaymentService.CreateOrder

Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ? |  |
| [Airwallex](connectors/airwallex.md) | ✓ |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ⚠ | Stuck on field: billing_address — Missing required field:... |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ✓ |  |
| [Razorpay V2](connectors/razorpayv2.md) | ✓ |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ? |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ✓ |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ✓ |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ✓ |  |
| [Authipay](connectors/authipay.md) | ✓ |  |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ |  |
| [Bambora](connectors/bambora.md) | ✓ |  |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ |  |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Invalid Configuration: connector_account_details.api_secret |
| [Barclaycard](connectors/barclaycard.md) | ✓ |  |
| [Billwerk](connectors/billwerk.md) | ✓ |  |
| [Bluesnap](connectors/bluesnap.md) | ✓ |  |
| [Braintree](connectors/braintree.md) | ✓ |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ✓ |  |
| [Checkout.com](connectors/checkout.md) | ✓ |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ✓ |  |
| [Datatrans](connectors/datatrans.md) | ✓ |  |
| [dLocal](connectors/dlocal.md) | ✓ |  |
| [Elavon](connectors/elavon.md) | ✓ |  |
| [Finix](connectors/finix.md) | ✓ |  |
| [Fiserv](connectors/fiserv.md) | ✓ |  |
| [Fiservemea](connectors/fiservemea.md) | ✓ |  |
| [Fiuu](connectors/fiuu.md) | ✓ |  |
| [Forte](connectors/forte.md) | ⚠ | Connector meta data not found |
| [Getnet](connectors/getnet.md) | ✓ |  |
| [Gigadat](connectors/gigadat.md) | ✓ |  |
| [Globalpay](connectors/globalpay.md) | ✓ |  |
| [Helcim](connectors/helcim.md) | ⚠ | Failed to encode connector request |
| [Hipay](connectors/hipay.md) | ✓ |  |
| [Hyperpg](connectors/hyperpg.md) | ✓ |  |
| [Iatapay](connectors/iatapay.md) | ✓ |  |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ✓ |  |
| [Multisafepay](connectors/multisafepay.md) | ✓ |  |
| [Nexinets](connectors/nexinets.md) | ✓ |  |
| [Nexixpay](connectors/nexixpay.md) | ✓ |  |
| [Nmi](connectors/nmi.md) | ✓ |  |
| [Noon](connectors/noon.md) | ✓ |  |
| [Novalnet](connectors/novalnet.md) | ✓ |  |
| [Nuvei](connectors/nuvei.md) | ✓ |  |
| [Paybox](connectors/paybox.md) | ✓ |  |
| [Payload](connectors/payload.md) | ⚠ | Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ✓ |  |
| [Razorpay V2](connectors/razorpayv2.md) | ✓ |  |
| [Redsys](connectors/redsys.md) | ⚠ | Failed to encode connector request |
| [Revolut](connectors/revolut.md) | ✓ |  |
| [Revolv3](connectors/revolv3.md) | ✓ |  |
| [Shift4](connectors/shift4.md) | ✓ |  |
| [Silverflow](connectors/silverflow.md) | ✓ |  |
| [Stax](connectors/stax.md) | ✓ |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ⚠ | Failed to decode message: None |
| [TrustPay](connectors/trustpay.md) | ✓ |  |
| [Trustpayments](connectors/trustpayments.md) | ✓ |  |
| [Tsys](connectors/tsys.md) | ✓ |  |
| [Volt](connectors/volt.md) | ✓ |  |
| [Wellsfargo](connectors/wellsfargo.md) | ✓ |  |
| [Worldpay](connectors/worldpay.md) | ✓ |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ✓ |  |
| [Worldpayxml](connectors/worldpayxml.md) | ✓ |  |
| [Xendit](connectors/xendit.md) | ✓ |  |
| [Zift](connectors/zift.md) | ✓ |  |

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ✓ |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ⚠ | Stuck on field: connector_customer_id is missing — Missin... |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ |  |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Invalid Configuration: connector_account_details.api_secret |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ✓ |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ✓ |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ⚠ | Stuck on field: order_category in metadata — Missing requ... |
| [Novalnet](connectors/novalnet.md) | ⚠ | Stuck on field: webhook_url — Missing required field: web... |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ⚠ | Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ✓ |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ✓ |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ✓ |  |

### RecurringPaymentService

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ✓ |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ⚠ | Stuck on field: valid mandate_id format — Missing require... |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ✓ |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ✓ |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ⚠ | Stuck on field: payment_method_data.billing.address.first... |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ⚠ | Stuck on field: description — Missing required field: des... |
| [Novalnet](connectors/novalnet.md) | ⚠ | Stuck on field: email — Missing required field: email |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ⚠ | Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ⚠ | Stuck on field: mandate_metadata — Missing required field... |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ✓ |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

### CustomerService

#### CustomerService.Create

Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ? |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ✓ |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ✓ |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

### PaymentMethodService

#### PaymentMethodService.Tokenize

Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ? |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ✓ |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ✓ |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ✓ |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ✓ |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ⚠ | Invalid Configuration: profile_token |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ⚠ | Stuck on field: return_url — Missing required field: retu... |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ✓ |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

### MerchantAuthenticationService

#### MerchantAuthenticationService.CreateAccessToken

Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ? |  |
| [Airwallex](connectors/airwallex.md) | ✓ |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ✓ |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ✓ |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ✓ |  |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ? |  |
| [Truelayer](connectors/truelayer.md) | ✓ |  |
| [TrustPay](connectors/trustpay.md) | ✓ |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ✓ |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

#### MerchantAuthenticationService.CreateSessionToken

Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ? |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ✓ |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ✓ |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ? |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

### PaymentMethodAuthenticationService

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ⚠ | Address is required |
| [Adyen](connectors/adyen.md) | ⚠ | Address is required |
| [Airwallex](connectors/airwallex.md) | ⚠ | Address is required |
| [Authipay](connectors/authipay.md) | ⚠ | Address is required |
| [Authorize.net](connectors/authorizedotnet.md) | ⚠ | Address is required |
| [Bambora](connectors/bambora.md) | ⚠ | Address is required |
| [Bamboraapac](connectors/bamboraapac.md) | ⚠ | Address is required |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Address is required |
| [Barclaycard](connectors/barclaycard.md) | ⚠ | Address is required |
| [Billwerk](connectors/billwerk.md) | ⚠ | Address is required |
| [Bluesnap](connectors/bluesnap.md) | ⚠ | Address is required |
| [Braintree](connectors/braintree.md) | ⚠ | Address is required |
| [Calida](connectors/calida.md) | ⚠ | Address is required |
| [Cashfree](connectors/cashfree.md) | ⚠ | Address is required |
| [CashtoCode](connectors/cashtocode.md) | ⚠ | Address is required |
| [Celero](connectors/celero.md) | ⚠ | Address is required |
| [Checkout.com](connectors/checkout.md) | ⚠ | Address is required |
| [CryptoPay](connectors/cryptopay.md) | ⚠ | Address is required |
| [CyberSource](connectors/cybersource.md) | ⚠ | Address is required |
| [Datatrans](connectors/datatrans.md) | ⚠ | Address is required |
| [dLocal](connectors/dlocal.md) | ⚠ | Address is required |
| [Elavon](connectors/elavon.md) | ⚠ | Address is required |
| [Finix](connectors/finix.md) | ⚠ | Address is required |
| [Fiserv](connectors/fiserv.md) | ⚠ | Address is required |
| [Fiservemea](connectors/fiservemea.md) | ⚠ | Address is required |
| [Fiuu](connectors/fiuu.md) | ⚠ | Address is required |
| [Forte](connectors/forte.md) | ⚠ | Address is required |
| [Getnet](connectors/getnet.md) | ⚠ | Address is required |
| [Gigadat](connectors/gigadat.md) | ⚠ | Address is required |
| [Globalpay](connectors/globalpay.md) | ⚠ | Address is required |
| [Helcim](connectors/helcim.md) | ⚠ | Address is required |
| [Hipay](connectors/hipay.md) | ⚠ | Address is required |
| [Hyperpg](connectors/hyperpg.md) | ⚠ | Address is required |
| [Iatapay](connectors/iatapay.md) | ⚠ | Address is required |
| [Jpmorgan](connectors/jpmorgan.md) | ⚠ | Address is required |
| [Loonio](connectors/loonio.md) | ⚠ | Address is required |
| [MiFinity](connectors/mifinity.md) | ⚠ | Address is required |
| [Mollie](connectors/mollie.md) | ⚠ | Address is required |
| [Multisafepay](connectors/multisafepay.md) | ⚠ | Address is required |
| [Nexinets](connectors/nexinets.md) | ⚠ | Address is required |
| [Nexixpay](connectors/nexixpay.md) | ⚠ | Address is required |
| [Nmi](connectors/nmi.md) | ⚠ | Address is required |
| [Noon](connectors/noon.md) | ⚠ | Address is required |
| [Novalnet](connectors/novalnet.md) | ⚠ | Address is required |
| [Nuvei](connectors/nuvei.md) | ⚠ | Address is required |
| [Paybox](connectors/paybox.md) | ⚠ | Address is required |
| [Payload](connectors/payload.md) | ⚠ | Address is required |
| [Payme](connectors/payme.md) | ⚠ | Address is required |
| [Paypal](connectors/paypal.md) | ⚠ | Address is required |
| [Paysafe](connectors/paysafe.md) | ⚠ | Address is required |
| [Paytm](connectors/paytm.md) | ⚠ | Address is required |
| [PayU](connectors/payu.md) | ⚠ | Address is required |
| [PhonePe](connectors/phonepe.md) | ⚠ | Address is required |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Address is required |
| [Powertranz](connectors/powertranz.md) | ⚠ | Address is required |
| [Rapyd](connectors/rapyd.md) | ⚠ | Address is required |
| [Razorpay](connectors/razorpay.md) | ⚠ | Address is required |
| [Razorpay V2](connectors/razorpayv2.md) | ⚠ | Address is required |
| [Redsys](connectors/redsys.md) | ⚠ | Address is required |
| [Revolut](connectors/revolut.md) | ⚠ | Address is required |
| [Revolv3](connectors/revolv3.md) | ⚠ | Address is required |
| [Shift4](connectors/shift4.md) | ⚠ | Address is required |
| [Silverflow](connectors/silverflow.md) | ⚠ | Address is required |
| [Stax](connectors/stax.md) | ⚠ | Address is required |
| [Stripe](connectors/stripe.md) | ⚠ | Address is required |
| [Truelayer](connectors/truelayer.md) | ⚠ | Address is required |
| [TrustPay](connectors/trustpay.md) | ⚠ | Address is required |
| [Trustpayments](connectors/trustpayments.md) | ⚠ | Address is required |
| [Tsys](connectors/tsys.md) | ⚠ | Address is required |
| [Volt](connectors/volt.md) | ⚠ | Address is required |
| [Wellsfargo](connectors/wellsfargo.md) | ⚠ | Address is required |
| [Worldpay](connectors/worldpay.md) | ⚠ | Address is required |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ⚠ | Address is required |
| [Worldpayxml](connectors/worldpayxml.md) | ⚠ | Address is required |
| [Xendit](connectors/xendit.md) | ⚠ | Address is required |
| [Zift](connectors/zift.md) | ⚠ | Address is required |

#### PaymentMethodAuthenticationService.Authenticate

Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ⚠ | Address is required |
| [Adyen](connectors/adyen.md) | ⚠ | Address is required |
| [Airwallex](connectors/airwallex.md) | ⚠ | Address is required |
| [Authipay](connectors/authipay.md) | ⚠ | Address is required |
| [Authorize.net](connectors/authorizedotnet.md) | ⚠ | Address is required |
| [Bambora](connectors/bambora.md) | ⚠ | Address is required |
| [Bamboraapac](connectors/bamboraapac.md) | ⚠ | Address is required |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Address is required |
| [Barclaycard](connectors/barclaycard.md) | ⚠ | Address is required |
| [Billwerk](connectors/billwerk.md) | ⚠ | Address is required |
| [Bluesnap](connectors/bluesnap.md) | ⚠ | Address is required |
| [Braintree](connectors/braintree.md) | ⚠ | Address is required |
| [Calida](connectors/calida.md) | ⚠ | Address is required |
| [Cashfree](connectors/cashfree.md) | ⚠ | Address is required |
| [CashtoCode](connectors/cashtocode.md) | ⚠ | Address is required |
| [Celero](connectors/celero.md) | ⚠ | Address is required |
| [Checkout.com](connectors/checkout.md) | ⚠ | Address is required |
| [CryptoPay](connectors/cryptopay.md) | ⚠ | Address is required |
| [CyberSource](connectors/cybersource.md) | ⚠ | Address is required |
| [Datatrans](connectors/datatrans.md) | ⚠ | Address is required |
| [dLocal](connectors/dlocal.md) | ⚠ | Address is required |
| [Elavon](connectors/elavon.md) | ⚠ | Address is required |
| [Finix](connectors/finix.md) | ⚠ | Address is required |
| [Fiserv](connectors/fiserv.md) | ⚠ | Address is required |
| [Fiservemea](connectors/fiservemea.md) | ⚠ | Address is required |
| [Fiuu](connectors/fiuu.md) | ⚠ | Address is required |
| [Forte](connectors/forte.md) | ⚠ | Address is required |
| [Getnet](connectors/getnet.md) | ⚠ | Address is required |
| [Gigadat](connectors/gigadat.md) | ⚠ | Address is required |
| [Globalpay](connectors/globalpay.md) | ⚠ | Address is required |
| [Helcim](connectors/helcim.md) | ⚠ | Address is required |
| [Hipay](connectors/hipay.md) | ⚠ | Address is required |
| [Hyperpg](connectors/hyperpg.md) | ⚠ | Address is required |
| [Iatapay](connectors/iatapay.md) | ⚠ | Address is required |
| [Jpmorgan](connectors/jpmorgan.md) | ⚠ | Address is required |
| [Loonio](connectors/loonio.md) | ⚠ | Address is required |
| [MiFinity](connectors/mifinity.md) | ⚠ | Address is required |
| [Mollie](connectors/mollie.md) | ⚠ | Address is required |
| [Multisafepay](connectors/multisafepay.md) | ⚠ | Address is required |
| [Nexinets](connectors/nexinets.md) | ⚠ | Address is required |
| [Nexixpay](connectors/nexixpay.md) | ⚠ | Address is required |
| [Nmi](connectors/nmi.md) | ⚠ | Address is required |
| [Noon](connectors/noon.md) | ⚠ | Address is required |
| [Novalnet](connectors/novalnet.md) | ⚠ | Address is required |
| [Nuvei](connectors/nuvei.md) | ⚠ | Address is required |
| [Paybox](connectors/paybox.md) | ⚠ | Address is required |
| [Payload](connectors/payload.md) | ⚠ | Address is required |
| [Payme](connectors/payme.md) | ⚠ | Address is required |
| [Paypal](connectors/paypal.md) | ⚠ | Address is required |
| [Paysafe](connectors/paysafe.md) | ⚠ | Address is required |
| [Paytm](connectors/paytm.md) | ⚠ | Address is required |
| [PayU](connectors/payu.md) | ⚠ | Address is required |
| [PhonePe](connectors/phonepe.md) | ⚠ | Address is required |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Address is required |
| [Powertranz](connectors/powertranz.md) | ⚠ | Address is required |
| [Rapyd](connectors/rapyd.md) | ⚠ | Address is required |
| [Razorpay](connectors/razorpay.md) | ⚠ | Address is required |
| [Razorpay V2](connectors/razorpayv2.md) | ⚠ | Address is required |
| [Redsys](connectors/redsys.md) | ⚠ | Address is required |
| [Revolut](connectors/revolut.md) | ⚠ | Address is required |
| [Revolv3](connectors/revolv3.md) | ⚠ | Address is required |
| [Shift4](connectors/shift4.md) | ⚠ | Address is required |
| [Silverflow](connectors/silverflow.md) | ⚠ | Address is required |
| [Stax](connectors/stax.md) | ⚠ | Address is required |
| [Stripe](connectors/stripe.md) | ⚠ | Address is required |
| [Truelayer](connectors/truelayer.md) | ⚠ | Address is required |
| [TrustPay](connectors/trustpay.md) | ⚠ | Address is required |
| [Trustpayments](connectors/trustpayments.md) | ⚠ | Address is required |
| [Tsys](connectors/tsys.md) | ⚠ | Address is required |
| [Volt](connectors/volt.md) | ⚠ | Address is required |
| [Wellsfargo](connectors/wellsfargo.md) | ⚠ | Address is required |
| [Worldpay](connectors/worldpay.md) | ⚠ | Address is required |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ⚠ | Address is required |
| [Worldpayxml](connectors/worldpayxml.md) | ⚠ | Address is required |
| [Xendit](connectors/xendit.md) | ⚠ | Address is required |
| [Zift](connectors/zift.md) | ⚠ | Address is required |

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ⚠ | Address is required |
| [Adyen](connectors/adyen.md) | ⚠ | Address is required |
| [Airwallex](connectors/airwallex.md) | ⚠ | Address is required |
| [Authipay](connectors/authipay.md) | ⚠ | Address is required |
| [Authorize.net](connectors/authorizedotnet.md) | ⚠ | Address is required |
| [Bambora](connectors/bambora.md) | ⚠ | Address is required |
| [Bamboraapac](connectors/bamboraapac.md) | ⚠ | Address is required |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Address is required |
| [Barclaycard](connectors/barclaycard.md) | ⚠ | Address is required |
| [Billwerk](connectors/billwerk.md) | ⚠ | Address is required |
| [Bluesnap](connectors/bluesnap.md) | ⚠ | Address is required |
| [Braintree](connectors/braintree.md) | ⚠ | Address is required |
| [Calida](connectors/calida.md) | ⚠ | Address is required |
| [Cashfree](connectors/cashfree.md) | ⚠ | Address is required |
| [CashtoCode](connectors/cashtocode.md) | ⚠ | Address is required |
| [Celero](connectors/celero.md) | ⚠ | Address is required |
| [Checkout.com](connectors/checkout.md) | ⚠ | Address is required |
| [CryptoPay](connectors/cryptopay.md) | ⚠ | Address is required |
| [CyberSource](connectors/cybersource.md) | ⚠ | Address is required |
| [Datatrans](connectors/datatrans.md) | ⚠ | Address is required |
| [dLocal](connectors/dlocal.md) | ⚠ | Address is required |
| [Elavon](connectors/elavon.md) | ⚠ | Address is required |
| [Finix](connectors/finix.md) | ⚠ | Address is required |
| [Fiserv](connectors/fiserv.md) | ⚠ | Address is required |
| [Fiservemea](connectors/fiservemea.md) | ⚠ | Address is required |
| [Fiuu](connectors/fiuu.md) | ⚠ | Address is required |
| [Forte](connectors/forte.md) | ⚠ | Address is required |
| [Getnet](connectors/getnet.md) | ⚠ | Address is required |
| [Gigadat](connectors/gigadat.md) | ⚠ | Address is required |
| [Globalpay](connectors/globalpay.md) | ⚠ | Address is required |
| [Helcim](connectors/helcim.md) | ⚠ | Address is required |
| [Hipay](connectors/hipay.md) | ⚠ | Address is required |
| [Hyperpg](connectors/hyperpg.md) | ⚠ | Address is required |
| [Iatapay](connectors/iatapay.md) | ⚠ | Address is required |
| [Jpmorgan](connectors/jpmorgan.md) | ⚠ | Address is required |
| [Loonio](connectors/loonio.md) | ⚠ | Address is required |
| [MiFinity](connectors/mifinity.md) | ⚠ | Address is required |
| [Mollie](connectors/mollie.md) | ⚠ | Address is required |
| [Multisafepay](connectors/multisafepay.md) | ⚠ | Address is required |
| [Nexinets](connectors/nexinets.md) | ⚠ | Address is required |
| [Nexixpay](connectors/nexixpay.md) | ⚠ | Address is required |
| [Nmi](connectors/nmi.md) | ⚠ | Address is required |
| [Noon](connectors/noon.md) | ⚠ | Address is required |
| [Novalnet](connectors/novalnet.md) | ⚠ | Address is required |
| [Nuvei](connectors/nuvei.md) | ⚠ | Address is required |
| [Paybox](connectors/paybox.md) | ⚠ | Address is required |
| [Payload](connectors/payload.md) | ⚠ | Address is required |
| [Payme](connectors/payme.md) | ⚠ | Address is required |
| [Paypal](connectors/paypal.md) | ⚠ | Address is required |
| [Paysafe](connectors/paysafe.md) | ⚠ | Address is required |
| [Paytm](connectors/paytm.md) | ⚠ | Address is required |
| [PayU](connectors/payu.md) | ⚠ | Address is required |
| [PhonePe](connectors/phonepe.md) | ⚠ | Address is required |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Address is required |
| [Powertranz](connectors/powertranz.md) | ⚠ | Address is required |
| [Rapyd](connectors/rapyd.md) | ⚠ | Address is required |
| [Razorpay](connectors/razorpay.md) | ⚠ | Address is required |
| [Razorpay V2](connectors/razorpayv2.md) | ⚠ | Address is required |
| [Redsys](connectors/redsys.md) | ⚠ | Address is required |
| [Revolut](connectors/revolut.md) | ⚠ | Address is required |
| [Revolv3](connectors/revolv3.md) | ⚠ | Address is required |
| [Shift4](connectors/shift4.md) | ⚠ | Address is required |
| [Silverflow](connectors/silverflow.md) | ⚠ | Address is required |
| [Stax](connectors/stax.md) | ⚠ | Address is required |
| [Stripe](connectors/stripe.md) | ⚠ | Address is required |
| [Truelayer](connectors/truelayer.md) | ⚠ | Address is required |
| [TrustPay](connectors/trustpay.md) | ⚠ | Address is required |
| [Trustpayments](connectors/trustpayments.md) | ⚠ | Address is required |
| [Tsys](connectors/tsys.md) | ⚠ | Address is required |
| [Volt](connectors/volt.md) | ⚠ | Address is required |
| [Wellsfargo](connectors/wellsfargo.md) | ⚠ | Address is required |
| [Worldpay](connectors/worldpay.md) | ⚠ | Address is required |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ⚠ | Address is required |
| [Worldpayxml](connectors/worldpayxml.md) | ⚠ | Address is required |
| [Xendit](connectors/xendit.md) | ⚠ | Address is required |
| [Zift](connectors/zift.md) | ⚠ | Address is required |

### DisputeService

#### DisputeService.SubmitEvidence

Upload evidence to dispute customer chargeback. Provides documentation like receipts and delivery proof to contest fraudulent transaction claims.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ? |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

#### DisputeService.Defend

Submit defense with reason code for dispute. Presents formal argument against customer's chargeback claim with supporting documentation.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ? |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

#### DisputeService.Accept

Concede dispute and accepts chargeback loss. Acknowledges liability and stops dispute defense process when evidence is insufficient.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ? |  |
| [Adyen](connectors/adyen.md) | ✓ |  |
| [Airwallex](connectors/airwallex.md) | ? |  |
| [Authipay](connectors/authipay.md) | ? |  |
| [Authorize.net](connectors/authorizedotnet.md) | ? |  |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ? |  |
| [Bankofamerica](connectors/bankofamerica.md) | ? |  |
| [Barclaycard](connectors/barclaycard.md) | ? |  |
| [Billwerk](connectors/billwerk.md) | ? |  |
| [Bluesnap](connectors/bluesnap.md) | ? |  |
| [Braintree](connectors/braintree.md) | ? |  |
| [Calida](connectors/calida.md) | ? |  |
| [Cashfree](connectors/cashfree.md) | ? |  |
| [CashtoCode](connectors/cashtocode.md) | ? |  |
| [Celero](connectors/celero.md) | ? |  |
| [Checkout.com](connectors/checkout.md) | ? |  |
| [CryptoPay](connectors/cryptopay.md) | ? |  |
| [CyberSource](connectors/cybersource.md) | ? |  |
| [Datatrans](connectors/datatrans.md) | ? |  |
| [dLocal](connectors/dlocal.md) | ? |  |
| [Elavon](connectors/elavon.md) | ? |  |
| [Finix](connectors/finix.md) | ? |  |
| [Fiserv](connectors/fiserv.md) | ? |  |
| [Fiservemea](connectors/fiservemea.md) | ? |  |
| [Fiuu](connectors/fiuu.md) | ? |  |
| [Forte](connectors/forte.md) | ? |  |
| [Getnet](connectors/getnet.md) | ? |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ? |  |
| [Helcim](connectors/helcim.md) | ? |  |
| [Hipay](connectors/hipay.md) | ? |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ? |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ? |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ? |  |
| [Nexixpay](connectors/nexixpay.md) | ? |  |
| [Nmi](connectors/nmi.md) | ? |  |
| [Noon](connectors/noon.md) | ? |  |
| [Novalnet](connectors/novalnet.md) | ? |  |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ? |  |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ? |  |
| [Paysafe](connectors/paysafe.md) | ? |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ? |  |
| [Powertranz](connectors/powertranz.md) | ? |  |
| [Rapyd](connectors/rapyd.md) | ? |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ? |  |
| [Revolut](connectors/revolut.md) | ? |  |
| [Revolv3](connectors/revolv3.md) | ? |  |
| [Shift4](connectors/shift4.md) | ? |  |
| [Silverflow](connectors/silverflow.md) | ? |  |
| [Stax](connectors/stax.md) | ? |  |
| [Stripe](connectors/stripe.md) | ? |  |
| [Truelayer](connectors/truelayer.md) | ? |  |
| [TrustPay](connectors/trustpay.md) | ? |  |
| [Trustpayments](connectors/trustpayments.md) | ? |  |
| [Tsys](connectors/tsys.md) | ? |  |
| [Volt](connectors/volt.md) | ? |  |
| [Wellsfargo](connectors/wellsfargo.md) | ? |  |
| [Worldpay](connectors/worldpay.md) | ? |  |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ? |  |
| [Worldpayxml](connectors/worldpayxml.md) | ? |  |
| [Xendit](connectors/xendit.md) | ? |  |
| [Zift](connectors/zift.md) | ? |  |

## Payment Methods

Payment methods probed for authorize flow (configured in `backend/field-probe/probe-config.toml`):

| Key | Display Name | Description |
|-----|--------------|-------------|
| Card | Card | Credit/Debit card payments |
| GooglePay | Google Pay | Google Pay digital wallet |
| ApplePay | Apple Pay | Apple Pay digital wallet |
| Sepa | SEPA | SEPA Direct Debit (EU bank transfers) |
| Bacs | BACS | BACS Direct Debit (UK bank transfers) |
| Ach | ACH | ACH Direct Debit (US bank transfers) |
| Becs | BECS | BECS Direct Debit (AU bank transfers) |
| Ideal | iDEAL | iDEAL (Netherlands bank redirect) |
| PaypalRedirect | PayPal | PayPal redirect payments |
| Blik | BLIK | BLIK (Polish mobile payment) |
| Klarna | Klarna | Klarna Buy Now Pay Later |
| Afterpay | Afterpay | Afterpay/Clearpay BNPL |
| UpiCollect | UPI | UPI Collect (India) |
| Affirm | Affirm | Affirm BNPL |
| SamsungPay | Samsung Pay | Samsung Pay digital wallet |

## Services Reference

Flow definitions are derived from `backend/grpc-api-types/proto/services.proto`:

| Service | Description |
|---------|-------------|
| PaymentService | Process payments from authorization to settlement |
| RecurringPaymentService | Charge and revoke recurring payments |
| RefundService | Retrieve and synchronize refund statuses |
| CustomerService | Create and manage customer profiles |
| PaymentMethodService | Tokenize and retrieve payment methods |
| MerchantAuthenticationService | Generate access tokens and session credentials |
| PaymentMethodAuthenticationService | Execute 3D Secure authentication flows |
| DisputeService | Manage chargeback disputes |
