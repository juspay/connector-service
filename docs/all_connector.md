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
| [Calida](connectors/calida.md) | ? | ? | ✓ | ? | ? |
| [Cashfree](connectors/cashfree.md) | ✓ | ? | ? | ? | ? |
| [CashtoCode](connectors/cashtocode.md) | ? | ? | ? | ? | ? |
| [Celero](connectors/celero.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Checkout.com](connectors/checkout.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [CryptoPay](connectors/cryptopay.md) | ? | ? | ✓ | ? | ? |
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
| [Gigadat](connectors/gigadat.md) | ? | ? | ✓ | ✓ | ? |
| [Globalpay](connectors/globalpay.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Helcim](connectors/helcim.md) | ✓ | ⚠ | ✓ | ⚠ | ⚠ |
| [Hipay](connectors/hipay.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Hyperpg](connectors/hyperpg.md) | ✓ | ? | ✓ | ✓ | ? |
| [Iatapay](connectors/iatapay.md) | ✓ | ? | ✓ | ✓ | ? |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Loonio](connectors/loonio.md) | ? | ? | ✓ | ? | ? |
| [MiFinity](connectors/mifinity.md) | ? | ? | ✓ | ? | ? |
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
| [Redsys](connectors/redsys.md) | ? | ⚠ | ⚠ | ⚠ | ⚠ |
| [Revolut](connectors/revolut.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Revolv3](connectors/revolv3.md) | ✓ | ✓ | ? | ✓ | ✓ |
| [Shift4](connectors/shift4.md) | ✓ | ✓ | ✓ | ✓ | ? |
| [Silverflow](connectors/silverflow.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Stax](connectors/stax.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Stripe](connectors/stripe.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Truelayer](connectors/truelayer.md) | ? | ? | ✓ | ⚠ | ? |
| [TrustPay](connectors/trustpay.md) | ✓ | ? | ✓ | ✓ | ? |
| [Trustpayments](connectors/trustpayments.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Tsys](connectors/tsys.md) | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Volt](connectors/volt.md) | ? | ? | ✓ | ✓ | ? |
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
| [ACI](connectors/aci.md) | ✓ | ? | ? | ? | ? | ? | ? | ✓ | ? | ? | ✓ | ✓ | ? | ✓ | ? |
| [Adyen](connectors/adyen.md) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? | ✓ | ? | ✓ | ✓ | ✓ | ? | ✓ | ? |
| [Airwallex](connectors/airwallex.md) | ✓ | ? | ? | ? | ? | ? | ? | ✓ | ? | ✓ | ? | ? | ? | ? | ? |
| [Authipay](connectors/authipay.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ | ⚠ | ⚠ | ? | ? | ✓ | ? | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ? |
| [Bambora](connectors/bambora.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Barclaycard](connectors/barclaycard.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Billwerk](connectors/billwerk.md) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? |
| [Bluesnap](connectors/bluesnap.md) | ✓ | ✓ | ✓ | ? | ? | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Braintree](connectors/braintree.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Calida](connectors/calida.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Cashfree](connectors/cashfree.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ✓ | ? | ? |
| [CashtoCode](connectors/cashtocode.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Celero](connectors/celero.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Checkout.com](connectors/checkout.md) | ✓ | ✓ | ✓ | ? | ? | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [CryptoPay](connectors/cryptopay.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [CyberSource](connectors/cybersource.md) | ✓ | ✓ | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Datatrans](connectors/datatrans.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [dLocal](connectors/dlocal.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Elavon](connectors/elavon.md) | ✓ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ? |
| [Finix](connectors/finix.md) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? |
| [Fiserv](connectors/fiserv.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Fiservemea](connectors/fiservemea.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Fiuu](connectors/fiuu.md) | ✓ | ✓ | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Forte](connectors/forte.md) | ✓ | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Getnet](connectors/getnet.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Gigadat](connectors/gigadat.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Globalpay](connectors/globalpay.md) | ✓ | ? | ? | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ? | ? | ? |
| [Helcim](connectors/helcim.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Hipay](connectors/hipay.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Hyperpg](connectors/hyperpg.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Iatapay](connectors/iatapay.md) | ? | ? | ? | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ✓ | ? | ? |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Loonio](connectors/loonio.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [MiFinity](connectors/mifinity.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Mollie](connectors/mollie.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Multisafepay](connectors/multisafepay.md) | ✓ | ✓ | ? | ? | ? | ? | ? | ✓ | ✓ | ? | ? | ? | ? | ? | ? |
| [Nexinets](connectors/nexinets.md) | ✓ | ? | ✓ | ? | ? | ? | ? | ✓ | ✓ | ? | ? | ? | ? | ? | ? |
| [Nexixpay](connectors/nexixpay.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Nmi](connectors/nmi.md) | ✓ | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Noon](connectors/noon.md) | ✓ | ✓ | ⚠ | ? | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ? | ? |
| [Novalnet](connectors/novalnet.md) | ✓ | ✓ | ✓ | ✓ | ? | ✓ | ? | ? | ✓ | ? | ? | ? | ? | ? | ? |
| [Nuvei](connectors/nuvei.md) | ⚠ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Paybox](connectors/paybox.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Payload](connectors/payload.md) | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ? |
| [Payme](connectors/payme.md) | ⚠ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Paypal](connectors/paypal.md) | ✓ | ? | ? | ? | ? | ? | ? | ✓ | ✓ | ? | ? | ? | ? | ? | ? |
| [Paysafe](connectors/paysafe.md) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? |
| [Paytm](connectors/paytm.md) | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ? |
| [PayU](connectors/payu.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ✓ | ? | ? |
| [PhonePe](connectors/phonepe.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ✓ | ? | ? |
| [PlacetoPay](connectors/placetopay.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Powertranz](connectors/powertranz.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Rapyd](connectors/rapyd.md) | ✓ | ✓ | ✓ | ? | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ? | ? |
| [Razorpay](connectors/razorpay.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ✓ | ? | ? |
| [Razorpay V2](connectors/razorpayv2.md) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? |
| [Redsys](connectors/redsys.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Revolut](connectors/revolut.md) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? |
| [Revolv3](connectors/revolv3.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Shift4](connectors/shift4.md) | ✓ | ? | ? | ? | ? | ? | ? | ✓ | ? | ? | ? | ? | ? | ? | ? |
| [Silverflow](connectors/silverflow.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Stax](connectors/stax.md) | ✓ | ? | ? | ✓ | ✓ | ✓ | ✓ | ? | ? | ? | ? | ? | ? | ? | ? |
| [Stripe](connectors/stripe.md) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? | ✓ | ✓ | ✓ | ? | ✓ | ? |
| [Truelayer](connectors/truelayer.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [TrustPay](connectors/trustpay.md) | ✓ | ? | ? | ? | ? | ? | ? | ✓ | ? | ✓ | ? | ? | ? | ? | ? |
| [Trustpayments](connectors/trustpayments.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Tsys](connectors/tsys.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Volt](connectors/volt.md) | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Wellsfargo](connectors/wellsfargo.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Worldpay](connectors/worldpay.md) | ✓ | ✓ | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Worldpayvantiv](connectors/worldpayvantiv.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Worldpayxml](connectors/worldpayxml.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Xendit](connectors/xendit.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| [Zift](connectors/zift.md) | ✓ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |

**Legend:** ✓ Supported | — Not Supported | ⚠ Error | ? Unknown

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| Connector | Supported | Notes |
|-----------|:---------:|-------|
| [ACI](connectors/aci.md) | ✓ |  |
| [Adyen](connectors/adyen.md) | ⚠ | Integration error: Failed to encode connector request |
| [Airwallex](connectors/airwallex.md) | ✓ |  |
| [Authipay](connectors/authipay.md) | ✓ |  |
| [Authorize.net](connectors/authorizedotnet.md) | ✓ |  |
| [Bambora](connectors/bambora.md) | ✓ |  |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ |  |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Integration error: Invalid Configuration: connector_accou... |
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
| [Paybox](connectors/paybox.md) | ⚠ | Stuck on field: connector_request_id — Integration error:... |
| [Payload](connectors/payload.md) | ⚠ | Integration error: Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ✓ |  |
| [PayU](connectors/payu.md) | ✓ |  |
| [PhonePe](connectors/phonepe.md) | ✓ |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Integration error: Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ✓ |  |
| [Razorpay V2](connectors/razorpayv2.md) | ✓ |  |
| [Redsys](connectors/redsys.md) | ⚠ | Integration error: Failed to encode connector request |
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
| [Zift](connectors/zift.md) | ⚠ | Integration error: Failed to encode connector request |

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
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Integration error: Invalid Configuration: connector_accou... |
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
| [Helcim](connectors/helcim.md) | ⚠ | Integration error: Failed to encode connector request |
| [Hipay](connectors/hipay.md) | ✓ |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ✓ |  |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ⚠ | Integration error: Parsing failed |
| [Nexixpay](connectors/nexixpay.md) | ✓ |  |
| [Nmi](connectors/nmi.md) | ✓ |  |
| [Noon](connectors/noon.md) | ✓ |  |
| [Novalnet](connectors/novalnet.md) | ✓ |  |
| [Nuvei](connectors/nuvei.md) | ✓ |  |
| [Paybox](connectors/paybox.md) | ✓ |  |
| [Payload](connectors/payload.md) | ⚠ | Integration error: Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Integration error: Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ? |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ⚠ | Integration error: Failed to encode connector request |
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
| [Zift](connectors/zift.md) | ⚠ | Integration error: Failed to encode connector request |

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
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Integration error: Invalid Configuration: connector_accou... |
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
| [Forte](connectors/forte.md) | ⚠ | Stuck on field: amount — Integration error: Missing requi... |
| [Getnet](connectors/getnet.md) | ✓ |  |
| [Gigadat](connectors/gigadat.md) | ? |  |
| [Globalpay](connectors/globalpay.md) | ✓ |  |
| [Helcim](connectors/helcim.md) | ⚠ | Integration error: Failed to encode connector request |
| [Hipay](connectors/hipay.md) | ✓ |  |
| [Hyperpg](connectors/hyperpg.md) | ? |  |
| [Iatapay](connectors/iatapay.md) | ? |  |
| [Jpmorgan](connectors/jpmorgan.md) | ✓ |  |
| [Loonio](connectors/loonio.md) | ? |  |
| [MiFinity](connectors/mifinity.md) | ? |  |
| [Mollie](connectors/mollie.md) | ⚠ | Stuck on field: description — Integration error: Missing ... |
| [Multisafepay](connectors/multisafepay.md) | ? |  |
| [Nexinets](connectors/nexinets.md) | ⚠ | Integration error: Parsing failed |
| [Nexixpay](connectors/nexixpay.md) | ✓ |  |
| [Nmi](connectors/nmi.md) | ✓ |  |
| [Noon](connectors/noon.md) | ✓ |  |
| [Novalnet](connectors/novalnet.md) | ✓ |  |
| [Nuvei](connectors/nuvei.md) | ✓ |  |
| [Paybox](connectors/paybox.md) | ⚠ | Stuck on field: connector_request_id — Integration error:... |
| [Payload](connectors/payload.md) | ⚠ | Integration error: Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Integration error: Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ✓ |  |
| [Razorpay V2](connectors/razorpayv2.md) | ? |  |
| [Redsys](connectors/redsys.md) | ⚠ | Integration error: Failed to encode connector request |
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
| [Zift](connectors/zift.md) | ⚠ | Integration error: Failed to encode connector request |

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
| [Cashfree](connectors/cashfree.md) | ⚠ | Stuck on field: billing_address — Integration error: Miss... |
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
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Integration error: Invalid Configuration: connector_accou... |
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
| [Forte](connectors/forte.md) | ⚠ | Integration error: Connector meta data not found |
| [Getnet](connectors/getnet.md) | ✓ |  |
| [Gigadat](connectors/gigadat.md) | ✓ |  |
| [Globalpay](connectors/globalpay.md) | ✓ |  |
| [Helcim](connectors/helcim.md) | ⚠ | Integration error: Failed to encode connector request |
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
| [Payload](connectors/payload.md) | ⚠ | Integration error: Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ✓ |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ✓ |  |
| [Paytm](connectors/paytm.md) | ? |  |
| [PayU](connectors/payu.md) | ? |  |
| [PhonePe](connectors/phonepe.md) | ? |  |
| [PlacetoPay](connectors/placetopay.md) | ⚠ | Integration error: Failed to encode connector request |
| [Powertranz](connectors/powertranz.md) | ✓ |  |
| [Rapyd](connectors/rapyd.md) | ✓ |  |
| [Razorpay](connectors/razorpay.md) | ✓ |  |
| [Razorpay V2](connectors/razorpayv2.md) | ✓ |  |
| [Redsys](connectors/redsys.md) | ⚠ | Integration error: Failed to encode connector request |
| [Revolut](connectors/revolut.md) | ✓ |  |
| [Revolv3](connectors/revolv3.md) | ✓ |  |
| [Shift4](connectors/shift4.md) | ✓ |  |
| [Silverflow](connectors/silverflow.md) | ✓ |  |
| [Stax](connectors/stax.md) | ✓ |  |
| [Stripe](connectors/stripe.md) | ✓ |  |
| [Truelayer](connectors/truelayer.md) | ⚠ | Integration error: Failed to decode message |
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
| [Authorize.net](connectors/authorizedotnet.md) | ⚠ | Stuck on field: connector_customer_id is missing — Integr... |
| [Bambora](connectors/bambora.md) | ? |  |
| [Bamboraapac](connectors/bamboraapac.md) | ✓ |  |
| [Bankofamerica](connectors/bankofamerica.md) | ⚠ | Integration error: Invalid Configuration: connector_accou... |
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
| [Noon](connectors/noon.md) | ⚠ | Stuck on field: order_category in metadata — Integration ... |
| [Novalnet](connectors/novalnet.md) | ⚠ | Stuck on field: webhook_url — Integration error: Missing ... |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ⚠ | Integration error: Failed to obtain authentication type |
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
| [Authorize.net](connectors/authorizedotnet.md) | ⚠ | Stuck on field: valid mandate_id format — Integration err... |
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
| [Noon](connectors/noon.md) | ⚠ | Stuck on field: description — Integration error: Missing ... |
| [Novalnet](connectors/novalnet.md) | ⚠ | Stuck on field: email — Integration error: Missing requir... |
| [Nuvei](connectors/nuvei.md) | ? |  |
| [Paybox](connectors/paybox.md) | ? |  |
| [Payload](connectors/payload.md) | ⚠ | Integration error: Failed to obtain authentication type |
| [Payme](connectors/payme.md) | ? |  |
| [Paypal](connectors/paypal.md) | ✓ |  |
| [Paysafe](connectors/paysafe.md) | ⚠ | Stuck on field: mandate_metadata — Integration error: Mis... |
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
| [Mollie](connectors/mollie.md) | ⚠ | Integration error: Invalid Configuration: profile_token |
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
| [Paysafe](connectors/paysafe.md) | ⚠ | Stuck on field: return_url — Integration error: Missing r... |
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
