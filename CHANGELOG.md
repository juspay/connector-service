# Changelog

All notable changes to Connector Service will be documented here.

- - -

## 2025.12.05.0

### Features

- **core:** Added SdkSessionToken Flow support ([#310](https://github.com/juspay/connector-service/pull/310)) ([`3cca3a3`](https://github.com/juspay/connector-service/commit/3cca3a3050e7681deece72cb8fc7216c847de1f1))

### Bug Fixes

- **bluesnap:** Address `merchantTransactionId` being `IRRELEVANT_ATTEMPT_ID` instead of actual `attempt_id` ([#342](https://github.com/juspay/connector-service/pull/342)) ([`937acfd`](https://github.com/juspay/connector-service/commit/937acfd79b35a46a215235676ca5a8b3d6fdfc7d))

**Full Changelog:** [`2025.12.04.0...2025.12.05.0`](https://github.com/juspay/connector-service/compare/2025.12.04.0...2025.12.05.0)

- - -

## 2025.12.04.0

### Features

- **connector:** [NEXIXPAY] Connector Integration ([#324](https://github.com/juspay/connector-service/pull/324)) ([`3f1b331`](https://github.com/juspay/connector-service/commit/3f1b331b04e061c5ec7d3f9d4b3f601a9bc6bec8))

### Bug Fixes

- Diff correction for multisafepay ([#332](https://github.com/juspay/connector-service/pull/332)) ([`136f32f`](https://github.com/juspay/connector-service/commit/136f32f3daf276a7d4d1584ed93d10d3b7bb5e10))

**Full Changelog:** [`2025.12.03.1...2025.12.04.0`](https://github.com/juspay/connector-service/compare/2025.12.03.1...2025.12.04.0)

- - -

## 2025.12.03.1

### Bug Fixes

- Fix Customer_Acceptance conversion from proto to connector_type ([#338](https://github.com/juspay/connector-service/pull/338)) ([`cd8fa9f`](https://github.com/juspay/connector-service/commit/cd8fa9f8c94e97f39ce9593bbd193814888df8d6))

### Miscellaneous Tasks

- Add trigger to push image to ghcr when tag is created ([#341](https://github.com/juspay/connector-service/pull/341)) ([`0f8fe65`](https://github.com/juspay/connector-service/commit/0f8fe6523aa6fca996e53affb78aee588a6827d8))

**Full Changelog:** [`2025.12.03.0...2025.12.03.1`](https://github.com/juspay/connector-service/compare/2025.12.03.0...2025.12.03.1)

- - -

## 2025.12.03.0

### Features

- **connector:** [IATAPAY] Connector Integration ([#304](https://github.com/juspay/connector-service/pull/304)) ([`01c575f`](https://github.com/juspay/connector-service/commit/01c575f41e61e5017b046edf41a9362d994275e3))

### Bug Fixes

- Reverting merchant_reference_payment_id field addition ([#336](https://github.com/juspay/connector-service/pull/336)) ([`eb91720`](https://github.com/juspay/connector-service/commit/eb9172021118181c7566960b4a8b25e3d7b290ba))
- Populate payment method token for AuthorizeOnly request ([#337](https://github.com/juspay/connector-service/pull/337)) ([`12ad641`](https://github.com/juspay/connector-service/commit/12ad641d908d0ec567fa968361bdd4bc54afd39e))

**Full Changelog:** [`2025.12.02.0...2025.12.03.0`](https://github.com/juspay/connector-service/compare/2025.12.02.0...2025.12.03.0)

- - -

## 2025.12.02.0

### Features

- **connector:** Added bamboraapac integration ([#298](https://github.com/juspay/connector-service/pull/298)) ([`3234bf0`](https://github.com/juspay/connector-service/commit/3234bf08c17ce07011e233a063cedd147c330b6b))

### Bug Fixes

- **Fiserv:** Authorize, Capture, Void, Refund diff check for connector Fiserv ([#314](https://github.com/juspay/connector-service/pull/314)) ([`458cab4`](https://github.com/juspay/connector-service/commit/458cab4afbdddc69e500e19ef13d9a1d62d650d7))

**Full Changelog:** [`2025.12.01.0...2025.12.02.0`](https://github.com/juspay/connector-service/compare/2025.12.01.0...2025.12.02.0)

- - -

## 2025.12.01.0

### Features

- **connector:** [SHIFT4] Connector Integration ([#326](https://github.com/juspay/connector-service/pull/326)) ([`2d652a8`](https://github.com/juspay/connector-service/commit/2d652a8fc693cddc5a3a56cc5071dd7c02291af4))

**Full Changelog:** [`2025.11.28.0...2025.12.01.0`](https://github.com/juspay/connector-service/compare/2025.11.28.0...2025.12.01.0)

- - -

## 2025.11.28.0

### Features

- **connector:**
  - [NMI] Connector Integration ([#300](https://github.com/juspay/connector-service/pull/300)) ([`45ac195`](https://github.com/juspay/connector-service/commit/45ac1957892fc34560bf3e26c502d0e6d6cb849b))
  - Add Forte Connector ([#238](https://github.com/juspay/connector-service/pull/238)) ([`3599dc8`](https://github.com/juspay/connector-service/commit/3599dc8fdf30e04394a1175578e166b92e129abd))
- Enhance gRPC payment requests with order_id, payment_method_token, and access_token support ([#325](https://github.com/juspay/connector-service/pull/325)) ([`7f28be8`](https://github.com/juspay/connector-service/commit/7f28be871568f5937975a99bde14ce47736fd81e))

### Bug Fixes

- Removed git from dockerignore to add build versions in health check ([#84](https://github.com/juspay/connector-service/pull/84)) ([`8cccab2`](https://github.com/juspay/connector-service/commit/8cccab2e07bd38588a66f683423442727dc93a0d))

**Full Changelog:** [`2025.11.27.0...2025.11.28.0`](https://github.com/juspay/connector-service/compare/2025.11.27.0...2025.11.28.0)

- - -

## 2025.11.27.0

### Bug Fixes

- **Rapyd:** Authorize diff check fix ([#323](https://github.com/juspay/connector-service/pull/323)) ([`38d44bc`](https://github.com/juspay/connector-service/commit/38d44bcfaaf4a888cec3a98a04b0e58e941cab3a))
- Merchant_reference_payment_id proto change ([#322](https://github.com/juspay/connector-service/pull/322)) ([`353a686`](https://github.com/juspay/connector-service/commit/353a686b17246eaa7e305fe77d1dab373d01cf3a))

**Full Changelog:** [`2025.11.26.0...2025.11.27.0`](https://github.com/juspay/connector-service/compare/2025.11.26.0...2025.11.27.0)

- - -

## 2025.11.26.0

### Bug Fixes

- **Trustpay:** AccessToken creation fix ([#321](https://github.com/juspay/connector-service/pull/321)) ([`3d11036`](https://github.com/juspay/connector-service/commit/3d110363ee671895ce5e28c58341127d37e5e395))
- Change address type for Customer Create and PaymenMethodToken Create Request ([#318](https://github.com/juspay/connector-service/pull/318)) ([`ae3b003`](https://github.com/juspay/connector-service/commit/ae3b0030cf670679f491ae649efe2b283db0db9b))
- Sandbox url fix ([#316](https://github.com/juspay/connector-service/pull/316)) ([`7b5e7af`](https://github.com/juspay/connector-service/commit/7b5e7af1c7480b605664072c4d8187ec24537bc9))
- [WORLDPAYVANTIV] sandbox url fix ([#320](https://github.com/juspay/connector-service/pull/320)) ([`0ab1279`](https://github.com/juspay/connector-service/commit/0ab12798f5d86736dda0c799dd3c59d33ad60eb5))

**Full Changelog:** [`2025.11.25.1...2025.11.26.0`](https://github.com/juspay/connector-service/compare/2025.11.25.1...2025.11.26.0)

- - -

## 2025.11.25.1

### Features

- **connector:** Billwerk Connector Integration ([#307](https://github.com/juspay/connector-service/pull/307)) ([`1581ed4`](https://github.com/juspay/connector-service/commit/1581ed4ae9f85345e0292eaebf864e691b797f5b))

### Miscellaneous Tasks

- **core:** Updating tokio and hyperswitch dependency ([#313](https://github.com/juspay/connector-service/pull/313)) ([`972c80d`](https://github.com/juspay/connector-service/commit/972c80d2b9d9555fb1b9cde37e032716313267b8))

**Full Changelog:** [`2025.11.25.0...2025.11.25.1`](https://github.com/juspay/connector-service/compare/2025.11.25.0...2025.11.25.1)

- - -

## 2025.11.25.0

### Features

- **connector:** [paysafe] integrate no3ds card, refund, void, capture ([#267](https://github.com/juspay/connector-service/pull/267)) ([`c2b013f`](https://github.com/juspay/connector-service/commit/c2b013fb8355ba375345cc3ae67d91fcb3ea1830))
- Added Config Overrides ([#18](https://github.com/juspay/connector-service/pull/18)) ([`44c5a4a`](https://github.com/juspay/connector-service/commit/44c5a4aa76e51ffc827d8d594117ef8380668bda))

### Bug Fixes

- Mapping wrongly done for hipay in types.rs ([#311](https://github.com/juspay/connector-service/pull/311)) ([`6671334`](https://github.com/juspay/connector-service/commit/667133432d6cb50639d6371f755fea1164df0489))
- Stripe connector_response diff fix ([#312](https://github.com/juspay/connector-service/pull/312)) ([`75a8240`](https://github.com/juspay/connector-service/commit/75a8240d44d110aa7d0048b265ee093bb0251489))

**Full Changelog:** [`2025.11.24.0...2025.11.25.0`](https://github.com/juspay/connector-service/compare/2025.11.24.0...2025.11.25.0)

- - -

## 2025.11.24.0

### Features

- **connector:**
  - [HIPAY] Connector Integration ([#299](https://github.com/juspay/connector-service/pull/299)) ([`ce21e56`](https://github.com/juspay/connector-service/commit/ce21e56a543320a56e4152f6da34ba2013a038ab))
  - [TRUSTPAYMENTS] Connector Integration ([#272](https://github.com/juspay/connector-service/pull/272)) ([`4805c87`](https://github.com/juspay/connector-service/commit/4805c8735ac565bcb78429849f3961affcd671af))
  - [GLOBALPAY] Connector Integration ([#241](https://github.com/juspay/connector-service/pull/241)) ([`ece29bb`](https://github.com/juspay/connector-service/commit/ece29bba21af617caa37e78c4fec23b5459e9697))
  - Add bluesnap -- no3ds authorize, void, capture, refund, psync, rsync and webhooks ([#285](https://github.com/juspay/connector-service/pull/285)) ([`3a952fe`](https://github.com/juspay/connector-service/commit/3a952fe86f19c8c554e5a6f587c769b0fd103a2b))
- Introduce register only grpc function ([#306](https://github.com/juspay/connector-service/pull/306)) ([`b5a367c`](https://github.com/juspay/connector-service/commit/b5a367c1c775c32503feb00cdc6cd063cc97ea3b))

### Refactors

- Use namespace imports for connectors in types.rs ([#308](https://github.com/juspay/connector-service/pull/308)) ([`63ec114`](https://github.com/juspay/connector-service/commit/63ec1148f0ec634a7f5b893db38b0387fbfeb54d))

**Full Changelog:** [`2025.11.21.0...2025.11.24.0`](https://github.com/juspay/connector-service/compare/2025.11.21.0...2025.11.24.0)

- - -

## 2025.11.21.0

### Features

- **connector:** [MULTISAFEPAY] Connector Integration ([#244](https://github.com/juspay/connector-service/pull/244)) ([`a853a4e`](https://github.com/juspay/connector-service/commit/a853a4e60fb980e8aea3364ea2666b45b73a5984))
- **trustpay:** Implement error type mapping and enhance error handling ([#302](https://github.com/juspay/connector-service/pull/302)) ([`ad9d441`](https://github.com/juspay/connector-service/commit/ad9d4419caaa7c4962af89be23609907abea9186))
- Client creation based on proxy ([#292](https://github.com/juspay/connector-service/pull/292)) ([`42afd04`](https://github.com/juspay/connector-service/commit/42afd040489c17f5f5801fb0c98f2907edaf16e1))
- Introduce connector customer create grpc function ([#290](https://github.com/juspay/connector-service/pull/290)) ([`d47f7d0`](https://github.com/juspay/connector-service/commit/d47f7d03e694756644ba3903d94528e9b611e03b))
- Encoded data in psync separate field ([#305](https://github.com/juspay/connector-service/pull/305)) ([`8edf9f7`](https://github.com/juspay/connector-service/commit/8edf9f744597c4f8712550a060a2bc1700c174d9))
- Introduce create order grpc function ([#284](https://github.com/juspay/connector-service/pull/284)) ([`d613db4`](https://github.com/juspay/connector-service/commit/d613db4f6f71718477d8d0499034b58d15c8a052))
- Introduce create payment method token create grpc function ([#291](https://github.com/juspay/connector-service/pull/291)) ([`dfa0d60`](https://github.com/juspay/connector-service/commit/dfa0d60f497d77fff2d520e560ace868970eec30))

### Bug Fixes

- **Braintree:** Refund diff check for connector Braintree ([#303](https://github.com/juspay/connector-service/pull/303)) ([`4c4b110`](https://github.com/juspay/connector-service/commit/4c4b1102c11e24401fc11c5256f1dc257b09979f))

### Refactors

- Flattened the payment method in proto ([#289](https://github.com/juspay/connector-service/pull/289)) ([`692f307`](https://github.com/juspay/connector-service/commit/692f3072a55b1a4864714f2484b267ca8b202fbb))

**Full Changelog:** [`2025.11.19.2...2025.11.21.0`](https://github.com/juspay/connector-service/compare/2025.11.19.2...2025.11.21.0)

- - -

## 2025.11.19.2

### Features

- **connector:**
  - [STAX] Connector Integration ([#297](https://github.com/juspay/connector-service/pull/297)) ([`c8d20f3`](https://github.com/juspay/connector-service/commit/c8d20f3b0c53f4cac47dc7ad8a726fa8d669bedc))
  - [Stripe] Add Apple pay, Google pay & PaymentMethodtoken flow for Stripe ([#255](https://github.com/juspay/connector-service/pull/255)) ([`e518f59`](https://github.com/juspay/connector-service/commit/e518f59bf80c096419fa59c5ebf3b86356429a44))
- Introduce payment authorize only create grpc function ([#296](https://github.com/juspay/connector-service/pull/296)) ([`5df0c7c`](https://github.com/juspay/connector-service/commit/5df0c7cde787b3d49ce222fb6ffbbe7932b0af4d))

### Miscellaneous Tasks

- Added dynamic content type selection and authorize flow for Trustpay ([#227](https://github.com/juspay/connector-service/pull/227)) ([`75d9793`](https://github.com/juspay/connector-service/commit/75d9793ce51cfaa524f68b2878b5e257d022e3ee))

**Full Changelog:** [`2025.11.19.1...2025.11.19.2`](https://github.com/juspay/connector-service/compare/2025.11.19.1...2025.11.19.2)

- - -

## 2025.11.19.1

### Bug Fixes

- Adyen Diff Check Resolve ([#268](https://github.com/juspay/connector-service/pull/268)) ([`6db1fe4`](https://github.com/juspay/connector-service/commit/6db1fe45ac5959ad71ecfc9d4aac9b678bb1010f))

**Full Changelog:** [`2025.11.19.0...2025.11.19.1`](https://github.com/juspay/connector-service/compare/2025.11.19.0...2025.11.19.1)

- - -

## 2025.11.19.0

### Features

- **connector:** [Paypal] Connector Integration ([#246](https://github.com/juspay/connector-service/pull/246)) ([`3d7af89`](https://github.com/juspay/connector-service/commit/3d7af89ba3483731c68dfc63c4e7141ba89b38a7))
- Introduce session token create grpc function ([#281](https://github.com/juspay/connector-service/pull/281)) ([`d49b576`](https://github.com/juspay/connector-service/commit/d49b576efb95a07790515e221a4c36874bf7d30e))
- Introduce access token create grpc function ([#282](https://github.com/juspay/connector-service/pull/282)) ([`6387ea3`](https://github.com/juspay/connector-service/commit/6387ea38cd1c9d9caf9e1f6cfcbc42f72fee120b))

### Bug Fixes

- Capture body changes and baseurl changes ([#269](https://github.com/juspay/connector-service/pull/269)) ([`3abc1a5`](https://github.com/juspay/connector-service/commit/3abc1a57c9f85970259c6fbf2e8daa367be85036))

**Full Changelog:** [`2025.11.18.0...2025.11.19.0`](https://github.com/juspay/connector-service/compare/2025.11.18.0...2025.11.19.0)

- - -

## 2025.11.18.0

### Features

- **connector:** [CELEROCOMMERCE] Connector Integration ([#245](https://github.com/juspay/connector-service/pull/245)) ([`331ee50`](https://github.com/juspay/connector-service/commit/331ee5033fb7d0ec0de8f4e9c5f96d6da6a9cdb9))

### Bug Fixes

- **noon:** Refund diff check for connector noon ([#295](https://github.com/juspay/connector-service/pull/295)) ([`9cae4aa`](https://github.com/juspay/connector-service/commit/9cae4aa0e029315bd91fdab56724ae3154fd8579))
- **razorpay:** Change payment_capture field type from boolean to integer ([#293](https://github.com/juspay/connector-service/pull/293)) ([`5bfd4e1`](https://github.com/juspay/connector-service/commit/5bfd4e1adb106133a72e9e06376963515a2c17d2))

**Full Changelog:** [`2025.11.17.1...2025.11.18.0`](https://github.com/juspay/connector-service/compare/2025.11.17.1...2025.11.18.0)

- - -

## 2025.11.17.1

### Features

- **connector:**
  - Added Refund flow for Authorizedotnet ([#279](https://github.com/juspay/connector-service/pull/279)) ([`b73ad11`](https://github.com/juspay/connector-service/commit/b73ad115ba0186fe31f5fcd31e1431d04ddc889f))
  - [SILVERFLOW] Connector Integration ([#240](https://github.com/juspay/connector-service/pull/240)) ([`9368fa6`](https://github.com/juspay/connector-service/commit/9368fa6a6bc69fa6cd9ad751252997e322ae35cb))
- Add wait screen information for UPI payments ([#259](https://github.com/juspay/connector-service/pull/259)) ([`290b9d1`](https://github.com/juspay/connector-service/commit/290b9d1bcbda28299a60d387e57daf25f3d88b36))

### Bug Fixes

- Add optional error_reason field to payment responses ([#288](https://github.com/juspay/connector-service/pull/288)) ([`c0e6d22`](https://github.com/juspay/connector-service/commit/c0e6d228787c8ab970cd045c658fec6ebb5da45c))
- Diff fixes for Novalnet Authorize flow ([#287](https://github.com/juspay/connector-service/pull/287)) ([`8abb1ba`](https://github.com/juspay/connector-service/commit/8abb1ba750df259f34e62de798ab9c66d6ee5242))

**Full Changelog:** [`2025.11.17.0...2025.11.17.1`](https://github.com/juspay/connector-service/compare/2025.11.17.0...2025.11.17.1)

- - -

## 2025.11.17.0

### Features

- **connector:** [AUTHIPAY] Connector Integration ([#277](https://github.com/juspay/connector-service/pull/277)) ([`ecd47f9`](https://github.com/juspay/connector-service/commit/ecd47f9d0761ea622d315643043a95beed308cd6))

### Bug Fixes

- **cybersource:** Update error handling to use message instead of reason ([#275](https://github.com/juspay/connector-service/pull/275)) ([`17badb2`](https://github.com/juspay/connector-service/commit/17badb24c6d8e7f689cfb7463d8b16fc9022f5d3))
- **noon:** Update error response message handling to use the correct message field ([#273](https://github.com/juspay/connector-service/pull/273)) ([`ff49a59`](https://github.com/juspay/connector-service/commit/ff49a594f3117705f8e904fca52caf8980cd5df0))
- **stripe:** Update error handling to use message instead of code for response errors ([#270](https://github.com/juspay/connector-service/pull/270)) ([`cf0626d`](https://github.com/juspay/connector-service/commit/cf0626d5b1ce4697fcf83bbf845751becd013b6c))

### Refactors

- **connector:** [PAYTM] refactor UPI flows for Paytm ([#264](https://github.com/juspay/connector-service/pull/264)) ([`fceeb43`](https://github.com/juspay/connector-service/commit/fceeb434975533e8c110c4c7f90637bbdd1ea2d9))

**Full Changelog:** [`2025.11.14.0...2025.11.17.0`](https://github.com/juspay/connector-service/compare/2025.11.14.0...2025.11.17.0)

- - -

## 2025.11.14.0

### Features

- **connector:** [DATATRANS] Connector Integration ([#250](https://github.com/juspay/connector-service/pull/250)) ([`3be2ccf`](https://github.com/juspay/connector-service/commit/3be2ccf99e0efdeae8258f545aa97a75e60ee30f))

### Bug Fixes

- Noon expiry year and fiuu three ds ([#274](https://github.com/juspay/connector-service/pull/274)) ([`dc5812d`](https://github.com/juspay/connector-service/commit/dc5812dfe927ece085501814d4ddfb6a0cd4a347))

### Refactors

- **connector:** [PHONEPE] refactor status mapping ([#278](https://github.com/juspay/connector-service/pull/278)) ([`5ff7d1f`](https://github.com/juspay/connector-service/commit/5ff7d1f2b97f32bf35d4502cce8a43539c48e00c))

### Miscellaneous Tasks

- Fixed Void and Capture flow as per diff checker ([#265](https://github.com/juspay/connector-service/pull/265)) ([`ec91d1b`](https://github.com/juspay/connector-service/commit/ec91d1b92127e29d3be4fa0f3ec5e74a723ea0e6))

**Full Changelog:** [`2025.11.13.0...2025.11.14.0`](https://github.com/juspay/connector-service/compare/2025.11.13.0...2025.11.14.0)

- - -

## 2025.11.13.0

### Features

- **connector:** [FISERVEMEA] Connector Integration ([#254](https://github.com/juspay/connector-service/pull/254)) ([`38fe2f7`](https://github.com/juspay/connector-service/commit/38fe2f7037b7f18465a96dbe4eabbe4d9586511a))
- Unmask x-shadow-mode header in logs ([#236](https://github.com/juspay/connector-service/pull/236)) ([`7c07363`](https://github.com/juspay/connector-service/commit/7c0736359401266a9f33d90e6c977f32f07696e3))
- Add test mode and mock PG API integration ([#257](https://github.com/juspay/connector-service/pull/257)) ([`faad595`](https://github.com/juspay/connector-service/commit/faad5954c7e2b893ace70290fa32693f6098537a))

**Full Changelog:** [`2025.11.12.0...2025.11.13.0`](https://github.com/juspay/connector-service/compare/2025.11.12.0...2025.11.13.0)

- - -

## 2025.11.12.0

### Bug Fixes

- Fixed xendit tests for pending cases ([#261](https://github.com/juspay/connector-service/pull/261)) ([`2ee9d08`](https://github.com/juspay/connector-service/commit/2ee9d085afed5b9986e25808e0ecfe61384447a8))

**Full Changelog:** [`2025.11.11.0...2025.11.12.0`](https://github.com/juspay/connector-service/compare/2025.11.11.0...2025.11.12.0)

- - -


## 2025.11.10.0

### Features

- **connector:** [payload] implement core flows, card payment method and webhooks ([#249](https://github.com/juspay/connector-service/pull/249)) ([`aacf887`](https://github.com/juspay/connector-service/commit/aacf8878e790af265bab32c2653bd78956044951))

### Refactors

- Use typed connector response with masking for events ([#256](https://github.com/juspay/connector-service/pull/256)) ([`58e4b93`](https://github.com/juspay/connector-service/commit/58e4b93c3ea3d68fa8d3bed332eae98ec6e61afd))

**Full Changelog:** [`2025.11.05.0...2025.11.10.0`](https://github.com/juspay/connector-service/compare/2025.11.05.0...2025.11.10.0)

- - -

## 2025.11.05.0

### Documentation

- **setup.md:** Toml always prod.toml issue fix for docker ([#242](https://github.com/juspay/connector-service/pull/242)) ([`6e1d41a`](https://github.com/juspay/connector-service/commit/6e1d41ae90f04e820f6fc372c1add2138337d42b))

### Build System / Dependencies

- Skip git commit hashes from typo check ([#243](https://github.com/juspay/connector-service/pull/243)) ([`88b7f9e`](https://github.com/juspay/connector-service/commit/88b7f9ecf72a304b4a5128183cb679c1be1eb914))

**Full Changelog:** [`2025.11.04.1...2025.11.05.0`](https://github.com/juspay/connector-service/compare/2025.11.04.1...2025.11.05.0)

- - -

## 2025.11.04.1

### Refactors

- **connector:** [RAZORPAY] update Razorpay connector diffs ([#237](https://github.com/juspay/connector-service/pull/237)) ([`4ddb48d`](https://github.com/juspay/connector-service/commit/4ddb48dfc8d0f1b806bf106b10d9840df5133ad3))

**Full Changelog:** [`2025.11.04.0...2025.11.04.1`](https://github.com/juspay/connector-service/compare/2025.11.04.0...2025.11.04.1)

- - -

## 2025.11.04.0

### Bug Fixes

- Authentication flow request and response handling fix ([#233](https://github.com/juspay/connector-service/pull/233)) ([`77eaaa6`](https://github.com/juspay/connector-service/commit/77eaaa6344de9657c83a65ed0d619f48dff0c4a5))

### Documentation

- **setup.md:** Add setup instructions for local development setup ([#239](https://github.com/juspay/connector-service/pull/239)) ([`e945aff`](https://github.com/juspay/connector-service/commit/e945aff95c71d7f9bf7701deddb7ea793a2f3fe3))

**Full Changelog:** [`2025.10.31.0...2025.11.04.0`](https://github.com/juspay/connector-service/compare/2025.10.31.0...2025.11.04.0)

- - -

## 2025.10.31.0

### Features

- **connector:**
  - Added SetupMandate, RepeatPayment and CreateConnectorCustomer flows for stripe ([#230](https://github.com/juspay/connector-service/pull/230)) ([`3ded301`](https://github.com/juspay/connector-service/commit/3ded3017f7fe1a722b694fab294b729d54be9f46))
  - Added RepeatPayment flow for cybersource ([#235](https://github.com/juspay/connector-service/pull/235)) ([`33633b1`](https://github.com/juspay/connector-service/commit/33633b15e588fd2724cf30456a5bba46056169e9))

**Full Changelog:** [`2025.10.30.0...2025.10.31.0`](https://github.com/juspay/connector-service/compare/2025.10.30.0...2025.10.31.0)

- - -

## 2025.10.30.0

### Bug Fixes

- **audit:** Ensure grpc audit events emit even for early request parsing failures ([#234](https://github.com/juspay/connector-service/pull/234)) ([`8fdfbbd`](https://github.com/juspay/connector-service/commit/8fdfbbd6fa638c46f7b96bde344af1f5df988add))

**Full Changelog:** [`2025.10.29.0...2025.10.30.0`](https://github.com/juspay/connector-service/compare/2025.10.29.0...2025.10.30.0)

- - -

## 2025.10.29.0

### Features

- **connector:** [Worldpayvantiv] Connector Integration and VoidPostCapture flow implemented ([#194](https://github.com/juspay/connector-service/pull/194)) ([`ce74f4f`](https://github.com/juspay/connector-service/commit/ce74f4ff61d791b2f504e1d2a914170a33f971fd))

### Bug Fixes

- **cybersource:** Use security_code and state_code in authorize flow ([#231](https://github.com/juspay/connector-service/pull/231)) ([`1d0d1e2`](https://github.com/juspay/connector-service/commit/1d0d1e2b31f20e3127e9bf2c5b759a7c4dd91484))

**Full Changelog:** [`2025.10.28.0...2025.10.29.0`](https://github.com/juspay/connector-service/compare/2025.10.28.0...2025.10.29.0)

- - -

## 2025.10.28.0

### Features

- **connector:** [Worldpay] Connector Integration ([#216](https://github.com/juspay/connector-service/pull/216)) ([`61945b2`](https://github.com/juspay/connector-service/commit/61945b24a70d6e50d8c607a519fa2634fac8a68d))

### Bug Fixes

- **Access_token_flow:** Added proto field to accept expires_in_seconds in request ([#232](https://github.com/juspay/connector-service/pull/232)) ([`a7ddd3c`](https://github.com/juspay/connector-service/commit/a7ddd3cb16f372c7d79358cc9e357c272f1a4ed4))

**Full Changelog:** [`2025.10.27.0...2025.10.28.0`](https://github.com/juspay/connector-service/compare/2025.10.27.0...2025.10.28.0)

- - -

## 2025.10.27.0

### Features

- **connector:** Diff check fixes for Stripe, Cybersource & Novalnet ([#226](https://github.com/juspay/connector-service/pull/226)) ([`2f8b321`](https://github.com/juspay/connector-service/commit/2f8b321665485d4ccf12a4ab06f4b8f36ece5135))

### Bug Fixes

- Fix typo in README.md ([`8f12995`](https://github.com/juspay/connector-service/commit/8f12995f0fd63e43ce2b15c049bc42bc9029661d))

**Full Changelog:** [`2025.10.23.0...2025.10.27.0`](https://github.com/juspay/connector-service/compare/2025.10.23.0...2025.10.27.0)

- - -

## 2025.10.23.0

### Features

- Adding_new_field_for_Merchant_account_metadata ([#228](https://github.com/juspay/connector-service/pull/228)) ([`46f7ddb`](https://github.com/juspay/connector-service/commit/46f7ddb6b533f887b4d9bcd218f3e16fd229d4ad))

### Bug Fixes

- **cybersource:** Use minor_refund_amount instead of minor_payment_amount in refund transformer ([#229](https://github.com/juspay/connector-service/pull/229)) ([`28d1e3e`](https://github.com/juspay/connector-service/commit/28d1e3e19c5bc7fae4cb431c531723e45b0970a0))
- Resolve disparity in Authorizedotnet flows (Authorize, RepeatPayment, SetupMandate) ([#225](https://github.com/juspay/connector-service/pull/225)) ([`2649fd8`](https://github.com/juspay/connector-service/commit/2649fd8902cdd812c1e4f7debfe4080c45a9fa55))

**Full Changelog:** [`2025.10.17.0...2025.10.23.0`](https://github.com/juspay/connector-service/compare/2025.10.17.0...2025.10.23.0)

- - -

## 2025.10.17.0

### Features

- **connector:** [CYBERSOURCE] Connector Integration ([#169](https://github.com/juspay/connector-service/pull/169)) ([`922d1c3`](https://github.com/juspay/connector-service/commit/922d1c3f786f9b83e005ea3a07d283817dd87833))
- **core:**
  - Added SecretString type for raw_connector_request and raw_connector_response ([#220](https://github.com/juspay/connector-service/pull/220)) ([`194c035`](https://github.com/juspay/connector-service/commit/194c0358122040f732ac23c9633a81eece63044c))
  - Added Create connector customer flow ([#222](https://github.com/juspay/connector-service/pull/222)) ([`29d8ad3`](https://github.com/juspay/connector-service/commit/29d8ad3771f4403431e7aaf52b4db9754a571884))

**Full Changelog:** [`2025.10.16.0...2025.10.17.0`](https://github.com/juspay/connector-service/compare/2025.10.16.0...2025.10.17.0)

- - -

## 2025.10.16.0

### Features

- **connector:** Added cards flow and tests for Stripe ([#108](https://github.com/juspay/connector-service/pull/108)) ([`0f2ecbc`](https://github.com/juspay/connector-service/commit/0f2ecbca214ff3961a5803cd114ae44275db803b))

### Miscellaneous Tasks

- Added webhooks support in Cryptopay ([#201](https://github.com/juspay/connector-service/pull/201)) ([`337cd51`](https://github.com/juspay/connector-service/commit/337cd51217bff2cc939dc8b4c100359ec25b7f66))

**Full Changelog:** [`2025.10.14.0...2025.10.16.0`](https://github.com/juspay/connector-service/compare/2025.10.14.0...2025.10.16.0)

- - -

## 2025.10.14.0

### Features

- **connector:** Added AccessToken flow for trustpay ([#219](https://github.com/juspay/connector-service/pull/219)) ([`d254128`](https://github.com/juspay/connector-service/commit/d254128376ca1dd3d1eab0d2a17fdd1c820b1d63))

**Full Changelog:** [`2025.10.10.1...2025.10.14.0`](https://github.com/juspay/connector-service/compare/2025.10.10.1...2025.10.14.0)

- - -

## 2025.10.10.1

### Refactors

- **connector:** Update phonepe sandbox endpoint ([#218](https://github.com/juspay/connector-service/pull/218)) ([`343fd67`](https://github.com/juspay/connector-service/commit/343fd67743060d4daa5d2e08122113eaab48a24c))

**Full Changelog:** [`2025.10.10.0...2025.10.10.1`](https://github.com/juspay/connector-service/compare/2025.10.10.0...2025.10.10.1)

- - -

## 2025.10.10.0

### Features

- **connector:** [TRUSTPAY] Connector Integration PSync flow ([#217](https://github.com/juspay/connector-service/pull/217)) ([`764aeba`](https://github.com/juspay/connector-service/commit/764aeba435816ce9dd2f21c972142ac4e036c0ef))

**Full Changelog:** [`2025.10.09.0...2025.10.10.0`](https://github.com/juspay/connector-service/compare/2025.10.09.0...2025.10.10.0)

- - -

## 2025.10.09.0

### Miscellaneous Tasks

- Added webhooks support in Noon ([#156](https://github.com/juspay/connector-service/pull/156)) ([`6b24ce3`](https://github.com/juspay/connector-service/commit/6b24ce3550cf384258953143843fc9715978af94))

**Full Changelog:** [`2025.10.08.0...2025.10.09.0`](https://github.com/juspay/connector-service/compare/2025.10.08.0...2025.10.09.0)

- - -

## 2025.10.08.0

### Features

- **connector:** [Aci] Connector Integration ([#212](https://github.com/juspay/connector-service/pull/212)) ([`ccd05e4`](https://github.com/juspay/connector-service/commit/ccd05e47115e33a14c9f4b804b3eafb7922ecc41))
- **framework:** Run UCS in Shadow mode ([#213](https://github.com/juspay/connector-service/pull/213)) ([`96bce38`](https://github.com/juspay/connector-service/commit/96bce38ad52b0ffcb2b81603e0ac6a9d0a6e11ef))

**Full Changelog:** [`2025.10.02.0...2025.10.08.0`](https://github.com/juspay/connector-service/compare/2025.10.02.0...2025.10.08.0)

- - -

## 2025.10.02.0

### Features

- **connector:** [Rapyd] Connector Integration ([#193](https://github.com/juspay/connector-service/pull/193)) ([`9051b40`](https://github.com/juspay/connector-service/commit/9051b406074d83f048e703488f297e4cac876db7))
- Emitting lineage id an reference id to kafka metadata in events ([#207](https://github.com/juspay/connector-service/pull/207)) ([`688e2a3`](https://github.com/juspay/connector-service/commit/688e2a368ff42d61ca1419cdbacc683320881295))

**Full Changelog:** [`2025.10.01.0...2025.10.02.0`](https://github.com/juspay/connector-service/compare/2025.10.01.0...2025.10.02.0)

- - -

## 2025.10.01.0

### Refactors

- **connector:** [PHONEPE] refactor phonepe and add UPI_QR support ([#209](https://github.com/juspay/connector-service/pull/209)) ([`8740d83`](https://github.com/juspay/connector-service/commit/8740d8344db63c1fec9c0fbd202035af503a65c1))

**Full Changelog:** [`2025.09.30.0...2025.10.01.0`](https://github.com/juspay/connector-service/compare/2025.09.30.0...2025.10.01.0)

- - -

## 2025.09.30.0

### Features

- **connector:** [Placetopay] Connector Integration ([#192](https://github.com/juspay/connector-service/pull/192)) ([`4d01054`](https://github.com/juspay/connector-service/commit/4d01054fe84c9ccd20a6fcf45c733824ff209348))
- Add configurable header masking to gRPC metadata with audit event emission ([#190](https://github.com/juspay/connector-service/pull/190)) ([`68ba3d9`](https://github.com/juspay/connector-service/commit/68ba3d9fdc9613cea5631aabc2980e10b79b534d))

**Full Changelog:** [`2025.09.29.0...2025.09.30.0`](https://github.com/juspay/connector-service/compare/2025.09.29.0...2025.09.30.0)

- - -

## 2025.09.29.0

### Miscellaneous Tasks

- Update git tag for hyperswitch repo ([#208](https://github.com/juspay/connector-service/pull/208)) ([`7bf6a22`](https://github.com/juspay/connector-service/commit/7bf6a22786517db253a78840927c33d458233380))

**Full Changelog:** [`2025.09.26.0...2025.09.29.0`](https://github.com/juspay/connector-service/compare/2025.09.26.0...2025.09.29.0)

- - -

## 2025.09.26.0

### Features

- **connector:** [Dlocal] Connector Integration ([#191](https://github.com/juspay/connector-service/pull/191)) ([`1ddd62b`](https://github.com/juspay/connector-service/commit/1ddd62ba6e9b7ccc89921345e3a8339f781d9f3e))
- **core:** PreAuthenticate, Authenticate and PostAuthenticate flow ([#176](https://github.com/juspay/connector-service/pull/176)) ([`0807495`](https://github.com/juspay/connector-service/commit/0807495b9ea45e925bd96c8695db1104aa325af7))

**Full Changelog:** [`2025.09.25.1...2025.09.26.0`](https://github.com/juspay/connector-service/compare/2025.09.25.1...2025.09.26.0)

- - -

## 2025.09.25.1

### Features

- **connector:** [HELCIM] Connector Integration ([#173](https://github.com/juspay/connector-service/pull/173)) ([`f7ab3e6`](https://github.com/juspay/connector-service/commit/f7ab3e6206a673a4736850df3a67a3bf5224841f))

### Miscellaneous Tasks

- Added OnlineBankingFpx, DuitNow payment methods support ([#198](https://github.com/juspay/connector-service/pull/198)) ([`b42f059`](https://github.com/juspay/connector-service/commit/b42f059f85a7820f16946daaa51ce2e5817cf532))

**Full Changelog:** [`2025.09.25.0...2025.09.25.1`](https://github.com/juspay/connector-service/compare/2025.09.25.0...2025.09.25.1)

- - -

## 2025.09.25.0

### Features

- Added raw_connector_request in ucs response ([#199](https://github.com/juspay/connector-service/pull/199)) ([`284d5cc`](https://github.com/juspay/connector-service/commit/284d5cc313f49d458058664afa39a142495474c0))
- Emit event for grpc request and refactor event publisher to synchronous ([#187](https://github.com/juspay/connector-service/pull/187)) ([`f077ada`](https://github.com/juspay/connector-service/commit/f077ada286199964a626456a449c1c8cdb1debb9))

**Full Changelog:** [`2025.09.24.0...2025.09.25.0`](https://github.com/juspay/connector-service/compare/2025.09.24.0...2025.09.25.0)

- - -

## 2025.09.24.0

### Refactors

- Added proper referer handling ([#184](https://github.com/juspay/connector-service/pull/184)) ([`f719688`](https://github.com/juspay/connector-service/commit/f719688943adf7bc17bb93dcb43f27485c17a96e))

**Full Changelog:** [`2025.09.23.0...2025.09.24.0`](https://github.com/juspay/connector-service/compare/2025.09.23.0...2025.09.24.0)

- - -

## 2025.09.23.0

### Features

- **connector:** Added authorize, psync and tests for Cryptopay and CryptoCurrency PaymentMethod ([#82](https://github.com/juspay/connector-service/pull/82)) ([`dc38d42`](https://github.com/juspay/connector-service/commit/dc38d425a5ba851898acce6bdbc83ead38483bd3))

### Miscellaneous Tasks

- Added webhooks support in Fiuu ([#185](https://github.com/juspay/connector-service/pull/185)) ([`567e767`](https://github.com/juspay/connector-service/commit/567e767433b49b4ca77879ce01fd6aab0c906250))

**Full Changelog:** [`2025.09.22.0...2025.09.23.0`](https://github.com/juspay/connector-service/compare/2025.09.22.0...2025.09.23.0)

- - -

## 2025.09.22.0

### Features

- **core:** Implement two step payment webhooks processing ([#177](https://github.com/juspay/connector-service/pull/177)) ([`c324184`](https://github.com/juspay/connector-service/commit/c3241847516663fe696e6401dc79ac67cdcddb4c))

### Bug Fixes

- **configs:** Add Bluecode's base url in sandbox and production configs ([#189](https://github.com/juspay/connector-service/pull/189)) ([`316aa94`](https://github.com/juspay/connector-service/commit/316aa94251a549d5890f13d060b299c9e9c81033))
- Docker public repo fix ([#186](https://github.com/juspay/connector-service/pull/186)) ([`528e6cf`](https://github.com/juspay/connector-service/commit/528e6cfb0e6737b9811bc63d34e17b7521b92101))

**Full Changelog:** [`2025.09.19.0...2025.09.22.0`](https://github.com/juspay/connector-service/compare/2025.09.19.0...2025.09.22.0)

- - -

## 2025.09.19.0

### Features

- **connector:** [BLUECODE] Added Bluecode Wallet in UCS ([#127](https://github.com/juspay/connector-service/pull/127)) ([`6074fc8`](https://github.com/juspay/connector-service/commit/6074fc8c64b5a678a1cdbc0439f19653bc665d67))
- Introduce production/sandbox configs ([#179](https://github.com/juspay/connector-service/pull/179)) ([`ab48178`](https://github.com/juspay/connector-service/commit/ab48178d6926dd5d7f7a4b1ef65071576c96e462))

**Full Changelog:** [`2025.09.18.0...2025.09.19.0`](https://github.com/juspay/connector-service/compare/2025.09.18.0...2025.09.19.0)

- - -

## 2025.09.18.0

### Miscellaneous Tasks

- Add amount conversion wrapper and integrity checks for Xendit ([#171](https://github.com/juspay/connector-service/pull/171)) ([`1db8901`](https://github.com/juspay/connector-service/commit/1db89016bef235f7f669cee7da4d723f57889013))
- Update git tag for hyperswitch repo ([#181](https://github.com/juspay/connector-service/pull/181)) ([`52f1b86`](https://github.com/juspay/connector-service/commit/52f1b863ef0a6bf845648ac0cbfc3501fa95f1ef))

**Full Changelog:** [`2025.09.17.0...2025.09.18.0`](https://github.com/juspay/connector-service/compare/2025.09.17.0...2025.09.18.0)

- - -

## 2025.09.17.0

### Features

- **connector:** [VOLT] Connector Integration ([#168](https://github.com/juspay/connector-service/pull/168)) ([`fd903df`](https://github.com/juspay/connector-service/commit/fd903df09fd2c177445bc6a25da21127ad6da4a6))

### Miscellaneous Tasks

- **core:** Removing debug logging which is set manually ([#175](https://github.com/juspay/connector-service/pull/175)) ([`0e395cb`](https://github.com/juspay/connector-service/commit/0e395cbba5ff05100b171915fdb964b3c8b17323))

**Full Changelog:** [`2025.09.15.0...2025.09.17.0`](https://github.com/juspay/connector-service/compare/2025.09.15.0...2025.09.17.0)

- - -
