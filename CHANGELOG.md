# Changelog

All notable changes to Connector Service will be documented here.

- - -

## 2026.02.26.0

### Features

- **connector:** [revolv3] add no-threeds card payments ([#520](https://github.com/juspay/connector-service/pull/520)) ([`4cf7158`](https://github.com/juspay/connector-service/commit/4cf7158a744fc77bf23765a0c00951059197cb8a))
- **core:** Added Missing BankTransfer, BankDebit & BankRedirect Payment Method Types ([#538](https://github.com/juspay/connector-service/pull/538)) ([`84493fe`](https://github.com/juspay/connector-service/commit/84493fefd9acfa016d380683a7a8c5e2e32d6b1f))
- [STAX] ACH BankDebit ([#548](https://github.com/juspay/connector-service/pull/548)) ([`50bf11c`](https://github.com/juspay/connector-service/commit/50bf11c04e0158e6e0b425b22d0695df380b9522))

### Miscellaneous Tasks

- Added Composite Authorize Flow ([#517](https://github.com/juspay/connector-service/pull/517)) ([`fedc4ad`](https://github.com/juspay/connector-service/commit/fedc4ad617862addc81c08016635380031accf12))

**Full Changelog:** [`2026.02.25.0...2026.02.26.0`](https://github.com/juspay/connector-service/compare/2026.02.25.0...2026.02.26.0)

- - -

## 2026.02.25.0

### Features

- **connector:** [Checkout] Implement googlepay and applepay decrypt flow and card ntid flow ([#546](https://github.com/juspay/connector-service/pull/546)) ([`576dfbe`](https://github.com/juspay/connector-service/commit/576dfbe4c3e3113a30d607c84d1bdcd43e26412b))
- Ach bankdebit integration for nmi ([#545](https://github.com/juspay/connector-service/pull/545)) ([`e07b1c3`](https://github.com/juspay/connector-service/commit/e07b1c3b71d02396fc6c8284dddee8958b8e3e40))

### Miscellaneous Tasks

- Refactored the wallet Payment Method ([#526](https://github.com/juspay/connector-service/pull/526)) ([`bb898de`](https://github.com/juspay/connector-service/commit/bb898deefab57b6100ca07754c1427a8035cfe50))

**Full Changelog:** [`2026.02.24.0...2026.02.25.0`](https://github.com/juspay/connector-service/compare/2026.02.24.0...2026.02.25.0)

- - -

## 2026.02.24.0

### Features

- **connector:** Adyen voucher paymentmethod added ([#500](https://github.com/juspay/connector-service/pull/500)) ([`948bd45`](https://github.com/juspay/connector-service/commit/948bd45c0a5ba816a25f2793265c2469609f4e69))

**Full Changelog:** [`2026.02.23.0...2026.02.24.0`](https://github.com/juspay/connector-service/compare/2026.02.23.0...2026.02.24.0)

- - -

## 2026.02.23.0

### Features

- **connector:** [trustpay] introduce wallet support - apple pay and google pay ([#503](https://github.com/juspay/connector-service/pull/503)) ([`5976300`](https://github.com/juspay/connector-service/commit/5976300a6eb3746990502970ca089b4eac4b4e24))

**Full Changelog:** [`2026.02.20.0...2026.02.23.0`](https://github.com/juspay/connector-service/compare/2026.02.20.0...2026.02.23.0)

- - -


## 2026.02.18.1

### Refactors

- **connector:** [PHONEPE] add Phonepe specific headers and target_app for upi request ([#507](https://github.com/juspay/connector-service/pull/507)) ([`0cf90e9`](https://github.com/juspay/connector-service/commit/0cf90e92e945fe4d7a641ca3029eba76955ca611))

**Full Changelog:** [`2026.02.18.0...2026.02.18.1`](https://github.com/juspay/connector-service/compare/2026.02.18.0...2026.02.18.1)

- - -

## 2026.02.18.0

### Features

- **connector:** Added ConnectorResponse for Connector Loonio ([#513](https://github.com/juspay/connector-service/pull/513)) ([`931f76b`](https://github.com/juspay/connector-service/commit/931f76bab2353ef69d2d5a90946ae6bffaa72385))
- **framework:** Changed access_token type from String to SecretString in proto and connector_types ([#490](https://github.com/juspay/connector-service/pull/490)) ([`425566c`](https://github.com/juspay/connector-service/commit/425566c6060cff496b7fcf03d6d4ba36ed3bdf64))

### Bug Fixes

- **redsys:** Correct XML element ordering in SOAP sync requests to comply with DTD validation ([#516](https://github.com/juspay/connector-service/pull/516)) ([`c1d5ae7`](https://github.com/juspay/connector-service/commit/c1d5ae7cf45e82684a43e55d13f1d060b4b7738b))

### Miscellaneous Tasks

- Added Crate for Composite Flows ([#512](https://github.com/juspay/connector-service/pull/512)) ([`8401920`](https://github.com/juspay/connector-service/commit/84019200ffa5f85dc849783583a378a5b6ae3a42))

**Full Changelog:** [`2026.02.16.0...2026.02.18.0`](https://github.com/juspay/connector-service/compare/2026.02.16.0...2026.02.18.0)

- - -

## 2026.02.16.0

### Bug Fixes

- Wellsfargo-diff-fix ([#461](https://github.com/juspay/connector-service/pull/461)) ([`3846d08`](https://github.com/juspay/connector-service/commit/3846d081720d02b179ccd5009bbf64e96f220bcf))

**Full Changelog:** [`2026.02.13.1...2026.02.16.0`](https://github.com/juspay/connector-service/compare/2026.02.13.1...2026.02.16.0)

- - -

## 2026.02.13.1

### Bug Fixes

- **connector:** Noon RSync Url & Default Status ([#511](https://github.com/juspay/connector-service/pull/511)) ([`92950a7`](https://github.com/juspay/connector-service/commit/92950a78ac3a7eacc4455fb3044fc251ffe6315e))
- Incremental_authorization_allowed and cybersource repeatpayment diff fix ([#510](https://github.com/juspay/connector-service/pull/510)) ([`e26ad9e`](https://github.com/juspay/connector-service/commit/e26ad9e26b30cc990e5b8c5b41d58ba6786cff19))

**Full Changelog:** [`2026.02.13.0...2026.02.13.1`](https://github.com/juspay/connector-service/compare/2026.02.13.0...2026.02.13.1)

- - -

## 2026.02.13.0

### Bug Fixes

- **connector:** Fixed Volt Default Response and PSync Response Handling ([#508](https://github.com/juspay/connector-service/pull/508)) ([`c10f357`](https://github.com/juspay/connector-service/commit/c10f357d26db23c34d777305c682ed743e5d411c))

**Full Changelog:** [`2026.02.12.0...2026.02.13.0`](https://github.com/juspay/connector-service/compare/2026.02.12.0...2026.02.13.0)

- - -

## 2026.02.12.0

### Features

- **connector:** Added Adyen paylater paymentmethod ([#496](https://github.com/juspay/connector-service/pull/496)) ([`f9e1283`](https://github.com/juspay/connector-service/commit/f9e1283687a9ae7d40b8eb10956aa98233b6f4f9))
- **framework:** Introduce BodyDecoding trait ([#502](https://github.com/juspay/connector-service/pull/502)) ([`8e7eede`](https://github.com/juspay/connector-service/commit/8e7eede8f60ee8be4ad62788411aceddbad715de))

### Bug Fixes

- **connector:** Mifinity 5xx Error Handling ([#505](https://github.com/juspay/connector-service/pull/505)) ([`1045fd3`](https://github.com/juspay/connector-service/commit/1045fd37ab767cecf0ef64ca068160e650f3dcd2))

**Full Changelog:** [`2026.02.11.1...2026.02.12.0`](https://github.com/juspay/connector-service/compare/2026.02.11.1...2026.02.12.0)

- - -

## 2026.02.11.1

### Bug Fixes

- Populate connector response for Repeat Everything Flow's Err response ([#504](https://github.com/juspay/connector-service/pull/504)) ([`1921e9d`](https://github.com/juspay/connector-service/commit/1921e9da5cab8c8edae0c62bf7961fbbecbfabb7))

**Full Changelog:** [`2026.02.11.0...2026.02.11.1`](https://github.com/juspay/connector-service/compare/2026.02.11.0...2026.02.11.1)

- - -

## 2026.02.11.0

### Features

- **connector:** Gigadat Macro Implementation ([#501](https://github.com/juspay/connector-service/pull/501)) ([`1ba0591`](https://github.com/juspay/connector-service/commit/1ba05915c289966a6ba9cdc15b2a83b9a3363afb))
- **payment_method_data:** [adyen] Auth code in payment response ([#498](https://github.com/juspay/connector-service/pull/498)) ([`d4b923c`](https://github.com/juspay/connector-service/commit/d4b923ce29c4c48cd9eb87682010ca7f5dee0ddc))

### Bug Fixes

- **connector:** Paypal Router Data Fix in Authorize and RepeatPayment Flow ([#499](https://github.com/juspay/connector-service/pull/499)) ([`cf8b523`](https://github.com/juspay/connector-service/commit/cf8b523d9019c98b70d3210fa96a5c4fcc6a7492))

### Miscellaneous Tasks

- Adding failure status to customer create response ([#497](https://github.com/juspay/connector-service/pull/497)) ([`558bac9`](https://github.com/juspay/connector-service/commit/558bac914e6e1453831460f8c6566cdec01aa40d))

**Full Changelog:** [`2026.02.10.0...2026.02.11.0`](https://github.com/juspay/connector-service/compare/2026.02.10.0...2026.02.11.0)

- - -

## 2026.02.10.0

### Features

- **connector:** Zift Connector Integration ([#480](https://github.com/juspay/connector-service/pull/480)) ([`21eb98b`](https://github.com/juspay/connector-service/commit/21eb98bf89c4597abb41d092b056a61c0222ed4a))

### Bug Fixes

- **payment_method:** Blik and sofort bank redirect payment method type defaulting to card ([#493](https://github.com/juspay/connector-service/pull/493)) ([`0c04185`](https://github.com/juspay/connector-service/commit/0c0418526daa56bcdd588d010229793834db57cd))

### Refactors

- Event publisher to log processed event even when publisher is disabled ([#491](https://github.com/juspay/connector-service/pull/491)) ([`9f83fd6`](https://github.com/juspay/connector-service/commit/9f83fd6eb1f938e8b02c0c09d0e3540d2b9ca025))

### Miscellaneous Tasks

- Added Resource ID, Service Name, and Service Type for UCS Events ([#460](https://github.com/juspay/connector-service/pull/460)) ([`430946c`](https://github.com/juspay/connector-service/commit/430946cc565cfe933b3fcf524c4bff2738ee4966))

**Full Changelog:** [`2026.02.06.1...2026.02.10.0`](https://github.com/juspay/connector-service/compare/2026.02.06.1...2026.02.10.0)

- - -

## 2026.02.06.1

### Features

- **framework:** Added missing CardNetwork Types ([#483](https://github.com/juspay/connector-service/pull/483)) ([`14ae8ee`](https://github.com/juspay/connector-service/commit/14ae8eef28619843086e07e34849117f2d0fb199))

### Bug Fixes

- **connector:**
  - [NEXIXPAY] DIFF FIX ([#476](https://github.com/juspay/connector-service/pull/476)) ([`d0592cc`](https://github.com/juspay/connector-service/commit/d0592cc54f405450e7e2c869dc3dba6516344000))
  - [Fiuu] Fixed payment status being sent as Pending for Fiuu when the connector response is FiuuPaymentsResponse::Error ([#482](https://github.com/juspay/connector-service/pull/482)) ([`00ffd3b`](https://github.com/juspay/connector-service/commit/00ffd3b1d753f72a93b3882585b3eda2a9c9ec55))
- Handled metadata Parsing Err Gracefully in Core ([#472](https://github.com/juspay/connector-service/pull/472)) ([`d0f78b5`](https://github.com/juspay/connector-service/commit/d0f78b529753ec573c6460aca6a36e06decb1cb8))
- Revert "Handled metadata Parsing Err Gracefully in Core" ([#489](https://github.com/juspay/connector-service/pull/489)) ([`ff256ac`](https://github.com/juspay/connector-service/commit/ff256ac10da20915a03673be4237a3a85e738c3a))
- PAYPAL Authorize 2xx error handling and connector_metadata diff in psync ([#477](https://github.com/juspay/connector-service/pull/477)) ([`884abad`](https://github.com/juspay/connector-service/commit/884abaded66344ff4a1e81719e57bf442c5e2f05))

**Full Changelog:** [`2026.02.06.0...2026.02.06.1`](https://github.com/juspay/connector-service/compare/2026.02.06.0...2026.02.06.1)

- - -

## 2026.02.06.0

### Features

- **connector:**
  - Razorpay - added pay mode handling in upi sync response ([#457](https://github.com/juspay/connector-service/pull/457)) ([`e63458a`](https://github.com/juspay/connector-service/commit/e63458abc229ff123e5462d8406f2a3a472f954a))
  - Implement incoming webhooks for trustpay ([#473](https://github.com/juspay/connector-service/pull/473)) ([`e192698`](https://github.com/juspay/connector-service/commit/e192698682e13120569f75ba27848531acfc3366))
- **framework:** Added VerifyRedirectResponse flow ([#449](https://github.com/juspay/connector-service/pull/449)) ([`c816ebd`](https://github.com/juspay/connector-service/commit/c816ebd0cc39fe3e84c7ee74a81e62c669a7f4e5))

### Bug Fixes

- **connector:** Request diff fix for Stripe & Cybersource ([#463](https://github.com/juspay/connector-service/pull/463)) ([`9421bac`](https://github.com/juspay/connector-service/commit/9421bace2f98cbad494a188b9ed971f714ba808c))

### Miscellaneous Tasks

- Updated the creds file ([#479](https://github.com/juspay/connector-service/pull/479)) ([`59a4ea2`](https://github.com/juspay/connector-service/commit/59a4ea23fc8af9536735a83147c03f7456d05ec7))

**Full Changelog:** [`2026.02.05.0...2026.02.06.0`](https://github.com/juspay/connector-service/compare/2026.02.05.0...2026.02.06.0)

- - -

## 2026.02.05.0

### Features

- Adyen gift card ([#431](https://github.com/juspay/connector-service/pull/431)) ([`e0164dc`](https://github.com/juspay/connector-service/commit/e0164dc4a7552fcfbda9ada07d0234317149ee2e))

**Full Changelog:** [`2026.02.04.0...2026.02.05.0`](https://github.com/juspay/connector-service/compare/2026.02.04.0...2026.02.05.0)

- - -

## 2026.02.04.0

### Features

- **connector:**
  - [Hyperpg] Integrate Card flows ([#429](https://github.com/juspay/connector-service/pull/429)) ([`337d2d0`](https://github.com/juspay/connector-service/commit/337d2d0dd234f26b591c8c504ee2fce08420e7b6))
  - Phonepe upi cc/cl response handling ([#437](https://github.com/juspay/connector-service/pull/437)) ([`8827276`](https://github.com/juspay/connector-service/commit/882727682e833236bca26330b070daa5a104efab))

### Bug Fixes

- **connector:** [NOVALNET] Populating connector transaction id during 2xx failures ([#470](https://github.com/juspay/connector-service/pull/470)) ([`f155fc8`](https://github.com/juspay/connector-service/commit/f155fc815abf89ca6321b0647d3e6abc1a444989))
- Added missing proto to domain conversion of merchant_account_metadata for setupmandate ([#467](https://github.com/juspay/connector-service/pull/467)) ([`7d09a51`](https://github.com/juspay/connector-service/commit/7d09a51b911f52d217487e9d2f1589b06aeef764))

### Refactors

- **connector:** [redsys] skip serializing fields that are `none` and sort fields in alphabetical order ([#468](https://github.com/juspay/connector-service/pull/468)) ([`2facec5`](https://github.com/juspay/connector-service/commit/2facec50889530a4ab11ab0e83f8056e63dabed9))

### Miscellaneous Tasks

- [Auth.net] Response field made optional ([#469](https://github.com/juspay/connector-service/pull/469)) ([`88bc959`](https://github.com/juspay/connector-service/commit/88bc9597d7a209a2f708f3075c11a0cc5dc9e97c))

**Full Changelog:** [`2026.02.03.0...2026.02.04.0`](https://github.com/juspay/connector-service/compare/2026.02.03.0...2026.02.04.0)

- - -

## 2026.02.03.0

### Features

- **framework:** Added redirection_data field in PSync response and test_mode field in PSync request ([#456](https://github.com/juspay/connector-service/pull/456)) ([`0e0a463`](https://github.com/juspay/connector-service/commit/0e0a4630b19d53ecb592f87dec071f3fdbe9836f))

### Bug Fixes

- Adyen webhook fix ([#462](https://github.com/juspay/connector-service/pull/462)) ([`d1a28bf`](https://github.com/juspay/connector-service/commit/d1a28bfe75ac219f7a3e5558c3b60fb67a64a5b0))

**Full Changelog:** [`2026.02.02.0...2026.02.03.0`](https://github.com/juspay/connector-service/compare/2026.02.02.0...2026.02.03.0)

- - -

## 2026.02.02.0

### Bug Fixes

- **connector:**
  - Map `Ds_State` to status in Redsys PSync when `Ds_Response` is absent ([#464](https://github.com/juspay/connector-service/pull/464)) ([`b71ee3a`](https://github.com/juspay/connector-service/commit/b71ee3ac9bc911bb54ecdbdfbca86f2d86367b3c))
  - Rapyd amount type in request ([#466](https://github.com/juspay/connector-service/pull/466)) ([`e6cae8e`](https://github.com/juspay/connector-service/commit/e6cae8e0bdb46bb5dc018fd2774f4ef2346328cb))
- **payload:** Do not pass `content-type` header in sync calls ([#465](https://github.com/juspay/connector-service/pull/465)) ([`995cbe5`](https://github.com/juspay/connector-service/commit/995cbe5375698368c5923b570749cba8bc55195b))

**Full Changelog:** [`2026.01.30.0...2026.02.02.0`](https://github.com/juspay/connector-service/compare/2026.01.30.0...2026.02.02.0)

- - -

## 2026.01.30.0

### Features

- Noon repeateverything flow implementation ([#450](https://github.com/juspay/connector-service/pull/450)) ([`23ae5ac`](https://github.com/juspay/connector-service/commit/23ae5acea8cfb1f1d35517dc95b7da8d101df5b9))

### Bug Fixes

- [CYBERSOURCE] PSYNC DIFF FIX ([#452](https://github.com/juspay/connector-service/pull/452)) ([`b6e66c2`](https://github.com/juspay/connector-service/commit/b6e66c24964b8af52f4f383ca7d619bf574030a7))
- Trustpay refund fix ([#459](https://github.com/juspay/connector-service/pull/459)) ([`7ef7bd0`](https://github.com/juspay/connector-service/commit/7ef7bd0a68273c6c363c99d535324821a3404f93))
- Paypal missing redirect_uri logic in form_fields for 3DS flow ([#453](https://github.com/juspay/connector-service/pull/453)) ([`bd68518`](https://github.com/juspay/connector-service/commit/bd6851817556e7e0d53c602635dc52b20fc08ec4))

**Full Changelog:** [`2026.01.29.0...2026.01.30.0`](https://github.com/juspay/connector-service/compare/2026.01.29.0...2026.01.30.0)

- - -

## 2026.01.29.0

### Miscellaneous Tasks

- Populate connector response field in error response ([#454](https://github.com/juspay/connector-service/pull/454)) ([`1abde2f`](https://github.com/juspay/connector-service/commit/1abde2fb6dd203fc7b0cf5b2b184ce1c0d964e37))

**Full Changelog:** [`2026.01.28.0...2026.01.29.0`](https://github.com/juspay/connector-service/compare/2026.01.28.0...2026.01.29.0)

- - -

## 2026.01.28.0

### Refactors

- Use proper error mapping instead of hardcoded connector_errors for Authorize ([#451](https://github.com/juspay/connector-service/pull/451)) ([`d4b22fb`](https://github.com/juspay/connector-service/commit/d4b22fb551053090231a67a474574202e7f9d5c8))

**Full Changelog:** [`2026.01.27.0...2026.01.28.0`](https://github.com/juspay/connector-service/compare/2026.01.27.0...2026.01.28.0)

- - -

## 2026.01.27.0

### Refactors

- **connector:** Add url safe base64 decoding support ([#447](https://github.com/juspay/connector-service/pull/447)) ([`3936c46`](https://github.com/juspay/connector-service/commit/3936c4636c95f3dcc08d75c0ad09657500f9cb5e))

**Full Changelog:** [`2026.01.26.0...2026.01.27.0`](https://github.com/juspay/connector-service/compare/2026.01.26.0...2026.01.27.0)

- - -

## 2026.01.26.0

### Features

- Disable gzip decompression in test mode ([#444](https://github.com/juspay/connector-service/pull/444)) ([`e2718db`](https://github.com/juspay/connector-service/commit/e2718dbc55d3c61f5acba713f3ad9dfcf5b91121))

**Full Changelog:** [`2026.01.23.0...2026.01.26.0`](https://github.com/juspay/connector-service/compare/2026.01.23.0...2026.01.26.0)

- - -

## 2026.01.23.0

### Features

- **connector:** [MOLLIE] Connector Integration ([#351](https://github.com/juspay/connector-service/pull/351)) ([`996c206`](https://github.com/juspay/connector-service/commit/996c206a6d7ba3c552b20c2a60c2cad7382a33b8))

**Full Changelog:** [`2026.01.22.0...2026.01.23.0`](https://github.com/juspay/connector-service/compare/2026.01.22.0...2026.01.23.0)

- - -

## 2026.01.22.0

### Features

- **connector:**
  - Braintree Card 3DS PaymentMethod ([#433](https://github.com/juspay/connector-service/pull/433)) ([`c5d2a1a`](https://github.com/juspay/connector-service/commit/c5d2a1a0c336b80899514bd1a8681eda0d9d83ef))
  - [redsys] integrate 3ds card, refund, void, capture ([#309](https://github.com/juspay/connector-service/pull/309)) ([`322985c`](https://github.com/juspay/connector-service/commit/322985c518b61470042c1eaa2537748d559741fb))

### Bug Fixes

- Diff fix for adyen and paypal repeat payments ([#434](https://github.com/juspay/connector-service/pull/434)) ([`38448d9`](https://github.com/juspay/connector-service/commit/38448d94435e44ed91a37d2eca36e0b777752ac9))

### Miscellaneous Tasks

- Proto code owners ([#438](https://github.com/juspay/connector-service/pull/438)) ([`25b68fe`](https://github.com/juspay/connector-service/commit/25b68fe65a6d681cfb6b2cd0b0831d2d585106f0))

**Full Changelog:** [`2026.01.21.0...2026.01.22.0`](https://github.com/juspay/connector-service/compare/2026.01.21.0...2026.01.22.0)

- - -

## 2026.01.21.0

### Features

- **connector:**
  - [Adyen] Implement Bank debits ([#421](https://github.com/juspay/connector-service/pull/421)) ([`0d3bc38`](https://github.com/juspay/connector-service/commit/0d3bc38022474571a45e8c259b940be421b2b1be))
  - [NovalNet] Implement Bank Debits ([#432](https://github.com/juspay/connector-service/pull/432)) ([`8aa92fa`](https://github.com/juspay/connector-service/commit/8aa92faa01a4cc14ac27ece85b4c78f21c4b9b2e))
  - [ADYEN] card redirect Integration ([#419](https://github.com/juspay/connector-service/pull/419)) ([`6b41d6a`](https://github.com/juspay/connector-service/commit/6b41d6a3a7fc93f92cb08d14c3a3d40319ce69dd))
- Add bank transfer support in adyen ([#420](https://github.com/juspay/connector-service/pull/420)) ([`d3cc4fe`](https://github.com/juspay/connector-service/commit/d3cc4fe1330311118d230a866f59d0a3638c404d))

### Bug Fixes

- Add secondary base url for Fiuu ([#435](https://github.com/juspay/connector-service/pull/435)) ([`0895852`](https://github.com/juspay/connector-service/commit/0895852c024b85036dda553c23b29f2dfd0164c3))

**Full Changelog:** [`2026.01.19.0...2026.01.21.0`](https://github.com/juspay/connector-service/compare/2026.01.19.0...2026.01.21.0)

- - -

## 2026.01.19.0

### Features

- **connector:** Refactored Cybersource Mandate Payments ([#426](https://github.com/juspay/connector-service/pull/426)) ([`488a70a`](https://github.com/juspay/connector-service/commit/488a70a294eb9c33c83c85e7ab897e3553299842))

### Bug Fixes

- RouterData diff fix for Fiuu PSync ([#427](https://github.com/juspay/connector-service/pull/427)) ([`e48db9a`](https://github.com/juspay/connector-service/commit/e48db9ae2f44c28d06ee04f7548e0c648681bdd7))

**Full Changelog:** [`2026.01.15.0...2026.01.19.0`](https://github.com/juspay/connector-service/compare/2026.01.15.0...2026.01.19.0)

- - -

## 2026.01.15.0

### Features

- **wellsfargo:** Connector integration ([#252](https://github.com/juspay/connector-service/pull/252)) ([`4794eff`](https://github.com/juspay/connector-service/commit/4794effbfde7f3cb4ca3a3356e1ff874a837677f))

**Full Changelog:** [`2026.01.14.1...2026.01.15.0`](https://github.com/juspay/connector-service/compare/2026.01.14.1...2026.01.15.0)

- - -

## 2026.01.14.1

### Bug Fixes

- RouterData diff fix for Novalnet & Cashtocode ([#424](https://github.com/juspay/connector-service/pull/424)) ([`3795371`](https://github.com/juspay/connector-service/commit/379537121aca364ece9b2d55421772c5927ea11c))

**Full Changelog:** [`2026.01.14.0...2026.01.14.1`](https://github.com/juspay/connector-service/compare/2026.01.14.0...2026.01.14.1)

- - -

## 2026.01.14.0

### Features

- **core:** Changed Metadata Type to SecretString ([#382](https://github.com/juspay/connector-service/pull/382)) ([`4c315ff`](https://github.com/juspay/connector-service/commit/4c315ff38101b12ce25849424b80d94835946e26))

**Full Changelog:** [`2026.01.13.2...2026.01.14.0`](https://github.com/juspay/connector-service/compare/2026.01.13.2...2026.01.14.0)

- - -

## 2026.01.13.2

### Bug Fixes

- Adyen shoppername to none for bankredirect, repeatpayment ([#423](https://github.com/juspay/connector-service/pull/423)) ([`938d6f2`](https://github.com/juspay/connector-service/commit/938d6f2b9d0e5f76a5dec2320e4b35f455c61633))

**Full Changelog:** [`2026.01.13.1...2026.01.13.2`](https://github.com/juspay/connector-service/compare/2026.01.13.1...2026.01.13.2)

- - -

## 2026.01.13.1

### Bug Fixes

- RepeatPayment Merchant configured Currency Handling ([#422](https://github.com/juspay/connector-service/pull/422)) ([`4cef8ef`](https://github.com/juspay/connector-service/commit/4cef8ef84ede9adac78eac27c557d161af36f306))

**Full Changelog:** [`2026.01.13.0...2026.01.13.1`](https://github.com/juspay/connector-service/compare/2026.01.13.0...2026.01.13.1)

- - -

## 2026.01.13.0

### Features

- **connector:** [GETNETGLOBAL] Connector Integration ([#381](https://github.com/juspay/connector-service/pull/381)) ([`a648f45`](https://github.com/juspay/connector-service/commit/a648f45d93309a083c90f59f73d4f2f5a95effb1))

**Full Changelog:** [`2026.01.12.1...2026.01.13.0`](https://github.com/juspay/connector-service/compare/2026.01.12.1...2026.01.13.0)

- - -

## 2026.01.12.1

### Bug Fixes

- **connector:** Fix Razorpay metadata to accept all values ([#418](https://github.com/juspay/connector-service/pull/418)) ([`4006a76`](https://github.com/juspay/connector-service/commit/4006a76b00ada9e9038a57a49a97f09e3ac9c4ce))

**Full Changelog:** [`2026.01.12.0...2026.01.12.1`](https://github.com/juspay/connector-service/compare/2026.01.12.0...2026.01.12.1)

- - -

## 2026.01.12.0

### Features

- **connector:** [Fiuu] Added RepeatPayment flow ([#414](https://github.com/juspay/connector-service/pull/414)) ([`b2f72d1`](https://github.com/juspay/connector-service/commit/b2f72d1e25d011dbb959a7d728e0ea57ed5a30ab))
- **core:** MandateRevoke flow ([#214](https://github.com/juspay/connector-service/pull/214)) ([`b251e1a`](https://github.com/juspay/connector-service/commit/b251e1a490b472a896c26d85d416afd471ba5a9d))
- **framework:** Added IncrementalAuthorization Flow support ([#410](https://github.com/juspay/connector-service/pull/410)) ([`be2fd45`](https://github.com/juspay/connector-service/commit/be2fd45b013ea6e04c2a58cfbbda028d6a71e19e))
- Added Network-level error details in proto ([#417](https://github.com/juspay/connector-service/pull/417)) ([`772548a`](https://github.com/juspay/connector-service/commit/772548a7d4139906ec1abc4b45a4549f91d8c777))

### Bug Fixes

- Resolved RouterData diffs in Prod for Authorizedotnet ([#413](https://github.com/juspay/connector-service/pull/413)) ([`8d2fcb8`](https://github.com/juspay/connector-service/commit/8d2fcb8baea8b0ab59636d4d02c51a1d9fe061ff))

**Full Changelog:** [`2026.01.09.0...2026.01.12.0`](https://github.com/juspay/connector-service/compare/2026.01.09.0...2026.01.12.0)

- - -

## 2026.01.09.0

### Features

- Add granular Claude rules for connector integration ([#365](https://github.com/juspay/connector-service/pull/365)) ([`144e5f2`](https://github.com/juspay/connector-service/commit/144e5f257bcf39ba7c5e0ca95cceb48b871ee37d))

### Bug Fixes

- Added Capture Method in Cybersource Repeat Payment Response ([#415](https://github.com/juspay/connector-service/pull/415)) ([`e67b4cc`](https://github.com/juspay/connector-service/commit/e67b4cc37a1fd7604865f4229f469e37e7960a49))
- CavvAlgorithm in proto missing field ([#416](https://github.com/juspay/connector-service/pull/416)) ([`4c40835`](https://github.com/juspay/connector-service/commit/4c408357ae80d7c0fd868ed9cc920fccb23dfc88))

**Full Changelog:** [`2026.01.08.0...2026.01.09.0`](https://github.com/juspay/connector-service/compare/2026.01.08.0...2026.01.09.0)

- - -

## 2026.01.08.0

### Features

- **connector:**
  - Braintree RepeatPayment Flow ([#399](https://github.com/juspay/connector-service/pull/399)) ([`27992ee`](https://github.com/juspay/connector-service/commit/27992eed49578cb2bbe413d63664ee88ffc3f113))
  - [GIGADAT] Connector Integration ([#408](https://github.com/juspay/connector-service/pull/408)) ([`2d2fba5`](https://github.com/juspay/connector-service/commit/2d2fba54408355ad1cbff6b46a3e591106c73652))
- Repeatpayment, nti flow for adyen ([#405](https://github.com/juspay/connector-service/pull/405)) ([`9df9321`](https://github.com/juspay/connector-service/commit/9df9321e23cb2d1735312ae32ed8a9f9ffd42b51))

### Bug Fixes

- Remove the parallel execution of test in Run test ([#412](https://github.com/juspay/connector-service/pull/412)) ([`50b72a1`](https://github.com/juspay/connector-service/commit/50b72a1db4cc6f21b6c05f459e8ed1a54577204a))
- Remove unused field ([#411](https://github.com/juspay/connector-service/pull/411)) ([`ffd9846`](https://github.com/juspay/connector-service/commit/ffd984675d93281d5f7613d1c952186a36fa92f8))

**Full Changelog:** [`2026.01.05.0...2026.01.08.0`](https://github.com/juspay/connector-service/compare/2026.01.05.0...2026.01.08.0)

- - -

## 2026.01.05.0

### Features

- **connector:**
  - Trustpay Bank Transfer & Bank Redirect Payment Method ([#406](https://github.com/juspay/connector-service/pull/406)) ([`e8a2708`](https://github.com/juspay/connector-service/commit/e8a270876fd29a6cf6e5a65f07de5f906bb4a1a1))
  - [PAYBOX] Connector Integration ([#387](https://github.com/juspay/connector-service/pull/387)) ([`70b74d8`](https://github.com/juspay/connector-service/commit/70b74d8412aa594771e8722f48b76ff38b9a8ba9))
  - [LOONIO] Connector Integration ([#401](https://github.com/juspay/connector-service/pull/401)) ([`62ee8c0`](https://github.com/juspay/connector-service/commit/62ee8c0092c5a3656e601ea3b675b52adfb56fb3))
- Adyen bankredirect payment method ([#400](https://github.com/juspay/connector-service/pull/400)) ([`bff3e26`](https://github.com/juspay/connector-service/commit/bff3e26bca3fb35d64f601cf3a8825a2f819b1b1))

### Refactors

- Refactor config override functionality ([#385](https://github.com/juspay/connector-service/pull/385)) ([`047fb05`](https://github.com/juspay/connector-service/commit/047fb05929cb1584100bf597a1eb511850192eca))

**Full Changelog:** [`2026.01.01.0...2026.01.05.0`](https://github.com/juspay/connector-service/compare/2026.01.01.0...2026.01.05.0)

- - -

## 2026.01.01.0

### Bug Fixes

- Adyen url on non test mode for authorize,void,etc ([#402](https://github.com/juspay/connector-service/pull/402)) ([`e1a2e3c`](https://github.com/juspay/connector-service/commit/e1a2e3c4e2655a73859c38c9f42dee4097a8c493))

**Full Changelog:** [`2025.12.31.0...2026.01.01.0`](https://github.com/juspay/connector-service/compare/2025.12.31.0...2026.01.01.0)

- - -

## 2025.12.31.0

### Features

- **connector:** [PAYPAL] Bank-Redirect ([#397](https://github.com/juspay/connector-service/pull/397)) ([`83c945f`](https://github.com/juspay/connector-service/commit/83c945fe302493e8d268895bcb3313254721b19c))
- **core:** Add connector_order_reference_id for Psync ([#395](https://github.com/juspay/connector-service/pull/395)) ([`3dcfd30`](https://github.com/juspay/connector-service/commit/3dcfd30ef1405c81ba711c370397cabba277e854))

**Full Changelog:** [`2025.12.30.0...2025.12.31.0`](https://github.com/juspay/connector-service/compare/2025.12.30.0...2025.12.31.0)

- - -

## 2025.12.30.0

### Features

- **connector:**
  - [AIRWALLEX] Bank-Redirect ([#388](https://github.com/juspay/connector-service/pull/388)) ([`7e26d93`](https://github.com/juspay/connector-service/commit/7e26d9325acff64c11a9194c91b420f6295ab83e))
  - [GLOBALPAY] Bank-Redirect ([#393](https://github.com/juspay/connector-service/pull/393)) ([`be59b37`](https://github.com/juspay/connector-service/commit/be59b3715966ee8282c19510c720c5c34bac5210))
  - Refactor Calida ([#394](https://github.com/juspay/connector-service/pull/394)) ([`625d71f`](https://github.com/juspay/connector-service/commit/625d71f81a7d269e14047461f16a278f53601468))

**Full Changelog:** [`2025.12.25.0...2025.12.30.0`](https://github.com/juspay/connector-service/compare/2025.12.25.0...2025.12.30.0)

- - -

## 2025.12.25.0

### Features

- **core:** Add support for NetworkTokenWithNTI and NetworkMandateId in RepeatPayment ([#389](https://github.com/juspay/connector-service/pull/389)) ([`a910df2`](https://github.com/juspay/connector-service/commit/a910df283e18aa625070dc9aea6cd31d83f7167e))

### Bug Fixes

- Diff check fixes for Dlocal ([#390](https://github.com/juspay/connector-service/pull/390)) ([`241cd4e`](https://github.com/juspay/connector-service/commit/241cd4e49d8b8094176eb10db91ddaa0d2f7f098))

### Refactors

- Made mandatory fields in authorize flow optional ([#386](https://github.com/juspay/connector-service/pull/386)) ([`ab2c078`](https://github.com/juspay/connector-service/commit/ab2c078e434d7b28bc63969dbd6ac9c3c37d498d))

**Full Changelog:** [`2025.12.24.0...2025.12.25.0`](https://github.com/juspay/connector-service/compare/2025.12.24.0...2025.12.25.0)

- - -

## 2025.12.24.0

### Features

- **connector:**
  - Revolut Connector Integration ([#328](https://github.com/juspay/connector-service/pull/328)) ([`212c6c4`](https://github.com/juspay/connector-service/commit/212c6c4697dfe37e5cd8ad52f35d55d770c732b1))
  - Revolut pay fix ([#391](https://github.com/juspay/connector-service/pull/391)) ([`768cac9`](https://github.com/juspay/connector-service/commit/768cac9a8284a91db2e808789b6386483b25633a))
- Added upi_source for cc/cl ([#368](https://github.com/juspay/connector-service/pull/368)) ([`6313849`](https://github.com/juspay/connector-service/commit/6313849618e5397e38960334fbf102f044c698ec))

**Full Changelog:** [`2025.12.23.0...2025.12.24.0`](https://github.com/juspay/connector-service/compare/2025.12.23.0...2025.12.24.0)

- - -

## 2025.12.23.0

### Features

- **connector:**
  - [SHIFT4] Bank-Redirect ([#383](https://github.com/juspay/connector-service/pull/383)) ([`042b281`](https://github.com/juspay/connector-service/commit/042b2815c6b219f418ba2e2fdd9478abb1aec2f3))
  - Jpmorgan ([#358](https://github.com/juspay/connector-service/pull/358)) ([`95358c3`](https://github.com/juspay/connector-service/commit/95358c33971ba82cd1558bc3d511a245a619a7c2))

**Full Changelog:** [`2025.12.19.0...2025.12.23.0`](https://github.com/juspay/connector-service/compare/2025.12.19.0...2025.12.23.0)

- - -

## 2025.12.19.0

### Features

- **connector:** [Stripe] Add Banktransfer, BNPL, BankRedirect PMs for stripe ([#371](https://github.com/juspay/connector-service/pull/371)) ([`24682d9`](https://github.com/juspay/connector-service/commit/24682d9e28b386f0ca9d45a30c230f7369397a95))

### Bug Fixes

- [WORLPAYVANTIV] Diff Checks ([#375](https://github.com/juspay/connector-service/pull/375)) ([`116c3b6`](https://github.com/juspay/connector-service/commit/116c3b6d4eccaee4364c0d44ebb8ffe169970f01))

**Full Changelog:** [`2025.12.18.0...2025.12.19.0`](https://github.com/juspay/connector-service/compare/2025.12.18.0...2025.12.19.0)

- - -

## 2025.12.18.0

### Features

- **connector:** [WORLDPAYXML] Connector Integration ([#361](https://github.com/juspay/connector-service/pull/361)) ([`8bb06fc`](https://github.com/juspay/connector-service/commit/8bb06fca660c530968a01d01442463354b9abf80))

### Bug Fixes

- **connector:** Paypal Capture & Void flow ([#376](https://github.com/juspay/connector-service/pull/376)) ([`b978b0e`](https://github.com/juspay/connector-service/commit/b978b0eac62ca98f291f70d4168e0ba1d62711cb))

**Full Changelog:** [`2025.12.17.0...2025.12.18.0`](https://github.com/juspay/connector-service/compare/2025.12.17.0...2025.12.18.0)

- - -

## 2025.12.17.0

### Features

- **connector:**
  - [TSYS] Connector Integration ([#347](https://github.com/juspay/connector-service/pull/347)) ([`549d00a`](https://github.com/juspay/connector-service/commit/549d00a820e8a564e666ccd905b0e7942575a0ab))
  - Refactored Volt connector and Refund & RSync flow implementation ([#362](https://github.com/juspay/connector-service/pull/362)) ([`e75ad17`](https://github.com/juspay/connector-service/commit/e75ad17ef5e6d181e378c47a0413f1450bcbfb6b))

### Bug Fixes

- **connector:** Fiserv RSync flow Diff fix ([#377](https://github.com/juspay/connector-service/pull/377)) ([`ddcf3c0`](https://github.com/juspay/connector-service/commit/ddcf3c092c813e1c982983fd6fb43c3319afec51))
- Correct mapping of metadata ([#367](https://github.com/juspay/connector-service/pull/367)) ([`0f0dd5f`](https://github.com/juspay/connector-service/commit/0f0dd5f23b19161f7ecef29f09d0022a3d86e3c6))
- Capture, Void, Refund Request ([#374](https://github.com/juspay/connector-service/pull/374)) ([`1b4c268`](https://github.com/juspay/connector-service/commit/1b4c2686c62cec0ee42e601b13663cc5b8b29134))
- Removed the authorization_indicator_type field from Authdotnet Req ([#372](https://github.com/juspay/connector-service/pull/372)) ([`a9bd19e`](https://github.com/juspay/connector-service/commit/a9bd19ebc7a475ab967710b2ecfd3acaf1b9e69c))

**Full Changelog:** [`2025.12.16.0...2025.12.17.0`](https://github.com/juspay/connector-service/compare/2025.12.16.0...2025.12.17.0)

- - -

## 2025.12.16.0

### Features

- **connector:**
  - [Checkout] Added Setupmandate & Repeatpayment flows for Checkout ([#366](https://github.com/juspay/connector-service/pull/366)) ([`54ea726`](https://github.com/juspay/connector-service/commit/54ea7265d715054101b56da85e4f76b200909679))
  - [PAYME] Connector Integration ([#364](https://github.com/juspay/connector-service/pull/364)) ([`8665908`](https://github.com/juspay/connector-service/commit/8665908b4be468052bc875f391ac4bdf99129fcd))

**Full Changelog:** [`2025.12.15.0...2025.12.16.0`](https://github.com/juspay/connector-service/compare/2025.12.15.0...2025.12.16.0)

- - -

## 2025.12.15.0

### Features

- Enable clippy for connector integration crate ([#359](https://github.com/juspay/connector-service/pull/359)) ([`a03dfc2`](https://github.com/juspay/connector-service/commit/a03dfc285aaaf33aa13182829cdcdc548e6f1a03))

### Bug Fixes

- **connector:** [bluesnap] pass `connector_request_ref_id` instead of `payment_id` ([#369](https://github.com/juspay/connector-service/pull/369)) ([`c814f81`](https://github.com/juspay/connector-service/commit/c814f81c517a8741be2a3099e7fdbf72831cb349))
- Diff check fixes for Xendit Authorize flow ([#357](https://github.com/juspay/connector-service/pull/357)) ([`82d3a1d`](https://github.com/juspay/connector-service/commit/82d3a1d9df95dddbb42de8cad18fb035a3fc8d5d))
- Adyen brand name lower case to match hyperswitch diff ([#356](https://github.com/juspay/connector-service/pull/356)) ([`286afff`](https://github.com/juspay/connector-service/commit/286afffd4de76427ba0216fdb496521aa319eb51))

**Full Changelog:** [`2025.12.12.0...2025.12.15.0`](https://github.com/juspay/connector-service/compare/2025.12.12.0...2025.12.15.0)

- - -

## 2025.12.12.0

### Features

- **connector:** [BAMBORA] Connector Integration ([#352](https://github.com/juspay/connector-service/pull/352)) ([`ca406f9`](https://github.com/juspay/connector-service/commit/ca406f94ba865a2552c5f429d31c688a4576636c))

**Full Changelog:** [`2025.12.11.1...2025.12.12.0`](https://github.com/juspay/connector-service/compare/2025.12.11.1...2025.12.12.0)

- - -

## 2025.12.11.1

### Bug Fixes

- **connector:** [paysafe] make payment method token calls work for authorizeonly flow ([#346](https://github.com/juspay/connector-service/pull/346)) ([`e2cb5b7`](https://github.com/juspay/connector-service/commit/e2cb5b7004642e6d2e784ac391981ea2f9851ec4))
- Status handling to use router_data.status during error case 2xx ([#363](https://github.com/juspay/connector-service/pull/363)) ([`350a6e4`](https://github.com/juspay/connector-service/commit/350a6e46d1ae5a9ebf631b11f10302025f8bbe3a))

**Full Changelog:** [`2025.12.11.0...2025.12.11.1`](https://github.com/juspay/connector-service/compare/2025.12.11.0...2025.12.11.1)

- - -

## 2025.12.11.0

### Features

- Setupmandate and repeat payment flow for paypal ([#355](https://github.com/juspay/connector-service/pull/355)) ([`3930b82`](https://github.com/juspay/connector-service/commit/3930b827af6483d6a46daafe89051a231e8c9d24))

**Full Changelog:** [`2025.12.10.1...2025.12.11.0`](https://github.com/juspay/connector-service/compare/2025.12.10.1...2025.12.11.0)

- - -

## 2025.12.10.1

### Features

- **connector:** Nexinets void flow & PSync, Capture, Refund, RSyns diff check fix ([#354](https://github.com/juspay/connector-service/pull/354)) ([`9315320`](https://github.com/juspay/connector-service/commit/9315320027a14d098cab75ca243fcd0ee61833af))
- Paypal Threeds flow Added ([#350](https://github.com/juspay/connector-service/pull/350)) ([`30b5a8c`](https://github.com/juspay/connector-service/commit/30b5a8c7106778891cbb1a50a9d617da09c697a0))

### Bug Fixes

- Checkout Diff check fixes ([#340](https://github.com/juspay/connector-service/pull/340)) ([`22e1c1f`](https://github.com/juspay/connector-service/commit/22e1c1f7a0e4c71bb028d47f5e04bbac93236dc2))
- Removed extra ; in payments.proto file ([#360](https://github.com/juspay/connector-service/pull/360)) ([`350e9e0`](https://github.com/juspay/connector-service/commit/350e9e05044fcf2c5fb5991b5fedf66bf633cd25))

**Full Changelog:** [`2025.12.10.0...2025.12.10.1`](https://github.com/juspay/connector-service/compare/2025.12.10.0...2025.12.10.1)

- - -

## 2025.12.10.0

### Features

- **connector:**
  - Trustpay Refund & RSync flow ([#344](https://github.com/juspay/connector-service/pull/344)) ([`505dd74`](https://github.com/juspay/connector-service/commit/505dd74f0844af1af8b81d69a8bbdc1404e9510a))
  - Bankofamerica Connector Integration ([#319](https://github.com/juspay/connector-service/pull/319)) ([`96f74dc`](https://github.com/juspay/connector-service/commit/96f74dc93271ac487fd1326d97886c64c1d6bdde))
  - [Powertranz] Connector Integration ([#334](https://github.com/juspay/connector-service/pull/334)) ([`98c9b42`](https://github.com/juspay/connector-service/commit/98c9b42c4bc3dded29b9d8bb877715be6005a339))
- **framework:** Implemented Custom HTTP Integration Layer ([#329](https://github.com/juspay/connector-service/pull/329)) ([`afac8b1`](https://github.com/juspay/connector-service/commit/afac8b19c7481b9385ae63ef71b8f435e2fa526a))

### Bug Fixes

- Fixed metadata to accept all values in Authorize flow ([#353](https://github.com/juspay/connector-service/pull/353)) ([`d7db406`](https://github.com/juspay/connector-service/commit/d7db40696d7f5b463df0159856544e6c0d0e7ece))

**Full Changelog:** [`2025.12.09.0...2025.12.10.0`](https://github.com/juspay/connector-service/compare/2025.12.09.0...2025.12.10.0)

- - -

## 2025.12.09.0

### Features

- **connector:** [AIRWALLEX] Connector Integration ([#333](https://github.com/juspay/connector-service/pull/333)) ([`f43fbfd`](https://github.com/juspay/connector-service/commit/f43fbfdb01f6d3086e4ed7f258369daceaf86518))
- Paypal refund rsync flow ([#349](https://github.com/juspay/connector-service/pull/349)) ([`70cccb9`](https://github.com/juspay/connector-service/commit/70cccb931bccb2c7ab7c72eebecc98f86aad92e1))

**Full Changelog:** [`2025.12.08.0...2025.12.09.0`](https://github.com/juspay/connector-service/compare/2025.12.08.0...2025.12.09.0)

- - -

## 2025.12.08.0

### Features

- **connector:**
  - [NUVEI] Connector Integration ([#331](https://github.com/juspay/connector-service/pull/331)) ([`1591db7`](https://github.com/juspay/connector-service/commit/1591db7741666709af7a46d7da24b8303ee3e902))
  - Introduce barclaycard ([#339](https://github.com/juspay/connector-service/pull/339)) ([`8b72783`](https://github.com/juspay/connector-service/commit/8b72783b1dc23c03725fc2bf27e06d8bafa7347a))
- GooglePayThirdPartySdk, ApplePayThirdPartySdk, PaypalSdk wallet support for braintree ([#335](https://github.com/juspay/connector-service/pull/335)) ([`d1b0ed3`](https://github.com/juspay/connector-service/commit/d1b0ed30a67dd5c78927cc3203f3620ace7c6950))

### Bug Fixes

- Adyen prod diff check parity ([#345](https://github.com/juspay/connector-service/pull/345)) ([`c95ea4f`](https://github.com/juspay/connector-service/commit/c95ea4fc8da270beb2802d90fa3f32c2509fa398))
- Diff checker changes in hipay ([#330](https://github.com/juspay/connector-service/pull/330)) ([`2b25613`](https://github.com/juspay/connector-service/commit/2b256130c60318d3f2e79df7da819587f425d04f))

**Full Changelog:** [`2025.12.05.0...2025.12.08.0`](https://github.com/juspay/connector-service/compare/2025.12.05.0...2025.12.08.0)

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
