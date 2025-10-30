# Changelog

All notable changes to Connector Service will be documented here.

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
