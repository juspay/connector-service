# Changelog

All notable changes to Connector Service will be documented here.

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
