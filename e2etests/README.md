# Hyperswitch → UCS card OTP test

Playwright API tests for fresh-card, No3DS one-time payments through **Hyperswitch → UCS → processor sandbox**.

Each case creates an isolated HS merchant, profile, connector account, and routing rule. It checks payment amounts, currency, authentication and mandate state, the recorded UCS gateway, and a processor transaction reference. Test retries are disabled.

## Coverage

| Connector     | Cases | Coverage                                                                                                                                                                                           |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stripe        |    11 | Separate and inline confirmation, publishable-key confirmation, customer/shipping/metadata/descriptor fields, billing-profile override, Connect direct charges, capture, void, full/partial refund |
| Adyen         |     9 | Automatic capture, merchant-supplied references, customer acceptance without future usage, AUD/EUR/GBP/CHF/SGD, capture/void/refund submissions                                                    |
| PayPal        |     8 | Automatic capture, publishable-key authorize/capture or void, USD/CAD/GBP/AUD, full/partial refund                                                                                                 |
| Authorize.net |     6 | Automatic capture, inline customer details, merchant-key and publishable-key capture/void                                                                                                          |
| Checkout      |     6 | Automatic capture, inline customer details, capture/void, full/partial refund                                                                                                                      |
| Cybersource   |     5 | Automatic capture, inline customer details, void, capture/refund submissions                                                                                                                       |

**Submission checks are distinct from terminal checks.** The five scenarios named `capture-submission`, `void-submission`, or `refund-submission` verify processor acceptance and saved references. They do not establish webhook/settlement completion. Terminal capture, cancellation, and refund scenarios require their final API status; a pending response does not satisfy those cases. Terminal Authorize.net refunds require a settled-payment fixture and are not covered. A forced retrieve can return a stored terminal result; it does not prove a new processor sync call occurred.

Stripe cases additionally read back PaymentIntents, PaymentMethods, or charges to verify amount/currency, metadata/descriptor, billing-profile forwarding, Connect application fees, and refunded amounts where applicable. These are read-only processor checks. Connect cases select an existing charge-enabled sandbox account; set `STRIPE_CONNECTED_ACCOUNT_ID` to select one explicitly. The platform test key must allow the corresponding account and payment reads. Accounts are never created by the fixture helper.

## Local execution

Prerequisites: Node.js 22+, Git, Docker Compose v2.24.4+, and a sandbox credentials JSON file. Browser installation is unnecessary for this API test.

```sh
cd e2etests
npm ci
export CONNECTOR_AUTH_FILE_PATH='/absolute/path/to/creds.json'
npm run stack:up
npm test                           # All six connectors; all credentials required
# Or start with one connector:
# E2E_VARIANT=baseline npm test -- otp/stripe
npx playwright show-report
npm run stack:down
```

The credentials reader accepts direct connector entries or named entries such as `stripe.connector_1`. This example contains only Stripe; add entries for every connector being run:

```json
{
  "stripe": {
    "connector_account_details": {
      "auth_type": "HeaderKey",
      "api_key": "YOUR_STRIPE_SANDBOX_KEY"
    }
  }
}
```

For credentials stored encrypted in S3, configure AWS authentication through the normal environment/profile and run:

```sh
export CONNECTOR_CREDS_S3_BUCKET_URI='s3://YOUR_BUCKET'
export S3_SOURCE_FILE_NAME='YOUR_ENCRYPTED_CREDENTIALS_FILE.json.gpg'
# Supply CONNECTOR_AUTH_PASSPHRASE through your secret manager/environment.
npm run credentials
export CONNECTOR_AUTH_FILE_PATH="$PWD/.secrets/creds.json"
```

Keep credentials and environment-specific overrides out of version control.

## Stack configuration

`stack:up` starts UCS from `juspaydotin/hyperswitch-prism:latest` on Docker Hub. A small image wrapper adds the standard gRPC health probe; no Rust build is performed. HS starts only after UCS reports `SERVING` through `grpc.health.v1.Health/Check`.

HS runs from `docker.juspay.io/juspaydotin/hyperswitch-router:latest`. Its configuration, migrations, and Compose dependencies come from the source revision reported by that image. Only runtime asset directories are downloaded and cached. Configuration changes automatically recreate HS.

All six connectors are routed through UCS. The test creates `ucs_enabled=true` when absent and fails if an existing value disables UCS. Default host ports are 8080 (HS), 15432 (PostgreSQL), and 8081 (Superposition). UCS and Redis are available only inside the Compose network. Existing services may conflict with published ports. `stack:down` preserves the test database volume.

| Variable                      | Purpose/default                                                        |
| ----------------------------- | ---------------------------------------------------------------------- |
| `HS_IMAGE`                    | `docker.juspay.io/juspaydotin/hyperswitch-router:latest`               |
| `UCS_IMAGE`                   | `juspaydotin/hyperswitch-prism:latest`                                 |
| `HS_REF`                      | Optional explicit matching HS source revision                          |
| `HS_SOURCE_DIR`               | Optional existing matching HS checkout                                 |
| `UCS_BASE_URL`                | Optional external gRPC origin reachable from Docker; skips managed UCS |
| `HS_BASE_URL`                 | Runner-to-HS endpoint; `http://localhost:8080`                         |
| `HS_ADMIN_API_KEY`            | `test_admin`                                                           |
| `HS_DB_PORT`                  | E2E PostgreSQL host port; `15432`                                      |
| `HS_DATABASE_URL`             | `postgresql://db_user:db_pass@127.0.0.1:15432/hyperswitch_db`          |
| `CONNECTOR_AUTH_FILE_PATH`    | Credentials JSON; `CYPRESS_CONNECTOR_AUTH_FILE_PATH` also accepted     |
| `E2E_OVERRIDES_FILE`          | Optional local configuration overrides                                 |
| `STRIPE_CONNECTED_ACCOUNT_ID` | Optional existing sandbox Connect account                              |
| `E2E_VARIANT`                 | Optional named variant selection                                       |

To use an existing UCS, set `UCS_BASE_URL` before `stack:up`, for example `http://host.docker.internal:8000`. This is the gRPC origin, not the UCS HTTP API. A gRPC health probe checks it before HS starts. Use an HTTPS origin for TLS. External UCS is never started or stopped by the harness.

For an existing dedicated sandbox HS, configure UCS routing and set `HS_BASE_URL`, `HS_ADMIN_API_KEY`, and `HS_DATABASE_URL`, then skip `stack:up`.

For reproducible runs, select image digests/releases. `.runtime/versions.json` records selected images and the HS source revision. Test accounts remain in the dedicated database for debugging.

## Structure and extension

```text
e2etests/
  otp/<connector>/card-no3ds/
    payment.spec.ts
    variants.ts
  support/
    cases.ts
    otp-scenarios.ts
    config.ts
    hs.ts
  docker/ucs.Dockerfile
  scripts/
  unit/
  playwright.config.ts
```

Add request variants in `variants.ts` and pass them to `otpSuite` from the connector spec. Add connector directories under `otp/<connector>/<variant>/` and extend the connector registry, card fixtures, and UCS connector configuration when adding support.

Copy `overrides.example.json` to an ignored `overrides.local.json` and set `E2E_OVERRIDES_FILE`. Connector settings support credential-entry selection, connector metadata, profile flags, and payment fields. Variant settings override a named request shape without changing credentials.

Resolution order: shared defaults → connector settings → built-in variant → variant overrides. Nested objects merge, arrays replace, and `null` clears a field. OTP guards reject future-usage, mandate, recurring-payment, wallet, and 3DS requests. Customer acceptance alone is allowed; the resulting payment must still have no future usage or mandate. Use synthetic fixture data.

## Reports and checks

```sh
npm run check       # TypeScript validation
npm run test:unit   # Offline harness checks
npm run list        # Test discovery
npm test            # Live sandbox payment
```

`npm test` generates terminal results, HTML at `playwright-report/`, and JUnit XML at `test-results/results.xml`. Open HTML with `npx playwright show-report`. Reports omit credential values and raw API payloads; API traces, screenshots, and videos are disabled.

Only card No3DS flows are covered. Browser/SDK interaction and callback-driven completion require additional tests. Type checks, unit tests, and discovery do not execute sandbox payments.
