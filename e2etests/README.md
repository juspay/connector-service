# Hyperswitch → UCS card OTP test

Playwright API tests for fresh-card, No3DS Stripe one-time payments through **Hyperswitch → UCS → Stripe sandbox**.

Each test creates an isolated HS merchant, profile, connector account, and routing rule, then creates a payment, confirms it with automatic capture, and forces payment sync. It requires `succeeded`, the expected amount/currency/connector, and a PostgreSQL gateway value of `unified_connector_service`, and a charged Stripe attempt with a processor transaction reference. Test retries are disabled.

## Stripe coverage

| Variant               | Behavior                                                                  |
| --------------------- | ------------------------------------------------------------------------- |
| `baseline`            | Create with a fresh card, then merchant-key confirmation                  |
| `client-confirm`      | Create without a card, then publishable-key/client-secret confirmation    |
| `inline-confirm`      | Create and confirm in one request                                         |
| `checkout-details`    | Inline payment with customer, billing, shipping, metadata, and descriptor |
| `connect-direct`      | Direct charge with a connected account and application fee                |
| `connect-no-shipping` | Direct charge with shipping omitted                                       |

Stripe PaymentIntents are read back using the sandbox key to verify amount/currency, metadata/descriptor, and application fee where applicable. These reads do not create or modify processor resources. Connect cases select an existing charge-enabled sandbox account; set `STRIPE_CONNECTED_ACCOUNT_ID` to select one explicitly. The key must allow the corresponding account and PaymentIntent reads. Accounts are never created by the fixture helper.

## Local execution

Prerequisites: Node.js 22+, Git, Docker Compose v2.24.4+, and a sandbox credentials JSON file. Browser installation is unnecessary for this API test.

```sh
cd e2etests
npm ci
export CONNECTOR_AUTH_FILE_PATH='/absolute/path/to/creds.json'
npm run stack:up
npm test
npx playwright show-report
npm run stack:down
```

The credentials reader accepts a direct connector entry or named entries such as `stripe.connector_1`:

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

Stripe is routed through UCS. The test creates `ucs_enabled=true` when absent and fails if an existing value disables UCS. Default host ports are 8080 (HS), 15432 (PostgreSQL), and 8081 (Superposition). UCS and Redis are available only inside the Compose network. Existing services may conflict with published ports. `stack:down` preserves the test database volume.

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
  otp/stripe/card-no3ds/
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

Add request variants in `variants.ts` and pass them to `otpSuite` from the connector spec. Add connector directories under `otp/<connector>/<variant>/` and extend the connector registry when adding support.

Copy `overrides.example.json` to an ignored `overrides.local.json` and set `E2E_OVERRIDES_FILE`. Connector settings support credential-entry selection, connector metadata, profile flags, and payment fields. Variant settings override a named request shape without changing credentials.

Resolution order: shared defaults → connector settings → built-in variant → variant overrides. Nested objects merge, arrays replace, and `null` clears a field. OTP guards reject mandate/setup fields, wallets, and 3DS requests. Use synthetic fixture data.

## Reports and checks

```sh
npm run check       # TypeScript validation
npm run test:unit   # Offline harness checks
npm run list        # Test discovery
npm test            # Live sandbox payment
```

`npm test` generates terminal results, HTML at `playwright-report/`, and JUnit XML at `test-results/results.xml`. Open HTML with `npx playwright show-report`. Reports omit credential values and raw API payloads; API traces, screenshots, and videos are disabled.

Stripe currently covers the six automatic-payment variants listed above. Additional lifecycles and connectors can be added separately. Type checks, unit tests, and discovery do not execute sandbox payments.
