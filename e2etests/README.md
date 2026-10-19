# Hyperswitch → UCS card OTP tests

Playwright API tests for No3DS card one-time payments through **Hyperswitch → UCS → processor sandbox**. Supported connectors: Adyen, Cybersource, Stripe, PayPal, Authorize.net, and Checkout.

## Coverage

| Scenario          | Sequence and assertions                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------ |
| Automatic capture | Create → confirm → forced payment sync; succeeded status and captured amount                                 |
| Manual capture    | Create → confirm → sync; authorized/capturable amount → capture → sync; succeeded status and captured amount |
| Void              | Authorize → sync → cancel → sync; cancelled status and zero capturable amount                                |
| Refund            | Capture → full refund → refund sync; succeeded refund with matching amount/payment                           |

**Adyen exception:** UCS does not implement Adyen refund sync. Its test is named `automatic-refund-submission`: it verifies refund submission is accepted (`pending` or `succeeded`) and reports this limit explicitly. It does not establish terminal refund completion, webhook handling, or RSync coverage. Payment sync still runs; connector preflight may intentionally preserve the current status without an external request.

The suite includes 24 baseline scenarios and six request variants. Adyen variants cover GBP with metadata/manual capture and EUR, CHF, AUD, and HKD with automatic capture. Stripe includes a statement-descriptor variant. The configured sandbox account must support the selected currencies and features.

Each scenario creates an isolated HS merchant, business profile, connector account, and routing rule. Tests verify payment amounts/statuses and check that the recorded gateway in PostgreSQL is `unified_connector_service`. Test retries are disabled.

## Local execution

Prerequisites: Node.js 22+, Docker Compose v2, a reachable UCS gRPC server, and a sandbox credentials JSON file in the HS connector-credentials format. Browser installation is unnecessary for API-only tests. Use dedicated sandbox services; do not point the harness at production.

```sh
cd e2etests
npm ci
export CONNECTOR_AUTH_FILE_PATH=/absolute/path/to/creds.json

# Alternatively, download an encrypted credentials file from S3.
# Configure AWS credentials/region through the normal environment/profile.
export CONNECTOR_CREDS_S3_BUCKET_URI='s3://YOUR_BUCKET'
export S3_SOURCE_FILE_NAME='YOUR_ENCRYPTED_CREDENTIALS_FILE.json.gpg'
# Supply CONNECTOR_AUTH_PASSPHRASE through your secret manager/environment.
npm run credentials
export CONNECTOR_AUTH_FILE_PATH="$PWD/.secrets/creds.json"

export UCS_BASE_URL=http://host.docker.internal:8000
npm run stack:up

# One automatic-capture smoke case, then baseline lifecycles, then variants.
E2E_VARIANT=baseline npm test -- otp/adyen --grep '^.*automatic @'
E2E_VARIANT=baseline npm test -- otp/adyen
npm test -- otp/adyen
npm test -- otp/cybersource
npm test -- otp/stripe
npm test
npm run stack:down
```

Use Playwright path filtering to select a connector, or `E2E_VARIANT` to select a request variant.

`stack:up` reads the router image's source revision and downloads the matching Compose dependencies, config, superposition seed, and migrations. Only runtime asset directories are checked out and cached; HS source is not compiled. It starts the router image and its dependencies. It forces the six connectors into `ucs_only_connectors`. Tests create `ucs_enabled=true` when absent and fail if an existing value disables UCS.

Default upstream host ports are 8080 (HS), 5432 (PostgreSQL), and 8081 (Superposition); existing services may conflict. Redis is available only inside the Compose network. For an existing dedicated sandbox HS instance, configure UCS routing and set `HS_BASE_URL`, `HS_ADMIN_API_KEY`, and `HS_DATABASE_URL`, then skip `stack:up`.

| Variable                   | Purpose/default                                                               |
| -------------------------- | ----------------------------------------------------------------------------- |
| `HS_IMAGE`                 | `docker.juspay.io/juspaydotin/hyperswitch-router:latest`                      |
| `HS_REF`                   | Image-reported source revision; optional explicit matching revision                                    |
| `HS_SOURCE_DIR`            | Optional existing matching HS checkout                                                 |
| `UCS_BASE_URL`             | Container-to-UCS gRPC endpoint; `http://host.docker.internal:8000`            |
| `HS_BASE_URL`              | Runner-to-HS API endpoint; `http://localhost:8080`                            |
| `HS_ADMIN_API_KEY`         | Local config default `test_admin`                                             |
| `HS_DATABASE_URL`          | `postgresql://db_user:db_pass@localhost:5432/hyperswitch_db`                  |
| `CONNECTOR_AUTH_FILE_PATH` | Sandbox credentials JSON; accepts `CYPRESS_CONNECTOR_AUTH_FILE_PATH` fallback |
| `E2E_VARIANT`              | Optional request variant ID such as `baseline`                                |
| `E2E_OVERRIDES_FILE`       | Optional JSON file with sandbox configuration overrides                       |

For reproducibility, use an HS image digest/release. By default, configuration and migrations follow the source revision reported by that image. `HS_REF` or `HS_SOURCE_DIR` can explicitly select matching runtime assets for custom builds. `.runtime/versions.json` records the requested image, UCS endpoint, and config checkout commit. Runtime assets are cached by source revision. Accounts remain in the test database for debugging; `stack:down` preserves volumes.

## Structure and extension

```text
e2etests/
  otp/
    adyen/card-no3ds/
      payment.spec.ts
      variants.ts
    stripe/card-no3ds/
      payment.spec.ts
      variants.ts
    cybersource/card-no3ds/payment.spec.ts
    paypal/card-no3ds/payment.spec.ts
    authorizedotnet/card-no3ds/payment.spec.ts
    checkout/card-no3ds/payment.spec.ts
  support/
    cases.ts                 # Lifecycle definitions and verification modes
    otp-scenarios.ts         # Shared sandbox setup and payment assertions
    config.ts                # Credential loading and configuration overrides
    hs.ts                    # HS HTTP client and database gateway verification
  scripts/                   # Docker setup and credential download
  unit/                      # Offline harness checks; no processor calls
  playwright.config.ts
```

Add request variants in the connector's `variants.ts`, select the applicable lifecycles, and pass them to `otpSuite(connector, variants)` in its spec. Use synthetic test data.

Copy `overrides.example.json` to an ignored `overrides.local.json`, configure the sandbox account, and set `E2E_OVERRIDES_FILE`:

- `connectors.<connector>`: credential-entry selector, connector metadata, business-profile flags, and common payment fields.
- `variants.<connector>/<variant>`: payment/configuration overrides for a named request variant. Credentials are selected at connector level.

Resolution order: shared defaults → connector settings → built-in request variant → variant overrides. Nested objects merge, arrays replace, and `null` clears a field. Connector metadata also inherits values from the selected credential entry. OTP guards reject mandate/setup fields and wallet/3DS requests.

Keep credential files and environment-specific overrides out of version control.

## Reports and checks

```sh
npm run check       # TypeScript only; no payment verification
npm run test:unit   # Offline tests of the harness only
npm run list        # Discover scenarios only
npm test            # Live HS → UCS → processor sandbox tests
```

`npm test` generates terminal results, an HTML report at `playwright-report/`, and JUnit XML at `test-results/results.xml`. Reports include the connector, variant, lifecycle, and verification mode. Gateway evidence excludes credentials and raw API payloads. API traces, screenshots, and videos are disabled.

Open the HTML report with:

```sh
npx playwright show-report
```

Type checks, unit tests, and test discovery do not execute sandbox payments. Run `npm test` against the target UCS build to validate payment behavior. Refund completion may depend on processor settlement; pending refunds do not satisfy tests that require a terminal result.
