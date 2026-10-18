# Hyperswitch → UCS card OTP tests

Playwright API tests exercise fresh-card, No3DS one-time payments through **Hyperswitch → UCS → processor sandbox**. They use our own sandbox credentials per connector. Production traffic patterns inform which lifecycles and request differences matter; committed tests contain no customer inventory, customer credentials, account identifiers, or production payment data.

The first cut has one baseline suite per connector: Adyen, Cybersource, Stripe, PayPal, Authorize.net, and Checkout. Equivalent merchant payment behaviors share a scenario. Additional synthetic request variants target only their relevant lifecycle, rather than repeating every test for each merchant.

## Coverage

| Scenario          | Sequence and assertions                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------ |
| Automatic capture | Create → confirm → forced payment sync; succeeded status and captured amount                                 |
| Manual capture    | Create → confirm → sync; authorized/capturable amount → capture → sync; succeeded status and captured amount |
| Void              | Authorize → sync → cancel → sync; cancelled status and zero capturable amount                                |
| Refund            | Capture → full refund → refund sync; succeeded refund with matching amount/payment                           |

**Adyen exception:** UCS does not implement Adyen refund sync. Its test is named `automatic-refund-submission`: it verifies refund submission is accepted (`pending` or `succeeded`) and reports this limit explicitly. It does not establish terminal refund completion, webhook handling, or RSync coverage. Payment sync still runs; connector preflight may intentionally preserve the current status without an external request.

There are 24 baseline scenarios plus six focused variants (30 discovered tests). Adyen variants cover GBP with request metadata/manual capture, and EUR/CHF/AUD/HKD with automatic capture. Stripe adds a descriptor variant. These are synthetic request shapes, not a claim of exact production parity. Sandbox accounts may require account-specific configuration or currency support; failures need investigation rather than silent skipping.

Each scenario creates an isolated HS test merchant, business profile, MCA and routing rule using the same connector sandbox credentials. The payment's recorded gateway in HS PostgreSQL must equal `unified_connector_service`; native HS connector execution cannot pass this check. Capture, void, sync and refund calls follow that isolated payment. Retries are disabled to avoid automatically resubmitting financial operations.

## Why Playwright

This cut uses Playwright Test's HTTP API client, assertions, polling, filtering, and reporters. It makes normal HTTP calls to HS. No browser is launched and no Web SDK is exercised yet. Later browser scenarios can use Playwright's `page` fixture and reuse the backend setup/evidence helpers.

## Local execution

Prerequisites: Node.js 22+, Docker Compose v2, a reachable UCS gRPC server, and our existing HS sandbox `creds.json`. Browser installation is unnecessary for API-only tests. Use dedicated sandbox services; do not point the harness at production.

```sh
cd e2etests
npm ci
export CONNECTOR_AUTH_FILE_PATH=/absolute/private/path/to/creds.json

# Optional download/decryption of the existing HS sandbox credential file.
# Configure AWS credentials/region through the normal environment/profile.
export CONNECTOR_CREDS_S3_BUCKET_URI='s3://YOUR_PRIVATE_BUCKET'
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

Run connectors in this order for the first validation pass: Adyen, Cybersource, Stripe, PayPal, Authorize.net, Checkout. Filesystem order is not treated as a deployment priority: run each connector explicitly or select a subset using Playwright path filtering.

`stack:up` reuses HS main's Compose dependencies, config, superposition seed, and migrations. It starts the router image and its dependencies, without compiling HS. It forces the six connectors into `ucs_only_connectors`. Tests create `ucs_enabled=true` when absent and fail if an existing value disables UCS.

Default upstream host ports are 8080 (HS), 5432 (PostgreSQL), 6379 (Redis), and 8081 (Superposition); existing services may conflict. For an existing dedicated sandbox HS instance, configure UCS routing and set `HS_BASE_URL`, `HS_ADMIN_API_KEY`, and `HS_DATABASE_URL`, then skip `stack:up`.

| Variable                   | Purpose/default                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------- |
| `HS_IMAGE`                 | `docker.juspay.io/juspaydotin/hyperswitch-router:latest`                                 |
| `HS_REF`                   | `main`; initial config/migrations checkout                                               |
| `HS_SOURCE_DIR`            | Optional existing HS checkout                                                            |
| `UCS_BASE_URL`             | Container-to-UCS gRPC endpoint; `http://host.docker.internal:8000`                       |
| `HS_BASE_URL`              | Runner-to-HS API endpoint; `http://localhost:8080`                                       |
| `HS_ADMIN_API_KEY`         | Local config default `test_admin`                                                        |
| `HS_DATABASE_URL`          | `postgresql://db_user:db_pass@localhost:5432/hyperswitch_db`                             |
| `CONNECTOR_AUTH_FILE_PATH` | Private HS sandbox credentials JSON; accepts `CYPRESS_CONNECTOR_AUTH_FILE_PATH` fallback |
| `E2E_VARIANT`              | Optional synthetic variant ID such as `baseline`                                         |
| `E2E_OVERRIDES_FILE`       | Optional private JSON file for our sandbox configuration                                 |

For reproducibility, use an HS image digest/release and matching source revision. Floating `latest` and `main` may drift. `.runtime/versions.json` records the requested image, UCS endpoint and config checkout commit. The checkout is retained between runs; update it or supply `HS_SOURCE_DIR` when changing versions. Accounts remain in the test database for debugging; `stack:down` preserves volumes.

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
    cases.ts                 # Lifecycle selection and explicit verification limits
    otp-scenarios.ts         # Shared sandbox setup and payment assertions
    config.ts                # Private credentials and small configuration patches
    hs.ts                    # HS HTTP client and database gateway verification
  scripts/                   # Docker setup and private credential download
  unit/                      # Offline harness checks; no processor calls
  playwright.config.ts
```

Add a distinct request shape to the relevant connector's `variants.ts`, select the lifecycle(s) needed, and call `otpSuite(connector, variants)` from its spec. Use public connector API fields and synthetic data. Keep real customer identities, mappings, credentials, tokens, payment IDs and production request samples outside the repository. CIT/MIT, wallets, 3DS, SDK/browser flows and nightly Jenkins wiring are later extensions.

`overrides.example.json` demonstrates the optional private configuration file. Copy it to an ignored `overrides.local.json`, replace placeholders with our sandbox account settings, and set `E2E_OVERRIDES_FILE`. The format has:

- `connectors.<connector>`: our sandbox account's `credential` selector, connector metadata, business-profile flags and common payment fields.
- `variants.<connector>/<synthetic-variant>`: request metadata/currency or configuration differences for that variant. Variants cannot select credentials.

Resolution: shared sandbox defaults → external connector settings → built-in request variant → external variant patch. Nested objects merge, arrays replace, and `null` clears a field. Connector metadata starts with metadata from our selected credential entry. Credentials themselves always come from the private credential file. Guards reject mandate/setup fields, wallet/3DS changes, and the old merchant-inventory format.

## Reports and validation limits

```sh
npm run check       # TypeScript only; no payment verification
npm run test:unit   # Offline tests of the harness only
npm run list        # Discover scenarios only
npm test            # Live HS → UCS → processor sandbox tests
```

`npm test` automatically generates terminal results, HTML at `playwright-report/`, and JUnit XML at `test-results/results.xml`. Reports identify the connector, request variant and lifecycle, with an explicit annotation for live sandbox execution and the Adyen refund coverage limit. Passing tests attach gateway evidence without payment IDs, account identifiers, credential values, or raw requests/responses. API traces, screenshots and videos are disabled. Keep runtime reports private; do not commit or publish them automatically.

A passing typecheck, offline test, or discovered scenario does not establish that a payment passed. Before treating this suite as deployment evidence, actually run the selected sandbox lifecycles against the UCS build being deployed and review failures and explicit coverage limits. Immediate refunds may need processor settlement; pending refunds do not pass the terminal verification cases. There is no Jenkins trigger in this PR.
