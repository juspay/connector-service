# Hyperswitch → UCS card OTP test

Playwright API tests for fresh-card, No3DS one-time payments through **Hyperswitch → UCS → processor sandbox**.

Each case creates an isolated HS merchant, profile, connector account, and routing rule. It checks payment amounts, currency, authentication and mandate state, the recorded UCS gateway, and a processor transaction reference. Test retries are disabled.

## Coverage

| Connector     | Cases | Coverage                                                                                                                                                                                           |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stripe        |    12 | Separate and inline confirmation, publishable-key confirmation, customer/shipping/metadata/descriptor fields, billing-profile override, Connect direct charges, capture, void, full/partial refund |
| Adyen         |     9 | Automatic capture, merchant-supplied references, customer acceptance without future usage, AUD/EUR/GBP/CHF/SGD, capture/void/refund submissions                                                    |
| PayPal        |     8 | Automatic capture, publishable-key authorize/capture or void, USD/CAD/GBP/AUD, full/partial refund                                                                                                 |
| Authorize.net |     6 | Automatic capture, inline customer details, merchant-key and publishable-key capture/void                                                                                                          |
| Checkout      |     6 | Automatic capture, inline customer details, capture/void, full/partial refund                                                                                                                      |
| Cybersource   |     5 | Automatic capture, inline customer details, void, capture/refund submissions                                                                                                                       |

**Submission checks are distinct from terminal checks.** The five scenarios named `capture-submission`, `void-submission`, or `refund-submission` verify processor acceptance and saved references. They do not establish webhook/settlement completion. Terminal capture, cancellation, and refund scenarios require their final API status; a pending response does not satisfy those cases. Terminal Authorize.net refunds require a settled-payment fixture and are not covered. A forced retrieve can return a stored terminal result; it does not prove a new processor sync call occurred.

All payment operations use the HS API. Checks use HS responses, recorded UCS routing, and processor references. The framework does not make direct processor API calls. Connect direct-charge cases require an existing sandbox account through `STRIPE_CONNECTED_ACCOUNT_ID` or a payment override; accounts are not discovered or created.

## Local execution

Prerequisites: Node.js 22+, Git, Docker Compose v2.24.4+, and a sandbox credentials JSON file. Browser installation is unnecessary for this API test.

```sh
cd tests/e2e
npm ci
export CONNECTOR_AUTH_FILE_PATH='/absolute/path/to/creds.json'
npm run stack:up
npm test                           # All six connectors; all credentials required
# Or start with one connector:
# E2E_VARIANT=baseline npm test -- --grep @stripe
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
| `STRIPE_CONNECTED_ACCOUNT_ID` | Existing sandbox Connect account for direct-charge cases               |
| `E2E_VARIANT`                 | Optional named variant selection                                       |

To use an existing UCS, set `UCS_BASE_URL` before `stack:up`, for example `http://host.docker.internal:8000`. This is the gRPC origin, not the UCS HTTP API. A gRPC health probe checks it before HS starts. Use an HTTPS origin for TLS. External UCS is never started or stopped by the harness.

For an existing dedicated sandbox HS, configure UCS routing and set `HS_BASE_URL`, `HS_ADMIN_API_KEY`, and `HS_DATABASE_URL`, then skip `stack:up`.

An explicit `UCS_IMAGE` may refer to a local Docker image. Startup reuses that image when present and fetches missing base images normally.

For reproducible runs, select image digests/releases. `.runtime/versions.json` records selected images and the HS source revision. Test accounts remain in the dedicated database for debugging.

## Structure and extension

```text
tests/e2e/
  otp/
    superset/card-no3ds/
      baseline.spec.ts
      client-confirm.spec.ts
      manual-capture.spec.ts
      refund-full.spec.ts
      ...
      requests.ts
    <connector>/card-no3ds/
      config.ts
      requests.ts              # Optional complete connector requests
  framework/
    scenario.ts                # Scenario types and connector registration
    runner.ts                  # Shared payment lifecycle execution
    config.ts                  # Credentials and external configuration
    hyperswitch.ts             # HS API client and local database checks
    audit.ts                   # Existing masked UCS event attachments
    checks.ts                  # Shared expected/actual assertions and output
    report.ts                  # Scenario descriptions and summaries
    tests/                     # Offline tests for framework helpers
  scripts/
    stack.mjs                  # Docker stack startup and shutdown
    credentials.sh             # Optional external credential retrieval
  docker/
    ucs.Dockerfile             # UCS image with a gRPC readiness probe
  playwright.config.ts
  package.json
  package-lock.json
  tsconfig.json
  overrides.example.json
```

Each superset spec contains its explanation, expected behavior, request data, API sequence, and test declaration. Explanations also appear in the HTML report. Scenarios are defined once and expanded across connectors that enable them.

Connector `config.ts` files select supported cases and supply differences such as test cards, currencies, profile options, and metadata. An empty case configuration uses the shared scenario unchanged. `completion: "submission"` explicitly checks acceptance rather than terminal completion. Currency variants expand a shared scenario without copying execution code.

Add scenarios in `otp/superset/card-no3ds/` and enable them in applicable connector configs. Register new connectors in `framework/scenario.ts` and the UCS stack configuration. `npm run list` shows enabled connector/scenario combinations. `npm test -- --grep @stripe` selects Stripe; `npm test -- otp/superset/card-no3ds/manual-capture.spec.ts` runs capture across enabled connectors.

Complete request definitions do not inherit shared optional payment fields. Runtime identifiers and client secrets are obtained during execution.

Copy `overrides.example.json` to an ignored `overrides.local.json` and set `E2E_OVERRIDES_FILE`. Connector settings support credential-entry selection, connector metadata, profile flags, and payment fields. Variant settings override a named request shape without changing credentials.

The superset chooses the request data; a connector can replace it completely or supply field overrides. External connector settings and named variant overrides are then resolved by the shared configuration helper. Nested objects merge, arrays replace, and `null` clears a field. OTP guards reject future-usage, mandate, recurring-payment, wallet, and 3DS requests. Customer acceptance alone is allowed; the resulting payment must still have no future usage or mandate. Use sandbox test data.

## Shared execution and reporting

Scenario specs declare requests and expected behavior, then call `runOtpScenario`. Connector directories contain configuration and optional request builders. One shared runner performs payment lifecycles through HS.

`framework/checks.ts` defines comparisons once using `equal(expected, actual)` or `oneOf([allowed, states], actual)`. The framework uses those same definitions for assertions and JSON attachments, including failed comparisons. Missing observations appear as `<missing>` and do not pass as null. Use boolean matches for identifiers or sensitive free-form values; whole response objects cannot be check values. Existing masked UCS audit events are attached unchanged and separately from comparisons.

## Reports and checks

```sh
npm run check       # TypeScript validation
npm run test:unit   # Offline harness checks
npm run list        # Test discovery
npm test            # Live sandbox payment
```

`npm test` generates terminal results, HTML at `playwright-report/`, and JUnit XML at `test-results/results.xml`. Open HTML with `npx playwright show-report`. API traces, screenshots, and videos are disabled. For payment and refund API calls, matching masked UCS `GrpcRequest` and `ConnectorCall` events are attached unchanged as individual JSON files. Attachment names identify the API action, flow, and stage; matching uses the HS response request ID. All matching flows and repeated calls are retained in event-timestamp order (completion order, not guaranteed call-start order). Events are not re-masked or reduced by the test harness.

Audit collection reads only the structured `ucs_event` field from JSON container logs. It does not scrape message text. The UCS image must include that field; older images report evidence as unavailable. Missing IDs, unavailable Docker logs, and collection limits are recorded as report annotations, not empty audit attachments. Audit attachments contain no collector status or additional metadata. Named payment steps attach expected and actual status and field values. UCS routing checks show the observed gateway and recorded processor outcome. Event collection does not determine payment success. Raw container logs are never attached. These local reports can contain sandbox identifiers; keep them out of version control.

The managed stack enables JSON console logging at INFO. By default, collection discovers the single running `ucs` service in Compose project `ucs-e2e`. Set `UCS_LOG_CONTAINER` explicitly for another Docker container. Remote log backends are not collected by this helper.

Only card No3DS flows are covered. Browser/SDK interaction and callback-driven completion require additional tests. Type checks, unit tests, and discovery do not execute sandbox payments.
