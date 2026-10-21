# End-to-end tests

This directory reserves the structure for end-to-end payment tests. The layout shows the planned files; this PR adds directories and documentation only.

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

- `otp/superset/<variant>/` defines shared scenarios once, including the request sequence and expected behavior. Each explanation appears alongside its test declaration.
- `otp/<connector>/<variant>/config.ts` supplies request differences and explicit scenario exclusions with reasons. Complete request definitions live in the shared superset `requests.ts`. Connector directories do not duplicate test execution.
- `framework/` supplies typed scenarios, connector registration, one lifecycle runner, HS access, audit collection, and shared assertion/report helpers. `hyperswitch.ts` makes HS API calls and reads local HS database records for UCS routing and processor-reference checks.
- `framework/tests/` checks shared helpers without starting the payment stack.
- `scripts/` operates the Docker stack and retrieves external credentials when configured.
- `docker/` contains the UCS image wrapper that adds the gRPC health probe used before HS starts.

A manual-capture scenario belongs in `otp/superset/card-no3ds/`. All applicable connectors run it by default and supply only differences. Adding a connector reuses the superset; adding a scenario extends the superset once. Test discovery lists connector/scenario combinations; reports show explicit exclusions and unmet capabilities as skipped with reasons.

Further payment flows can be added beside `otp/`. The `.gitkeep` files preserve empty directories. Test implementation, dependencies, credentials, and CI configuration are outside this scaffold PR.
