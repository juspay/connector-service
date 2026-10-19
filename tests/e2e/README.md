# End-to-end tests

This directory reserves the structure for end-to-end payment tests.

```text
tests/
  e2e/
    otp/
      superset/
        card-no3ds/
      <connector>/
        card-no3ds/
    support/
    scripts/
    docker/
```

- `otp/superset/<variant>/`: shared one-time payment scenarios. Each scenario will describe its request sequence and expected behavior once, for reuse across connectors.
- `otp/<connector>/<variant>/`: connector request/configuration overrides and supported scenario settings. Connector directories do not duplicate scenario implementations.
- `support/`: shared fixtures, API clients, and assertions.
- `scripts/`: setup and execution helpers.
- `docker/`: container configuration for the test environment.

For example, a manual-capture scenario belongs in `otp/superset/card-no3ds/`. A connector can supply its sandbox card or metadata and specify whether capture verifies submission acceptance or terminal completion. Adding another connector reuses the superset through overrides; adding another OTP scenario extends the superset once.

Additional payment flows can be added beside `otp/`. The `.gitkeep` files preserve empty directories. Test implementation and runner configuration will follow separately.
