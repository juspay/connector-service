# End-to-end tests

This directory reserves the structure for end-to-end payment tests.

```text
tests/
  e2e/
    otp/
      <connector>/
        card-no3ds/
    support/
    scripts/
    docker/
    unit/
```

- `otp/<connector>/<variant>/`: one-time payment scenarios grouped by connector and request variant.
- `support/`: shared fixtures, API clients, and assertions.
- `scripts/`: setup and execution helpers.
- `docker/`: container configuration for the test environment.
- `unit/`: tests for the shared test helpers.

Additional payment flows can be added beside `otp/`. The `.gitkeep` files preserve empty directories. Test implementation and runner configuration will follow separately.
