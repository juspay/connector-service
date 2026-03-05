# UCS Test Writing Pattern

Every connector suite should use the same test shape so reviewers can quickly see:

1. what request fields are overridden,
2. how the final request is built,
3. what assertions are expected from the response.

## Required structure

For each scenario-driven flow file (`authorize`, `capture`, `refund`, etc.), use:

- `enum <Flow>Scenario`
- `struct <Flow>Overrides`
- `struct <Flow>Expectation`
- `fn scenario_overrides(...) -> <Flow>Overrides`
- `fn scenario_expectation(...) -> <Flow>Expectation`
- `fn apply_overrides(...)` (if request fields need mutation)
- `fn assert_expectation(...)`
- `pub async fn execute(...)`

## Execution order inside `execute`

Inside `execute`, keep this order:

1. Resolve scenario config:
   - `let overrides = scenario_overrides(...)`
   - `let expectation = scenario_expectation(...)`
2. Build the request from base request + overrides.
3. Apply propagated flow context.
4. Call connector via executor.
5. Assert with `assert_expectation`.
6. Capture response context for next flow.

## Input variants

Tests should iterate `generated_input_variants()` to run the same scenario with multiple valid input variants.

Purpose:

- detect data-dependent issues,
- keep one readable scenario per test function,
- avoid hardcoding a single payload shape.

## Naming

- Test function names should describe connector + flow + scenario + expected outcome.
- Avoid referencing external project names in test names.
