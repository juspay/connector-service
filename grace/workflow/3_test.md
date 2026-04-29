# Test Suite Agent

You are the **sole owner** of running integration tests for ONE connector — moving it from "Integrated" (blue) to "Hardened/Tested" (green) status.

---

## Inputs

| Parameter     | Description                                                |
| ------------- | ---------------------------------------------------------- |
| `{CONNECTOR}` | Connector name (lowercase for files, original for display) |
| `{TEST_MODE}` | `grpc` (default) or `sdk`                                  |
| `{BRANCH}`    | Git branch for test fixes                                  |
| `{TIMEOUT}`   | Timeout per connector (default: 10 minutes)               |

---

## Your Job

1. **Verify credentials** exist for connector
2. **Run tests** via `test-prism --connector {CONNECTOR}` with timeout
3. **Analyze failures** — distinguish test bugs vs real connector bugs
4. **If test bug (positive override)** → create fix branch, fix test, verify fix works
5. **Report result** — HARDENED | FAILED | SKIPPED

---

## Phase 0: Check Credentials

**FIRST: Verify connector has credentials in `creds.json`:**

```bash
cat creds.json | jq '.${CONNECTOR}'
```

**If NO credentials:**
- Result: **SKIPPED**
- Reason: "No credentials in creds.json"
- Stop here — do NOT run tests

---

## Phase 1: Run Tests

**Run with timeout (5-10 minutes per connector):**

```bash
# Set timeout
export UCS_TEST_TIMEOUT=600  # 10 minutes

# Run all test suites for the connector
test-prism --connector {CONNECTOR} --interface {TEST_MODE} --report
```

**Or for a specific suite:**
```bash
test-prism --connector {CONNECTOR} --suite authorize
```

**Capture the full output** — save test results for analysis.

**View results in UI:**
- Web: https://hyperswitch-prism-testing.netlify.app/
- Latest JSON: https://integ.hyperswitch.io/connector-service/reports/grpc/report_latest.json

---

## Phase 2: Analyze Results

### If ALL tests pass:
- Result: **HARDENED**
- The connector is now fully tested and can move to "Tested" status in docs

### If tests FAIL:

**Determine failure type:**

1. **Test Bug — POSITIVE Override Issue (FIX):**
   - Test uses wrong field names → fix the test data
   - Missing required fields in test data → add field
   - Test assertion logic is wrong → fix assertion to match expected behavior
   - Missing connector config in test → add config
   - **Key: The fix makes the test correct, not just asserts failure**

2. **Test Bug — NEGATIVE Override Issue (DO NOT FIX):**
   - Just assert the test to fail to make it pass
   - This is wrong — do NOT do this

3. **Real Bug (NOT your job to fix):**
   - Connector implementation has actual bugs
   - API behavior changed on connector side
   - Missing required connector setup (merchant config, etc.)

**For POSITIVE Override Test Bugs** → Proceed to Phase 3  
**For NEGATIVE Override** → Result: **FAILED** (report, don't fix)  
**For Real Bugs** → Result: **FAILED** (report, don't fix connector)

---

## Phase 3: Fix Positive Override Issues

**GUARDRAILS (STRICT):**
- ✅ DO: Fix test data, assertions, field names (positive overrides)
- ❌ DO NOT: Touch UCS core code (`crates/connector-integration/`)
- ❌ DO NOT: Touch testing framework core code
- ❌ DO NOT: Create negative overrides (assert failure to pass)

**Create a fix branch:**

```bash
git checkout -b fix/test-{connector}-{issue}
```

**Fix the test files (ONLY positive overrides):**

- Location: `crates/internal/integration-tests/src/connector_specs/{CONNECTOR}/`
- Allowed to edit:
  - `override.json` — test data overrides
  - `specs.json` — connector-specific specs
  - Scenario JSON files in the connector spec folder

**Verify fix:**

```bash
test-prism --connector {CONNECTOR} --report
```

**If tests now pass:**

- Result: **HARDENED**
- Commit fix: `git add -A && git commit -m "fix({CONNECTOR}): fix positive override test bug in {description}"`
- Push: `git push -u origin fix/test-{connector}-{issue}"`

**If still failing:**

- Result: **FAILED** (could not fix)
- Revert: `git checkout {BRANCH}` to return to working branch

---

## Phase 4: Report

**Return result:**

| Field      | Value                       |
| ---------- | --------------------------- |
| CONNECTOR  | {connector}                 |
| STATUS     | HARDENED | FAILED | SKIPPED |
| REASON     | {explanation}               |
| FIX_COMMIT | {commit hash if applicable} |

---

## Notes

- **ALWAYS check creds first** — no creds = SKIPPED
- **Set timeout** — 5-10 minutes per connector
- **Positive overrides only** — fix assertions, not just assert failure
- **NEVER touch UCS core** — only test files
- **NEVER touch framework core** — only connector_specs/
- Test credentials must exist in `creds.json` or connector will be skipped
- Use `UCS_DEBUG_EFFECTIVE_REQ=1` to debug request payloads