import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { frameworkViolations } from "../support/framework-contract.js";

function inspect(path: string, source: string) {
  const root = mkdtempSync(join(tmpdir(), "e2e-contract-"));
  try {
    mkdirSync(join(root, "otp"), { recursive: true });
    mkdirSync(join(root, "support/processors"), { recursive: true });
    writeFileSync(join(root, "support/otp-scenarios.ts"), "");
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), source);
    return frameworkViolations(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("a connector-specific spec or inline scenario assertion is rejected before execution", () => {
  assert.match(
    inspect("otp/example/card-no3ds/custom.spec.ts", "").join("\n"),
    /move the scenario into otp\/superset/,
  );
  const errors = inspect(
    "otp/superset/card-no3ds/custom.spec.ts",
    'import { test, expect } from "@playwright/test"; test("custom", async () => { expect(true).toBe(true); });',
  );
  assert.match(errors.join("\n"), /common runOtpScenario/);
});

test("overrides cannot perform I/O and processor adapters cannot invent assertions or attachments", () => {
  assert.match(
    inspect(
      "otp/example/card-no3ds/overrides.ts",
      'export const overrides = fetch("https://example.com");',
    ).join("\n"),
    /data transformations only/,
  );
  assert.match(
    inspect(
      "support/processors/example.ts",
      'import { expect } from "@playwright/test"; export function verify(info: any) { info.attach("custom", {}); expect(true).toBe(true); }',
    ).join("\n"),
    /shared runner|shared check\/report writer/,
  );
});

test("data overrides cannot hide custom execution hooks", () => {
  assert.match(
    inspect(
      "otp/example/card-no3ds/overrides.ts",
      "export const overrides = { payment: { prepare: () => null } };",
    ).join("\n"),
    /cannot contain execution callbacks/,
  );
});

test("fixture-only overrides and shared check construction stay valid", () => {
  assert.deepEqual(
    inspect(
      "otp/example/card-no3ds/overrides.ts",
      "export const overrides = { cases: { baseline: {} } };",
    ),
    [],
  );
  assert.deepEqual(
    inspect(
      "support/processors/example.ts",
      'import { equal, type Checks } from "../checks.js"; export function observed(): Checks { return { status: equal("succeeded", "succeeded") }; }',
    ),
    [],
  );
});
