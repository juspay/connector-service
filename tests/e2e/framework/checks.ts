import { expect, type TestInfo } from "@playwright/test";

type Value = string | number | boolean | null;
export type Check = Readonly<{
  expected: Value | readonly Value[];
  actual: Value | undefined;
}>;
export type Checks = Readonly<Record<string, Check>>;
type Report = Pick<TestInfo, "attach">;

function scalar(value: unknown): Value | undefined {
  if (
    value === undefined ||
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  )
    return value;
  throw new Error(
    "Checks require scalar observations; use a boolean match for structured or sensitive fields",
  );
}

export function equal(expected: Value, actual: unknown): Check {
  if (scalar(expected) === undefined)
    throw new Error("A check requires an explicit expected value");
  return { expected, actual: scalar(actual) };
}

export function oneOf(
  expected: readonly [Value, ...Value[]],
  actual: unknown,
): Check {
  if (!expected.length || expected.some((value) => scalar(value) === undefined))
    throw new Error("Allowed-state checks require explicit expected values");
  return { expected, actual: scalar(actual) };
}

export function assertChecks(checks: Checks, group = "Checks") {
  if (!Object.keys(checks).length)
    throw new Error("A verification group must contain checks");
  for (const [field, check] of Object.entries(checks)) {
    const assertion = expect(check.actual, `${group}: ${field}`);
    if (Array.isArray(check.expected))
      expect(check.expected, `${group}: ${field}`).toContain(check.actual);
    else assertion.toEqual(check.expected);
  }
}

// The same definitions drive assertions and report output, including failure evidence.
export async function recordChecks(
  report: Report,
  name: string,
  checks: Checks,
) {
  const evidence = Object.fromEntries(
    Object.entries(checks).map(([field, check]) => [
      field,
      {
        expected: check.expected,
        actual: check.actual === undefined ? "<missing>" : check.actual,
      },
    ]),
  );
  await report.attach(name, {
    body: JSON.stringify(evidence, null, 2),
    contentType: "application/json",
  });
}

export async function verifyChecks(
  report: Report,
  name: string,
  checks: Checks,
) {
  try {
    assertChecks(checks, name);
  } finally {
    await recordChecks(report, name, checks);
  }
}
