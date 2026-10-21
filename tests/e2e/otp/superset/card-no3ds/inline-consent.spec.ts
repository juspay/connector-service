import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "inline-consent",
  description:
    "Confirm inline with customer acceptance but no future usage or mandate setup.",
  verifies:
    "The payment succeeds without creating a mandate; supplied payment and order references are preserved.",

  sequence: [
    "Create and confirm payment",
    "Verify no mandate or future usage",
    "Verify payment and order references",
  ],
  request: {
    ...basicCardPayment(),
    confirm: true,
    customer: { name: "Test Buyer", email: "ucs-e2e@example.com" },
    customer_acceptance: {
      acceptance_type: "online",
      online: { ip_address: "192.0.2.1", user_agent: "Test browser" },
    },
    metadata: { fixture_case: "inline-consent" },
  },
  scenarios: ["automatic"],
};

for (const { connector, scenario: selected, skipReason } of otpSupersetCases(
  scenario,
)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      test.skip(!!skipReason, skipReason);
      await runOtpScenario(connector, selected, info);
    });
  });
}
