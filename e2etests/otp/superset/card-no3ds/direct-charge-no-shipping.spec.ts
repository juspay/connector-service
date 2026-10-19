import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { checkoutPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "direct-charge-no-shipping",
  description:
    "Confirm a platform direct charge with shipping explicitly null.",
  verifies:
    "HS and the connected-account processor payment succeed with the expected amount, currency, metadata, and application fee.",
  coverage: "regression",
  sequence: [
    "Resolve eligible sandbox connected account",
    "Create direct charge without shipping",
    "Retrieve terminal payment",
    "Verify UCS routing and processor payment",
  ],
  request: checkoutPayment(),
  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
