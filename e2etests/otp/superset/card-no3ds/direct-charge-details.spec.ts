import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { checkoutPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "direct-charge-details",
  description:
    "Confirm an inline platform direct charge with contact fields, descriptor, fraud metadata, shipping, partner details, and an application fee.",
  verifies:
    "HS and the processor succeed; description, descriptor, metadata, received amount, currency, and application fee match.",
  coverage: "regression",
  sequence: [
    "Resolve eligible sandbox connected account",
    "Create and confirm direct charge",
    "Retrieve terminal payment",
    "Verify UCS routing",
    "Verify processor fields and application fee",
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
