import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { checkoutPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "direct-charge",
  description:
    "Confirm an inline platform direct charge with customer, billing, shipping, partner details, metadata, and an application fee.",
  verifies:
    "HS and the connected-account processor payment succeed; received amount, currency, description, metadata, and application fee match.",
  coverage: "regression",
  sequence: [
    "Resolve eligible sandbox connected account",
    "Create and confirm direct charge",
    "Retrieve terminal payment",
    "Verify UCS routing",
    "Read processor payment under connected account",
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
