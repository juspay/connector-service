import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { checkoutPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "direct-charge",
  description:
    "Confirm an inline platform direct charge with customer, billing, shipping, partner details, metadata, and an application fee.",
  verifies:
    "The HS direct-charge payment succeeds with matching amount and currency, UCS routing, and a recorded processor reference.",

  sequence: [
    "Resolve eligible sandbox connected account",
    "Create and confirm direct charge",
    "Retrieve terminal payment",
    "Verify UCS routing",
    "Verify payment fields and UCS routing",
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
