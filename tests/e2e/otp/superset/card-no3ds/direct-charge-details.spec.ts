import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { connectDetailedPayment } from "./requests.js";

const scenario: OtpScenario = {
  requires: "stripe-connect",
  id: "direct-charge-details",
  description:
    "Confirm an inline platform direct charge with contact fields, descriptor, fraud metadata, shipping, partner details, and an application fee.",
  verifies:
    "The HS payment succeeds with the detailed direct-charge request, matching amount and currency, UCS routing, and a recorded processor reference.",

  sequence: [
    "Read configured sandbox connected account",
    "Create and confirm direct charge",
    "Retrieve terminal payment",
    "Verify UCS routing",
    "Verify payment fields and UCS routing",
  ],
  request: connectDetailedPayment(),
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
