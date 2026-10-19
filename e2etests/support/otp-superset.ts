import {
  connectors,
  type ConnectorScenarioConfig,
  type OtpScenario,
  type Scenario,
} from "./cases.js";
import { merge } from "./config.js";
import { overrides as adyen } from "../otp/adyen/card-no3ds/overrides.js";
import { overrides as paypal } from "../otp/paypal/card-no3ds/overrides.js";
import { overrides as authorizedotnet } from "../otp/authorizedotnet/card-no3ds/overrides.js";
import { overrides as cybersource } from "../otp/cybersource/card-no3ds/overrides.js";
import { overrides as checkout } from "../otp/checkout/card-no3ds/overrides.js";
import { overrides as stripe } from "../otp/stripe/card-no3ds/overrides.js";

const configurations: Record<
  (typeof connectors)[number],
  ConnectorScenarioConfig
> = {
  stripe,
  adyen,
  paypal,
  authorizedotnet,
  cybersource,
  checkout,
};

// A connector opts into shared cases and supplies only request/configuration differences.
export function otpSupersetCases(scenario: OtpScenario) {
  if (scenario.scenarios.length !== 1)
    throw new Error("Each superset spec must declare exactly one lifecycle");
  const cases: {
    connector: (typeof connectors)[number];
    scenario: OtpScenario;
  }[] = [];
  for (const connector of connectors) {
    const config = configurations[connector];
    const configured = config.cases[scenario.id];
    if (!configured) continue;
    const overrides = Array.isArray(configured) ? configured : [configured];
    for (const override of overrides) {
      const { completion, ...patch } = override;
      const lifecycle = scenario.scenarios[0];
      const submission: Partial<Record<Scenario, Scenario>> = {
        "manual-capture": "capture-submission",
        "manual-void": "void-submission",
        "refund-full": "refund-submission",
      };
      if (completion && !submission[lifecycle])
        throw new Error(
          `Submission verification is unsupported for ${scenario.id}`,
        );
      const selected: OtpScenario = {
        ...scenario,
        ...patch,
        id: patch.id ?? scenario.id,
        payment: merge(config.payment ?? {}, patch.payment),
        scenarios: completion ? [submission[lifecycle]!] : scenario.scenarios,
        ...(completion
          ? {
              verifies:
                "Authorization succeeds and the processor accepts the requested operation with a saved processor reference. Terminal completion is not asserted.",
            }
          : {}),
      };
      if (process.env.E2E_VARIANT && process.env.E2E_VARIANT !== selected.id)
        continue;
      if (completion)
        selected.sequence = [
          ...scenario.sequence.slice(0, lifecycle === "refund-full" ? -2 : -1),
          "Verify submission acceptance and processor reference",
        ];
      cases.push({ connector, scenario: selected });
    }
  }
  return cases;
}
