import type { Json } from "./config.js";

export const connectors = [
  "stripe",
  "adyen",
  "paypal",
  "authorizedotnet",
  "cybersource",
  "checkout",
] as const;
export type Connector = (typeof connectors)[number];
export const scenarios = [
  "automatic",
  "manual-capture",
  "manual-void",
  "refund-full",
  "refund-partial",
  "capture-submission",
  "void-submission",
  "refund-submission",
] as const;
export type Scenario = (typeof scenarios)[number];
export type RequestVariant = {
  id: string;
  fixture?: "merchant-reference";
  clientConfirmation?: boolean;
  payment?: Json;
  request?: Json;
  confirmRequest?: Json;
  description?: string;
  verifies?: string;
  sequence?: readonly string[];

  connectorMetadata?: Json;
  profile?: Json;
  scenarios: readonly [Scenario];
};

export type OtpScenario = RequestVariant & {
  description: string;
  verifies: string;
  sequence: readonly string[];

  request: Json;
};

export type ConnectorCaseOverride = Pick<
  RequestVariant,
  | "payment"
  | "request"
  | "confirmRequest"
  | "connectorMetadata"
  | "profile"
  | "fixture"
> & {
  id?: string;
  completion?: "submission";
};
export type ConnectorScenarioConfig = {
  payment?: Json;
  cases: Record<
    string,
    ConnectorCaseOverride | readonly ConnectorCaseOverride[]
  >;
};

import { merge } from "./config.js";

import { overrides as adyen } from "../otp/adyen/card-no3ds/config.js";
import { overrides as paypal } from "../otp/paypal/card-no3ds/config.js";
import { overrides as authorizedotnet } from "../otp/authorizedotnet/card-no3ds/config.js";
import { overrides as cybersource } from "../otp/cybersource/card-no3ds/config.js";
import { overrides as checkout } from "../otp/checkout/card-no3ds/config.js";
import { overrides as stripe } from "../otp/stripe/card-no3ds/config.js";

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
  if (!scenario.id || !/^[a-z][a-z0-9-]{0,47}$/.test(scenario.id))
    throw new Error("Each scenario requires a stable scenario identifier");
  if (
    ![scenario.description, scenario.verifies].every(
      (text) => typeof text === "string" && text.trim().length > 0,
    ) ||
    !Array.isArray(scenario.sequence) ||
    !scenario.sequence.length ||
    scenario.sequence.some((step) => typeof step !== "string" || !step.trim())
  )
    throw new Error(
      "Each scenario requires an explanation, verification intent, and nonempty sequence",
    );
  if (
    scenario.scenarios.length !== 1 ||
    !scenarios.includes(scenario.scenarios[0])
  )
    throw new Error(
      "Each superset spec must declare exactly one supported lifecycle",
    );
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
