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
  fixture?: "stripe-connect" | "merchant-reference";
  clientConfirmation?: boolean;
  payment?: Json;
  request?: Json;
  confirmRequest?: Json;
  description?: string;
  verifies?: string;
  sequence?: readonly string[];
  coverage?: "reference-pattern" | "regression";
  connectorMetadata?: Json;
  profile?: Json;
  scenarios: readonly [Scenario];
};

export type OtpScenario = RequestVariant & {
  description: string;
  verifies: string;
  sequence: readonly string[];
  coverage: "reference-pattern" | "regression";
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
  | "coverage"
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
