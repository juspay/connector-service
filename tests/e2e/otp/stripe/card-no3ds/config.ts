import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
  cases: {
    baseline: {},
    "billing-profile": {},
    "refund-full": {},
    "refund-partial": {},
    "manual-capture": {},
    "manual-void": {},
    "client-confirm": {},
    "inline-confirm": {},
    "checkout-details": {},
    "direct-charge": {},
    "direct-charge-details": {},
    "direct-charge-no-shipping": {},
  },
};
