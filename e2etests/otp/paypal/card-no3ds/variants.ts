import type { RequestVariant } from "../../../support/cases.js";

export const variants: readonly RequestVariant[] = [
  { id: "refund-full", scenarios: ["refund-full"] },
  { id: "refund-partial", scenarios: ["refund-partial"] },
  {
    id: "client-capture",
    clientConfirmation: true,
    scenarios: ["manual-capture"],
  },
  { id: "client-void", clientConfirmation: true, scenarios: ["manual-void"] },
  ...["CAD", "GBP", "AUD"].map((currency) => ({
    id: `client-capture-${currency.toLowerCase()}`,
    clientConfirmation: true,
    payment: { currency },
    scenarios: ["manual-capture"] as const,
  })),
];
