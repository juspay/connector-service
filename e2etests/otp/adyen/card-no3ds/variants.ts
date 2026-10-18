import type { RequestVariant } from "../../../support/cases.js";

// Synthetic request shapes. These use our existing Adyen sandbox account.
export const variants: readonly RequestVariant[] = [
  {
    id: "gbp-metadata",
    payment: { currency: "GBP", metadata: { fixture_case: "order" } },
    scenarios: ["manual-capture"],
  },
  { id: "eur", payment: { currency: "EUR" }, scenarios: ["automatic"] },
  { id: "chf", payment: { currency: "CHF" }, scenarios: ["automatic"] },
  { id: "aud", payment: { currency: "AUD" }, scenarios: ["automatic"] },
  { id: "hkd", payment: { currency: "HKD" }, scenarios: ["automatic"] },
];
