import type { Overrides } from "../support/config.js";

// Generic synthetic examples of supported overrides; no customer mappings or production samples.
export const builtinOverrides: Record<string, Overrides> = {
  "fixture_org/adyen_profile_01/adyen": {
    payment: { currency: "GBP", metadata: { fixture_case: "order-metadata" } },
  },
  "fixture_org/adyen_profile_02/adyen": {
    paymentVariants: { eur: { currency: "EUR" }, chf: { currency: "CHF" } },
  },
  "fixture_org/adyen_profile_03/adyen": {
    payment: {
      currency: "HKD",
      metadata: { fixture_case: "currency-override" },
    },
  },
  "fixture_org/adyen_profile_04/adyen": {
    payment: {
      currency: "AUD",
      metadata: { fixture_case: "metadata-override" },
    },
  },
  "fixture_org/stripe_profile_01/stripe": {
    payment: { currency: "USD", statement_descriptor_suffix: "E2E" },
  },
};
