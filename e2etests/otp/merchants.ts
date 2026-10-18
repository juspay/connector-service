import type { Merchant } from "../support/config.js";

// Synthetic sandbox profiles only. Keep environment-specific inventories in private files.
const connectors = [
  "adyen",
  "stripe",
  "paypal",
  "authorizedotnet",
  "cybersource",
  "checkout",
] as const;

export const merchants: Merchant[] = connectors.flatMap((connector) =>
  Array.from({ length: 8 }, (_, index) => ({
    org: "fixture_org",
    merchant: `${connector}_profile_${String(index + 1).padStart(2, "0")}`,
    connector,
  })),
);
