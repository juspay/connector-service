import type { RequestVariant } from "../../../support/cases.js";

export const variants: readonly RequestVariant[] = [
  {
    id: "descriptor",
    payment: { statement_descriptor_suffix: "E2E" },
    scenarios: ["automatic"],
  },
];
