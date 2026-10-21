import type { TestInfo } from "@playwright/test";
import type { Connector, OtpScenario } from "./scenario.js";

export async function reportScenario(info: TestInfo, scenario: OtpScenario) {
  info.annotations.push(
    { type: "Scenario", description: scenario.description },
    { type: "Verifies", description: scenario.verifies },
    { type: "execution", description: "live sandbox: HS → UCS → processor" },
  );
  if (scenario.scenarios[0].endsWith("submission"))
    info.annotations.push({
      type: "coverage-limit",
      description:
        "Processor submission is validated; terminal webhook/settlement completion is not checked",
    });
  await info.attach("Scenario and verification", {
    body: JSON.stringify(
      {
        scenario: scenario.description,
        verifies: scenario.verifies,
        sequence: scenario.sequence,
      },
      null,
      2,
    ),
    contentType: "application/json",
  });
}

export async function reportSummary(
  info: TestInfo,
  summary: {
    connector: Connector;
    scenario: string;
    outcome: string;
    verification: "submission-only" | "terminal";
    requestVariant: string;
  },
) {
  await info.attach("Test summary", {
    body: JSON.stringify(
      {
        ...summary,
        gateway: "unified_connector_service",
        processorReferenceVerified: true,
        fixture: "sandbox",
      },
      null,
      2,
    ),
    contentType: "application/json",
  });
}
