import path from "node:path";
import { promises as fs } from "node:fs";
import type { Checkpoint, CodegenResult, L3Analysis } from "../types.js";
import { runAI } from "../tools/runner-factory.js";
import {
  CODEGEN_AGENT_SYSTEM,
  buildCodegenPayload,
} from "../generators/codegen-agent-prompt.js";

/**
 * Ensure tech spec is saved to disk for the Codegen Agent to read
 */
async function ensureTechSpecFile(
  projectRoot: string,
  connector: string,
  flow: string,
  specContent: string | undefined
): Promise<string> {
  const techSpecsDir = path.join(projectRoot, "techspecs");
  const specPath = path.join(techSpecsDir, `${connector}_${flow}_spec.md`);

  // Ensure directory exists
  await fs.mkdir(techSpecsDir, { recursive: true });

  // If we have specContent, write it to file
  if (specContent) {
    await fs.writeFile(specPath, specContent, "utf-8");
    return specPath;
  }

  // If file already exists, return its path
  try {
    await fs.access(specPath);
    return specPath;
  } catch {
    // File doesn't exist and no content provided
    throw new Error(`Tech spec not found at ${specPath} and no specContent provided`);
  }
}

/**
 * Implementation Checkpoint - Phase 5 ONLY from 2.3_codegen.md
 *
 * Implements connector flows by delegating to the Codegen Agent:
 * 1. Phase 4: Read & Analyze (including L3 spec)
 * 2. Phase 5: Implements the code (macros, TryFrom, RouterDataV2)
 *
 * NOTE: Build and test are handled by separate checkpoints.
 */
export const implementationCheckpoint: Checkpoint = {
  id: "implementation",
  name: "Implementation",
  description:
    "Implements the connector flow using 2.3_codegen.md Phase 5 ONLY.",
  retryFrom: "implementation",
  timeout: 30 * 60 * 1000, // 30 min (code writing only)

  async run(ctx) {
    const l3 = ctx.artifacts.l3 as L3Analysis | undefined;

    if (!l3) {
      return { passed: false, errors: ["Missing L3 analysis"] };
    }

    // Check for L3 specification
    if (!l3.specification) {
      return {
        passed: false,
        errors: ["L3 Analysis does not contain implementation specification. Run L3 Analysis first."]
      };
    }

    // Log specification summary
    ctx.log(`[implementation] Specification:`, "info");
    ctx.log(`  - Request struct: ${l3.specification.requestStruct.name}`, "info");
    ctx.log(`  - Response struct: ${l3.specification.responseStruct.name}`, "info");
    ctx.log(`  - Files to change: ${l3.specification.filesChangedPreview.length}`, "info");

    const task = ctx.artifacts.task;
    if (!task?.targetConnectors?.[0]) {
      return { passed: false, errors: ["Missing connector in task"] };
    }

    const connector = task.targetConnectors[0];
    const flow = task.paymentMethod || "Unknown";
    const projectRoot = task.projectRoot;
    const l2 = ctx.artifacts.l2;
    const l3SpecPath = ctx.artifacts.l3SpecPath as string | undefined;

    ctx.log("[implementation] ╔═══════════════════════════════════════════════════════════╗", "info");
    ctx.log("[implementation] ║  Implementation (2.3_codegen.md Phase 5 ONLY)           ║", "info");
    ctx.log("[implementation] ╚═══════════════════════════════════════════════════════════╝", "info");
    ctx.log(`[implementation] Connector: ${connector}`, "info");
    ctx.log(`[implementation] Flow: ${flow}`, "info");
    ctx.log(`[implementation] L3 Spec: ${l3SpecPath || "Not available"}`, "info");

    // Display L3 analysis summary
    ctx.log(`[implementation] Analysis: ${l3.analysis.patternsIdentified.length} patterns identified`, "info");
    ctx.log(`[implementation] Files to modify: ${l3.analysis.filesToModify.length}`, "info");

    // Log implementation type for clarity
    const implementationType = l3.implementationType || "new_flow";
    const parentFlow = l3.parentFlow;
    const paymentMethod = l3.paymentMethod;

    ctx.log(`[implementation] Implementation Type: ${implementationType}`, "info");

    if (implementationType === "payment_method_addition") {
      ctx.log(`[implementation]   Parent Flow: ${parentFlow}`, "info");
      ctx.log(`[implementation]   Payment Method: ${paymentMethod}`, "info");
      ctx.log(`[implementation]   Action: Extending PaymentInformation enum`, "info");
    } else if (implementationType === "new_flow") {
      ctx.log(`[implementation]   Action: Creating new flow structs`, "info");
    } else if (implementationType === "flow_completion") {
      ctx.log(`[implementation]   Action: Completing existing flow`, "info");
    }

    // Read L3 spec content if available
    let l3SpecContent = "";
    if (l3SpecPath) {
      try {
        l3SpecContent = await fs.readFile(l3SpecPath, 'utf-8');
        ctx.log("[implementation] Loaded L3 spec content", "info");
      } catch (err) {
        ctx.log(`[implementation] Warning: Could not read L3 spec: ${err}`, "warn");
      }
    }

    // Ensure tech spec is available on disk
    let techSpecPath: string;
    try {
      techSpecPath = await ensureTechSpecFile(
        projectRoot,
        connector,
        flow,
        l2?.specContent
      );
      ctx.log(`[implementation] Tech spec: ${techSpecPath}`, "info");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[implementation] Failed to locate tech spec: ${msg}`, "error");
      return {
        passed: false,
        errors: [`Tech spec not available: ${msg}`],
      };
    }

    // Read workflow file for Phase 5 restriction
    let workflowContent = "";
    try {
      const workflowPath = path.join(projectRoot, "grace/workflow/2.3_codegen.md");
      workflowContent = await fs.readFile(workflowPath, 'utf-8');
      ctx.log("[implementation] Loaded workflow file", "info");
    } catch (err) {
      ctx.log(`[implementation] Warning: Could not read workflow: ${err}`, "warn");
    }

    // Determine which implementation guidance to use
    const isPaymentMethodAddition = implementationType === "payment_method_addition";

    if (isPaymentMethodAddition) {
      ctx.log("[implementation] Using PAYMENT METHOD ADDITION system prompt", "info");
    }

    // Build custom system prompt with Phase 5 restriction
    const systemPrompt = `You are the Code Generation Agent.

## CRITICAL RESTRICTION - PHASE 5 ONLY
You are in IMPLEMENTATION-ONLY MODE.

**EXECUTE ONLY:**
- Phase 4: Read & Analyze
- Phase 5: Implement (write code)

**DO NOT EXECUTE:**
- Phase 6: Build & Test Loop - DO NOT run cargo build
- DO NOT start any services
- DO NOT run grpcurl tests

The Compiler Check checkpoint will handle building.
The gRPC Test checkpoint will handle testing.

You MUST stop after writing code. Do not attempt to build or test.

## OUTPUT FORMAT - STRICT JSON ONLY

After completing the implementation, return ONLY a valid JSON object. NO prose, NO markdown, NO explanations before or after the JSON.

The FIRST character of your response must be \\\{ and the LAST character must be \\\}.

Required JSON structure:
\\\`\\\`\\\`json
{
  "success": true,
  "connector": "${connector}",
  "flow": "${flow}",
  "buildIterations": 0,
  "grpcurlResult": "NOT_RUN",
  "filesModified": [
    "crates/integrations/connector-integration/src/connectors/${connector.toLowerCase()}/transformers.rs"
  ],
  "fixLog": [],
  "grpcurlOutput": "",
  "executionLog": {
    "phasesCompleted": ["5"],
    "commandsExecuted": [],
    "serverLogsChecked": false
  },
  "reason": "Implementation complete (Phase 5 only)"
}
\\\`\\\`\\\`

CRITICAL:
- Use EXACT field names shown above (camelCase)
- filesModified MUST include all files you edited
- success MUST be true if code was written successfully
- Return ONLY the JSON object - no other text

## L3 Analysis Data
${l3SpecContent ? `\n\`\`\`json\n${l3SpecContent}\n\`\`\`\n` : 'L3 spec not available'}

## Implementation Type Guidance

Current implementation type: ${implementationType}
${isPaymentMethodAddition ? `
## PAYMENT METHOD ADDITION - CRITICAL INSTRUCTIONS

You are implementing a PAYMENT METHOD ADDITION (not a new flow).

### What NOT to do:
- Do NOT create ${connector}${paymentMethod}Request struct
- Do NOT create ${connector}${paymentMethod}Response struct
- Do NOT add to create_all_prerequisites! macro as a new flow
- Do NOT add a new flow variant

### What TO do:
1. Find the PaymentInformation enum in transformers.rs
2. Add a new variant: ${paymentMethod}(Box<${paymentMethod}PaymentInformation>)
3. Create the ${paymentMethod}PaymentInformation struct with fields from the L3 spec
4. Find the existing ${parentFlow} TryFrom implementation
5. Add a match arm for PaymentMethodData::${paymentMethod}
6. Map the payment method fields to the new PaymentInformation variant

### Example Pattern:
Before (existing card pattern):
  PaymentMethodData::Card(card_data) => PaymentInformation::Card(...)

After (adding your new payment method):
  PaymentMethodData::${paymentMethod}(pm_data) => PaymentInformation::${paymentMethod}(Box::new(${paymentMethod}PaymentInformation { ... }))
` : `
## NEW FLOW IMPLEMENTATION - STANDARD INSTRUCTIONS

You are implementing a NEW FLOW.

### Steps:
1. Add the flow to create_all_prerequisites! macro in ${connector}.rs
2. Create ${connector}${flow}Request struct (Serialize)
3. Create ${connector}${flow}Response struct (Deserialize)
4. Implement TryFrom<RouterDataV2> for ${connector}${flow}Request
5. Implement TryFrom<${connector}${flow}Response> for RouterDataV2
6. Add macro_connector_implementation! invocation
`}

## Workflow File
${workflowContent}
`;

    // Build payload for Codegen Agent
    const payload = buildCodegenPayload(connector, flow, projectRoot, techSpecPath, l3);

    ctx.log("[implementation] Starting Codegen Agent (Phase 5 ONLY)...", "warn");
    ctx.log("[implementation]   Phase 4: Read & Analyze", "info");
    ctx.log("[implementation]   Phase 5: Implement code (NO build/test)", "info");

    let result: CodegenResult;
    try {
      const rawResult = await runAI<CodegenResult>({
        skillBody: systemPrompt,  // Use custom prompt with Phase 5 restriction
        userPayload: payload,
        cwd: projectRoot,
        label: "implementation:codegen",
        timeoutMs: 25 * 60 * 1000, // 25 min (no build/test, just code writing)
      });
      result = rawResult;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[implementation] Codegen Agent failed: ${msg}`, "error");
      return {
        passed: false,
        errors: [`Implementation failed: ${msg}`],
      };
    }

    // Normalize result keys from UPPERCASE to camelCase (agent may return either format)
    const normalizedResult: CodegenResult = {
      success: result.success ?? (result as unknown as Record<string, unknown>).STATUS === "SUCCESS",
      connector: result.connector ?? (result as unknown as Record<string, unknown>).CONNECTOR as string,
      flow: result.flow ?? (result as unknown as Record<string, unknown>).FLOW as string,
      buildIterations: result.buildIterations ?? 0,
      grpcurlResult: result.grpcurlResult ?? "NOT_RUN",
      filesModified: result.filesModified ?? (result as unknown as Record<string, string[]>).FILES_MODIFIED ?? [],
      fixLog: result.fixLog ?? [],
      grpcurlOutput: result.grpcurlOutput ?? "",
      executionLog: result.executionLog ?? { phasesCompleted: [], commandsExecuted: [], serverLogsChecked: false },
      reason: result.reason ?? (result as unknown as Record<string, string>).REASON,
    };
    result = normalizedResult;

    // Log results
    if (result.filesModified && result.filesModified.length > 0) {
      ctx.log(`[implementation] Files modified: ${result.filesModified.length}`, "info");
      for (const file of result.filesModified) {
        ctx.log(`  - ${file}`, "info");
      }
    }

    // Validate result (check for code written, not grpcurl)
    const hasCodeWritten = result.filesModified && result.filesModified.length > 0;
    const success = result.success || hasCodeWritten;

    if (!success) {
      ctx.log("[implementation] ✗ Failed - No code was written", "error");
      return {
        passed: false,
        errors: [result.reason || "Implementation did not write any code"],
        artifacts: { implementation: result },
      };
    }

    ctx.log("[implementation] ╔═══════════════════════════════════════════════════════════╗", "success");
    ctx.log("[implementation] ║  ✓ Implementation Complete (Phase 5)                   ║", "success");
    ctx.log("[implementation] ╚═══════════════════════════════════════════════════════════╝", "success");
    ctx.log("[implementation] Code written. Build and test will be handled by subsequent checkpoints.", "success");

    return {
      passed: true,
      artifacts: {
        implementation: result,
      },
    };
  },
};
