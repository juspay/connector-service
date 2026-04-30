import path from "node:path";
import { promises as fs } from "node:fs";
import type { Checkpoint, CodegenResult, L3Analysis } from "../types.js";
import { runOpencode } from "../tools/opencode-runner.js";
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
 * Implementation Checkpoint - Phase 5+6-7 from 2.3_codegen.md
 *
 * Implements connector flows by delegating to the Codegen Agent which:
 * 1. Phase 5: Implements the code (macros, TryFrom, RouterDataV2)
 * 2. Phase 6-7: Runs build/test loop with anti-loop safeguards
 */
export const implementationCheckpoint: Checkpoint = {
  id: "implementation",
  name: "Implementation",
  description:
    "Implements the connector flow using 2.3_codegen.md Phase 5+6-7: Codegen Agent builds and tests until grpcurl passes.",
  retryFrom: "implementation",
  timeout: 60 * 60 * 1000, // 60 min (includes build/test loop)

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

    ctx.log("[implementation] ╔═══════════════════════════════════════════════════════════╗", "info");
    ctx.log("[implementation] ║  Implementation (2.3_codegen.md Phase 5+6-7)            ║", "info");
    ctx.log("[implementation] ╚═══════════════════════════════════════════════════════════╝", "info");
    ctx.log(`[implementation] Connector: ${connector}`, "info");
    ctx.log(`[implementation] Flow: ${flow}`, "info");

    // Display L3 analysis summary
    ctx.log(`[implementation] Analysis: ${l3.analysis.patternsIdentified.length} patterns identified`, "info");
    ctx.log(`[implementation] Files to modify: ${l3.analysis.filesToModify.length}`, "info");

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

    // Build payload for Codegen Agent
    const payload = buildCodegenPayload(connector, flow, projectRoot, techSpecPath, l3);

    ctx.log("[implementation] Starting Codegen Agent (this may take 30-60 minutes)...", "warn");
    ctx.log("[implementation]   Phase 5: Implement code", "info");
    ctx.log("[implementation]   Phase 6-7: Build & Test loop with anti-loop safeguards", "info");

    let result: CodegenResult;
    try {
      const rawResult = await runOpencode<CodegenResult>({
        skillBody: CODEGEN_AGENT_SYSTEM,
        userPayload: payload,
        cwd: projectRoot,
        label: "implementation:codegen",
        timeoutMs: 55 * 60 * 1000, // 55 min (leaving buffer for checkpoint overhead)
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

    // Log results
    ctx.log(`[implementation] Build iterations: ${result.buildIterations}`, "info");
    ctx.log(`[implementation] grpcurl result: ${result.grpcurlResult}`,
      result.grpcurlResult === "PASS" ? "success" : "error"
    );

    if (result.fixLog && result.fixLog.length > 0) {
      ctx.log("[implementation] Fix log:", "info");
      for (const entry of result.fixLog) {
        ctx.log(`  Iteration ${entry.iteration}: ${entry.error}`, "info");
        ctx.log(`    → ${entry.fileChanged}: ${entry.changeDescription}`, "info");
      }
    }

    if (result.filesModified && result.filesModified.length > 0) {
      ctx.log(`[implementation] Files modified: ${result.filesModified.length}`, "info");
      for (const file of result.filesModified) {
        ctx.log(`  - ${file}`, "info");
      }
    }

    // Validate result
    if (!result.grpcurlOutput) {
      ctx.log("[implementation] Warning: Missing grpcurl output", "warn");
    }

    if (!result.success || result.grpcurlResult !== "PASS") {
      ctx.log("[implementation] ✗ Failed", "error");
      return {
        passed: false,
        errors: [result.reason || "Implementation did not pass grpcurl tests"],
        artifacts: { implementation: result },
      };
    }

    ctx.log("[implementation] ╔═══════════════════════════════════════════════════════════╗", "success");
    ctx.log("[implementation] ║  ✓ Implementation Complete                               ║", "success");
    ctx.log("[implementation] ╚═══════════════════════════════════════════════════════════╝", "success");
    ctx.log(`[implementation] Passed after ${result.buildIterations} iterations`, "success");

    return {
      passed: true,
      artifacts: {
        implementation: result,
      },
    };
  },
};
