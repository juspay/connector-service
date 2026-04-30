import type { Checkpoint, L3Analysis } from "../types.js";
import { runOpencode } from "../tools/opencode-runner.js";
import {
  L3_ANALYSIS_SYSTEM,
  buildL3AnalysisPayload,
} from "../generators/l3-analysis-prompt.js";
import * as path from "node:path";
import * as fs from "node:fs/promises";

function valid(analysis: unknown): analysis is L3Analysis {
  if (!analysis || typeof analysis !== "object") return false;
  const a = analysis as Record<string, unknown>;

  // Check top-level fields
  if (
    typeof a.connector !== "string" ||
    typeof a.flow !== "string" ||
    typeof a.implementationNotes !== "string"
  ) {
    return false;
  }

  // Check analysis object
  const analysisObj = a.analysis as Record<string, unknown>;
  if (!analysisObj || typeof analysisObj !== "object") return false;

  // Check arrays
  if (
    !Array.isArray(analysisObj.patternsIdentified) ||
    !Array.isArray(analysisObj.filesToModify) ||
    !Array.isArray(analysisObj.existingFlows)
  ) {
    return false;
  }

  // Check prerequisitesStatus
  if (
    analysisObj.prerequisitesStatus !== "complete" &&
    analysisObj.prerequisitesStatus !== "incomplete"
  ) {
    return false;
  }

  // Check specification object (required)
  const spec = a.specification as Record<string, unknown>;
  if (!spec || typeof spec !== "object") return false;

  // Check required specification fields
  if (!spec.requestStruct || !spec.responseStruct || !spec.connectorChanges) {
    return false;
  }

  // Check filesChangedPreview (required)
  if (!Array.isArray(spec.filesChangedPreview)) return false;

  return true;
}

/**
 * Ensure tech spec is saved to disk for the L3 Analysis Agent to read
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

export const l3AnalysisCheckpoint: Checkpoint = {
  id: "l3_analysis",
  name: "L3 Analysis",
  description:
    "Phase 4 from 2.3_codegen.md: Read and analyze 6 reference files (tech spec, patterns, macros, domain types, existing connector code, transformers).",
  retryFrom: "l3_analysis",
  timeout: 30 * 60 * 1000, // 30 min for reading and analyzing files

  async run(ctx) {
    const l2 = ctx.artifacts.l2;

    if (!l2) {
      return { passed: false, errors: ["Missing L2 plan"] };
    }

    const task = ctx.artifacts.task;
    if (!task?.targetConnectors?.[0]) {
      return { passed: false, errors: ["Missing connector in task"] };
    }

    const connector = task.targetConnectors[0];
    const flow = task.paymentMethod || "Unknown";
    const projectRoot = task.projectRoot;

    ctx.log("[l3_analysis] ╔═══════════════════════════════════════════════════════════╗", "info");
    ctx.log("[l3_analysis] ║  L3 Analysis (2.3_codegen.md Phase 4)                    ║", "info");
    ctx.log("[l3_analysis] ╚═══════════════════════════════════════════════════════════╝", "info");
    ctx.log(`[l3_analysis] Connector: ${connector}`, "info");
    ctx.log(`[l3_analysis] Flow: ${flow}`, "info");

    // Ensure tech spec is available on disk
    let techSpecPath: string;
    try {
      techSpecPath = await ensureTechSpecFile(
        projectRoot,
        connector,
        flow,
        l2?.specContent
      );
      ctx.log(`[l3_analysis] Tech spec: ${techSpecPath}`, "info");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[l3_analysis] Failed to locate tech spec: ${msg}`, "error");
      return {
        passed: false,
        errors: [`Tech spec not available: ${msg}`],
      };
    }

    // Build payload for L3 Analysis Agent
    const payload = buildL3AnalysisPayload(
      connector,
      flow,
      techSpecPath,
      projectRoot,
      "/Users/jeeva.ramachandran/Workspace/hyperswitch-prism/grace/workflow/2.3_codegen.md"
    );

    ctx.log("[l3_analysis] Starting Phase 4 analysis (reading 6 files)...", "warn");
    ctx.log("[l3_analysis]   1. Tech Spec", "info");
    ctx.log("[l3_analysis]   2. Pattern Guide", "info");
    ctx.log("[l3_analysis]   3. Macro Reference", "info");
    ctx.log("[l3_analysis]   4. Domain Types", "info");
    ctx.log("[l3_analysis]   5. Existing Connector Code", "info");
    ctx.log("[l3_analysis]   6. Existing Transformers", "info");

    let result: L3Analysis;
    try {
      const rawResult = await runOpencode<L3Analysis>({
        skillBody: L3_ANALYSIS_SYSTEM,
        userPayload: payload,
        cwd: projectRoot,
        label: "l3:analysis",
        timeoutMs: 25 * 60 * 1000, // 25 min (leaving buffer for checkpoint overhead)
      });
      result = rawResult;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[l3_analysis] L3 Analysis Agent failed: ${msg}`, "error");
      return {
        passed: false,
        errors: [`L3 Analysis failed: ${msg}`],
      };
    }

    // Validate result
    if (!valid(result)) {
      ctx.log("[l3_analysis] ✗ Validation failed", "error");
      return {
        passed: false,
        errors: ["L3 Analysis result failed validation"],
        artifacts: { l3: result },
      };
    }

    // Check if flow already exists
    if (result.analysis.flowAlreadyExists) {
      ctx.log("[l3_analysis] ⚠ Flow already implemented - SKIPPING", "warn");
      return {
        passed: false,
        errors: ["Flow already implemented - SKIPPED"],
        artifacts: { l3: result },
      };
    }

    // Check prerequisites status
    if (result.analysis.prerequisitesStatus === "incomplete") {
      ctx.log(
        `[l3_analysis] ✗ Prerequisites incomplete: ${result.analysis.missingPrerequisites?.join(", ")}`,
        "error"
      );
      return {
        passed: false,
        errors: [
          `Prerequisites incomplete: ${result.analysis.missingPrerequisites?.join(", ")}`,
        ],
        artifacts: { l3: result },
      };
    }

    // Check specification completeness
    if (!result.specification) {
      ctx.log("[l3_analysis] ✗ Missing implementation specification", "error");
      return {
        passed: false,
        errors: ["L3 Analysis did not produce implementation specification"],
        artifacts: { l3: result },
      };
    }

    // Check files changed preview
    if (!result.specification.filesChangedPreview || result.specification.filesChangedPreview.length === 0) {
      ctx.log("[l3_analysis] ✗ Missing files changed preview", "error");
      return {
        passed: false,
        errors: ["L3 Analysis did not produce filesChangedPreview"],
        artifacts: { l3: result },
      };
    }

    // Log ambiguities if any
    if (result.specification.ambiguities && result.specification.ambiguities.length > 0) {
      ctx.log(`[l3_analysis] ⚠ ${result.specification.ambiguities.length} ambiguous specification(s)`, "warn");
      for (const ambiguity of result.specification.ambiguities) {
        ctx.log(`[l3_analysis]   • ${ambiguity.field}: ${ambiguity.issue}`, "warn");
      }
    }

    // Log results
    ctx.log(`[l3_analysis] ✓ Patterns identified: ${result.analysis.patternsIdentified.length}`, "success");
    for (const pattern of result.analysis.patternsIdentified) {
      ctx.log(`[l3_analysis]   • ${pattern}`, "info");
    }

    ctx.log(`[l3_analysis] ✓ Files to modify: ${result.analysis.filesToModify.length}`, "success");
    for (const file of result.analysis.filesToModify) {
      ctx.log(`[l3_analysis]   • ${file}`, "info");
    }

    ctx.log(`[l3_analysis] ✓ Existing flows: ${result.analysis.existingFlows.join(", ") || "None"}`, "info");

    // Log files changed preview
    const preview = result.specification.filesChangedPreview;
    const totalAdditions = preview.reduce((sum, f) => sum + f.linesAdded, 0);
    const totalDeletions = preview.reduce((sum, f) => sum + f.linesRemoved, 0);
    ctx.log(`[l3_analysis] ✓ Files to change: ${preview.length} (+${totalAdditions}/-${totalDeletions})`, "success");
    for (const file of preview) {
      const icon = file.changeType === "created" ? "+" : file.changeType === "deleted" ? "−" : "•";
      ctx.log(`[l3_analysis]   ${icon} ${file.path} (+${file.linesAdded}/-${file.linesRemoved})`, "info");
    }

    if (result.riskAssessment && result.riskAssessment.length > 0) {
      ctx.log(`[l3_analysis] ⚠ Risks identified: ${result.riskAssessment.length}`, "warn");
      for (const risk of result.riskAssessment) {
        ctx.log(`[l3_analysis]   • ${risk}`, "warn");
      }
    }

    ctx.log("[l3_analysis] ╔═══════════════════════════════════════════════════════════╗", "success");
    ctx.log("[l3_analysis] ║  ✓ Phase 4 Analysis Complete                             ║", "success");
    ctx.log("[l3_analysis] ╚═══════════════════════════════════════════════════════════╝", "success");

    delete ctx.artifacts.l3RegeneratePrompt;

    return {
      passed: true,
      artifacts: {
        l3: result,
      },
    };
  },
};
