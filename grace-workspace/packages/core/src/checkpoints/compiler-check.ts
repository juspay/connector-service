import path from "node:path";
import { promises as fs } from "node:fs";
import type { Checkpoint, RepairBrief } from "../types.js";
import { runAI } from "../tools/runner-factory.js";

/**
 * Compiler Check Checkpoint - Phase 6 ONLY from 2.3_codegen.md
 *
 * Runs cargo build to verify the code compiles without errors.
 * Does NOT modify source files. On failure, the engine rolls back to
 * `implementation` and a `repairBrief` artifact carries the rustc errors so
 * the writer can fix the compilation problem.
 */
export const compilerCheckCheckpoint: Checkpoint = {
  id: "compiler_check",
  name: "Compiler Check",
  description: "Verify code compiles without errors using cargo build (Phase 6 ONLY)",
  // On failure, only `implementation` can fix the underlying source bug.
  // Re-running cargo build against unchanged code never changes the outcome.
  retryFrom: "implementation",
  timeout: 15 * 60 * 1000, // 15 min for build

  async run(ctx) {
    const task = ctx.artifacts.task;
    const connector = task?.targetConnectors?.[0];
    const flow = task?.paymentMethod || "Unknown";
    const projectRoot = task?.projectRoot;

    if (!projectRoot) {
      return { passed: false, errors: ["Missing project root"] };
    }

    ctx.log("[compiler_check] ╔═══════════════════════════════════════════════════════════╗", "info");
    ctx.log("[compiler_check] ║  Compiler Check (2.3_codegen.md Phase 6 ONLY)           ║", "info");
    ctx.log("[compiler_check] ╚═══════════════════════════════════════════════════════════╝", "info");
    ctx.log(`[compiler_check] Connector: ${connector}`, "info");
    ctx.log(`[compiler_check] Flow: ${flow}`, "info");

    // Read workflow file
    let workflowContent = "";
    try {
      const workflowPath = path.join(projectRoot, "grace/workflow/2.3_codegen.md");
      workflowContent = await fs.readFile(workflowPath, 'utf-8');
      ctx.log("[compiler_check] Loaded workflow file", "info");
    } catch (err) {
      ctx.log(`[compiler_check] Warning: Could not read workflow: ${err}`, "warn");
    }

    // Build restricted system prompt
    const systemPrompt = `You are the Compiler Check Agent.

## CRITICAL RESTRICTION - COMPILE-ONLY MODE
You are in COMPILE-ONLY MODE.

**EXECUTE ONLY:**
- Phase 6: Build step (cargo build)

**DO NOT EXECUTE:**
- Phase 4 (Read & Analyze) - already done
- Phase 5 (Implement) - code is already written
- grpcurl tests - handled by gRPC Test checkpoint

You MUST:
1. Read the workflow below
2. Find the build command in Phase 6
3. Run ONLY: cargo build --package connector-integration
4. Report build success or failure
5. Do NOT modify source files
6. Do NOT run tests

## Workflow File (execute ONLY Phase 6 build)
${workflowContent}
`;

    const payload = {
      CONNECTOR: connector,
      FLOW: flow,
      COMMAND: "cargo build --package connector-integration 2>&1",
    };

    ctx.log("[compiler_check] Starting cargo build...", "warn");

    try {
      type CompilerCheckResult = {
        status?: string;
        build_output?: string;
        output?: string;
        errors?: string;
        reason?: string;
      };

      const result = await runAI<CompilerCheckResult>({
        skillBody: systemPrompt,
        userPayload: payload,
        cwd: projectRoot,
        label: "compiler:check",
        timeoutMs: 10 * 60 * 1000, // 10 min for build
      });

      // Check for build success
      const buildOutput = result.build_output || result.output || "";
      const hasErrors = buildOutput.includes("error[") ||
                       (buildOutput.includes("Compiling") === false && buildOutput.includes("Finished") === false);
      const buildPassed = result.status === "SUCCESS" ||
                         (buildOutput.includes("Finished") && !hasErrors);

      if (buildPassed) {
        ctx.log("[compiler_check] ✓ Build successful", "success");
        ctx.log("[compiler_check] ╔═══════════════════════════════════════════════════════════╗", "success");
        ctx.log("[compiler_check] ║  ✓ Compiler Check Passed                                 ║", "success");
        ctx.log("[compiler_check] ╚═══════════════════════════════════════════════════════════╝", "success");

        return {
          passed: true,
          artifacts: {
            compilerCheck: result,
            buildOutput: buildOutput,
            // Clear any stale repairBrief on success.
            repairBrief: undefined,
          },
        };
      } else {
        ctx.log("[compiler_check] ✗ Build failed", "error");
        ctx.log("[compiler_check] ╔═══════════════════════════════════════════════════════════╗", "error");
        ctx.log("[compiler_check] ║  ✗ Compiler Check Failed                                 ║", "error");
        ctx.log("[compiler_check] ╚═══════════════════════════════════════════════════════════╝", "error");

        const rustcErrors = extractRustcErrors(buildOutput);
        const rootCauseFile = extractRustcFile(buildOutput);
        const rootCauseLine = extractRustcLine(buildOutput);

        const repairBrief: RepairBrief = {
          source: "compiler_check",
          flow,
          errorKind: "build_error",
          buildOutput,
          rustcErrors,
          rootCauseFile,
          rootCauseLine,
        };

        return {
          passed: false,
          errors: ["Build failed", buildOutput.slice(0, 2000)],
          artifacts: {
            compilerCheck: result,
            buildOutput: buildOutput,
            repairBrief,
          },
        };
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[compiler_check] Build check failed: ${msg}`, "error");
      const repairBrief: RepairBrief = {
        source: "compiler_check",
        flow,
        errorKind: msg.includes("timed out") ? "infra" : "build_error",
        buildOutput: msg,
      };
      return {
        passed: false,
        errors: [`Compiler check failed: ${msg}`],
        artifacts: { repairBrief },
      };
    }
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function extractRustcErrors(buildOutput: string): string[] {
  // Capture each `error[E####]: ...` block up to the next blank line.
  const out: string[] = [];
  const re = /error(?:\[E\d+\])?:[^\n]*(?:\n\s+[^\n]*)*/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(buildOutput)) !== null) {
    out.push(match[0]);
    if (out.length >= 10) break; // cap to keep prompts small
  }
  return out;
}

function extractRustcFile(buildOutput: string): string | undefined {
  // rustc points at the offending file with `--> path/to/file.rs:LL:CC`
  const m = buildOutput.match(/-->\s+([^\s:]+\.rs):\d+:\d+/);
  return m?.[1];
}

function extractRustcLine(buildOutput: string): number | undefined {
  const m = buildOutput.match(/-->\s+[^\s:]+\.rs:(\d+):\d+/);
  return m ? Number(m[1]) : undefined;
}
