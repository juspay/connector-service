import path from "node:path";
import { promises as fs } from "node:fs";
import type { Checkpoint } from "../types.js";
import { runAI } from "../tools/runner-factory.js";

/**
 * gRPC Test Checkpoint - Phase 6-7 gRPC testing from 2.3_codegen.md
 *
 * Runs grpcurl tests to validate the connector implementation.
 * Replaces: Design Match, Cypress E2E Test, Playwright Tests
 * Does NOT modify source files.
 * Does NOT rebuild.
 */
export const grpcTestCheckpoint: Checkpoint = {
  id: "grpc_test",
  name: "gRPC Test",
  description: "Test connector via gRPC calls using grpcurl (replaces Design Match/Cypress/Playwright)",
  retryFrom: "implementation",
  timeout: 10 * 60 * 1000, // 10 min for testing
  continueOnFailure: true, // Continue to PR review even if gRPC tests fail

  async run(ctx) {
    const task = ctx.artifacts.task;
    const connector = task?.targetConnectors?.[0];
    const flow = task?.paymentMethod || "Unknown";
    const projectRoot = task?.projectRoot;

    if (!projectRoot) {
      return { passed: false, errors: ["Missing project root"] };
    }

    ctx.log("[grpc_test] ╔═══════════════════════════════════════════════════════════╗", "info");
    ctx.log("[grpc_test] ║  gRPC Test (2.3_codegen.md Phase 6-7)                  ║", "info");
    ctx.log("[grpc_test] ╚═══════════════════════════════════════════════════════════╝", "info");
    ctx.log(`[grpc_test] Connector: ${connector}`, "info");
    ctx.log(`[grpc_test] Flow: ${flow}`, "info");

    // Read workflow file
    let workflowContent = "";
    try {
      const workflowPath = path.join(projectRoot, "grace/workflow/2.3_codegen.md");
      workflowContent = await fs.readFile(workflowPath, 'utf-8');
      ctx.log("[grpc_test] Loaded workflow file", "info");
    } catch (err) {
      ctx.log(`[grpc_test] Warning: Could not read workflow: ${err}`, "warn");
    }

    // Check for field_probe data
    let fieldProbePath: string | null = null;
    let hasFieldProbe = false;
    try {
      const probePath = path.join(projectRoot, "data", "field_probe", `${connector?.toLowerCase() || "unknown"}.json`);
      await fs.access(probePath);
      fieldProbePath = probePath;
      hasFieldProbe = true;
      ctx.log(`[grpc_test] Field probe data found: ${probePath}`, "info");
    } catch {
      ctx.log("[grpc_test] No field probe data available", "warn");
    }

    // Build restricted system prompt
    const systemPrompt = `You are the gRPC Test Agent.

## CRITICAL RESTRICTION - TEST-ONLY MODE
You are in TEST-ONLY MODE.

**EXECUTE ONLY:**
- Phase 6-7: gRPC testing (grpcurl)

**DO NOT EXECUTE:**
- Phase 4 (Read & Analyze) - already done
- Phase 5 (Implement) - code already written
- cargo build - already done by Compiler Check

You MUST:
1. Read the workflow below
2. Find the gRPC testing steps in Phase 6-7
3. Start service if needed (kill ports 8000/8080, cargo run --bin grpc-server)
4. Wait for health check
5. Run grpcurl tests against localhost:8000
6. Validate response status is one of: authorized, PENDING, charged
7. Report test results including FULL grpcurl command and FULL response
8. Do NOT modify source files
9. Do NOT rebuild

## Output Format

Return ONLY valid JSON:
{
  "status": "SUCCESS" | "FAILED",
  "grpcurl_result": "PASS" | "FAIL",
  "grpcurl_command": "the full grpcurl command used (may use temp file)",
  "copy_paste_command": "COMPLETE command with JSON payload embedded inline - user should be able to copy and run this directly without any temp files",
  "request_payload": "the exact JSON payload sent in the request",
  "grpcurl_output": "the full output including command and response",
  "response_summary": "brief summary of the response received"
}

## Workflow File (execute ONLY Phase 6-7 gRPC testing)
${workflowContent}
`;

    const payload = {
      CONNECTOR: connector,
      FLOW: flow,
      HAS_FIELD_PROBE: hasFieldProbe,
      FIELD_PROBE_PATH: fieldProbePath || "",
      SERVER_HOST: "localhost:8000",
      CREDS_PATH: path.join(projectRoot, "creds.json"),
    };

    ctx.log("[grpc_test] Starting gRPC tests...", "warn");

    type GrpcTestResult = {
      status?: string;
      grpcurl_result?: string;
      grpcurl_command?: string;
      copy_paste_command?: string;
      request_payload?: string;
      grpcurl_output?: string;
      response_summary?: string;
      output?: string;
      reason?: string;
    };

    let result: GrpcTestResult | undefined;
    try {
      result = await runAI<GrpcTestResult>({
        skillBody: systemPrompt,
        userPayload: payload,
        cwd: projectRoot,
        label: "grpc:test",
        timeoutMs: 8 * 60 * 1000, // 8 min for testing
      });

      const testPassed = result.status === "SUCCESS" ||
                        (result.grpcurl_result === "PASS");

      const grpcCommand = result.grpcurl_command || "";
      const grpcOutput = result.grpcurl_output || result.output || "";
      const responseSummary = result.response_summary || "";

      // Build output for UI display
      const uiOutput = `gRPC Test Results
═══════════════════════════════════════════════════════════════

COMMAND USED:
${grpcCommand || "Not captured"}

RESPONSE RECEIVED:
${responseSummary || grpcOutput.slice(0, 2000)}

FULL OUTPUT:
${grpcOutput.slice(0, 3000)}
`;

      if (testPassed) {
        ctx.log("[grpc_test] ✓ gRPC tests passed", "success");
        ctx.log("[grpc_test] ╔═══════════════════════════════════════════════════════════╗", "success");
        ctx.log("[grpc_test] ║  ✓ gRPC Test Passed                                      ║", "success");
        ctx.log("[grpc_test] ╚═══════════════════════════════════════════════════════════╝", "success");

        return {
          passed: true,
          output: uiOutput,
          artifacts: {
            grpcTest: result,
            grpcurlOutput: grpcOutput,
            grpcurlCommand: grpcCommand,
            grpcResponse: responseSummary,
          },
        };
      } else {
        ctx.log("[grpc_test] ⚠ gRPC tests failed", "warn");
        ctx.log("[grpc_test] ╔═══════════════════════════════════════════════════════════╗", "warn");
        ctx.log("[grpc_test] ║  ⚠ gRPC Test Failed - Recording details                ║", "warn");
        ctx.log("[grpc_test] ╚═══════════════════════════════════════════════════════════╝", "warn");

        const errorMsg = result.reason || "gRPC test failed";

        // Store errors for implementation retry
        ctx.artifacts.grpcTestErrors = [errorMsg, grpcOutput].filter(Boolean);
        ctx.artifacts.grpcurlOutput = grpcOutput;

        return {
          passed: false,
          output: uiOutput,
          errors: [errorMsg],
          artifacts: {
            grpcTest: result,
            grpcurlOutput: grpcOutput,
            grpcurlCommand: grpcCommand,
            grpcResponse: responseSummary,
            grpcTestFailed: true,
            grpcTestError: errorMsg,
          },
        };
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // This output is what gets displayed in the dashboard UI
      const errorOutput = `gRPC Test Error: ${msg}

═══════════════════════════════════════════════════════════════
COMMAND ATTEMPTED:
═══════════════════════════════════════════════════════════════
${result?.grpcurl_command || "Not captured - test timed out before execution"}

═══════════════════════════════════════════════════════════════
RESPONSE/OUTPUT:
═══════════════════════════════════════════════════════════════
${result?.grpcurl_output || result?.output || "No output captured"}`;

      ctx.log(`[grpc_test] gRPC test failed: ${msg}`, "error");

      // Build a grpcTest result object for UI display (matches GrpcTestArtifact expectations)
      const errorResult: GrpcTestResult = {
        status: "FAILED",
        grpcurl_result: "FAIL",
        reason: `gRPC test failed: ${msg}`,
        grpcurl_command: result?.grpcurl_command || "",
        grpcurl_output: errorOutput,
        output: errorOutput,
      };

      return {
        passed: false,
        output: errorOutput,
        errors: [`gRPC test failed: ${msg}`],
        artifacts: {
          grpcTest: errorResult,
          grpcurlOutput: errorOutput,
          grpcTestFailed: true,
        },
      };
    }
  },
};
