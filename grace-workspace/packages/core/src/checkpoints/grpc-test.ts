import path from "node:path";
import { promises as fs } from "node:fs";
import type { Checkpoint } from "../types.js";
import { runAI } from "../tools/runner-factory.js";
import {
  killStaleProcesses,
  startGrpcServer,
  waitForBuildComplete,
  waitForHealthy,
  tailLogFile,
  type ServerHandle,
} from "./grpc-server-lifecycle.js";

/**
 * gRPC Test Checkpoint — Phase 6-7 of 2.3_codegen.md, but with the server
 * lifecycle owned by the orchestrator (TypeScript) instead of the agent.
 *
 * Flow:
 *   1. Pre-flight: kill any stale process holding ports 8000/8080.
 *   2. Start grpc-server, redirecting stdout+stderr to a per-run log file.
 *   3. Wait for TCP healthy on localhost:8000 (≤45s).
 *   4. Hand the agent a slim prompt: "server is up at localhost:8000, run
 *      grpcurl, validate, return JSON."
 *   5. Always kill the server on exit (finally), regardless of agent outcome.
 *
 * Why: the prior version asked the agent to run `cargo run --bin grpc-server &`
 * inline. Background `&` from a remote agent's bash tool is unreliable; the
 * server often vanished between tool calls and the agent looped on grpcurl
 * until the 480s runner timeout fired with empty stderr — the exact failure
 * mode this rewrite eliminates.
 */

const SLIM_PROMPT = `You are the gRPC Test Agent.

## CRITICAL RESTRICTION — TEST-ONLY MODE
The gRPC server is already running at SERVER_HOST. Do NOT start, kill, build,
or modify code. Do NOT run cargo. Do NOT touch source files. Your single
responsibility is: run grpcurl against the running server, validate the
response, return JSON.

## What to do

1. Read CREDS_PATH (a JSON file at the project root) to obtain the connector
   credentials. Pick the entry matching CONNECTOR.
2. If HAS_FIELD_PROBE is true, read FIELD_PROBE_PATH and use the captured
   payload structure as the source of truth for the request body. Field probe
   is authoritative — prefer it over guessing field names.
3. Discover the gRPC method to call. Useful commands:
     grpcurl -plaintext SERVER_HOST list
     grpcurl -plaintext SERVER_HOST describe <service>
4. Construct the grpcurl request:
   - Pass connector credentials via -H headers. Header names are
     connector-specific; populate them from CREDS_PATH. Do not invent headers
     that aren't in the credentials file.
   - The request body must match what FLOW expects (Authorize, BankDebit,
     etc.) for CONNECTOR. Use field_probe if available.
   - Capture both the FULL command and FULL response.
5. Run the grpcurl call.
6. Validate the response:
   - PASS if status is one of: authorized, PENDING, charged, requires_capture,
     succeeded.
   - FAIL if response contains "Error invoking method", "PAYMENT_FLOW_ERROR",
     HTTP 4xx/5xx, or any explicit error/failure status.
7. On FAIL: read the server log at SERVER_LOG_PATH (the grpc-server's
   stdout+stderr for this run) to find the actual root cause — serialization
   error, missing field, wrong URL, panic, auth rejection, etc. Include the
   relevant log excerpt in response_summary.

## Output format

Return ONLY a single valid JSON object. No prose, no markdown fences. First
character must be \`{\`, last must be \`}\`.

{
  "status": "SUCCESS" | "FAILED",
  "grpcurl_result": "PASS" | "FAIL",
  "grpcurl_command": "the full grpcurl command used",
  "copy_paste_command": "complete command with JSON payload embedded inline",
  "request_payload": "the exact JSON payload sent",
  "grpcurl_output": "the full output including command and response",
  "response_summary": "brief summary, plus relevant SERVER_LOG_PATH excerpt on FAIL"
}
`;

export const grpcTestCheckpoint: Checkpoint = {
  id: "grpc_test",
  name: "gRPC Test",
  description:
    "Test connector via gRPC calls using grpcurl (orchestrator-managed server)",
  retryFrom: "implementation",
  // Outer budget covers preflight (~5s) + cargo build (≤15min cold) +
  // server start + health wait (≤45s) + agent runAI (≤6min) + cleanup (~5s)
  // with margin.
  timeout: 30 * 60 * 1000,
  continueOnFailure: true,

  async run(ctx) {
    const task = ctx.artifacts.task;
    const connector = task?.targetConnectors?.[0];
    const flow = task?.paymentMethod || "Unknown";
    const projectRoot = task?.projectRoot;

    if (!projectRoot) {
      return { passed: false, errors: ["Missing project root"] };
    }

    ctx.log(
      "[grpc_test] ╔═══════════════════════════════════════════════════════════╗",
      "info"
    );
    ctx.log(
      "[grpc_test] ║  gRPC Test (orchestrator-managed server)               ║",
      "info"
    );
    ctx.log(
      "[grpc_test] ╚═══════════════════════════════════════════════════════════╝",
      "info"
    );
    ctx.log(`[grpc_test] Connector: ${connector}`, "info");
    ctx.log(`[grpc_test] Flow: ${flow}`, "info");

    const serverHost = "localhost:8000";
    const credsPath = path.join(projectRoot, "creds.json");
    const logFile = path.join(
      projectRoot,
      ".grace",
      `grpc-server-${ctx.runId}.log`
    );

    // Field probe is optional — the agent uses it as authoritative payload
    // structure when present, otherwise builds from spec.
    let fieldProbePath: string | null = null;
    let hasFieldProbe = false;
    try {
      const probePath = path.join(
        projectRoot,
        "data",
        "field_probe",
        `${connector?.toLowerCase() || "unknown"}.json`
      );
      await fs.access(probePath);
      fieldProbePath = probePath;
      hasFieldProbe = true;
      ctx.log(`[grpc_test] Field probe: ${probePath}`, "info");
    } catch {
      ctx.log("[grpc_test] No field probe data available", "warn");
    }

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
    let server: ServerHandle | undefined;

    const tsLog = (msg: string, level: "info" | "warn" | "error" = "info") =>
      ctx.log(`[grpc_test] ${msg}`, level);

    try {
      tsLog("preflight: killing stale processes on :8000/:8080");
      await killStaleProcesses(tsLog);

      tsLog(`starting grpc-server, log → ${logFile}`);
      server = await startGrpcServer({ projectRoot, logFile }, tsLog);

      // Cold cargo builds can take 10-20 min on this tree (diesel + macros);
      // the TCP probe's 45s budget is only correct once the binary is exec'd.
      // Watch the log for cargo's "Running `target/.../grpc-server`" marker
      // first, then probe TCP.
      tsLog("waiting for cargo build to finish (≤20min for cold builds)");
      await waitForBuildComplete(
        { logFile, timeoutMs: 20 * 60 * 1000 },
        tsLog
      );

      tsLog(`waiting for ${serverHost} to become healthy (≤45s)`);
      await waitForHealthy(
        { host: "localhost", port: 8000, timeoutMs: 45_000 },
        tsLog
      );

      tsLog("server healthy — invoking agent for grpcurl test");

      result = await runAI<GrpcTestResult>({
        skillBody: SLIM_PROMPT,
        userPayload: {
          CONNECTOR: connector,
          FLOW: flow,
          SERVER_HOST: serverHost,
          CREDS_PATH: credsPath,
          SERVER_LOG_PATH: logFile,
          HAS_FIELD_PROBE: hasFieldProbe,
          FIELD_PROBE_PATH: fieldProbePath || "",
        },
        cwd: projectRoot,
        label: "grpc:test",
        // Strictly less than the outer checkpoint timeout so the finally
        // block has room to clean up after the agent.
        timeoutMs: 6 * 60 * 1000,
      });

      const testPassed =
        result.status === "SUCCESS" || result.grpcurl_result === "PASS";

      const grpcCommand = result.grpcurl_command || "";
      const grpcOutput = result.grpcurl_output || result.output || "";
      const responseSummary = result.response_summary || "";

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
        tsLog("✓ gRPC tests passed", "info");
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
      }

      tsLog("⚠ gRPC tests failed", "warn");
      const errorMsg = result.reason || "gRPC test failed";
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
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // Tail the server log so the dashboard shows real diagnostics instead of
      // "No output captured" — this is the failure mode that motivated the
      // whole refactor.
      const logTail = await tailLogFile(logFile, 2048);
      const errorOutput = `gRPC Test Error: ${msg}

═══════════════════════════════════════════════════════════════
COMMAND ATTEMPTED:
═══════════════════════════════════════════════════════════════
${result?.grpcurl_command || "Not captured - test timed out before execution"}

═══════════════════════════════════════════════════════════════
RESPONSE/OUTPUT:
═══════════════════════════════════════════════════════════════
${result?.grpcurl_output || result?.output || "No output captured"}

═══════════════════════════════════════════════════════════════
SERVER LOG TAIL (${logFile}):
═══════════════════════════════════════════════════════════════
${logTail || "(empty — server produced no output before timeout)"}`;

      tsLog(`gRPC test failed: ${msg}`, "error");

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
    } finally {
      if (server) {
        try {
          await server.kill();
          tsLog(`server pid=${server.pid} stopped`);
        } catch (e) {
          tsLog(
            `warning: server cleanup failed: ${e instanceof Error ? e.message : String(e)}`,
            "warn"
          );
        }
      }
    }
  },
};
