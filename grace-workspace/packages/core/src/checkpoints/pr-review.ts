import path from "node:path";
import { promises as fs } from "node:fs";
import type { Checkpoint, PRReviewResult } from "../types.js";
import { runAI } from "../tools/runner-factory.js";
import { safeParseJson } from "../utils.js";
import { getConfig } from "../config.js";
import { askYesNo } from "../prompts/cli-prompts.js";

const SYSTEM = `You are the PR Agent for hyperswitch-prism: you BOTH (a) review the implementation for spec compliance AND (b) drive the full PR-creation workflow in 2.4_pr.md (commit on dev branch → cherry-pick to clean PR branch → scrub credentials → push → \`gh pr create\`).

## Tool Access

You have FULL ACCESS to all tools including Read, Edit, Write, Bash, Grep, Glob, and WebFetch. Use whatever you need to complete BOTH the review and the PR creation.

## Workflow Compliance

STRICTLY FOLLOW the workflow defined in:
- Local: /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/grace/workflow/2.4_pr.md

The user payload below provides every input the workflow declares (CONNECTOR, FLOW, DEV_BRANCH, CONNECTOR_STATUS, FAILURE_REASON, GRPCURL_OUTPUT, CONNECTOR_SOURCE_FILES). Use those values directly — do not re-derive them from the implementation artifact.

Additional checks:
- Branch naming: PR branch must be \`feat/grace-{connector}-{flow}\` (lowercase, kebab-case). The DEV_BRANCH input is intentionally distinct (suffixed \`-dev\`) so Phase 2's \`git checkout -b\` does not collide.
- If a PR already exists for the head branch (per \`2.4_pr.md\` Phase 6a), return its URL — do NOT open a duplicate.

## Output

Return ONLY valid JSON. The very first character must be \`{\` and the very last must be \`}\`. Include both the review verdict and the PR-creation outputs:

{
  "approved": boolean,
  "specComplianceScore": number (0..1),
  "comments": [{ "file": "string", "line": number | null, "comment": "string", "severity": "info"|"warning"|"blocking" }],
  "status": "SUCCESS" | "FAILED",
  "prUrl": "https://github.com/juspay/hyperswitch-prism/pull/<N>",
  "prBranch": "feat/grace-{connector}-{flow}",
  "reason": "(empty on SUCCESS, failure detail on FAILED)"
}

\`prUrl\` must be the exact URL \`gh pr create\` printed (or, on the idempotent path, the URL returned by \`gh pr list\`). \`status\` is FAILED if any phase of 2.4_pr.md aborted (e.g., cherry-pick conflict, push denied, no files to commit). All other top-level fields are mandatory.`;

const COLOR: Record<string, string> = {
  info: "\x1b[36m",
  warning: "\x1b[33m",
  blocking: "\x1b[31m",
};

export const prReviewCheckpoint: Checkpoint = {
  id: "pr_review",
  name: "PR review (automated + human gate)",
  description:
    "LLM reviews for spec compliance; human confirms on non-approved output.",
  retryFrom: "pr_review",
  async run(ctx) {
    const implementation = ctx.artifacts.implementation;
    if (!implementation)
      return { passed: false, errors: ["Missing implementation result"] };

    const files: Array<{ path: string; contents: string }> = [];
    const seen = new Set<string>();

    // Get files from implementation result
    const implFiles =
      (implementation as any).filesModified ??
      (implementation as any).files?.map((f: any) => f.path) ??
      [];
    const touched = [...implFiles];
    if (touched.length === 0) {
      return { passed: false, errors: ["No files found in implementation"] };
    }
    ctx.log("[pr_review] Following Grace workflow: 2.4_pr.md", "info");

    for (const rel of touched) {
      if (seen.has(rel)) continue;
      seen.add(rel);
      const abs = path.isAbsolute(rel)
        ? rel
        : path.join(ctx.task.projectRoot, rel);
      try {
        const contents = await fs.readFile(abs, "utf-8");
        files.push({ path: rel, contents: contents.slice(0, 8000) });
      } catch {
        /* ignore */
      }
    }

    // Build the 2.4_pr.md inputs from existing artifacts. None of these are
    // re-derived inside the agent any more — the wiring used to leave the
    // agent guessing, which was the primary reason PR creation was flaky.
    const connector = ctx.task.targetConnectors?.[0] ?? "unknown";
    const flow = ctx.task.paymentMethod ?? "unknown";
    const devBranch =
      (ctx.artifacts.devBranch as string | undefined) ??
      (ctx.artifacts.branch as string | undefined) ??
      `feat/grace-${connector.toLowerCase()}-${flow.toLowerCase()}-dev`;

    const grpcTest = ctx.artifacts.grpcTest as
      | { grpcurl_output?: string; output?: string; reason?: string }
      | undefined;
    const grpcurlOutput =
      (ctx.artifacts.grpcurlOutput as string | undefined) ??
      grpcTest?.grpcurl_output ??
      grpcTest?.output ??
      "";
    const grpcTestErrors =
      (ctx.artifacts.grpcTestErrors as string[] | undefined) ?? [];
    const grpcTestFailed = Boolean(ctx.artifacts.grpcTestFailed);

    const connectorStatus: "SUCCESS" | "FAILED" = grpcTestFailed
      ? "FAILED"
      : "SUCCESS";
    const failureReason = grpcTestFailed
      ? grpcTestErrors.join("; ") || grpcTest?.reason || "grpc_test failed"
      : "";

    let parsed: PRReviewResult;
    try {
      parsed = await runAI<PRReviewResult>({
        skillBody: SYSTEM,
        userPayload: {
          // 2.4_pr.md required inputs
          CONNECTOR: connector,
          FLOW: flow,
          DEV_BRANCH: devBranch,
          CONNECTOR_STATUS: connectorStatus,
          FAILURE_REASON: failureReason,
          GRPCURL_OUTPUT: grpcurlOutput,
          CONNECTOR_SOURCE_FILES: touched,
          // review-context fields (used for spec-compliance check)
          l2: ctx.artifacts.l2,
          l3: ctx.artifacts.l3,
          implementation: ctx.artifacts.implementation,
          files,
        },
        cwd: ctx.task.projectRoot,
        label: "pr_review",
        timeoutMs: 10 * 60 * 1000,
        allowWrite: true, // Grant full tool access to PR review agent
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[pr_review] AI runner failed: ${msg}`, "error");
      return {
        passed: false,
        errors: [`PR review AI call failed: ${msg}`],
      };
    }

    if (
      !parsed ||
      typeof parsed.approved !== "boolean" ||
      !Array.isArray(parsed.comments)
    ) {
      return {
        passed: false,
        errors: [
          `Invalid PR review JSON: ${JSON.stringify(parsed).slice(0, 300)}`,
        ],
      };
    }

    for (const c of parsed.comments) {
      const color = COLOR[c.severity] ?? "";
      // eslint-disable-next-line no-console
      console.log(
        `${color}[${c.severity.toUpperCase()}]\x1b[0m ${c.file}${c.line ? `:${c.line}` : ""} — ${c.comment}`,
      );
    }

    // Surface the PR-creation outputs in engine logs so they're visible
    // before any retry/failure path runs. The dashboard already gets the
    // full prReview artifact via artifact:update.
    if (parsed.status) {
      const level = parsed.status === "SUCCESS" ? "info" : "warn";
      ctx.log(`[pr_review] PR status: ${parsed.status}`, level);
    }
    if (parsed.prUrl) {
      ctx.log(`[pr_review] PR URL: ${parsed.prUrl}`, "info");
    }
    if (parsed.prBranch) {
      ctx.log(`[pr_review] PR branch: ${parsed.prBranch}`, "info");
    }

    // Lowered threshold for more permissive reviews
    const scoreOk = parsed.specComplianceScore >= 0.6;
    // Auto-pass if approved and score is ok
    const autoPass = parsed.approved && scoreOk;

    if (autoPass) {
      return { passed: true, artifacts: { prReview: parsed } };
    }

    // If autoApproveReviews is enabled, pass despite issues
    if (ctx.options.autoApproveReviews) {
      ctx.log("[pr_review] Auto-approving despite issues (autoApproveReviews enabled)", "warn");
      return { passed: true, artifacts: { prReview: parsed } };
    }

    const cfg = getConfig().checkpoints.pr_review;
    // If human approval is not required, pass through to allow pushing changes
    if (!cfg.requireHumanApproval) {
      ctx.log("[pr_review] Passing without human approval (requireHumanApproval: false)", "warn");
      return { passed: true, artifacts: { prReview: parsed } };
    }

    const timeoutMs = cfg.humanApprovalTimeoutMs;
    const promptP = askYesNo(
      `Manual override: approve this PR despite the review? (score=${parsed.specComplianceScore})`,
      false,
    );
    const timeoutP = new Promise<boolean>((resolve) =>
      setTimeout(() => resolve(false), timeoutMs),
    );
    const approved = await Promise.race([promptP, timeoutP]);
    if (approved) {
      return {
        passed: true,
        artifacts: { prReview: { ...parsed, approved: true } },
      };
    }
    return {
      passed: false,
      errors: ["Human reviewer rejected PR review"],
      artifacts: { prReview: parsed },
    };
  },
};
