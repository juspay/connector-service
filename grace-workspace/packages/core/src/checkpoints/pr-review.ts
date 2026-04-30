import path from "node:path";
import { promises as fs } from "node:fs";
import type { Checkpoint, PRReviewResult } from "../types.js";
import { runOpencode } from "../tools/opencode-runner.js";
import { safeParseJson } from "../utils.js";
import { getConfig } from "../config.js";
import { askYesNo } from "../prompts/cli-prompts.js";

const SYSTEM = `You are a senior engineer performing a spec-compliance code review on a hyperswitch-prism PR.

## Reference Workflow

FOLLOW the workflow defined in:
- Local: /Users/tushar.shukla/Downloads/Work/UCS-dup/connector-service/grace/workflow/2.4_pr.md
- GitHub: https://github.com/juspay/hyperswitch-prism/blob/main/grace/workflow/2.4_pr.md

This defines the complete PR creation workflow including:
- Phase 1: Commit on Dev Branch
- Phase 2: Prepare the PR Branch (cherry-pick from dev)
- Phase 3: Credential Scrub (MANDATORY)
- Phase 4: Push the Branch
- Phase 5: Prepare PR Description
- Phase 6: Create the Pull Request

Key rules from the reference:
- Target repo: juspay/hyperswitch-prism
- Use --repo flag for all gh commands
- Credential scrub is mandatory
- Sanitize ALL grpcurl output
- Failed connectors get "do not merge" label

## Your Task

You will receive: the L2/L3/L4 spec and the generated files (path + contents) plus test results.

SPAWN MULTIPLE SUB-AGENTS to review different aspects in parallel:
1. One sub-agent to check spec compliance (do files match the L4 plan?)
2. One sub-agent to verify acceptance criteria coverage
3. One sub-agent to check code quality and patterns
4. One sub-agent to review test coverage

Each sub-agent should use tools (read_file, glob, grep) to verify their assigned aspect.

After collecting all sub-agent reports, synthesize into a final review.

Return ONLY valid JSON:
{
  "approved": boolean,
  "specComplianceScore": number (0..1),
  "comments": [{ "file": "string", "line": number | null, "comment": "string", "severity": "info"|"warning"|"blocking" }]
}
Flag spec deviations, missing acceptance criteria coverage, and obvious defects.`;

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
  retryFrom: "compiler",
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

    let parsed: PRReviewResult;
    try {
      parsed = await runOpencode<PRReviewResult>({
        skillBody: SYSTEM,
        userPayload: {
          l2: ctx.artifacts.l2,
          l3: ctx.artifacts.l3,
          implementation: ctx.artifacts.implementation,
          files,
          cypressReport: ctx.artifacts.cypressReport,
          playwrightReport: ctx.artifacts.playwrightReport,
        },
        cwd: ctx.task.projectRoot,
        label: "pr_review",
        timeoutMs: 10 * 60 * 1000,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[pr_review] opencode failed: ${msg}`, "error");
      return {
        passed: false,
        errors: [`PR review opencode call failed: ${msg}`],
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

    const hasBlocking = parsed.comments.some((c) => c.severity === "blocking");
    const scoreOk = parsed.specComplianceScore >= 0.8;
    const autoPass = parsed.approved && !hasBlocking && scoreOk;

    if (autoPass) {
      return { passed: true, artifacts: { prReview: parsed } };
    }

    // Human override
    if (ctx.options.autoApproveReviews) {
      return {
        passed: false,
        errors: [
          hasBlocking
            ? "blocking comments present"
            : `spec compliance ${parsed.specComplianceScore}`,
        ],
        artifacts: { prReview: parsed },
      };
    }

    const cfg = getConfig().checkpoints.pr_review;
    if (!cfg.requireHumanApproval) {
      return {
        passed: false,
        errors: ["PR review not approved and human override disabled"],
        artifacts: { prReview: parsed },
      };
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
