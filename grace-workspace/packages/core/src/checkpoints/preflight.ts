import type { Checkpoint } from "../types.js";
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

export const preflightCheckpoint: Checkpoint = {
  id: "preflight",
  name: "Preflight Setup",
  description: "Create git branch and verify prerequisites for implementation",
  retryFrom: "preflight",
  timeout: 5 * 60 * 1000, // 5 min
  async run(ctx) {
    const task = ctx.artifacts.task;
    if (!task) {
      return { passed: false, errors: ["Missing task artifact"] };
    }

    const connector = task.targetConnectors?.[0] || "unknown";
    const flow = task.paymentMethod || "unknown";
    // Working dev branch — kept distinct from the PR branch the pr_review
    // agent creates from origin/main in 2.4_pr.md Phase 2. Same prefix would
    // collide on `git checkout -b` in that phase, so we suffix with `-dev`.
    const devBranch = `feat/grace-${connector.toLowerCase()}-${flow.toLowerCase()}-dev`;

    ctx.log("[preflight] Following Grace workflow: 1_orchestrator.md", "info");
    ctx.log(`[preflight] Dev branch: ${devBranch}`, "info");

    try {
      // Check if we're in a git repo
      const projectRoot = task.projectRoot;
      const gitDir = path.join(projectRoot, ".git");
      if (!existsSync(gitDir)) {
        return { passed: false, errors: ["Not a git repository"] };
      }

      // Create-or-reset the dev branch. `-B` (vs `-b`) is the documented
      // idempotent form: it reuses the branch if it exists instead of
      // failing on retries.
      ctx.log(`[preflight] git checkout -B ${devBranch}`, "info");
      execSync(`git checkout -B ${devBranch}`, { cwd: projectRoot, stdio: "pipe" });

      // Verify creds.json exists
      const credsPath = path.join(projectRoot, "creds.json");
      if (existsSync(credsPath)) {
        ctx.log("[preflight] Credentials file found", "info");
      } else {
        ctx.log("[preflight] Warning: creds.json not found", "warn");
      }

      ctx.log(`[preflight] ✓ Ready on dev branch: ${devBranch}`, "success");

      return {
        passed: true,
        artifacts: {
          // `branch` retained for any existing dashboard consumers; `devBranch`
          // is the canonical name pr_review reads as DEV_BRANCH input.
          branch: devBranch,
          devBranch,
          projectRoot,
        },
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[preflight] Failed: ${msg}`, "error");
      return {
        passed: false,
        errors: [`Preflight failed: ${msg}`],
      };
    }
  },
};
