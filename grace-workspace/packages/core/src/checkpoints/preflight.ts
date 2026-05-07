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
    const branchName = `feat/grace-${connector.toLowerCase()}-${flow.toLowerCase()}`;

    ctx.log("[preflight] Following Grace workflow: 1_orchestrator.md", "info");
    ctx.log(`[preflight] Creating branch: ${branchName}`, "info");

    try {
      // Check if we're in a git repo
      const projectRoot = task.projectRoot;
      const gitDir = path.join(projectRoot, ".git");
      if (!existsSync(gitDir)) {
        return { passed: false, errors: ["Not a git repository"] };
      }

      // Pull latest changes on current branch
      // ctx.log("[preflight] Pulling latest changes...", "info");
      // execSync("git pull", { cwd: projectRoot, stdio: "pipe" });

      // Create and checkout the new feature branch
      ctx.log(`[preflight] Creating and checking out branch: ${branchName}`, "info");
      execSync(`git checkout -b ${branchName}`, { cwd: projectRoot, stdio: "pipe" });

      // Verify creds.json exists
      const credsPath = path.join(projectRoot, "creds.json");
      if (existsSync(credsPath)) {
        ctx.log("[preflight] Credentials file found", "info");
      } else {
        ctx.log("[preflight] Warning: creds.json not found", "warn");
      }

      ctx.log(`[preflight] ✓ Ready on branch: ${branchName}`, "success");

      return {
        passed: true,
        artifacts: {
          branch: branchName,
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
