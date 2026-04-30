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

    const paymentMethod = task.paymentMethod || "unknown";
    const now = new Date();
    const date = now.toISOString().split("T")[0].replace(/-/g, "");
    const time = now.toTimeString().split(" ")[0].replace(/:/g, ""); // HHMMSS
    const branchName = `feat/byne-${paymentMethod.toLowerCase()}-${date}-${time}`;

    ctx.log("[preflight] Following Grace workflow: 1_orchestrator.md", "info");
    ctx.log(`[preflight] Creating branch: ${branchName}`, "info");

    try {
      // Check if we're in a git repo
      const projectRoot = task.projectRoot;
      const gitDir = path.join(projectRoot, ".git");
      if (!existsSync(gitDir)) {
        return { passed: false, errors: ["Not a git repository"] };
      }

      // Checkout add-grace-app branch
      ctx.log("[preflight] Checking out add-grace-app branch...", "info");
      execSync("git checkout add-grace-app", { cwd: projectRoot, stdio: "pipe" });

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
