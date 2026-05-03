import path from "node:path";
import type { Checkpoint, TaskDefinition } from "../types.js";
import { ask, askMultiline } from "../prompts/cli-prompts.js";
import { getConfig, setConfig } from "../config.js";

function validTask(t: unknown): t is TaskDefinition {
  if (!t || typeof t !== "object") return false;
  const r = t as Record<string, unknown>;
  return (
    typeof r.title === "string" &&
    (r.title as string).trim().length > 0 &&
    Array.isArray(r.acceptanceCriteria)
  );
}

export const taskCheckpoint: Checkpoint = {
  id: "task",
  name: "Task definition",
  description: "Collect the task description, acceptance criteria, and target project root.",
  retryFrom: "task",
  timeout: 24 * 60 * 60 * 1000,
  async run(ctx) {
    // If the task is already populated (resume, config-supplied, or re-entry), reuse it.
    // Only the title is required — description and acceptance criteria are optional.
    const existing = ctx.artifacts.task;
    if (existing && existing.title?.trim()) {
      ctx.task = existing;
      ctx.log(`Re-using task from saved state: "${existing.title}"`, "info");
      return { passed: true, artifacts: { task: existing } };
    }

    // UI-driven mode: wait for a task:submit message over WebSocket.
    if (ctx.options.taskFromUi) {
      if (!ctx.bus) {
        return {
          passed: false,
          errors: ["--task-from-ui requires dashboard WebSocket to be enabled"],
        };
      }
      ctx.log(
        "[task] ⏳ Waiting for task submission from the dashboard (http://localhost:3141)...",
        "warn"
      );
      ctx.bus.emit("task:awaiting", "task", { waitingForTaskInput: true });
      ctx.bus.emitHumanWaiting("task", { waitingForTaskInput: true });
      while (true) {
        const payload = await ctx.bus.waitFor<Partial<TaskDefinition>>("task:submit");
        const cfg = getConfig();
        const candidate: TaskDefinition = {
          title: payload.title ?? "",
          description: payload.description ?? "",
          acceptanceCriteria: Array.isArray(payload.acceptanceCriteria)
            ? payload.acceptanceCriteria
            : [],
          connectorDocUrls: Array.isArray(payload.connectorDocUrls)
            ? payload.connectorDocUrls
            : undefined,
          targetFiles: payload.targetFiles,
          projectRoot: path.isAbsolute(payload.projectRoot ?? "")
            ? (payload.projectRoot as string)
            : path.resolve(payload.projectRoot || cfg.projectRoot),
          attachments: Array.isArray(payload.attachments)
            ? payload.attachments
            : undefined,
          // GRACE/Byne workflow fields
          paymentMethod: payload.paymentMethod,
          targetConnectors: Array.isArray(payload.targetConnectors)
            ? payload.targetConnectors
            : undefined,
          paymentMethodCategory: payload.paymentMethodCategory,
          priority: payload.priority,
          connectorDocs: Array.isArray(payload.connectorDocs)
            ? payload.connectorDocs
            : undefined,
          prerequisites: Array.isArray(payload.prerequisites)
            ? payload.prerequisites
            : undefined,
          estimatedComplexity: payload.estimatedComplexity,
          runner: payload.runner,
          runnerModel: payload.runnerModel,
        };
        if (!validTask(candidate)) {
          ctx.bus.emit("task:rejected", "task", {
            reason: "Invalid task — a non-empty title is required",
          });
          ctx.log("[task] Submitted task rejected — waiting for another.", "warn");
          continue;
        }

        // Apply runner configuration from the task
        if (candidate.runner) {
          const cfg = getConfig();
          cfg.runner = candidate.runner;
          if (candidate.runnerModel) {
            if (candidate.runner === "claude-code") {
              cfg.claudeCode.model = candidate.runnerModel;
            } else {
              cfg.opencode.model = candidate.runnerModel;
            }
          }
          setConfig(cfg);
          ctx.log(`[task] Using AI runner: ${candidate.runner}${candidate.runnerModel ? ` (${candidate.runnerModel})` : ""}`, "info");
        }

        ctx.task = candidate;
        ctx.bus.emit("task:accepted", "task", { task: candidate });
        ctx.log(`[task] ✓ Received task from UI: "${candidate.title}"`, "success");
        return { passed: true, artifacts: { task: candidate } };
      }
    }

    const cfg = getConfig();
    const title = await ask("Task title: ");
    const description = await askMultiline("Task description:");
    if (!description.trim()) {
      return { passed: false, errors: ["Description is required"] };
    }

    const criteriaRaw = await askMultiline(
      "Acceptance criteria (one per line, at least 2):"
    );
    const acceptanceCriteria = criteriaRaw
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (acceptanceCriteria.length < 2) {
      return {
        passed: false,
        errors: [`Need at least 2 acceptance criteria (got ${acceptanceCriteria.length})`],
      };
    }

    const connectorDocUrlsRaw = await ask("Connector reference document URLs (comma-separated, optional): ");
    const connectorDocUrls = connectorDocUrlsRaw
      ? connectorDocUrlsRaw.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined;
    const targetRaw = await ask("Target file paths (comma-separated, optional): ");
    const targetFiles = targetRaw
      ? targetRaw.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined;

    const projectRootInput = await ask(
      `Project root [${cfg.projectRoot}]: `
    );
    const projectRoot = path.resolve(projectRootInput || cfg.projectRoot);

    const task: TaskDefinition = {
      title,
      description,
      acceptanceCriteria,
      connectorDocUrls,
      targetFiles,
      projectRoot,
    };
    ctx.task = task;
    return { passed: true, artifacts: { task } };
  },
};
