import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ALL_CHECKPOINTS,
  PipelineEngine,
  PipelineEventBus,
  StateManager,
  loadConfig,
  newRunId,
  setConfig,
  checkAIHealth,
  type CheckpointId,
  type CheckpointStatus,
  type PipelineContext,
  type PipelineOptions,
  type TaskDefinition,
} from "@byne/core";

interface RunOpts {
  taskFile?: string;
  startFrom?: CheckpointId;
  project?: string;
  dryRun?: boolean;
  maxRetries?: number;
  threshold?: number;
  dashboard?: boolean;
  autoApproveReviews?: boolean;
  reviewTimeout?: number;
  resume?: string;
  config?: string;
  taskFromUi?: boolean;
  autoMode?: boolean;
}

/**
 * Which artifact keys each checkpoint produces. Used by the rewind path on
 * resume-from-step so re-running a stage doesn't see its own stale output
 * in the LLM context.
 */
const ARTIFACT_KEYS_BY_STAGE: Record<string, string[]> = {
  task: [],
  product_alignment: ["productAlignment", "pmClarifications"],
  feature_research: ["featureResearch"],
  design_gate: ["designGate"],
  l2_gen: ["l2"],
  l2_review: ["l2Review", "l2RegeneratePrompt", "previousL2"],
  l3_gen: ["l3"],
  l3_review: ["l3Review", "l3RegeneratePrompt", "previousL3"],
  l4_gen: ["l4"],
  l4_review: ["l4Review", "l4RegeneratePrompt", "previousL4"],
  implementation: ["implementation", "implementationFiles"],
  compiler: ["compiledFiles"],
  design_match: ["designDiff"],
  cypress: ["cypressReport"],
  playwright: ["playwrightReport"],
  pr_review: ["prReview"],
  regression: ["regression"],
};

export async function runCommand(opts: RunOpts): Promise<void> {
  const cfg = loadConfig(opts.config);
  setConfig(cfg);

  if (opts.project) cfg.projectRoot = path.resolve(opts.project);

  const state = new StateManager();

  // Clean out any empty/abandoned runs from prior sessions.
  try {
    const pruned = await state.pruneEmptyRuns();
    if (pruned > 0) {
      // eslint-disable-next-line no-console
      console.log(`\x1b[90m[byne] pruned ${pruned} empty run(s)\x1b[0m`);
    }
  } catch {
    /* ignore */
  }

  // node --watch handoff: check for a pending resume intent written by a prior
  // dashboard "resume from stage" click.
  const resumeFile = path.join(os.homedir(), ".byne", "resume.json");
  let autoResume: { runId: string; startFrom?: CheckpointId } | undefined;
  try {
    if (fs.existsSync(resumeFile)) {
      const txt = fs.readFileSync(resumeFile, "utf-8");
      autoResume = JSON.parse(txt);
      fs.unlinkSync(resumeFile); // consume it
      // eslint-disable-next-line no-console
      console.log(
        `\x1b[35m[byne] handoff file consumed: resume=${autoResume?.runId} startFrom=${autoResume?.startFrom ?? "(auto)"}\x1b[0m`
      );
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[byne] bad handoff file:`, err);
  }
  if (autoResume && !opts.resume) opts.resume = autoResume.runId;
  if (autoResume?.startFrom && !opts.startFrom)
    opts.startFrom = autoResume.startFrom;

  let runId: string;
  let task: TaskDefinition;
  let artifacts: Record<string, unknown> = {};
  let retryCount: Record<string, number> = {};

  if (opts.resume) {
    const preLoad = await state.load(opts.resume);
    if (!preLoad) {
      // eslint-disable-next-line no-console
      console.warn(
        `\x1b[33m[byne] resume target ${opts.resume} not found — falling back to a fresh run\x1b[0m`
      );
      opts.resume = undefined;
      opts.startFrom = undefined;
    }
  }

  if (opts.resume) {
    const saved = await state.load(opts.resume);
    if (!saved) {
      throw new Error(`No saved run with id ${opts.resume}`);
    }
    runId = saved.runId;
    task = saved.task;
    artifacts = saved.artifacts;
    retryCount = saved.retryCount;
    // Ensure the task is also in the artifacts so the task checkpoint
    // doesn't re-prompt when resuming.
    if (!artifacts.task) artifacts.task = task;

    // eslint-disable-next-line no-console
    console.log(
      `\x1b[90m[byne] loaded run ${runId} — saved checkpoint states:\x1b[0m`
    );
    for (const cp of ALL_CHECKPOINTS) {
      const st = saved.checkpointStates[cp.id] ?? "(none)";
      // eslint-disable-next-line no-console
      console.log(`\x1b[90m         ${cp.id.padEnd(20)} ${st}\x1b[0m`);
    }

    // Auto-compute resume point: first non-passed checkpoint in pipeline order.
    if (!opts.startFrom) {
      const firstUnfinished = ALL_CHECKPOINTS.find(
        (c) =>
          (saved.checkpointStates[c.id] as CheckpointStatus | undefined) !==
          "passed"
      );
      if (firstUnfinished) {
        opts.startFrom = firstUnfinished.id;
        // eslint-disable-next-line no-console
        console.log(
          `\x1b[35m[byne] auto-resuming at "${firstUnfinished.id}" (first non-passed)\x1b[0m`
        );
      } else {
        // eslint-disable-next-line no-console
        console.log(
          `\x1b[32m[byne] run was already complete — nothing to resume\x1b[0m`
        );
        return;
      }
    } else {
      // eslint-disable-next-line no-console
      console.log(
        `\x1b[35m[byne] explicit resume at "${opts.startFrom}"\x1b[0m`
      );
    }

    // Resume semantics: "give it another go, fresh". Reset the retry counter
    // for the stage we're resuming at + every downstream stage, AND wipe the
    // stored artifacts those stages produced so the re-run doesn't see its
    // own stale output in context.
    if (opts.startFrom) {
      const startIdx = ALL_CHECKPOINTS.findIndex((c) => c.id === opts.startFrom);
      if (startIdx >= 0) {
        const clearedStages: CheckpointId[] = [];
        const clearedKeys: string[] = [];
        for (let i = startIdx; i < ALL_CHECKPOINTS.length; i++) {
          const cpId = ALL_CHECKPOINTS[i]!.id;
          clearedStages.push(cpId);
          retryCount[cpId] = 0;
          for (const key of ARTIFACT_KEYS_BY_STAGE[cpId] ?? []) {
            if (artifacts[key] !== undefined) {
              delete artifacts[key];
              clearedKeys.push(key);
            }
          }
        }
        // eslint-disable-next-line no-console
        console.log(
          `\x1b[35m[byne] rewind: reset retry counters for ${clearedStages.length} stage(s) from "${opts.startFrom}"\x1b[0m`
        );
        if (clearedKeys.length > 0) {
          // eslint-disable-next-line no-console
          console.log(
            `\x1b[35m[byne] rewind: cleared artifacts: ${clearedKeys.join(", ")}\x1b[0m`
          );
        }
        // Persist the rewound state so the DB reflects reality before engine.run
        await state.rewindRun(runId, artifacts, retryCount, clearedStages);
      }
    }
  } else {
    runId = newRunId();
    if (opts.taskFile) {
      const raw = fs.readFileSync(opts.taskFile, "utf-8");
      task = JSON.parse(raw) as TaskDefinition;
      if (!task.projectRoot) task.projectRoot = cfg.projectRoot;
      artifacts = { task };
    } else {
      task = {
        title: "",
        description: "",
        acceptanceCriteria: [],
        projectRoot: cfg.projectRoot,
      };
    }
  }

  const bus = opts.dashboard === false ? undefined : new PipelineEventBus(runId, cfg.wsPort);

  // Inbound dashboard commands: abort, list runs, resume a run.
  if (bus) {
    (
      bus as unknown as {
        onInbound: (h: (m: { type: string; payload?: any }) => void) => void;
      }
    ).onInbound(async (msg) => {
      if (msg.type === "pipeline:abort") {
        // eslint-disable-next-line no-console
        console.log(
          "\x1b[31m[byne] pipeline:abort received from dashboard — exiting\x1b[0m"
        );
        bus.emit("pipeline:abort", undefined, { error: "cancelled from dashboard" });
        try {
          const entry = process.argv[1];
          if (entry && fs.existsSync(entry)) {
            const now = new Date();
            fs.utimesSync(entry, now, now);
          }
        } catch {
          /* ignore */
        }
        setTimeout(() => process.exit(0), 150);
        return;
      }

      if (msg.type === "auto-mode:set") {
        const p = msg.payload as { enabled: boolean; agentName?: string };
        pipelineOptions.autoMode = !!p?.enabled;
        pipelineOptions.agentName = p?.agentName?.trim() || undefined;
        const label = pipelineOptions.agentName || "auto-reviewer";
        // eslint-disable-next-line no-console
        console.log(
          `\x1b[35m[byne] auto-mode ${pipelineOptions.autoMode ? "ON" : "OFF"} (agent: ${label})\x1b[0m`
        );
        bus.emit("auto-mode:state", undefined, {
          enabled: pipelineOptions.autoMode,
          agentName: pipelineOptions.agentName,
        });
        return;
      }

      if (msg.type === "runs:list") {
        try {
          const runs = await state.listRuns();
          // Fetch per-checkpoint status for each so the UI can show a quick summary
          const withHistory = await Promise.all(
            runs.map(async (r) => ({
              ...r,
              checkpoints: await state.getCheckpointHistory(r.runId),
            }))
          );
          // eslint-disable-next-line no-console
          console.log(
            `\x1b[90m[byne] runs:list → ${withHistory.length} run(s)\x1b[0m`
          );
          bus.emit("runs:list:response", undefined, { runs: withHistory });
        } catch (err) {
          bus.emit("runs:list:response", undefined, {
            runs: [],
            error: err instanceof Error ? err.message : String(err),
          });
        }
        return;
      }

      if (msg.type === "runs:new") {
        // Start a brand-new run: delete any pending resume marker so the
        // restarted engine doesn't auto-resume the current run, then bounce
        // the entry file so `node --watch` restarts. The new process will
        // create a fresh runId and wait for task:submit from the dashboard.
        try {
          const resumePath = path.join(os.homedir(), ".byne", "resume.json");
          if (fs.existsSync(resumePath)) fs.unlinkSync(resumePath);
          // eslint-disable-next-line no-console
          console.log(
            `\x1b[35m[byne] runs:new received — restarting engine for a fresh run\x1b[0m`
          );
          bus.emit("runs:new:ack", undefined, { ok: true });
          try {
            const entry =
              process.argv[1] && fs.existsSync(process.argv[1])
                ? process.argv[1]
                : null;
            if (entry) {
              const content = fs.readFileSync(entry);
              fs.writeFileSync(entry, content);
            }
          } catch (err) {
            // eslint-disable-next-line no-console
            console.error(`[byne] runs:new: failed to bounce entry file:`, err);
          }
          setTimeout(() => process.exit(0), 250);
        } catch (err) {
          bus.emit("runs:new:ack", undefined, {
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
        return;
      }

      if (msg.type === "runs:resume") {
        const target = msg.payload as { runId: string; startFrom?: CheckpointId };
        if (!target?.runId) return;
        try {
          fs.mkdirSync(path.join(os.homedir(), ".byne"), { recursive: true });
          fs.writeFileSync(
            path.join(os.homedir(), ".byne", "resume.json"),
            JSON.stringify(target),
            "utf-8"
          );
          bus.emit("runs:resuming", undefined, target);
          // eslint-disable-next-line no-console
          console.log(
            `\x1b[35m[byne] resume requested for ${target.runId}${target.startFrom ? ` from ${target.startFrom}` : ""} — restarting engine\x1b[0m`
          );
          // Force `node --watch` to restart by rewriting the entry file's bytes.
          // `utimesSync` (mtime-only) is unreliable on macOS FSEvents — a real
          // content write guarantees a change event fires.
          try {
            const entry =
              process.argv[1] && fs.existsSync(process.argv[1])
                ? process.argv[1]
                : null;
            if (entry) {
              const content = fs.readFileSync(entry);
              fs.writeFileSync(entry, content);
            }
          } catch (err) {
            // eslint-disable-next-line no-console
            console.error(`[byne] resume: failed to bounce entry file:`, err);
          }
          // Exit after a beat so the rewrite + bus flush can propagate.
          setTimeout(() => process.exit(0), 250);
        } catch (err) {
          bus.emit("runs:resuming", undefined, {
            error: err instanceof Error ? err.message : String(err),
          });
        }
        return;
      }
    });
  }

  // Auto-enable UI task input when the dashboard is on and we're not in CI-auto mode.
  // (We intentionally keep this on for resume — the dashboard is still the input surface.)
  const autoTaskFromUi =
    opts.dashboard !== false && !opts.autoApproveReviews;

  const pipelineOptions: PipelineOptions = {
    autoApproveReviews: opts.autoApproveReviews,
    reviewTimeoutMs: opts.reviewTimeout,
    dryRun: opts.dryRun,
    maxRetries: opts.maxRetries ?? cfg.maxRetries,
    designMatchThreshold: opts.threshold ?? cfg.designMatchThreshold,
    devServerUrl: cfg.devServerUrl,
    regressionCommand: cfg.checkpoints.regression.command,
    dashboard: opts.dashboard !== false,
    model: cfg.llm.model,
    taskFromUi: opts.taskFromUi ?? autoTaskFromUi,
    autoMode: opts.autoMode,
  };

  const ctx: PipelineContext = {
    runId,
    task,
    artifacts,
    retryCount,
    options: pipelineOptions,
    bus: bus
      ? {
          waitFor: (type, timeoutMs) => bus.waitFor(type, timeoutMs),
          emit: (type, cp, payload) => bus.emit(type, cp, payload),
          emitHumanWaiting: (cp, spec) => bus.emitHumanWaiting(cp, spec),
        }
      : undefined,
    log: (msg, level = "info") => {
      const cleaned = msg.replace(/^\[\w+\]\s*/, "");
      if (bus) bus.log(inferCheckpoint(msg), cleaned, level);
      else {
        const ts = new Date().toISOString();
        // eslint-disable-next-line no-console
        console.log(`${ts} ${level.toUpperCase()} ${msg}`);
      }
    },
  };

  // When resuming, replay saved checkpoint statuses and artifacts so the dashboard
  // rebuilds the sidebar state immediately. Use the in-memory `artifacts` (which
  // already has `task` merged in via line 92) rather than re-reading from the DB —
  // runs that never finished the `task` checkpoint won't have it in artifacts_json.
  if (opts.resume && bus) {
    const saved = await state.load(opts.resume);
    if (saved) {
      for (const [cpId, status] of Object.entries(saved.checkpointStates)) {
        bus.emit("checkpoint:status", cpId as CheckpointId, { status });
      }
      bus.emit("artifact:update", undefined, { artifacts });
      bus.emit("task:accepted", "task", { task });
    }
  }

  // Broadcast initial auto-mode state so new dashboard connections see the toggle.
  if (bus) {
    bus.emit("auto-mode:state", undefined, {
      enabled: !!pipelineOptions.autoMode,
      agentName: pipelineOptions.agentName,
    });
  }

  // eslint-disable-next-line no-console
  console.log(`\x1b[1m\x1b[35m[byne] runId=${runId}\x1b[0m`);
  // eslint-disable-next-line no-console
  console.log(`\x1b[90m[byne] project=${task.projectRoot}\x1b[0m`);
  // eslint-disable-next-line no-console
  console.log(
    `\x1b[90m[byne] taskFromUi=${pipelineOptions.taskFromUi} dashboard=${pipelineOptions.dashboard} llm=${cfg.llm.model}@${cfg.llm.baseUrl}\x1b[0m`
  );
  // eslint-disable-next-line no-console
  console.log(`\x1b[90m[byne] built from ${new Date().toISOString()} runtime load\x1b[0m`);

  // Pre-flight: check AI runner connectivity
  const aiHealth = await checkAIHealth();
  const runnerLabel = aiHealth.runner === "claude-code" ? "Claude Code" : "OpenCode";
  if (aiHealth.connected) {
    // eslint-disable-next-line no-console
    console.log(
      `\x1b[32m[byne] ✓ ${runnerLabel} connected (${aiHealth.connectionInfo}${aiHealth.latencyMs ? `, ${aiHealth.latencyMs}ms` : ""})\x1b[0m`
    );
  } else {
    // eslint-disable-next-line no-console
    console.log(
      `\x1b[31m[byne] ✕ ${runnerLabel} NOT connected — ${aiHealth.error}\x1b[0m`
    );
    if (aiHealth.runner === "opencode") {
      // eslint-disable-next-line no-console
      console.log(
        `\x1b[33m[byne]   Implementation steps may fail. Start opencode with: opencode serve\x1b[0m`
      );
    } else {
      // eslint-disable-next-line no-console
      console.log(
        `\x1b[33m[byne]   Implementation steps may fail. Ensure 'claude' CLI is installed.\x1b[0m`
      );
    }
  }
  if (bus) {
    bus.emit("ai:health", undefined, aiHealth);
  }

  const engine = new PipelineEngine(ALL_CHECKPOINTS, state, bus);

  try {
    await engine.run(ctx, opts.startFrom);
  } catch (err) {
    ctx.log(`Pipeline aborted: ${err instanceof Error ? err.message : String(err)}`, "error");
    bus?.emit("pipeline:abort", undefined, {
      error: err instanceof Error ? err.message : String(err),
    });
    process.exitCode = 1;
  } finally {
    bus?.close();
    state.close();
  }
}

function inferCheckpoint(msg: string): "pipeline" | CheckpointId {
  const m = msg.match(/^\[(\w+)\]/);
  if (!m) return "pipeline";
  return m[1] as CheckpointId;
}
