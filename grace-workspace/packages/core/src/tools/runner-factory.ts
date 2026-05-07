import { getConfig, type RunnerType } from "../config.js";
import {
  runOpencode,
  checkOpencodeHealth,
  type OpencodeRunOptions,
  type OpencodeHealthResult,
} from "./opencode-runner.js";
import {
  runClaudeCode,
  checkClaudeCodeHealth,
  type ClaudeCodeRunOptions,
  type ClaudeCodeHealthResult,
} from "./claude-code-runner.js";

/**
 * Unified options for running AI tasks - compatible with both OpenCode and Claude Code.
 * This is a superset of both OpencodeRunOptions and ClaudeCodeRunOptions.
 */
export interface AIRunOptions {
  /** The skill body / system prompt — describes what to produce. */
  skillBody: string;
  /** Structured user payload (JSON-serializable). */
  userPayload: unknown;
  /** Working directory the runner should run in (the target repo root). */
  cwd: string;
  /** Short label for logs. */
  label: string;
  /** Optional model override. */
  model?: string;
  /** Hard timeout in ms. Default 10 min. */
  timeoutMs?: number;
  /**
   * If true, the answer is treated as raw text and returned as a string
   * instead of JSON.parse'd. Use for research / summary agents that return
   * markdown or plain prose.
   */
  rawText?: boolean;
  /** Additional CLI arguments to pass to the runner. */
  extraArgs?: string[];
  /**
   * If true, the agent is allowed to use all tools including write and edit.
   * Default is false (read-only tools).
   */
  allowWrite?: boolean;
}

/**
 * Unified health result type - compatible with both runner health results.
 */
export interface AIHealthResult {
  connected: boolean;
  /** The runner type that was checked. */
  runner: RunnerType;
  /** URL or version info depending on runner type. */
  connectionInfo?: string;
  error?: string;
  latencyMs?: number;
}

/**
 * Interface that both runners must implement.
 */
export interface RunnerInterface {
  run<T>(opts: AIRunOptions): Promise<T>;
  checkHealth(): Promise<AIHealthResult>;
}

/**
 * Get the currently configured runner type.
 */
export function getConfiguredRunner(): RunnerType {
  return getConfig().runner ?? "opencode";
}

/**
 * Check if the configured runner is healthy.
 * This is a unified health check that works with both OpenCode and Claude Code.
 */
export async function checkAIHealth(): Promise<AIHealthResult> {
  const runner = getConfiguredRunner();

  if (runner === "claude-code") {
    const result = await checkClaudeCodeHealth();
    return {
      connected: result.connected,
      runner: "claude-code",
      connectionInfo: result.version,
      error: result.error,
      latencyMs: result.latencyMs,
    };
  } else {
    const result = await checkOpencodeHealth();
    return {
      connected: result.connected,
      runner: "opencode",
      connectionInfo: result.url,
      error: result.error,
      latencyMs: result.latencyMs,
    };
  }
}

/**
 * Run an AI task using the configured runner.
 * This is the main entry point for checkpoint code - it automatically
 * delegates to the appropriate runner based on configuration.
 */
export async function runAI<T = unknown>(opts: AIRunOptions): Promise<T> {
  const runner = getConfiguredRunner();

  if (runner === "claude-code") {
    const ccOpts: ClaudeCodeRunOptions = {
      skillBody: opts.skillBody,
      userPayload: opts.userPayload,
      cwd: opts.cwd,
      label: opts.label,
      model: opts.model,
      timeoutMs: opts.timeoutMs,
      rawText: opts.rawText,
      extraArgs: opts.extraArgs,
      allowWrite: opts.allowWrite,
    };
    return runClaudeCode<T>(ccOpts);
  } else {
    const ocOpts: OpencodeRunOptions = {
      skillBody: opts.skillBody,
      userPayload: opts.userPayload,
      cwd: opts.cwd,
      label: opts.label,
      model: opts.model,
      timeoutMs: opts.timeoutMs,
      rawText: opts.rawText,
    };
    return runOpencode<T>(ocOpts);
  }
}

/**
 * Temporarily override the runner for a single operation.
 * This is useful when the task specifies a different runner than the config.
 *
 * Usage:
 *   const result = await withRunner("claude-code", () => runAI({ ... }));
 */
export async function withRunner<T>(
  runner: RunnerType,
  fn: () => Promise<T>
): Promise<T> {
  const original = getConfig().runner;
  try {
    getConfig().runner = runner;
    return await fn();
  } finally {
    getConfig().runner = original;
  }
}
