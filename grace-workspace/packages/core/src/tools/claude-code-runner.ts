import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { getConfig } from "../config.js";

/**
 * Shells out to the local `claude` CLI to run a planning step.
 *
 * This runner provides equivalent functionality to opencode-runner but for
 * Anthropic's Claude Code CLI. It spawns the `claude` command with appropriate
 * flags and captures the output for downstream processing.
 *
 * To avoid brittle stdout parsing we instruct the prompt to reply with ONLY
 * the raw JSON in the chat message. Claude's stdout is captured for progress
 * logging and the final answer is extracted.
 */

export interface ClaudeCodeRunOptions {
  /** The skill body / system prompt — describes what to produce. */
  skillBody: string;
  /** Structured user payload (JSON-serializable). */
  userPayload: unknown;
  /** Working directory claude should run in (the target repo root). */
  cwd: string;
  /** Short label for logs. */
  label: string;
  /** Optional model override, e.g. "claude-sonnet-4-6". */
  model?: string;
  /** Hard timeout in ms. Default 10 min. */
  timeoutMs?: number;
  /**
   * If true, the answer is treated as raw text and returned as a string
   * instead of JSON.parse'd. Use for research / summary agents that return
   * markdown or plain prose.
   */
  rawText?: boolean;
  /** Additional CLI arguments to pass to claude. */
  extraArgs?: string[];
}

function dbg(...args: unknown[]) {
  // eslint-disable-next-line no-console
  console.error("\x1b[90m[claude-code]", ...args, "\x1b[0m");
}

export interface ClaudeCodeHealthResult {
  connected: boolean;
  version?: string;
  error?: string;
  latencyMs?: number;
}

/**
 * Check if the claude CLI is available and get its version.
 * Returns a result object with availability status and version info.
 */
export async function checkClaudeCodeHealth(): Promise<ClaudeCodeHealthResult> {
  const start = Date.now();

  return new Promise<ClaudeCodeHealthResult>((resolve) => {
    const child = spawn("claude", ["--version"], {
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    let stdout = "";
    let stderr = "";

    child.stdout!.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf-8");
    });

    child.stderr!.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf-8");
    });

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      resolve({
        connected: false,
        error: "Timeout checking claude version (5s)",
        latencyMs: Date.now() - start,
      });
    }, 5000);

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        connected: false,
        error: err.message,
        latencyMs: Date.now() - start,
      });
    });

    child.on("exit", (code) => {
      clearTimeout(timer);
      const latencyMs = Date.now() - start;

      if (code === 0) {
        const version = stdout.trim() || stderr.trim();
        resolve({
          connected: true,
          version: version || "unknown",
          latencyMs,
        });
      } else {
        resolve({
          connected: false,
          error: `claude --version exited with code ${code}: ${stderr || stdout}`,
          latencyMs,
        });
      }
    });
  });
}

export async function runClaudeCode<T = unknown>(
  opts: ClaudeCodeRunOptions
): Promise<T> {
  const absCwdEarly = path.resolve(opts.cwd);

  const answerInstructions = opts.rawText
    ? [
        "## How to return your answer",
        "",
        "IMPORTANT: Do NOT use your write or edit tools to create any files. Do NOT create answer.json or any other output files. Just reply in chat with your final report as plain text (markdown is fine).",
        "",
        "Use your read tools (Read, Grep, Glob, Bash) to gather evidence BEFORE replying. Then reply with the report directly in your message.",
      ]
    : [
        "## How to return your answer",
        "",
        "IMPORTANT: Do NOT use your write or edit tools to create any files. Do NOT create answer.json or any other output files. Do NOT write prose or explanation — reply with ONLY the raw JSON object in your chat message. No markdown fences, no thinking out loud, no preamble. The very first character of your reply must be `{` and the very last must be `}`.",
        "",
        "Use your read tools (Read, Grep, Glob, Bash) to gather evidence BEFORE replying. Then reply with ONLY the JSON.",
      ];

  const prompt = [
    opts.skillBody.trim(),
    "",
    "## Input",
    "",
    "```json",
    JSON.stringify(opts.userPayload, null, 2),
    "```",
    "",
    ...answerInstructions,
  ].join("\n");

  const absCwd = absCwdEarly;

  const cc = getConfig().claudeCode;
  // Caller override > config.yml > default. Env vars are escape hatches only.
  const model =
    opts.model ?? process.env.BYNE_CLAUDE_CODE_MODEL ?? cc.model;

  const args: string[] = [];

  // Add model if specified
  if (model) {
    args.push("--model", model);
  }

  // Add verbose output flags
  args.push("--verbose");

  // Add any extra args from config or options
  const extraArgs = opts.extraArgs ?? cc.extraArgs ?? [];
  if (extraArgs.length > 0) {
    args.push(...extraArgs);
  }

  // Add the prompt as the final argument
  args.push(prompt);

  const timeoutMs = opts.timeoutMs ?? cc.timeoutMs ?? 10 * 60 * 1000;
  const startedAt = Date.now();
  // eslint-disable-next-line no-console
  console.log(
    `\x1b[36m[claude-code] → ${opts.label} · cwd=${absCwd} · model=${model ?? "default"} · prompt=${prompt.length}ch\x1b[0m`
  );

  // Capture stdout and stderr to extract the model's answer and error details.
  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];

  await new Promise<void>((resolve, reject) => {
    const child = spawn("claude", args, {
      cwd: absCwd,
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    // Capture stdout into a buffer AND mirror it to process.stdout so the
    // user still sees claude's progress output in the engine logs.
    child.stdout!.on("data", (chunk: Buffer) => {
      stdoutChunks.push(chunk);
      process.stdout.write(chunk);
    });

    // Capture stderr for error diagnostics AND mirror to process.stderr.
    child.stderr!.on("data", (chunk: Buffer) => {
      stderrChunks.push(chunk);
      process.stderr.write(chunk);
    });

    const timer = setTimeout(() => {
      dbg(`timeout after ${timeoutMs}ms — killing claude`);
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 5000).unref();
      const stderr = Buffer.concat(stderrChunks).toString("utf-8").trim();
      const detail = stderr ? ` — stderr: ${stderr.slice(-500)}` : "";
      reject(new Error(`claude timed out after ${timeoutMs}ms (label: ${opts.label})${detail}`));
    }, timeoutMs);
    timer.unref();

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`claude spawn failed: ${err.message}`));
    });
    child.on("exit", (code, signal) => {
      clearTimeout(timer);
      const stderr = Buffer.concat(stderrChunks).toString("utf-8").trim();
      const detail = stderr ? ` — stderr: ${stderr.slice(-500)}` : "";
      if (signal) {
        reject(new Error(`claude killed by signal ${signal} (label: ${opts.label})${detail}`));
      } else if (code !== 0) {
        reject(new Error(`claude exited with code ${code} (label: ${opts.label})${detail}`));
      } else {
        resolve();
      }
    });
  });

  // Clean up stray files the model may have created (answer.json, answer.txt, etc.)
  const strayFiles = ["answer.json", "answer.txt"];
  for (const name of strayFiles) {
    const stray = path.join(absCwd, name);
    fs.rm(stray, { force: true }).catch(() => undefined);
  }
  // Also clean up temp directories if they exist
  fs.rm(path.join(absCwd, ".claude-tmp"), { recursive: true, force: true }).catch(() => undefined);

  const elapsed = Date.now() - startedAt;
  const raw = Buffer.concat(stdoutChunks).toString("utf-8");
  // eslint-disable-next-line no-console
  console.log(`\x1b[36m[claude-code] ← ${opts.label} · ${elapsed}ms · stdout=${raw.length}ch\x1b[0m`);

  if (!raw.trim()) {
    throw new Error(
      `claude finished but produced no output (label: ${opts.label}). stdout was empty.`
    );
  }

  // Strip BOM and ANSI escape codes.
  // eslint-disable-next-line no-control-regex
  let cleaned = raw.trim().replace(/^﻿/, "").replace(/\x1b\[[0-9;]*m/g, "");

  if (opts.rawText) {
    // Drop claude chrome lines ("> build", "[0m", etc.)
    const lines = cleaned.split("\n");
    const contentStart = lines.findIndex(
      (l) => l.trim().length > 0 && !l.trim().startsWith(">") && !l.startsWith("[0m")
    );
    if (contentStart >= 0) {
      cleaned = lines.slice(contentStart).join("\n").trim();
    }
    return cleaned as unknown as T;
  }

  // JSON mode: find the last complete JSON object in the output.
  // The model's chat reply may include tool-call chatter before the final JSON.
  if (cleaned.startsWith("```")) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "");
  }

  const lastBrace = cleaned.lastIndexOf("}");
  if (lastBrace >= 0) {
    let depth = 0;
    let start = -1;
    for (let i = lastBrace; i >= 0; i--) {
      if (cleaned[i] === "}") depth++;
      if (cleaned[i] === "{") depth--;
      if (depth === 0) {
        start = i;
        break;
      }
    }
    if (start >= 0) {
      cleaned = cleaned.slice(start, lastBrace + 1);
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    // The model may have output raw file contents instead of wrapping in
    // {"contents": "..."}. If the label looks like an implementation step
    // and the content looks like source code, auto-wrap it.
    if (opts.label.startsWith("implementation:") && cleaned.length > 20) {
      dbg(
        `${opts.label}: JSON parse failed — auto-wrapping as {contents} (${cleaned.length}ch)`
      );
      parsed = { contents: cleaned, deleted: false, notes: "auto-wrapped: model returned raw code instead of JSON" };
    } else {
      throw new Error(
        `claude answer is not valid JSON (label: ${opts.label}): ` +
          `First 500 chars: ${cleaned.slice(0, 500)}`
      );
    }
  }

  return parsed as T;
}
