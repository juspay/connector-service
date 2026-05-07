import { spawn, type ChildProcess } from "node:child_process";
import { promises as fs, openSync, closeSync } from "node:fs";
import path from "node:path";
import net from "node:net";

/**
 * gRPC server lifecycle helpers used by the grpc-test checkpoint.
 *
 * Why this exists: the previous workflow asked the agent to start the server
 * inline via `cargo run --bin grpc-server &`. That pattern is unreliable when
 * driven from a remote agent's Bash tool — backgrounded children may not
 * survive across tool calls, and there is no log file the agent can read to
 * diagnose failures. Owning the server lifecycle in TypeScript:
 *   - guarantees pre-flight cleanup of stale processes,
 *   - gives the agent a known-good `localhost:8000`,
 *   - captures stdout+stderr to a log file the agent can Read,
 *   - guarantees cleanup on every exit path via the returned `kill` handle.
 */

export interface ServerHandle {
  pid: number;
  /** Best-effort SIGTERM, then SIGKILL after a grace period. Idempotent. */
  kill: () => Promise<void>;
}

export interface StartGrpcServerOptions {
  projectRoot: string;
  /** Absolute path; this function ensures the parent directory exists. */
  logFile: string;
}

export interface WaitForHealthyOptions {
  host: string;
  port: number;
  timeoutMs: number;
  /** How often to retry the TCP probe. Default 500ms. */
  pollIntervalMs?: number;
}

type Logger = (msg: string, level?: "info" | "warn" | "error") => void;

const noopLog: Logger = () => undefined;

async function runShell(
  cmd: string,
  log: Logger
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve) => {
    const child = spawn("bash", ["-c", cmd], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout!.on("data", (b: Buffer) => (stdout += b.toString("utf-8")));
    child.stderr!.on("data", (b: Buffer) => (stderr += b.toString("utf-8")));
    child.on("error", (err) => {
      log(`shell error: ${err.message}`, "warn");
      resolve({ stdout, stderr, code: null });
    });
    child.on("exit", (code) => resolve({ stdout, stderr, code }));
  });
}

/**
 * Kill anything bound to ports 8000/8080 and any leftover grpc-server binary
 * processes from previous runs. Idempotent and best-effort: if nothing is
 * running, succeeds silently.
 */
export async function killStaleProcesses(log: Logger = noopLog): Promise<void> {
  // lsof emits non-zero when nothing matches; swallow with `|| true`.
  const cmds = [
    "lsof -ti:8000 | xargs -r kill -9 2>/dev/null || true",
    "lsof -ti:8080 | xargs -r kill -9 2>/dev/null || true",
    "pkill -9 -f 'target/debug/grpc-server' 2>/dev/null || true",
  ];
  for (const cmd of cmds) {
    await runShell(cmd, log);
  }
  // Give the kernel a beat to release sockets before we try to bind again.
  await new Promise((r) => setTimeout(r, 500));
}

/**
 * Start `cargo run --bin grpc-server` in the project root, redirecting
 * stdout+stderr to `logFile`. Returns a handle with the pid and an idempotent
 * kill function. The child is *not* detached — it lives and dies with the
 * parent process so we never leak servers past a pipeline run.
 */
export async function startGrpcServer(
  opts: StartGrpcServerOptions,
  log: Logger = noopLog
): Promise<ServerHandle> {
  await fs.mkdir(path.dirname(opts.logFile), { recursive: true });
  // Truncate the log on each start so the agent reads only this run's output.
  const fd = openSync(opts.logFile, "w");
  try {
    const child: ChildProcess = spawn(
      "cargo",
      ["run", "--bin", "grpc-server"],
      {
        cwd: opts.projectRoot,
        stdio: ["ignore", fd, fd],
        env: process.env,
      }
    );

    if (typeof child.pid !== "number") {
      throw new Error("failed to spawn cargo run --bin grpc-server (no pid)");
    }

    log(`grpc-server started pid=${child.pid} log=${opts.logFile}`);

    let killed = false;
    const kill = async (): Promise<void> => {
      if (killed) return;
      killed = true;
      if (child.exitCode !== null || child.signalCode !== null) {
        return; // already dead
      }
      try {
        child.kill("SIGTERM");
      } catch {
        // process may have already exited
      }
      // Give cargo+server up to 3s to exit cleanly, then SIGKILL.
      const exited = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), 3000);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve(true);
        });
      });
      if (!exited) {
        try {
          child.kill("SIGKILL");
        } catch {
          // ignore
        }
      }
      // Also clean up the bound ports — `cargo run` spawns a child binary
      // (target/debug/grpc-server) which may outlive the cargo wrapper if
      // SIGTERM only reached the wrapper.
      await runShell(
        "lsof -ti:8000 | xargs -r kill -9 2>/dev/null || true",
        log
      );
      await runShell(
        "lsof -ti:8080 | xargs -r kill -9 2>/dev/null || true",
        log
      );
    };

    return { pid: child.pid, kill };
  } finally {
    closeSync(fd);
  }
}

/**
 * Resolve when a TCP connection to host:port succeeds. Used as a liveness
 * signal for the gRPC server — TCP-bound is sufficient because the very next
 * step is the agent's `grpcurl list`, which will surface any "service not
 * registered yet" issue with a clear error message.
 *
 * Rejects with the last connection error if `timeoutMs` elapses without
 * success.
 */
export async function waitForHealthy(
  opts: WaitForHealthyOptions,
  log: Logger = noopLog
): Promise<void> {
  const pollIntervalMs = opts.pollIntervalMs ?? 500;
  const deadline = Date.now() + opts.timeoutMs;
  let lastErr: Error = new Error(
    `grpc-server did not become healthy within ${opts.timeoutMs}ms`
  );

  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((resolve) => {
      const sock = net.createConnection({ host: opts.host, port: opts.port });
      const done = (success: boolean, err?: Error) => {
        sock.destroy();
        if (err) lastErr = err;
        resolve(success);
      };
      sock.once("connect", () => done(true));
      sock.once("error", (err) => done(false, err));
      sock.setTimeout(1000, () =>
        done(false, new Error("tcp connect timeout"))
      );
    });
    if (ok) {
      log(`grpc-server healthy at ${opts.host}:${opts.port}`);
      return;
    }
    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }
  throw lastErr;
}

/**
 * Read up to the last `maxBytes` of a file. Returns "" if the file can't be
 * read (e.g. server crashed before any output). Used to attach server log
 * tails to error reports so the dashboard surfaces real diagnostics.
 */
export async function tailLogFile(
  logFile: string,
  maxBytes = 2048
): Promise<string> {
  try {
    const stat = await fs.stat(logFile);
    const start = Math.max(0, stat.size - maxBytes);
    const fh = await fs.open(logFile, "r");
    try {
      const buf = Buffer.alloc(stat.size - start);
      await fh.read(buf, 0, buf.length, start);
      return buf.toString("utf-8");
    } finally {
      await fh.close();
    }
  } catch {
    return "";
  }
}
