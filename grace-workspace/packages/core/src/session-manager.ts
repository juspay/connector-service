import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  DEFAULT_SESSION_ID,
  StateManager,
  type SessionCopyStrategy,
  type SessionMetadata,
  type SessionRecord,
} from "./state.js";

export interface CreateSessionInput {
  name: string;
  description?: string;
  /** Source folder to copy/worktree from. Must contain a git repo for `git-worktree`. */
  sourcePath: string;
  /** Defaults to git-worktree (recommended for git projects). */
  strategy?: SessionCopyStrategy;
}

/**
 * Owns the on-disk lifecycle of a session's isolated workspace under
 * `~/.byne/sessions/<id>/<projectName>`. Database state is delegated to
 * StateManager; this class only deals with directories, git worktrees,
 * and disk usage.
 */
export class SessionManager {
  private readonly root: string;

  constructor(
    private readonly state: StateManager,
    rootDir?: string
  ) {
    this.root =
      rootDir ?? path.join(os.homedir(), ".byne", "sessions");
    fs.mkdirSync(this.root, { recursive: true });
  }

  /**
   * Create a new session: provision its isolated workspace, then record it
   * in the DB. On any provisioning failure we don't persist a half-baked
   * row — the caller can retry with a different strategy.
   */
  async create(input: CreateSessionInput): Promise<SessionRecord> {
    if (!input.name?.trim()) {
      throw new Error("Session name is required");
    }
    const sourcePath = path.resolve(input.sourcePath);
    if (!fs.existsSync(sourcePath)) {
      throw new Error(`Source path does not exist: ${sourcePath}`);
    }
    const strategy: SessionCopyStrategy = input.strategy ?? "git-worktree";
    const sessionId = `session_${crypto.randomBytes(6).toString("hex")}`;
    const sessionDir = path.join(this.root, sessionId);
    const projectName = path.basename(sourcePath);
    const projectRoot = path.join(sessionDir, projectName);

    fs.mkdirSync(sessionDir, { recursive: true });

    try {
      switch (strategy) {
        case "git-worktree":
          await this.provisionGitWorktree(sourcePath, projectRoot, input.name);
          break;
        case "shallow":
          await this.provisionShallowClone(sourcePath, projectRoot);
          break;
        case "full":
          await this.provisionFullCopy(sourcePath, projectRoot);
          break;
        case "legacy":
          // legacy = "no copy", session re-uses caller-provided path. Not
          // typically reachable from create() but supported for the default
          // session migration path.
          fs.rmdirSync(sessionDir);
          return this.state.createSession({
            sessionId,
            name: input.name,
            description: input.description ?? null,
            projectRoot: sourcePath,
            metadata: {
              originalPath: sourcePath,
              copyStrategy: "legacy",
            },
          });
        default: {
          const _exhaustive: never = strategy;
          throw new Error(`Unknown strategy: ${_exhaustive}`);
        }
      }
    } catch (err) {
      try {
        fs.rmSync(sessionDir, { recursive: true, force: true });
      } catch {
        /* leave the dir, the user can clean it up */
      }
      throw err;
    }

    const metadata: SessionMetadata = {
      originalPath: sourcePath,
      copyStrategy: strategy,
    };
    return this.state.createSession({
      sessionId,
      name: input.name,
      description: input.description ?? null,
      projectRoot,
      metadata,
    });
  }

  /**
   * Resolve the on-disk project root for a session. Throws if missing.
   */
  resolveProjectRoot(sessionId: string): string {
    const session = this.state.getSession(sessionId);
    if (!session) throw new Error(`No such session: ${sessionId}`);
    if (!session.projectRoot) {
      throw new Error(`Session ${sessionId} has no projectRoot configured`);
    }
    return session.projectRoot;
  }

  /**
   * Mark the session archived in the DB. Files are kept on disk so the user
   * can still inspect them; `delete` removes both.
   */
  async archive(sessionId: string): Promise<void> {
    if (sessionId === DEFAULT_SESSION_ID) {
      throw new Error("Cannot archive the default session");
    }
    this.state.archiveSession(sessionId);
  }

  /**
   * Permanently remove a session's worktree + folder + DB row.
   */
  async delete(sessionId: string): Promise<void> {
    const session = this.state.getSession(sessionId);
    if (!session) return;
    const sessionDir = path.join(this.root, sessionId);

    if (session.metadata.copyStrategy === "git-worktree") {
      // Best-effort `git worktree remove --force` so git's bookkeeping is
      // updated; if it fails, fall back to rm -rf on the directory. The
      // worktree's source repo is the originalPath in metadata.
      const worktreePath = session.projectRoot;
      const sourceRepo = session.metadata.originalPath;
      if (sourceRepo && fs.existsSync(sourceRepo)) {
        try {
          execSync(`git worktree remove --force ${quote(worktreePath)}`, {
            cwd: sourceRepo,
            stdio: "ignore",
          });
        } catch {
          /* fall back to rm */
        }
      }
    }

    if (fs.existsSync(sessionDir)) {
      fs.rmSync(sessionDir, { recursive: true, force: true });
    }
    this.state.deleteSession(sessionId);
  }

  /**
   * Recursive du. Cheap enough to call on dashboard load for a few dozen
   * sessions; if it ever gets slow we cache it in metadata_json.
   */
  async diskUsage(sessionId: string): Promise<number> {
    const sessionDir = path.join(this.root, sessionId);
    if (!fs.existsSync(sessionDir)) return 0;
    return du(sessionDir);
  }

  // ─── Provisioning strategies ────────────────────────────────────────────

  private async provisionGitWorktree(
    sourcePath: string,
    projectRoot: string,
    taskName: string
  ): Promise<void> {
    const isGit = fs.existsSync(path.join(sourcePath, ".git"));
    if (!isGit) {
      throw new Error(
        `git-worktree strategy requires a git repo at ${sourcePath}`
      );
    }
    const branch = `grace/${slugifyTaskName(taskName)}-${branchTimestamp()}`;
    execSync(
      `git worktree add -b ${quote(branch)} ${quote(projectRoot)} HEAD`,
      { cwd: sourcePath, stdio: "ignore" }
    );
  }

  private async provisionShallowClone(
    sourcePath: string,
    projectRoot: string
  ): Promise<void> {
    execSync(
      `git clone --depth=1 --no-tags ${quote(sourcePath)} ${quote(projectRoot)}`,
      { stdio: "ignore" }
    );
  }

  private async provisionFullCopy(
    sourcePath: string,
    projectRoot: string
  ): Promise<void> {
    fs.mkdirSync(projectRoot, { recursive: true });
    // cp -R with exclusions for the heavyweight ones. Using rsync would be
    // nicer but we don't want to add a system-tool dep.
    const entries = fs.readdirSync(sourcePath, { withFileTypes: true });
    const skip = new Set(["node_modules", "target", ".byne", "dist"]);
    for (const entry of entries) {
      if (skip.has(entry.name)) continue;
      const src = path.join(sourcePath, entry.name);
      const dst = path.join(projectRoot, entry.name);
      execSync(`cp -R ${quote(src)} ${quote(dst)}`, { stdio: "ignore" });
    }
  }
}

function quote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function slugifyTaskName(name: string): string {
  const slug = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/, "");
  return slug || "task";
}

function branchTimestamp(d: Date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
    `-${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`
  );
}

function du(dir: string): number {
  let total = 0;
  const stack: string[] = [dir];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = path.join(cur, e.name);
      try {
        const st = fs.lstatSync(p);
        if (st.isDirectory()) stack.push(p);
        else total += st.size;
      } catch {
        /* ignore */
      }
    }
  }
  return total;
}
