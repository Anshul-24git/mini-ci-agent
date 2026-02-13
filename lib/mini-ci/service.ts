import "server-only";

import { randomUUID } from "node:crypto";

import { Sandbox } from "@vercel/sandbox";

import type {
  AnalyzeResponse,
  ApplyFixResponse,
  CiStepLog,
  PackageManager,
  ProposeFixResponse,
  RepoSummary,
  RunCiResponse,
  SessionHint,
  TraceEvent,
} from "@/lib/mini-ci/contracts";

type RunSession = {
  runId: string;
  repoUrl: string;
  sandboxId: string;
  repoRoot: string;
  hasPackageJson: boolean;
  packageManager: PackageManager;
  scripts: Record<string, string>;
  frameworkGuess: string;
  topLevelTree: string[];
  lastCiLogs: CiStepLog[];
  createdAt: number;
  updatedAt: number;
};

declare global {
  // eslint-disable-next-line no-var
  var __miniCiRunSessions: Map<string, RunSession> | undefined;
}

const runSessions = globalThis.__miniCiRunSessions ?? new Map<string, RunSession>();
globalThis.__miniCiRunSessions = runSessions;

const COMMAND_ALLOWLIST = new Set(["git", "node", "npm", "pnpm", "yarn", "python", "python3"]);
const DEFAULT_COMMAND_TIMEOUT_MS = 120_000;
const INSTALL_TIMEOUT_MS = 300_000;
const SANDBOX_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_OUTPUT_CHARS = 12_000;
const TRACE_SNIPPET_CHARS = 240;
const MAX_PROPOSE_LOG_CHARS = 20_000;
const MAX_DIFF_CHARS = 100_000;
const LLM_MAX_OUTPUT_TOKENS = 2200;
const MAX_OPENAI_ERROR_CHARS = 20_000;
const MAX_PROPOSE_ATTEMPTS = 3;
const MAX_CONTEXT_FILES = 3;
const MAX_CONTEXT_FILE_CHARS = 4_000;
const MAX_CANDIDATE_PATHS = 12;
const FILE_EXTENSIONS_FOR_CONTEXT = new Set([
  "ts",
  "tsx",
  "js",
  "jsx",
  "mjs",
  "cjs",
  "json",
  "py",
  "go",
  "java",
  "rb",
  "php",
  "cs",
  "rs",
  "md",
  "yml",
  "yaml",
]);

type SafeCommandInput = {
  step: string;
  cmd: string;
  args?: string[];
  cwd?: string;
  timeoutMs?: number;
  inputSummary?: string;
};

type SafeCommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  commandLabel: string;
  trace: TraceEvent;
};

type StructuredEdit = {
  filePath: string;
  find: string;
  replace: string;
};

type StructuredEditsProposal = {
  explanation?: string;
  edits?: StructuredEdit[];
};

type DetectInfo = {
  hasPackageJson: boolean;
  packageManager: PackageManager;
  scripts: Record<string, string>;
  frameworkGuess: string;
};

type SandboxCredentials = {
  teamId: string;
  projectId: string;
  token: string;
};

export class MiniCiServiceError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode = 500) {
    super(message);
    this.name = "MiniCiServiceError";
    this.statusCode = statusCode;
  }
}

function truncate(value: string, maxChars: number): string {
  if (value.length <= maxChars) {
    return value;
  }

  return `${value.slice(0, maxChars)}\n...[truncated ${value.length - maxChars} chars]`;
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

function nowIso(): string {
  return new Date().toISOString();
}

function getSandboxCredentialsFromEnv(): SandboxCredentials | undefined {
  const token = process.env.VERCEL_TOKEN?.trim();
  if (!token) {
    return undefined;
  }

  const teamId = process.env.VERCEL_TEAM_ID?.trim();
  const projectId = process.env.VERCEL_PROJECT_ID?.trim();
  if (!teamId || !projectId) {
    const missing = [teamId ? null : "VERCEL_TEAM_ID", projectId ? null : "VERCEL_PROJECT_ID"]
      .filter(Boolean)
      .join(", ");
    throw new Error(
      `Incomplete Vercel Sandbox credentials. Missing: ${missing}. ` +
        "When using VERCEL_TOKEN, both VERCEL_TEAM_ID and VERCEL_PROJECT_ID are required.",
    );
  }

  return { teamId, projectId, token };
}

function validateRunId(runId: string): void {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(runId)) {
    throw new Error("Invalid runId format.");
  }
}

function normalizeGithubRepoUrl(input: string): string {
  let parsed: URL;
  try {
    parsed = new URL(input.trim());
  } catch {
    throw new Error("Repository URL must be a valid URL.");
  }

  if (parsed.protocol !== "https:" || parsed.hostname !== "github.com") {
    throw new Error("Only public GitHub HTTPS URLs are supported.");
  }

  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 2) {
    throw new Error("Repository URL must include owner and repo name.");
  }

  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, "");
  if (!owner || !repo) {
    throw new Error("Repository URL must include owner and repo name.");
  }

  return `https://github.com/${owner}/${repo}.git`;
}

function parseJsonLine<T>(rawOutput: string): T | null {
  const lines = rawOutput
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .reverse();

  for (const line of lines) {
    if (!line.startsWith("{") || !line.endsWith("}")) {
      continue;
    }

    try {
      return JSON.parse(line) as T;
    } catch {
      // keep scanning
    }
  }

  return null;
}

function ensureCommandAllowed(cmd: string): void {
  if (!COMMAND_ALLOWLIST.has(cmd)) {
    throw new Error(`Command '${cmd}' is not in the allowlist.`);
  }
}

function formatCommand(cmd: string, args: string[]): string {
  return [cmd, ...args].join(" ").trim();
}

async function runSafeCommand(sandbox: Sandbox, input: SafeCommandInput): Promise<SafeCommandResult> {
  ensureCommandAllowed(input.cmd);

  const args = input.args ?? [];
  const label = formatCommand(input.cmd, args);
  const timeoutMs = input.timeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
  const startedAt = Date.now();
  const ts = nowIso();

  let exitCode = -1;
  let stdout = "";
  let stderr = "";

  try {
    const command = await sandbox.runCommand({
      cmd: input.cmd,
      args,
      cwd: input.cwd,
      detached: true,
    });

    const finishedPromise = command.wait();
    const outcome = await Promise.race([
      finishedPromise.then((finished) => ({ timedOut: false, finished })),
      new Promise<{ timedOut: true; finished?: undefined }>((resolve) => {
        setTimeout(() => resolve({ timedOut: true }), timeoutMs);
      }),
    ]);

    if (outcome.timedOut) {
      await command.kill("SIGTERM").catch(() => undefined);
      await Promise.race([
        finishedPromise.catch(() => undefined),
        new Promise<void>((resolve) => {
          setTimeout(() => resolve(), 2_000);
        }),
      ]);

      const [rawStdout, rawStderr] = await Promise.all([
        command.stdout().catch(() => ""),
        command.stderr().catch(() => ""),
      ]);

      exitCode = 124;
      stdout = truncate(rawStdout, MAX_OUTPUT_CHARS);
      stderr = truncate(
        `${rawStderr}\nCommand timed out after ${timeoutMs}ms`.trim(),
        MAX_OUTPUT_CHARS,
      );
    } else {
      exitCode = outcome.finished.exitCode;

      const [rawStdout, rawStderr] = await Promise.all([
        outcome.finished.stdout().catch(() => ""),
        outcome.finished.stderr().catch(() => ""),
      ]);

      stdout = truncate(rawStdout, MAX_OUTPUT_CHARS);
      stderr = truncate(rawStderr, MAX_OUTPUT_CHARS);
    }
  } catch (error) {
    const message = `Command failed: ${toErrorMessage(error)}`;
    stderr = truncate(message, MAX_OUTPUT_CHARS);
    exitCode = 1;
  }

  const durationMs = Date.now() - startedAt;
  const trace: TraceEvent = {
    ts,
    step: input.step,
    tool: "sandbox.runCommand",
    inputSummary: input.inputSummary ?? label,
    exitCode,
    stdoutSnippet: truncate(stdout, TRACE_SNIPPET_CHARS),
    stderrSnippet: truncate(stderr, TRACE_SNIPPET_CHARS),
    durationMs,
  };

  return {
    exitCode,
    stdout,
    stderr,
    durationMs,
    commandLabel: label,
    trace,
  };
}

function requireSession(runId: string): RunSession {
  validateRunId(runId);
  const session = runSessions.get(runId);
  if (!session) {
    throw new Error("No sandbox session found for this runId. Run analyze first.");
  }

  return session;
}

function buildSessionHintFromSession(session: RunSession): SessionHint {
  return {
    runId: session.runId,
    sandboxId: session.sandboxId,
    repoRoot: session.repoRoot,
    repoUrl: session.repoUrl,
    hasPackageJson: session.hasPackageJson,
    packageManager: session.packageManager,
    scripts: session.scripts,
    frameworkGuess: session.frameworkGuess,
    topLevelTree: session.topLevelTree,
  };
}

function buildSessionFromHint(runId: string, hint?: SessionHint): RunSession | null {
  if (!hint) {
    return null;
  }

  if (hint.runId && hint.runId !== runId) {
    throw new MiniCiServiceError("runId does not match session hint.", 400);
  }

  if (!hint.sandboxId || !hint.repoRoot) {
    throw new MiniCiServiceError(
      "Session hint is incomplete. Run Analyze Repo again to refresh sandbox context.",
      400,
    );
  }

  const now = Date.now();
  return {
    runId,
    repoUrl: hint.repoUrl || "",
    sandboxId: hint.sandboxId,
    repoRoot: hint.repoRoot,
    hasPackageJson: hint.hasPackageJson,
    packageManager: hint.packageManager,
    scripts: hint.scripts ?? {},
    frameworkGuess: hint.frameworkGuess || "Unknown",
    topLevelTree: hint.topLevelTree ?? [],
    lastCiLogs: [],
    createdAt: now,
    updatedAt: now,
  };
}

function resolveSession(runId: string, hint?: SessionHint): RunSession {
  validateRunId(runId);
  const existing = runSessions.get(runId);
  if (existing) {
    return existing;
  }

  const hydrated = buildSessionFromHint(runId, hint);
  if (hydrated) {
    runSessions.set(runId, hydrated);
    return hydrated;
  }

  throw new MiniCiServiceError("No sandbox session found for this runId. Run analyze first.", 500);
}

function createSkippedLog(step: string, reason: string): CiStepLog {
  return {
    step,
    command: "",
    status: "skipped",
    exitCode: null,
    stdout: "",
    stderr: reason,
    durationMs: 0,
  };
}

function toCiLog(step: string, result: SafeCommandResult): CiStepLog {
  return {
    step,
    command: result.commandLabel,
    status: result.exitCode === 0 ? "passed" : "failed",
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    durationMs: result.durationMs,
  };
}

function installCommandFor(packageManager: PackageManager): { cmd: string; args: string[] } {
  if (packageManager === "pnpm") {
    return { cmd: "pnpm", args: ["install", "--no-frozen-lockfile"] };
  }

  if (packageManager === "yarn") {
    return { cmd: "yarn", args: ["install", "--ignore-engines"] };
  }

  return { cmd: "npm", args: ["install", "--no-audit", "--no-fund"] };
}

function runScriptCommandFor(packageManager: PackageManager, scriptName: string): { cmd: string; args: string[] } {
  if (packageManager === "yarn") {
    return { cmd: "yarn", args: ["run", scriptName] };
  }

  return { cmd: packageManager, args: ["run", scriptName] };
}

const DETECTION_SCRIPT = [
  'const fs = require("fs");',
  'const path = require("path");',
  "const cwd = process.cwd();",
  'const pkgPath = path.join(cwd, "package.json");',
  "const hasPackageJson = fs.existsSync(pkgPath);",
  "let pkg = { scripts: {}, dependencies: {}, devDependencies: {} };",
  "if (hasPackageJson) {",
  "  try {",
  '    pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));',
  "  } catch {}",
  "}",
  'const hasPnpm = fs.existsSync(path.join(cwd, "pnpm-lock.yaml"));',
  'const hasYarn = fs.existsSync(path.join(cwd, "yarn.lock"));',
  'const packageManager = hasPnpm ? "pnpm" : hasYarn ? "yarn" : "npm";',
  "const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };",
  'let frameworkGuess = "Unknown";',
  'if (deps.next) frameworkGuess = "Next.js";',
  'else if (deps.nuxt || deps["nuxt"]) frameworkGuess = "Nuxt";',
  'else if (deps.vite) frameworkGuess = "Vite";',
  'else if (deps.react) frameworkGuess = "React";',
  'else if (deps.vue) frameworkGuess = "Vue";',
  'else if (deps.svelte) frameworkGuess = "Svelte";',
  'else if (deps["@angular/core"]) frameworkGuess = "Angular";',
  'else if (deps.express) frameworkGuess = "Node/Express";',
  "const output = {",
  "  hasPackageJson,",
  "  packageManager,",
  "  scripts: pkg.scripts || {},",
  "  frameworkGuess",
  "};",
  "console.log(JSON.stringify(output));",
].join("\n");

async function executeCi(session: RunSession, sandbox: Sandbox): Promise<{ passed: boolean; logs: CiStepLog[]; trace: TraceEvent[] }> {
  const logs: CiStepLog[] = [];
  const trace: TraceEvent[] = [];

  if (!session.hasPackageJson) {
    logs.push(createSkippedLog("install", "No package.json found. Install skipped."));
    logs.push(createSkippedLog("lint", "No package.json found. Lint skipped."));
    logs.push(createSkippedLog("test", "No package.json found. Test skipped."));
    logs.push(createSkippedLog("build", "No package.json found. Build skipped."));

    session.lastCiLogs = logs;
    session.updatedAt = Date.now();
    runSessions.set(session.runId, session);

    return { passed: true, logs, trace };
  }

  const install = installCommandFor(session.packageManager);
  const installResult = await runSafeCommand(sandbox, {
    step: "ci-install",
    cmd: install.cmd,
    args: install.args,
    cwd: session.repoRoot,
    timeoutMs: INSTALL_TIMEOUT_MS,
  });
  logs.push(toCiLog("install", installResult));
  trace.push(installResult.trace);

  const ciScripts: Array<"lint" | "test" | "build"> = ["lint", "test", "build"];
  for (const scriptName of ciScripts) {
    if (!session.scripts[scriptName]) {
      logs.push(createSkippedLog(scriptName, `No '${scriptName}' script found.`));
      continue;
    }

    const command = runScriptCommandFor(session.packageManager, scriptName);
    const scriptResult = await runSafeCommand(sandbox, {
      step: `ci-${scriptName}`,
      cmd: command.cmd,
      args: command.args,
      cwd: session.repoRoot,
      timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS,
    });

    logs.push(toCiLog(scriptName, scriptResult));
    trace.push(scriptResult.trace);
  }

  const passed = logs.every((log) => log.status !== "failed");
  session.lastCiLogs = logs;
  session.updatedAt = Date.now();
  runSessions.set(session.runId, session);

  return { passed, logs, trace };
}

export async function analyzeRepository(input: { runId?: string; repoUrl: string }): Promise<AnalyzeResponse> {
  const runId = input.runId?.trim() || randomUUID();
  validateRunId(runId);

  const repoUrl = normalizeGithubRepoUrl(input.repoUrl);
  const credentials = getSandboxCredentialsFromEnv();
  const trace: TraceEvent[] = [];

  const createStartedAt = Date.now();
  let sandbox: Sandbox;
  try {
    sandbox = await Sandbox.create({
      ...(credentials ?? {}),
      source: {
        type: "git",
        url: repoUrl,
      },
      runtime: "node22",
      timeout: SANDBOX_TIMEOUT_MS,
    });
  } catch (error) {
    const message = toErrorMessage(error);
    if (message.includes("OIDC")) {
      throw new Error(
        "Vercel Sandbox authentication failed (OIDC token). " +
          "Run `vercel env pull .env.local` to refresh VERCEL_OIDC_TOKEN, " +
          "or set VERCEL_TOKEN + VERCEL_TEAM_ID + VERCEL_PROJECT_ID.",
      );
    }
    throw error;
  }

  trace.push({
    ts: nowIso(),
    step: "create-sandbox",
    tool: "sandbox.create",
    inputSummary: repoUrl,
    exitCode: 0,
    stdoutSnippet: `sandboxId=${sandbox.sandboxId}`,
    stderrSnippet: "",
    durationMs: Date.now() - createStartedAt,
  });

  const repoRootResult = await runSafeCommand(sandbox, {
    step: "repo-root",
    cmd: "git",
    args: ["rev-parse", "--show-toplevel"],
  });
  trace.push(repoRootResult.trace);

  if (repoRootResult.exitCode !== 0) {
    throw new Error(`Failed to resolve repository root: ${repoRootResult.stderr}`);
  }

  const repoRoot = repoRootResult.stdout.trim();

  const detectResult = await runSafeCommand(sandbox, {
    step: "detect-project",
    cmd: "node",
    args: ["-e", DETECTION_SCRIPT],
    cwd: repoRoot,
  });
  trace.push(detectResult.trace);

  let detectInfo: DetectInfo = {
    hasPackageJson: false,
    packageManager: "npm",
    scripts: {},
    frameworkGuess: "Unknown",
  };

  if (detectResult.exitCode === 0) {
    const parsed = parseJsonLine<DetectInfo>(detectResult.stdout);
    if (parsed) {
      detectInfo = {
        hasPackageJson: Boolean(parsed.hasPackageJson),
        packageManager: parsed.packageManager,
        scripts: parsed.scripts ?? {},
        frameworkGuess: parsed.frameworkGuess || "Unknown",
      };
    }
  }

  const treeResult = await runSafeCommand(sandbox, {
    step: "top-level-tree",
    cmd: "git",
    args: ["ls-tree", "--name-only", "HEAD"],
    cwd: repoRoot,
  });
  trace.push(treeResult.trace);

  const fileTreeTopLevel =
    treeResult.exitCode === 0
      ? treeResult.stdout
          .split(/\r?\n/)
          .map((item) => item.trim())
          .filter(Boolean)
          .slice(0, 50)
      : [];

  const summary: RepoSummary = {
    frameworkGuess: detectInfo.frameworkGuess,
    packageManager: detectInfo.packageManager,
    scripts: detectInfo.scripts,
    fileTreeTopLevel,
  };

  const session: RunSession = {
    runId,
    repoUrl,
    sandboxId: sandbox.sandboxId,
    repoRoot,
    hasPackageJson: detectInfo.hasPackageJson,
    packageManager: detectInfo.packageManager,
    scripts: detectInfo.scripts,
    frameworkGuess: detectInfo.frameworkGuess,
    topLevelTree: fileTreeTopLevel,
    lastCiLogs: [],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  runSessions.set(runId, session);

  return {
    runId,
    sandboxId: sandbox.sandboxId,
    summary,
    sessionHint: buildSessionHintFromSession(session),
    trace,
  };
}

export async function runCi(runId: string, sessionHint?: SessionHint): Promise<RunCiResponse> {
  const session = resolveSession(runId, sessionHint);
  const credentials = getSandboxCredentialsFromEnv();
  const sandbox = await Sandbox.get({
    ...(credentials ?? {}),
    sandboxId: session.sandboxId,
  });
  const ciResult = await executeCi(session, sandbox);

  return {
    runId,
    passed: ciResult.passed,
    logs: ciResult.logs,
    trace: ciResult.trace,
  };
}

function serializeFailingLogs(input: unknown): string {
  if (typeof input === "string") {
    return truncate(input, MAX_PROPOSE_LOG_CHARS);
  }

  try {
    return truncate(JSON.stringify(input, null, 2), MAX_PROPOSE_LOG_CHARS);
  } catch {
    return "";
  }
}

function normalizeCandidatePath(raw: string): string | null {
  let value = raw.trim();
  value = value.replace(/^['"`(<{\[]+/, "").replace(/['"`)>}\],;]+$/, "");
  value = value.replace(/:\d+(?::\d+)?$/, "");
  value = value.replace(/^\.\/+/, "");

  if (!value || value.startsWith("/") || value.includes("\\") || value.includes("\0")) {
    return null;
  }
  if (value.split("/").some((segment) => !segment || segment === "..")) {
    return null;
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(value)) {
    return null;
  }

  const dot = value.lastIndexOf(".");
  if (dot <= 0 || dot === value.length - 1) {
    return null;
  }
  const extension = value.slice(dot + 1).toLowerCase();
  if (!FILE_EXTENSIONS_FOR_CONTEXT.has(extension)) {
    return null;
  }

  return value;
}

function extractCandidatePathsFromLogs(serializedLogs: string): string[] {
  const candidates = serializedLogs.match(/[A-Za-z0-9._/-]+\.[A-Za-z0-9]+(?::\d+(?::\d+)?)?/g) ?? [];
  const seen = new Set<string>();
  const output: string[] = [];

  for (const candidate of candidates) {
    const normalized = normalizeCandidatePath(candidate);
    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    output.push(normalized);
    if (output.length >= MAX_CANDIDATE_PATHS) {
      break;
    }
  }

  return output;
}

async function collectRelevantFileContexts(
  sandbox: Sandbox,
  session: RunSession,
  serializedLogs: string,
): Promise<{ contextText: string; trace: TraceEvent[] }> {
  const trace: TraceEvent[] = [];
  const candidates = extractCandidatePathsFromLogs(serializedLogs);
  if (!candidates.length) {
    return { contextText: "", trace };
  }

  const blocks: string[] = [];
  for (const filePath of candidates) {
    const show = await runSafeCommand(sandbox, {
      step: `read-context-${filePath}`,
      cmd: "git",
      args: ["show", `HEAD:${filePath}`],
      cwd: session.repoRoot,
      timeoutMs: 30_000,
      inputSummary: filePath,
    });
    trace.push(show.trace);

    if (show.exitCode !== 0 || !show.stdout.trim()) {
      continue;
    }

    blocks.push(`FILE: ${filePath}\n${truncate(show.stdout, MAX_CONTEXT_FILE_CHARS)}`);
    if (blocks.length >= MAX_CONTEXT_FILES) {
      break;
    }
  }

  if (!blocks.length) {
    return { contextText: "", trace };
  }

  return {
    contextText: [
      "Repository file snapshots (authoritative current content; use these exact lines for patch hunks):",
      ...blocks,
    ].join("\n\n"),
    trace,
  };
}

function parseStructuredEditsProposal(rawText: string): StructuredEditsProposal {
  const parsed = parseProposalJson(rawText) as {
    explanation?: unknown;
    edits?: unknown;
  };

  const explanation = typeof parsed.explanation === "string" ? parsed.explanation.trim() : "";
  const rawEdits = Array.isArray(parsed.edits) ? parsed.edits : [];
  const edits: StructuredEdit[] = [];

  for (const candidate of rawEdits) {
    if (!candidate || typeof candidate !== "object") {
      continue;
    }
    const asRecord = candidate as Record<string, unknown>;
    const filePath = typeof asRecord.filePath === "string" ? normalizeCandidatePath(asRecord.filePath) : null;
    const find = typeof asRecord.find === "string" ? asRecord.find : null;
    const replace = typeof asRecord.replace === "string" ? asRecord.replace : null;
    if (!filePath || find == null || replace == null || !find) {
      continue;
    }
    edits.push({ filePath, find, replace });
    if (edits.length >= 6) {
      break;
    }
  }

  return {
    explanation,
    edits,
  };
}

async function readFileAtHead(
  sandbox: Sandbox,
  session: RunSession,
  filePath: string,
): Promise<{ content: string; trace: TraceEvent }> {
  const show = await runSafeCommand(sandbox, {
    step: `read-head-${filePath}`,
    cmd: "git",
    args: ["show", `HEAD:${filePath}`],
    cwd: session.repoRoot,
    timeoutMs: 30_000,
    inputSummary: filePath,
  });

  if (show.exitCode !== 0) {
    const message = (show.stderr || show.stdout || `Failed to read ${filePath}`).trim();
    throw new MiniCiServiceError(`Unable to read '${filePath}' from repository HEAD: ${message}`, 502);
  }

  return {
    content: show.stdout,
    trace: show.trace,
  };
}

function applyStructuredEditsToContent(filePath: string, baseContent: string, edits: StructuredEdit[]): string {
  let content = baseContent;

  for (const edit of edits) {
    const index = content.indexOf(edit.find);
    if (index === -1) {
      throw new MiniCiServiceError(
        `Structured edit could not find target snippet in '${filePath}'.`,
        502,
      );
    }

    content = `${content.slice(0, index)}${edit.replace}${content.slice(index + edit.find.length)}`;
  }

  return content;
}

async function buildDiffFromUpdatedFiles(
  sandbox: Sandbox,
  session: RunSession,
  originalFiles: Map<string, string>,
  updatedFiles: Map<string, string>,
): Promise<{ diff: string; trace: TraceEvent[] }> {
  const trace: TraceEvent[] = [];
  const filePaths = [...updatedFiles.keys()];

  const writeStartedAt = Date.now();
  await sandbox.writeFiles(
    filePaths.map((filePath) => ({
      path: `${session.repoRoot}/${filePath}`,
      content: Buffer.from(updatedFiles.get(filePath) ?? "", "utf8"),
    })),
  );
  trace.push({
    ts: nowIso(),
    step: "write-structured-updated-files",
    tool: "sandbox.writeFiles",
    inputSummary: `${filePaths.length} file(s) updated in repo`,
    exitCode: 0,
    stdoutSnippet: "Structured fallback candidate changes written.",
    stderrSnippet: "",
    durationMs: Date.now() - writeStartedAt,
  });

  let diff = "";
  let diffFailure: Error | null = null;

  try {
    const diffResult = await runSafeCommand(sandbox, {
      step: "diff-structured-files",
      cmd: "git",
      args: ["diff", "--unified=3", "--", ...filePaths],
      cwd: session.repoRoot,
      timeoutMs: 30_000,
      inputSummary: filePaths.join(", "),
    });
    trace.push(diffResult.trace);

    if (diffResult.exitCode !== 0 && !diffResult.stdout.trim()) {
      const reason = (diffResult.stderr || diffResult.stdout || "git diff failed").trim();
      throw new MiniCiServiceError(`Unable to generate diff from structured edits: ${reason}`, 502);
    }

    diff = diffResult.stdout.trim();
    if (!diff) {
      throw new MiniCiServiceError("Structured edits produced no diff output.", 502);
    }
  } catch (error) {
    diffFailure = error instanceof Error ? error : new Error(String(error));
  } finally {
    const restoreStartedAt = Date.now();
    await sandbox.writeFiles(
      filePaths.map((filePath) => ({
        path: `${session.repoRoot}/${filePath}`,
        content: Buffer.from(originalFiles.get(filePath) ?? "", "utf8"),
      })),
    );
    trace.push({
      ts: nowIso(),
      step: "restore-structured-updated-files",
      tool: "sandbox.writeFiles",
      inputSummary: `${filePaths.length} file(s) restored`,
      exitCode: 0,
      stdoutSnippet: "Structured fallback candidate changes reverted.",
      stderrSnippet: "",
      durationMs: Date.now() - restoreStartedAt,
    });
  }

  if (diffFailure) {
    throw diffFailure;
  }

  return {
    diff,
    trace,
  };
}

async function proposeFixWithStructuredEditsFallback(input: {
  sandbox: Sandbox;
  session: RunSession;
  model: string;
  useResponsesApi: boolean;
  endpoint: string;
  key: string;
  toolName: string;
  debugLlm: boolean;
  serializedLogs: string;
  contextText: string;
  failureReason: string;
}): Promise<{ explanation: string; diff: string; trace: TraceEvent[] }> {
  const trace: TraceEvent[] = [];

  const fallbackSystemPrompt = [
    "You are a CI-fix agent fallback mode.",
    "Return ONLY valid JSON with keys:",
    "- explanation: string",
    "- edits: array of { filePath: string, find: string, replace: string }",
    "Rules:",
    "- Provide 1 to 3 edits only.",
    "- filePath must be repository-relative.",
    "- find must be an exact snippet from the target file.",
    "- replace must be the exact replacement snippet.",
    "- Do not return unified diff text.",
    "- Do not include markdown fences.",
  ].join("\n");

  const fallbackPrompt = [
    "Previous direct unified diff attempts failed to apply.",
    `Failure reason: ${input.failureReason}`,
    "Provide exact textual find/replace edits so patch can be generated deterministically.",
    "",
    `Framework guess: ${input.session.frameworkGuess}`,
    `Package manager: ${input.session.packageManager}`,
    `Scripts: ${JSON.stringify(input.session.scripts)}`,
    `Top-level files: ${JSON.stringify(input.session.topLevelTree)}`,
    "",
    "Failing logs:",
    input.serializedLogs,
    input.contextText,
  ].join("\n");

  const requestBody = input.useResponsesApi
    ? {
        model: input.model,
        input: [
          {
            role: "system",
            content: [{ type: "input_text", text: fallbackSystemPrompt }],
          },
          {
            role: "user",
            content: [{ type: "input_text", text: fallbackPrompt }],
          },
        ],
        reasoning: { effort: "low" },
        text: { verbosity: "low" },
        max_output_tokens: LLM_MAX_OUTPUT_TOKENS,
      }
    : {
        model: input.model,
        max_tokens: LLM_MAX_OUTPUT_TOKENS,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content: fallbackSystemPrompt,
          },
          {
            role: "user",
            content: fallbackPrompt,
          },
        ],
      };

  const startedAt = Date.now();
  const response = await fetch(input.endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${input.key}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(requestBody),
  });
  const durationMs = Date.now() - startedAt;
  const payload = await parseJsonOrTextBody(response);

  if (!response.ok) {
    const openAiError = serializeOpenAiError(payload);
    if (input.debugLlm) {
      console.error("OpenAI structured-fallback error payload:", payload);
    }

    trace.push({
      ts: nowIso(),
      step: "propose-fix-structured-fallback",
      tool: input.toolName,
      inputSummary: `model=${input.model}`,
      exitCode: 1,
      stdoutSnippet: "",
      stderrSnippet: truncate(openAiError, TRACE_SNIPPET_CHARS),
      durationMs,
    });

    throw new MiniCiServiceError(
      `OpenAI request failed during structured fallback (${response.status} ${response.statusText}): ${openAiError}`,
      502,
    );
  }

  const modelText = input.useResponsesApi
    ? extractResponsesText(payload)
    : extractChatCompletionsText(payload);
  if (!modelText) {
    throw new MiniCiServiceError("Structured fallback returned empty content.", 502);
  }

  const proposal = parseStructuredEditsProposal(modelText);
  const edits = proposal.edits ?? [];
  if (!edits.length) {
    throw new MiniCiServiceError(
      `Structured fallback returned no usable edits. Raw output: ${truncate(modelText, 1500)}`,
      502,
    );
  }

  const byFile = new Map<string, StructuredEdit[]>();
  for (const edit of edits.slice(0, 3)) {
    const list = byFile.get(edit.filePath) ?? [];
    list.push(edit);
    byFile.set(edit.filePath, list);
  }

  const updatedFiles = new Map<string, string>();
  const originalFiles = new Map<string, string>();
  for (const [filePath, fileEdits] of byFile.entries()) {
    const currentFile = await readFileAtHead(input.sandbox, input.session, filePath);
    trace.push(currentFile.trace);

    originalFiles.set(filePath, currentFile.content);
    const updated = applyStructuredEditsToContent(filePath, currentFile.content, fileEdits);
    if (updated !== currentFile.content) {
      updatedFiles.set(filePath, updated);
    }
  }

  if (!updatedFiles.size) {
    throw new MiniCiServiceError("Structured fallback produced no file changes.", 502);
  }

  const diffResult = await buildDiffFromUpdatedFiles(
    input.sandbox,
    input.session,
    originalFiles,
    updatedFiles,
  );
  trace.push(...diffResult.trace);

  const diff = normalizeDiffPatch(diffResult.diff);
  const validation = validateUnifiedDiff(diff);
  if (!validation.ok) {
    throw new MiniCiServiceError(
      `Structured fallback generated invalid unified patch (${validation.reason}).`,
      502,
    );
  }

  const patchCheck = await checkPatchInSandbox(input.sandbox, input.session, diff, 99);
  trace.push(...patchCheck.trace);
  if (!patchCheck.ok) {
    throw new MiniCiServiceError(
      `Structured fallback patch is not applicable in sandbox: ${patchCheck.reason}`,
      502,
    );
  }

  return {
    explanation: proposal.explanation || "Generated a deterministic patch from structured edits.",
    diff,
    trace,
  };
}

function isResponsesApiModel(model: string): boolean {
  return model.trim().toLowerCase().startsWith("gpt-5-mini");
}

async function parseJsonOrTextBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { raw: text };
  }
}

function serializeUnknown(input: unknown): string {
  try {
    return JSON.stringify(input);
  } catch {
    return String(input);
  }
}

function serializeOpenAiError(payload: unknown): string {
  return truncate(serializeUnknown(payload), MAX_OPENAI_ERROR_CHARS);
}

function getResponsesIncompleteReason(payload: unknown): string {
  if (!payload || typeof payload !== "object") {
    return "";
  }

  const details = (payload as { incomplete_details?: unknown }).incomplete_details;
  if (!details || typeof details !== "object") {
    return "";
  }

  const reason = (details as { reason?: unknown }).reason;
  return typeof reason === "string" ? reason : "";
}

function extractResponsesText(payload: unknown): string {
  if (!payload || typeof payload !== "object") {
    return "";
  }

  const asRecord = payload as Record<string, unknown>;
  const outputText = asRecord.output_text;
  if (typeof outputText === "string" && outputText.trim()) {
    return outputText;
  }
  if (Array.isArray(outputText)) {
    const joined = outputText.filter((item) => typeof item === "string").join("\n").trim();
    if (joined) {
      return joined;
    }
  }

  const chunks: string[] = [];
  const output = asRecord.output;
  if (Array.isArray(output)) {
    for (const entry of output) {
      if (!entry || typeof entry !== "object") {
        continue;
      }
      const content = (entry as { content?: unknown }).content;
      if (!Array.isArray(content)) {
        continue;
      }
      for (const item of content) {
        if (!item || typeof item !== "object") {
          continue;
        }
        const candidate = item as { type?: unknown; text?: unknown };
        if ((candidate.type === "output_text" || candidate.type === "text") && typeof candidate.text === "string") {
          chunks.push(candidate.text);
        }
      }
    }
  }

  return chunks.join("\n").trim();
}

function extractChatCompletionsText(payload: unknown): string {
  if (!payload || typeof payload !== "object") {
    return "";
  }

  const maybeContent = (payload as { choices?: Array<{ message?: { content?: unknown } }> }).choices?.[0]
    ?.message?.content;

  if (typeof maybeContent === "string") {
    return maybeContent;
  }

  if (Array.isArray(maybeContent)) {
    return maybeContent
      .map((part) => {
        if (part && typeof part === "object" && "text" in part && typeof part.text === "string") {
          return part.text;
        }
        return "";
      })
      .join("\n")
      .trim();
  }

  return "";
}

function parseProposalJson(rawText: string): { explanation?: string; diff?: string } {
  const trimmed = rawText.trim();
  const candidates = [trimmed];
  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    candidates.push(trimmed.slice(firstBrace, lastBrace + 1));
  }

  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate) as { explanation?: string; diff?: string };
    } catch {
      // try next candidate
    }
  }

  throw new MiniCiServiceError(
    `LLM returned invalid JSON. Raw output: ${truncate(trimmed, MAX_OPENAI_ERROR_CHARS)}`,
    502,
  );
}

function parseSectionedProposal(rawText: string): { explanation?: string; diff?: string } | null {
  const xmlExplanation = rawText.match(/<explanation>\s*([\s\S]*?)\s*<\/explanation>/i)?.[1]?.trim();
  const xmlDiff = rawText.match(/<diff>\s*([\s\S]*?)\s*<\/diff>/i)?.[1]?.trim();
  if (xmlDiff) {
    return {
      explanation: xmlExplanation || "No explanation was returned.",
      diff: xmlDiff,
    };
  }

  const diffSectionMatch = rawText.match(/(?:^|\n)DIFF:\s*/i);
  if (!diffSectionMatch || diffSectionMatch.index == null) {
    return null;
  }

  const diffBody = rawText.slice(diffSectionMatch.index + diffSectionMatch[0].length).trim();
  if (!diffBody) {
    return null;
  }

  const diffMarker = diffBody.search(/diff --git /);
  const diff = (diffMarker >= 0 ? diffBody.slice(diffMarker) : diffBody).trim();
  if (!diff) {
    return null;
  }

  const explanationMatch = rawText.match(/(?:^|\n)EXPLANATION:\s*([\s\S]*?)(?:\nDIFF:\s*|$)/i);
  const explanation = explanationMatch?.[1]?.trim() || "No explanation was returned.";

  return { explanation, diff };
}

function unescapeJsonLikeString(value: string): string {
  return value
    .replace(/\\\\/g, "\\")
    .replace(/\\"/g, '"')
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t");
}

function parseProposalContent(rawText: string): { explanation?: string; diff?: string } {
  const sectioned = parseSectionedProposal(rawText);
  if (sectioned) {
    return sectioned;
  }

  try {
    return parseProposalJson(rawText);
  } catch (error) {
    const explanationMatch = rawText.match(/"explanation"\s*:\s*"([\s\S]*?)"\s*,/);
    const explanationFromJson = explanationMatch?.[1]
      ? unescapeJsonLikeString(explanationMatch[1]).trim()
      : "";

    const diffFieldMatch = rawText.match(/"diff"\s*:\s*"([\s\S]*)/);
    if (diffFieldMatch?.[1]) {
      let encoded = diffFieldMatch[1];
      encoded = encoded.replace(/"\s*[,}]\s*$/, "");
      return {
        explanation: explanationFromJson || "Model returned non-strict JSON output.",
        diff: unescapeJsonLikeString(encoded).trim(),
      };
    }

    const diffMarker = rawText.search(/diff --git /);
    if (diffMarker !== -1) {
      const explanationHead = rawText.slice(0, diffMarker).trim();
      const explanation = explanationFromJson
        || explanationHead.replace(/^["'{\s]+/, "").replace(/["'}\s,]+$/, "").trim()
        || "Model returned patch without a structured explanation.";
      const diff = rawText.slice(diffMarker).trim();

      return { explanation, diff };
    }

    throw error;
  }
}

function normalizeDiffPatch(rawDiff: string): string {
  let text = rawDiff.replace(/\r\n/g, "\n").trim();
  if (!text) {
    return "";
  }

  const fenced = text.match(/```(?:diff|patch)?\s*([\s\S]*?)```/i);
  if (fenced?.[1]) {
    text = fenced[1].trim();
  }

  const marker = text.match(/(^diff --git .*$|^---\s+\S+.*$)/m);
  if (marker?.index && marker.index > 0) {
    text = text.slice(marker.index).trim();
  }

  if (!text.includes("\n") && text.includes("\\n")) {
    text = text.replace(/\\n/g, "\n");
  }

  if (text.includes('\\"')) {
    text = text.replace(/\\"/g, '"');
  }

  if (!text.endsWith("\n")) {
    text += "\n";
  }

  return text.trim();
}

function hasUnifiedDiffStructure(diff: string): boolean {
  if (!diff) {
    return false;
  }

  const hasGitHeader = /^diff --git .+/m.test(diff);
  const hasFileHeaders = /^---\s+\S+/m.test(diff) && /^\+\+\+\s+\S+/m.test(diff);
  const hasHunks = /^@@\s+/m.test(diff);
  const hasModeOnlyChange = /^(new file mode|deleted file mode|Binary files)/m.test(diff);

  return (hasGitHeader || hasFileHeaders) && (hasHunks || hasModeOnlyChange);
}

function validateUnifiedDiff(diff: string): { ok: boolean; reason?: string } {
  if (!hasUnifiedDiffStructure(diff)) {
    return { ok: false, reason: "Missing unified diff headers/hunks." };
  }

  const lines = diff.replace(/\r\n/g, "\n").split("\n");
  let inHunk = false;

  const fileMetaPattern =
    /^(diff --git |index |new file mode |deleted file mode |old mode |new mode |similarity index |rename from |rename to |--- |\+\+\+ |Binary files )/;

  for (const line of lines) {
    if (!line) {
      continue;
    }

    if (fileMetaPattern.test(line)) {
      inHunk = false;
      continue;
    }

    if (line.startsWith("@@")) {
      const match = line.match(/^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@/);
      if (!match) {
        return { ok: false, reason: `Malformed hunk header: '${line}'.` };
      }
      inHunk = true;
      continue;
    }

    if (inHunk) {
      if (
        line.startsWith("+") ||
        line.startsWith("-") ||
        line.startsWith(" ") ||
        line === "\\ No newline at end of file"
      ) {
        continue;
      }
      return { ok: false, reason: `Unexpected line inside hunk: '${line}'.` };
    }

    return { ok: false, reason: `Unexpected line outside diff sections: '${line}'.` };
  }

  return { ok: true };
}

async function checkPatchInSandbox(
  sandbox: Sandbox,
  session: RunSession,
  diff: string,
  attempt: number,
): Promise<{ ok: boolean; reason: string; trace: TraceEvent[] }> {
  const trace: TraceEvent[] = [];
  const patchPath = `${session.repoRoot}/.mini-ci-agent.proposed-${attempt}.patch`;
  const writeStartedAt = Date.now();
  await sandbox.writeFiles([
    {
      path: patchPath,
      content: Buffer.from(diff, "utf8"),
    },
  ]);

  trace.push({
    ts: nowIso(),
    step: `write-proposed-patch-${attempt}`,
    tool: "sandbox.writeFiles",
    inputSummary: `${patchPath} (${diff.length} chars)`,
    exitCode: 0,
    stdoutSnippet: "Proposed patch written for validation.",
    stderrSnippet: "",
    durationMs: Date.now() - writeStartedAt,
  });

  const checkResult = await runSafeCommand(sandbox, {
    step: `check-proposed-patch-${attempt}`,
    cmd: "git",
    args: ["apply", "--check", "--whitespace=fix", "--recount", patchPath],
    cwd: session.repoRoot,
  });
  trace.push(checkResult.trace);

  const reason =
    checkResult.exitCode === 0
      ? ""
      : (checkResult.stderr || checkResult.stdout || `git apply --check failed with exit code ${checkResult.exitCode}`).trim();

  return {
    ok: checkResult.exitCode === 0,
    reason,
    trace,
  };
}

export async function proposeFix(input: {
  runId: string;
  failingLogs?: unknown;
  sessionHint?: SessionHint;
}): Promise<ProposeFixResponse> {
  const session = resolveSession(input.runId, input.sessionHint);
  const credentials = getSandboxCredentialsFromEnv();
  const sandbox = await Sandbox.get({
    ...(credentials ?? {}),
    sandboxId: session.sandboxId,
  });
  const key = process.env.OPENAI_API_KEY;
  if (!key) {
    throw new MiniCiServiceError("OPENAI_API_KEY is missing on the server.", 500);
  }

  const failedLogs =
    input.failingLogs ?? session.lastCiLogs.filter((log) => log.status === "failed");
  const serializedLogs = serializeFailingLogs(failedLogs);
  if (!serializedLogs || serializedLogs === "[]") {
    throw new MiniCiServiceError("No failing logs were provided for fix proposal.", 400);
  }

  const model = process.env.OPENAI_MODEL ?? "gpt-5-mini";
  const useResponsesApi = isResponsesApiModel(model);
  const endpoint = useResponsesApi
    ? "https://api.openai.com/v1/responses"
    : "https://api.openai.com/v1/chat/completions";
  const toolName = useResponsesApi ? "openai.responses" : "openai.chat.completions";
  const debugLlm = process.env.DEBUG_LLM === "1";
  const trace: TraceEvent[] = [];

  const contextResult = await collectRelevantFileContexts(sandbox, session, serializedLogs);
  trace.push(...contextResult.trace);

  const systemPrompt = [
    "You are a CI-fix agent.",
    "Return plain text with exactly two sections and no markdown fences:",
    "EXPLANATION:",
    "<one concise paragraph>",
    "DIFF:",
    "<a complete unified diff>",
    "Rules for DIFF:",
    "- Start with 'diff --git'.",
    "- Use numeric hunk headers: @@ -<start>,<count> +<start>,<count> @@",
    "- Do not output bare '@@' headers.",
    "- Do not use placeholders like '<snip>' or '[truncated]'.",
    "- The patch must apply with: git apply --check --whitespace=fix --recount",
  ].join("\n");

  const prompt = [
    "Given repository metadata and failing CI logs, produce a likely minimal patch.",
    "Return only the EXPLANATION and DIFF sections defined above.",
    "If uncertain, still propose the smallest safe patch.",
    "",
    `Framework guess: ${session.frameworkGuess}`,
    `Package manager: ${session.packageManager}`,
    `Scripts: ${JSON.stringify(session.scripts)}`,
    `Top-level files: ${JSON.stringify(session.topLevelTree)}`,
    "",
    "Failing logs:",
    serializedLogs,
    contextResult.contextText,
  ].join("\n");

  let lastFailure = "";
  let lastRawOutput = "";
  let terminalFailure = "";

  for (let attempt = 1; attempt <= MAX_PROPOSE_ATTEMPTS; attempt += 1) {
    const attemptPrompt =
      attempt === 1
        ? prompt
        : [
            prompt,
            "",
            "The previous patch was invalid.",
            `Failure reason: ${lastFailure || "Invalid patch format"}`,
            "Return a complete corrected patch in EXPLANATION/DIFF format. Do not truncate output.",
          ].join("\n");

    const requestBody = useResponsesApi
      ? {
          model,
          input: [
            {
              role: "system",
              content: [{ type: "input_text", text: systemPrompt }],
            },
            {
              role: "user",
              content: [{ type: "input_text", text: attemptPrompt }],
            },
          ],
          reasoning: { effort: "low" },
          text: { verbosity: "low" },
          max_output_tokens: LLM_MAX_OUTPUT_TOKENS,
        }
      : {
          model,
          max_tokens: LLM_MAX_OUTPUT_TOKENS,
          messages: [
            {
              role: "system",
              content: systemPrompt,
            },
            {
              role: "user",
              content: attemptPrompt,
            },
          ],
        };

    const startedAt = Date.now();
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    });
    const durationMs = Date.now() - startedAt;
    const payload = await parseJsonOrTextBody(response);

    if (!response.ok) {
      const openAiError = serializeOpenAiError(payload);
      if (debugLlm) {
        console.error("OpenAI propose-fix error payload:", payload);
      }

      trace.push({
        ts: nowIso(),
        step: `propose-fix-attempt-${attempt}`,
        tool: toolName,
        inputSummary: `model=${model}`,
        exitCode: 1,
        stdoutSnippet: "",
        stderrSnippet: truncate(openAiError, TRACE_SNIPPET_CHARS),
        durationMs,
      });

      throw new MiniCiServiceError(
        `OpenAI request failed (${response.status} ${response.statusText}): ${openAiError}`,
        502,
      );
    }

    const modelText = useResponsesApi ? extractResponsesText(payload) : extractChatCompletionsText(payload);
    if (!modelText) {
      const serializedPayload = serializeOpenAiError(payload);
      const incompleteReason = useResponsesApi ? getResponsesIncompleteReason(payload) : "";
      const failureMessage = incompleteReason
        ? `LLM returned empty content (incomplete: ${incompleteReason}).`
        : "LLM returned empty content.";

      trace.push({
        ts: nowIso(),
        step: `propose-fix-attempt-${attempt}`,
        tool: toolName,
        inputSummary: `model=${model}`,
        exitCode: 1,
        stdoutSnippet: "",
        stderrSnippet: truncate(failureMessage, TRACE_SNIPPET_CHARS),
        durationMs,
      });

      lastFailure = `${failureMessage} Response payload: ${serializedPayload}`;
      if (attempt < MAX_PROPOSE_ATTEMPTS) {
        continue;
      }
      terminalFailure = lastFailure;
      break;
    }

    lastRawOutput = modelText;

    let parsed: { explanation?: string; diff?: string };
    try {
      parsed = parseProposalContent(modelText);
    } catch (error) {
      const message = toErrorMessage(error);
      trace.push({
        ts: nowIso(),
        step: `propose-fix-attempt-${attempt}`,
        tool: toolName,
        inputSummary: `model=${model}`,
        exitCode: 1,
        stdoutSnippet: "",
        stderrSnippet: truncate(message, TRACE_SNIPPET_CHARS),
        durationMs,
      });

      if (attempt < MAX_PROPOSE_ATTEMPTS) {
        lastFailure = `Model output was not parseable JSON: ${message}`;
        continue;
      }

      terminalFailure = `Model output was not parseable JSON: ${message}`;
      break;
    }

    const explanation = parsed.explanation?.trim() || "No explanation was returned.";
    const rawDiff = parsed.diff?.trim() || "";
    const diff = normalizeDiffPatch(rawDiff);
    const validation = validateUnifiedDiff(diff);

    trace.push({
      ts: nowIso(),
      step: `propose-fix-attempt-${attempt}`,
      tool: toolName,
      inputSummary: `model=${model}`,
      exitCode: validation.ok && Boolean(diff) ? 0 : 1,
      stdoutSnippet: truncate(diff, TRACE_SNIPPET_CHARS),
      stderrSnippet: validation.ok ? "" : truncate(validation.reason || "No diff produced.", TRACE_SNIPPET_CHARS),
      durationMs,
    });

    if (!diff) {
      lastFailure = "LLM did not return a diff proposal.";
      if (attempt < MAX_PROPOSE_ATTEMPTS) {
        continue;
      }
      terminalFailure = lastFailure;
      break;
    }

    if (diff.length > MAX_DIFF_CHARS) {
      lastFailure = `LLM diff exceeded maximum size (${MAX_DIFF_CHARS} chars).`;
      if (attempt < MAX_PROPOSE_ATTEMPTS) {
        continue;
      }
      terminalFailure = lastFailure;
      break;
    }

    if (!validation.ok) {
      lastFailure = validation.reason || "LLM returned an invalid unified patch.";
      if (attempt < MAX_PROPOSE_ATTEMPTS) {
        continue;
      }
      terminalFailure = `LLM returned an invalid unified patch: ${lastFailure}. Raw diff snippet: ${truncate(rawDiff, 1500)}`;
      break;
    }

    const patchCheck = await checkPatchInSandbox(sandbox, session, diff, attempt);
    trace.push(...patchCheck.trace);
    if (!patchCheck.ok) {
      lastFailure = `Patch failed git apply --check: ${patchCheck.reason}`;
      if (attempt < MAX_PROPOSE_ATTEMPTS) {
        continue;
      }
      terminalFailure = `Generated patch is not applicable in sandbox: ${patchCheck.reason}`;
      break;
    }

    return {
      runId: session.runId,
      explanation,
      diff,
      trace,
    };
  }

  const fallbackReason =
    terminalFailure
    || lastFailure
    || `Unable to generate a valid patch after ${MAX_PROPOSE_ATTEMPTS} attempts. Raw output: ${truncate(lastRawOutput, 1500)}`;

  try {
    const fallbackResult = await proposeFixWithStructuredEditsFallback({
      sandbox,
      session,
      model,
      useResponsesApi,
      endpoint,
      key,
      toolName,
      debugLlm,
      serializedLogs,
      contextText: contextResult.contextText,
      failureReason: fallbackReason,
    });
    trace.push(...fallbackResult.trace);
    return {
      runId: session.runId,
      explanation: fallbackResult.explanation,
      diff: fallbackResult.diff,
      trace,
    };
  } catch (fallbackError) {
    throw new MiniCiServiceError(
      `${fallbackReason}. Structured fallback failed: ${toErrorMessage(fallbackError)}`,
      502,
    );
  }
}

export async function applyFix(input: {
  runId: string;
  diff: string;
  sessionHint?: SessionHint;
}): Promise<ApplyFixResponse> {
  const session = resolveSession(input.runId, input.sessionHint);
  const normalizedDiff = normalizeDiffPatch(input.diff);
  if (!normalizedDiff) {
    throw new Error("Diff is required.");
  }

  if (normalizedDiff.length > MAX_DIFF_CHARS) {
    throw new Error(`Diff too large (>${MAX_DIFF_CHARS} chars).`);
  }

  const validation = validateUnifiedDiff(normalizedDiff);
  if (!validation.ok) {
    throw new MiniCiServiceError(
      `Proposed diff is not a valid unified patch (${validation.reason}). Please generate a new fix proposal.`,
      400,
    );
  }

  const credentials = getSandboxCredentialsFromEnv();
  const sandbox = await Sandbox.get({
    ...(credentials ?? {}),
    sandboxId: session.sandboxId,
  });
  const trace: TraceEvent[] = [];
  const logs: CiStepLog[] = [];

  const patchPath = `${session.repoRoot}/.mini-ci-agent.patch`;
  const writeStartedAt = Date.now();
  await sandbox.writeFiles([
    {
      path: patchPath,
      content: Buffer.from(normalizedDiff, "utf8"),
    },
  ]);

  trace.push({
    ts: nowIso(),
    step: "write-patch",
    tool: "sandbox.writeFiles",
    inputSummary: `${patchPath} (${normalizedDiff.length} chars)`,
    exitCode: 0,
    stdoutSnippet: "Patch written to sandbox.",
    stderrSnippet: "",
    durationMs: Date.now() - writeStartedAt,
  });

  const checkPatchResult = await runSafeCommand(sandbox, {
    step: "check-patch",
    cmd: "git",
    args: ["apply", "--check", "--whitespace=fix", "--recount", patchPath],
    cwd: session.repoRoot,
  });
  trace.push(checkPatchResult.trace);

  if (checkPatchResult.exitCode !== 0) {
    logs.push({
      step: "apply_patch",
      command: checkPatchResult.commandLabel,
      status: "failed",
      exitCode: checkPatchResult.exitCode,
      stdout: checkPatchResult.stdout,
      stderr: checkPatchResult.stderr,
      durationMs: checkPatchResult.durationMs,
    });
    return {
      runId: session.runId,
      passed: false,
      logs,
      diff: "",
      trace,
    };
  }

  const applyResult = await runSafeCommand(sandbox, {
    step: "apply-patch",
    cmd: "git",
    args: ["apply", "--whitespace=fix", "--recount", patchPath],
    cwd: session.repoRoot,
  });
  trace.push(applyResult.trace);

  const applyLog: CiStepLog = {
    step: "apply_patch",
    command: applyResult.commandLabel,
    status: applyResult.exitCode === 0 ? "passed" : "failed",
    exitCode: applyResult.exitCode,
    stdout: applyResult.stdout,
    stderr: applyResult.stderr,
    durationMs: applyResult.durationMs,
  };
  logs.push(applyLog);

  if (applyResult.exitCode !== 0) {
    return {
      runId: session.runId,
      passed: false,
      logs,
      diff: "",
      trace,
    };
  }

  const ciResult = await executeCi(session, sandbox);
  logs.push(...ciResult.logs);
  trace.push(...ciResult.trace);

  const finalDiffResult = await runSafeCommand(sandbox, {
    step: "final-diff",
    cmd: "git",
    args: ["diff", "HEAD", "--"],
    cwd: session.repoRoot,
  });
  trace.push(finalDiffResult.trace);

  return {
    runId: session.runId,
    passed: applyResult.exitCode === 0 && ciResult.passed,
    logs,
    diff: finalDiffResult.stdout,
    trace,
  };
}
