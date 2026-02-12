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
  const teamId = process.env.VERCEL_TEAM_ID?.trim();
  const projectId = process.env.VERCEL_PROJECT_ID?.trim();
  const token = process.env.VERCEL_TOKEN?.trim();

  const provided = [teamId, projectId, token].filter(Boolean).length;
  if (provided === 0) {
    return undefined;
  }

  if (!teamId || !projectId || !token) {
    const missing = [
      teamId ? null : "VERCEL_TEAM_ID",
      projectId ? null : "VERCEL_PROJECT_ID",
      token ? null : "VERCEL_TOKEN",
    ]
      .filter(Boolean)
      .join(", ");
    throw new Error(
      `Incomplete Vercel Sandbox credentials. Missing: ${missing}. ` +
        "Set all three env vars or remove them to use Vercel OIDC.",
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

  runSessions.set(runId, {
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
  });

  return {
    runId,
    sandboxId: sandbox.sandboxId,
    summary,
    trace,
  };
}

export async function runCi(runId: string): Promise<RunCiResponse> {
  const session = requireSession(runId);
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

export async function proposeFix(input: { runId: string; failingLogs?: unknown }): Promise<ProposeFixResponse> {
  const session = requireSession(input.runId);
  const key = process.env.OPENAI_API_KEY;
  if (!key) {
    throw new Error("OPENAI_API_KEY is missing on the server.");
  }

  const failedLogs =
    input.failingLogs ?? session.lastCiLogs.filter((log) => log.status === "failed");
  const serializedLogs = serializeFailingLogs(failedLogs);
  if (!serializedLogs || serializedLogs === "[]") {
    throw new Error("No failing logs were provided for fix proposal.");
  }

  const model = process.env.OPENAI_MODEL ?? "gpt-5-mini";
  const prompt = [
    "You are a CI-fix agent.",
    "Given repository metadata and failing CI logs, produce a likely minimal patch.",
    "Return a JSON object with keys: explanation (string), diff (string).",
    "The diff must be a valid unified diff against repository root.",
    "Do not include markdown fences.",
    "If uncertain, still propose the smallest safe patch.",
    "",
    `Framework guess: ${session.frameworkGuess}`,
    `Package manager: ${session.packageManager}`,
    `Scripts: ${JSON.stringify(session.scripts)}`,
    `Top-level files: ${JSON.stringify(session.topLevelTree)}`,
    "",
    "Failing logs:",
    serializedLogs,
  ].join("\n");

  const startedAt = Date.now();
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You output strict JSON with fields explanation and diff. diff is unified patch text.",
        },
        {
          role: "user",
          content: prompt,
        },
      ],
    }),
  });

  const durationMs = Date.now() - startedAt;
  const trace: TraceEvent[] = [];

  const payload = await response.json();

  if (!response.ok) {
    trace.push({
      ts: nowIso(),
      step: "propose-fix",
      tool: "openai.chat.completions",
      inputSummary: `model=${model}`,
      exitCode: 1,
      stdoutSnippet: "",
      stderrSnippet: truncate(JSON.stringify(payload), TRACE_SNIPPET_CHARS),
      durationMs,
    });
    throw new Error("LLM request failed while proposing fix.");
  }

  const content = payload?.choices?.[0]?.message?.content;

  let explanation = "No explanation was returned.";
  let diff = "";

  if (typeof content === "string") {
    try {
      const parsed = JSON.parse(content) as { explanation?: string; diff?: string };
      explanation = parsed.explanation?.trim() || explanation;
      diff = parsed.diff?.trim() || "";
    } catch {
      explanation = "The model response was not valid JSON.";
    }
  }

  trace.push({
    ts: nowIso(),
    step: "propose-fix",
    tool: "openai.chat.completions",
    inputSummary: `model=${model}`,
    exitCode: diff ? 0 : 1,
    stdoutSnippet: truncate(diff, TRACE_SNIPPET_CHARS),
    stderrSnippet: diff ? "" : "No diff produced.",
    durationMs,
  });

  if (!diff) {
    throw new Error("LLM did not return a diff proposal.");
  }

  if (diff.length > MAX_DIFF_CHARS) {
    throw new Error(`LLM diff exceeded maximum size (${MAX_DIFF_CHARS} chars).`);
  }

  return {
    runId: session.runId,
    explanation,
    diff,
    trace,
  };
}

export async function applyFix(input: { runId: string; diff: string }): Promise<ApplyFixResponse> {
  const session = requireSession(input.runId);
  const rawDiff = input.diff.trim();
  if (!rawDiff) {
    throw new Error("Diff is required.");
  }

  if (rawDiff.length > MAX_DIFF_CHARS) {
    throw new Error(`Diff too large (>${MAX_DIFF_CHARS} chars).`);
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
      content: Buffer.from(rawDiff, "utf8"),
    },
  ]);

  trace.push({
    ts: nowIso(),
    step: "write-patch",
    tool: "sandbox.writeFiles",
    inputSummary: `${patchPath} (${rawDiff.length} chars)`,
    exitCode: 0,
    stdoutSnippet: "Patch written to sandbox.",
    stderrSnippet: "",
    durationMs: Date.now() - writeStartedAt,
  });

  const applyResult = await runSafeCommand(sandbox, {
    step: "apply-patch",
    cmd: "git",
    args: ["apply", "--whitespace=fix", patchPath],
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
