export type TraceEvent = {
  ts: string;
  step: string;
  tool: string;
  inputSummary: string;
  exitCode: number | null;
  stdoutSnippet: string;
  stderrSnippet: string;
  durationMs: number;
};

export type PackageManager = "npm" | "pnpm" | "yarn";

export type RepoSummary = {
  frameworkGuess: string;
  packageManager: PackageManager;
  scripts: Record<string, string>;
  fileTreeTopLevel: string[];
};

export type CiStepStatus = "passed" | "failed" | "skipped";

export type CiStepLog = {
  step: string;
  command: string;
  status: CiStepStatus;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
};

export type AnalyzeResponse = {
  runId: string;
  sandboxId: string;
  summary: RepoSummary;
  trace: TraceEvent[];
};

export type RunCiResponse = {
  runId: string;
  passed: boolean;
  logs: CiStepLog[];
  trace: TraceEvent[];
};

export type ProposeFixResponse = {
  runId: string;
  explanation: string;
  diff: string;
  trace: TraceEvent[];
};

export type ApplyFixResponse = {
  runId: string;
  passed: boolean;
  logs: CiStepLog[];
  diff: string;
  trace: TraceEvent[];
};
