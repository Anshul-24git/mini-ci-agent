"use client";

import { useEffect, useMemo, useState } from "react";

import type {
  AnalyzeResponse,
  ApplyFixResponse,
  CiStepLog,
  ProposeFixResponse,
  RepoSummary,
  RunCiResponse,
  SessionHint,
  TraceEvent,
} from "@/lib/mini-ci/contracts";

type BusyAction = "analyze" | "run-ci" | "propose-fix" | "apply-fix" | null;

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const statusFromPayload =
      payload && typeof payload === "object" && "statusCode" in payload && typeof payload.statusCode === "number"
        ? payload.statusCode
        : response.status;

    const serverMessage =
      payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
        ? payload.error
        : "";

    throw new Error(serverMessage ? `[${statusFromPayload}] ${serverMessage}` : `Request failed (${statusFromPayload})`);
  }

  return payload as T;
}

function formatDuration(ms: number): string {
  if (!Number.isFinite(ms)) {
    return "n/a";
  }

  if (ms < 1000) {
    return `${ms}ms`;
  }

  return `${(ms / 1000).toFixed(1)}s`;
}

export default function HomePage() {
  const [repoUrl, setRepoUrl] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<BusyAction>(null);
  const [errorMessage, setErrorMessage] = useState<string>("");

  const [repoSummary, setRepoSummary] = useState<RepoSummary | null>(null);
  const [sessionHint, setSessionHint] = useState<SessionHint | null>(null);
  const [ciResult, setCiResult] = useState<RunCiResponse | null>(null);
  const [proposal, setProposal] = useState<ProposeFixResponse | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyFixResponse | null>(null);
  const [timeline, setTimeline] = useState<TraceEvent[]>([]);

  const activeLogs = useMemo<CiStepLog[]>(() => {
    if (applyResult?.logs) {
      return applyResult.logs;
    }

    return ciResult?.logs ?? [];
  }, [applyResult, ciResult]);

  useEffect(() => {
    setRunId((current) => current ?? crypto.randomUUID());
  }, []);

  async function withAction(action: BusyAction, task: () => Promise<void>): Promise<void> {
    setErrorMessage("");
    setBusyAction(action);
    try {
      await task();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setErrorMessage(message);
    } finally {
      setBusyAction(null);
    }
  }

  async function onAnalyze(): Promise<void> {
    await withAction("analyze", async () => {
      const response = await postJson<AnalyzeResponse>("/api/analyze", {
        runId: runId ?? undefined,
        repoUrl,
      });

      setRunId(response.runId);
      setRepoSummary(response.summary);
      setSessionHint(response.sessionHint);
      setCiResult(null);
      setProposal(null);
      setApplyResult(null);
      setTimeline(response.trace);
    });
  }

  async function onRunCi(): Promise<void> {
    if (!runId) {
      setErrorMessage("Run ID not ready yet. Please try again.");
      return;
    }

    await withAction("run-ci", async () => {
      const response = await postJson<RunCiResponse>("/api/run-ci", {
        runId,
        sessionHint,
      });
      setCiResult(response);
      setApplyResult(null);
      setTimeline((current) => [...current, ...response.trace]);
    });
  }

  async function onProposeFix(): Promise<void> {
    if (!runId) {
      setErrorMessage("Run ID not ready yet. Please try again.");
      return;
    }

    await withAction("propose-fix", async () => {
      const failingLogs = activeLogs.filter((log) => log.status === "failed");
      const response = await postJson<ProposeFixResponse>("/api/propose-fix", {
        runId,
        failingLogs,
        sessionHint,
      });
      setProposal(response);
      setTimeline((current) => [...current, ...response.trace]);
    });
  }

  async function onApplyFix(): Promise<void> {
    if (!proposal?.diff) {
      setErrorMessage("No proposed diff is available.");
      return;
    }

    if (!runId) {
      setErrorMessage("Run ID not ready yet. Please try again.");
      return;
    }

    await withAction("apply-fix", async () => {
      const response = await postJson<ApplyFixResponse>("/api/apply-fix", {
        runId,
        diff: proposal.diff,
        sessionHint,
      });
      setApplyResult(response);
      setTimeline((current) => [...current, ...response.trace]);
    });
  }

  const isBusy = busyAction !== null;

  return (
    <main className="page-shell">
      <section className="header-panel">
        <h1>Mini CI Agent</h1>
        <p>Analyze a public GitHub repository, run CI in a sandbox, and iterate with patch proposals.</p>

        <div className="repo-input-row">
          <input
            type="url"
            placeholder="https://github.com/owner/repo"
            value={repoUrl}
            onChange={(event) => setRepoUrl(event.target.value)}
          />
        </div>

        <div className="button-row">
          <button type="button" onClick={onAnalyze} disabled={isBusy || !repoUrl.trim()}>
            Analyze Repo
          </button>
          <button type="button" onClick={onRunCi} disabled={isBusy || !repoSummary}>
            Run CI
          </button>
          <button
            type="button"
            onClick={onProposeFix}
            disabled={isBusy || activeLogs.every((log) => log.status !== "failed")}
          >
            Propose Fix
          </button>
          <button type="button" onClick={onApplyFix} disabled={isBusy || !proposal?.diff}>
            Apply Fix + Re-run
          </button>
        </div>

        <div className="meta-row">
          <span>Run ID: {runId ?? "initializing..."}</span>
          <span>{busyAction ? `Running ${busyAction}...` : "Idle"}</span>
        </div>

        {errorMessage ? <p className="error-box">{errorMessage}</p> : null}
      </section>

      <section className="panel-grid">
        <article className="panel">
          <h2>Repo Summary</h2>
          {repoSummary ? (
            <pre>{JSON.stringify(repoSummary, null, 2)}</pre>
          ) : (
            <p className="placeholder">Run Analyze Repo to populate repository metadata.</p>
          )}
        </article>

        <article className="panel">
          <h2>CI Logs</h2>
          {activeLogs.length > 0 ? (
            <div className="log-list">
              {activeLogs.map((log, index) => (
                <div key={`${log.step}-${index}`} className={`log-item status-${log.status}`}>
                  <div className="log-item-header">
                    <span>{log.step}</span>
                    <span>{log.status}</span>
                    <span>{formatDuration(log.durationMs)}</span>
                  </div>
                  <div className="log-command">{log.command || "(skipped)"}</div>
                  {log.stderr ? <pre>{log.stderr}</pre> : null}
                  {log.stdout ? <pre>{log.stdout}</pre> : null}
                </div>
              ))}
            </div>
          ) : (
            <p className="placeholder">Run CI to populate structured logs.</p>
          )}
        </article>

        <article className="panel">
          <h2>Proposed Diff</h2>
          {proposal ? (
            <>
              <p>{proposal.explanation}</p>
              <pre>{proposal.diff}</pre>
            </>
          ) : (
            <p className="placeholder">Use Propose Fix after a failing CI run.</p>
          )}

          {applyResult?.diff ? (
            <>
              <h3>Final Diff After Apply</h3>
              <pre>{applyResult.diff}</pre>
            </>
          ) : null}
        </article>

        <article className="panel">
          <h2>Execution Trace Timeline</h2>
          {timeline.length > 0 ? (
            <div className="trace-list">
              {timeline.map((event, index) => (
                <div key={`${event.ts}-${event.step}-${index}`} className="trace-item">
                  <div className="trace-title-row">
                    <span>{event.step}</span>
                    <span>{event.tool}</span>
                    <span>exit={event.exitCode ?? "n/a"}</span>
                    <span>{formatDuration(event.durationMs)}</span>
                  </div>
                  <div className="trace-meta">{event.ts}</div>
                  <div className="trace-meta">{event.inputSummary}</div>
                  {event.stdoutSnippet ? <pre>{event.stdoutSnippet}</pre> : null}
                  {event.stderrSnippet ? <pre>{event.stderrSnippet}</pre> : null}
                </div>
              ))}
            </div>
          ) : (
            <p className="placeholder">Trace events will appear after each action.</p>
          )}
        </article>
      </section>
    </main>
  );
}
