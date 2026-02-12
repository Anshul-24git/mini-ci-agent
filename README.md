# Mini CI Agent

A Next.js 15 (App Router) + TypeScript web app that analyzes a public GitHub repo, runs CI in a Vercel Sandbox, proposes a patch from failing logs, then applies and re-runs CI.

## Setup

1. Install dependencies:

```bash
npm install
```

2. Set server environment variables:

```bash
OPENAI_API_KEY=your_openai_key
# Optional
OPENAI_MODEL=gpt-5-mini
```

3. Configure Vercel Sandbox authentication (one option):

- OIDC (recommended for local dev, expires periodically):

```bash
vercel env pull .env.local
```

- or explicit access token credentials:

```bash
VERCEL_TEAM_ID=team_xxx
VERCEL_PROJECT_ID=prj_xxx
VERCEL_TOKEN=vercel_pat_xxx
```

4. Start the app:

```bash
npm run dev
```

## Architecture And Flow

### UI (`/`)

The homepage in `/app/page.tsx` includes:
- Public GitHub URL input
- Actions: Analyze Repo, Run CI, Propose Fix, Apply Fix + Re-run
- Panels:
  - Repo Summary
  - CI Logs
  - Proposed Diff
  - Execution Trace Timeline

Each action calls one backend route and appends trace events to the timeline.

### API routes (`/app/api`)

- `POST /api/analyze`
  - Validates GitHub URL
  - Creates a Vercel Sandbox with git source clone
  - Detects package manager/scripts/framework guess
  - Collects top-level file tree
  - Persists sandbox session by `runId`

- `POST /api/run-ci`
  - Reuses sandbox from `runId`
  - Runs install + lint + test + build (best effort based on scripts)
  - Returns structured logs and pass/fail

- `POST /api/propose-fix`
  - Reads failing CI logs
  - Calls LLM using `OPENAI_API_KEY` on server only
  - Returns explanation + unified diff text
  - Does not apply patch

- `POST /api/apply-fix`
  - Writes diff file inside the same sandbox
  - Applies patch with `git apply`
  - Re-runs CI
  - Returns updated logs and final `git diff`

### Shared service layer

`/lib/mini-ci/service.ts` handles:
- In-memory `runId -> sandbox session` map
- Command execution with:
  - Allowlist enforcement (`git`, `node`, `npm`, `pnpm`, `yarn`, `python`)
  - Timeout via detached command + `SIGTERM` kill
  - Output truncation for logs/snippets
- Trace event generation for every tool call

### Trace format

Every action returns a `trace` array with this shape:

```ts
{
  ts,
  step,
  tool,
  inputSummary,
  exitCode,
  stdoutSnippet,
  stderrSnippet,
  durationMs
}
```

## Security Guardrails

- No arbitrary shell input from the user is executed.
- Repo URL must be an HTTPS GitHub URL.
- Commands are routed through an explicit allowlist.
- LLM API key is read from server env vars and never exposed client-side.
- Command outputs and diffs are truncated to bounded sizes.
