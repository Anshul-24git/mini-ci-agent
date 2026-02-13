import { NextRequest, NextResponse } from "next/server";

import type { SessionHint } from "@/lib/mini-ci/contracts";
import { applyFix, MiniCiServiceError } from "@/lib/mini-ci/service";

export const runtime = "nodejs";

function shortenErrorMessage(input: string, maxChars = 1200): string {
  const clean = input.replace(/\s+/g, " ").trim();
  if (clean.length <= maxChars) {
    return clean;
  }

  return `${clean.slice(0, maxChars)}...[truncated]`;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = (await request.json()) as {
      runId?: string;
      diff?: string;
      sessionHint?: SessionHint;
    };
    if (!body.runId || typeof body.runId !== "string") {
      return NextResponse.json({ error: "runId is required." }, { status: 400 });
    }

    if (!body.diff || typeof body.diff !== "string") {
      return NextResponse.json({ error: "diff is required." }, { status: 400 });
    }

    const result = await applyFix({
      runId: body.runId,
      diff: body.diff,
      sessionHint: body.sessionHint,
    });

    return NextResponse.json(result);
  } catch (error) {
    const statusCode = error instanceof MiniCiServiceError ? error.statusCode : 500;
    const rawMessage = error instanceof Error ? error.message : "Apply fix failed.";
    const message = shortenErrorMessage(rawMessage);
    return NextResponse.json({ error: message, statusCode, trace: [] }, { status: statusCode });
  }
}
