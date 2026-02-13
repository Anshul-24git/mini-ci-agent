import { NextRequest, NextResponse } from "next/server";

import type { SessionHint } from "@/lib/mini-ci/contracts";
import { applyFix } from "@/lib/mini-ci/service";

export const runtime = "nodejs";

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
    const message = error instanceof Error ? error.message : "Apply fix failed.";
    return NextResponse.json({ error: message, trace: [] }, { status: 500 });
  }
}
