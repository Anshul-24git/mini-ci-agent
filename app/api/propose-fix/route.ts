import { NextRequest, NextResponse } from "next/server";

import { proposeFix } from "@/lib/mini-ci/service";

export const runtime = "nodejs";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = (await request.json()) as { runId?: string; failingLogs?: unknown };
    if (!body.runId || typeof body.runId !== "string") {
      return NextResponse.json({ error: "runId is required." }, { status: 400 });
    }

    const result = await proposeFix({
      runId: body.runId,
      failingLogs: body.failingLogs,
    });

    return NextResponse.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Propose fix failed.";
    return NextResponse.json({ error: message, trace: [] }, { status: 500 });
  }
}
