import { NextRequest, NextResponse } from "next/server";

import { MiniCiServiceError, proposeFix } from "@/lib/mini-ci/service";

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
    const body = (await request.json()) as { runId?: string; failingLogs?: unknown };
    if (!body.runId || typeof body.runId !== "string") {
      return NextResponse.json({ error: "runId is required.", statusCode: 400 }, { status: 400 });
    }

    const result = await proposeFix({
      runId: body.runId,
      failingLogs: body.failingLogs,
    });

    return NextResponse.json(result);
  } catch (error) {
    const statusCode = error instanceof MiniCiServiceError ? error.statusCode : 500;
    const rawMessage = error instanceof Error ? error.message : "Propose fix failed.";
    const message = shortenErrorMessage(rawMessage);
    return NextResponse.json({ error: message, statusCode, trace: [] }, { status: statusCode });
  }
}
