import { randomUUID } from "node:crypto";

import { NextRequest, NextResponse } from "next/server";

import { analyzeRepository } from "@/lib/mini-ci/service";

export const runtime = "nodejs";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = (await request.json()) as { runId?: string; repoUrl?: string };

    if (!body.repoUrl || typeof body.repoUrl !== "string") {
      return NextResponse.json({ error: "repoUrl is required." }, { status: 400 });
    }

    const result = await analyzeRepository({
      runId: typeof body.runId === "string" ? body.runId : randomUUID(),
      repoUrl: body.repoUrl,
    });

    return NextResponse.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Analyze failed.";
    return NextResponse.json({ error: message, trace: [] }, { status: 500 });
  }
}
