import { model, modelID } from "@/ai/providers";
import { weatherTool } from "@/ai/tools";
import { streamText, UIMessage } from "ai";

// Allow streaming responses up to 30 seconds
export const maxDuration = 30;

const BACKEND_URL =
  process.env.BACKEND_API_URL || process.env.NEXT_PUBLIC_FLASK_URL || "http://localhost:5000";

export async function POST(req: Request) {
  const {
    messages,
    selectedModel,
    authToken,
    machineId,
  }: {
    messages: UIMessage[];
    selectedModel: modelID;
    authToken?: string;
    machineId?: string;
  } = await req.json();

  // Authoritative gate: ask the Python backend whether this session is
  // allowed to use the requested model at its current access tier. This is
  // what prevents a user from bypassing the frontend model picker.
  if (!authToken) {
    return new Response(JSON.stringify({ error: "Missing auth token" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  }

  const gate = await fetch(`${BACKEND_URL}/api/access/check-model`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Authorization: `Bearer ${authToken}`,
    },
    body: JSON.stringify({ model: selectedModel, machine_id: machineId }),
  });

  if (!gate.ok) {
    const body = await gate.json().catch(() => ({}));
    return new Response(
      JSON.stringify({
        error: "Model not permitted",
        reason: body.reason,
        tier: body.tier,
      }),
      { status: 403, headers: { "content-type": "application/json" } },
    );
  }

  const result = streamText({
    model: model.languageModel(selectedModel),
    system: "You are a helpful assistant.",
    messages,
    tools: {
      getWeather: weatherTool,
    },
    experimental_telemetry: {
      isEnabled: true,
    },
  });

  return result.toDataStreamResponse({ sendReasoning: true });
}
