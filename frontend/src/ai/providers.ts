import { groq } from "@ai-sdk/groq";
import { customProvider } from "ai";

// Registered Groq models. The canonical list of what's *available to a user*
// comes from the Python backend's /api/access/models endpoint — this file
// just registers everything Argus can possibly route to, including inactive
// preview models so the admin can toggle them on without a code change.
export const model = customProvider({
  languageModels: {
    "openai/gpt-oss-20b": groq("openai/gpt-oss-20b"),
    "llama-3.1-8b-instant": groq("llama-3.1-8b-instant"),
    "llama-3.3-70b-versatile": groq("llama-3.3-70b-versatile"),
    "openai/gpt-oss-120b": groq("openai/gpt-oss-120b"),
    "meta-llama/llama-4-scout-17b": groq("meta-llama/llama-4-scout-17b"),
    "qwen/qwen3-32b": groq("qwen/qwen3-32b"),
  },
});

export type modelID = Parameters<(typeof model)["languageModel"]>["0"];
