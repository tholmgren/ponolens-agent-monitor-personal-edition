const GENERATE_FIELDS = Object.freeze(["prompt", "system", "suffix"]);

function contentText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((part) => typeof part === "string" ? part : typeof part?.text === "string" ? part.text : "").filter(Boolean).join("\n");
}

function mapContent(content, transform) {
  if (typeof content === "string") return transform(content);
  if (!Array.isArray(content)) return content;
  return content.map((part) => {
    if (typeof part === "string") return transform(part);
    if (part && typeof part === "object" && typeof part.text === "string") return { ...part, text: transform(part.text) };
    return part;
  });
}

export function ollamaPromptText(body, endpoint) {
  if (!body || typeof body !== "object") return "";
  if (endpoint === "generate") return GENERATE_FIELDS.map((field) => typeof body[field] === "string" ? body[field] : "").filter(Boolean).join("\n");
  if (endpoint === "chat") return (Array.isArray(body.messages) ? body.messages : []).map((message) => contentText(message?.content)).filter(Boolean).join("\n");
  return "";
}

export function rewriteOllamaPrompt(body, endpoint, transform) {
  const rewritten = { ...body };
  if (endpoint === "generate") {
    for (const field of GENERATE_FIELDS) if (typeof rewritten[field] === "string") rewritten[field] = transform(rewritten[field]);
  }
  if (endpoint === "chat" && Array.isArray(rewritten.messages)) {
    rewritten.messages = rewritten.messages.map((message) => message && typeof message === "object" ? { ...message, content: mapContent(message.content, transform) } : message);
  }
  return rewritten;
}

export function ollamaMetrics(body) {
  if (!body || typeof body !== "object") return {};
  return {
    model: typeof body.model === "string" ? body.model : null,
    promptTokens: Number.isFinite(Number(body.prompt_eval_count)) ? Number(body.prompt_eval_count) : null,
    responseTokens: Number.isFinite(Number(body.eval_count)) ? Number(body.eval_count) : null,
    totalDurationNs: Number.isFinite(Number(body.total_duration)) ? Number(body.total_duration) : null,
  };
}
