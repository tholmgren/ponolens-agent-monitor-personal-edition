import test from "node:test";
import assert from "node:assert/strict";
import { ollamaMetrics, ollamaPromptText, rewriteOllamaPrompt } from "../src/ollama-gateway.mjs";
import { analyzeEvent } from "../src/risk-engine.mjs";
import { DEFAULT_POLICY, normalizePolicy } from "../src/policy.mjs";
import { featureEnabled } from "../public/product-config.js";

test("Ollama Gateway prototype is disabled in the current product build", () => {
  assert.equal(featureEnabled("ollamaGateway"), false);
});

test("extracts supported Ollama generate and chat text without treating images as text", () => {
  assert.equal(ollamaPromptText({ prompt: "Draft for jane@example.com", system: "Be concise", suffix: "End" }, "generate"), "Draft for jane@example.com\nBe concise\nEnd");
  assert.equal(ollamaPromptText({ messages: [{ role: "system", content: "Be concise" }, { role: "user", content: [{ type: "text", text: "Email jane@example.com" }, { type: "image", image: "base64-data" }] }] }, "chat"), "Be concise\nEmail jane@example.com");
});

test("rewrites only supported Ollama prompt fields and preserves request structure", () => {
  const source = { model: "gemma3", stream: false, messages: [{ role: "user", content: [{ type: "text", text: "jane@example.com" }, { type: "image", image: "unchanged" }] }], tools: [{ function: { name: "lookup" } }] };
  const rewritten = rewriteOllamaPrompt(source, "chat", (value) => value.replace("jane@example.com", "[REDACTED]"));
  assert.equal(rewritten.messages[0].content[0].text, "[REDACTED]");
  assert.equal(rewritten.messages[0].content[1].image, "unchanged");
  assert.deepEqual(rewritten.tools, source.tools);
  assert.equal(source.messages[0].content[0].text, "jane@example.com");
});

test("captures non-streaming Ollama metrics without retaining response text", () => {
  assert.deepEqual(ollamaMetrics({ model: "gemma3", response: "private reply", prompt_eval_count: 12, eval_count: 34, total_duration: 5000 }), { model: "gemma3", promptTokens: 12, responseTokens: 34, totalDurationNs: 5000 });
});

test("Ollama Gateway honors report, redact, and block policy actions before submission", () => {
  const event = { harness: "ollama-gateway", action: "prompt", hookEvent: "gateway", source: "test", destination: "Ollama on this device", destinationTrust: "trusted", content: "Email jane@example.com" };
  const report = analyzeEvent(event, normalizePolicy({ ...DEFAULT_POLICY, mode: "observe" }));
  const redact = analyzeEvent(event, normalizePolicy({ ...DEFAULT_POLICY, mode: "redact" }));
  const block = analyzeEvent(event, normalizePolicy({ ...DEFAULT_POLICY, mode: "block_critical" }));
  assert.equal(report.decision, "allowed");
  assert.equal(report.policyResult.action, "warn");
  assert.equal(redact.decision, "blocked");
  assert.equal(redact.policyResult.action, "redact");
  assert.equal(block.decision, "blocked");
  assert.equal(block.policyResult.action, "block");
  assert.equal(block.interception.capable, true);
});
