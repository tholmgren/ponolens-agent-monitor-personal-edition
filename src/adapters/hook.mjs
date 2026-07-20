#!/usr/bin/env node
import { homedir } from "node:os";
import { join } from "node:path";
import { analyzeEvent, redactContent, redactEventForStorage } from "../risk-engine.mjs";
import { EventStore } from "../store.mjs";
import { normalizeHookEvent, shouldRecordEvent } from "./event-normalizer.mjs";
import { DEFAULT_POLICY, normalizePolicy } from "../policy.mjs";

const harness = process.argv[2] || "unknown";
const dataDir = process.env.PONOLENS_DATA_DIR || join(homedir(), ".ponolens");
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);

try {
  const raw = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  const event = normalizeHookEvent(raw, harness);
  const store = new EventStore(join(dataDir, "ponolens.db"));
  const policy = normalizePolicy(store.getSetting("protection_policy", DEFAULT_POLICY));
  const analysis = analyzeEvent(event, policy);
  if (shouldRecordEvent(event, policy)) store.add(redactEventForStorage(event, policy), analysis);

  if (analysis.decision === "blocked") {
    const protectedPrompt = analysis.policyResult?.action === "redact" && event.action === "prompt" ? redactContent(event.content, policy) : "";
    const reason = analysis.policyResult?.action === "redact"
      ? `PonoLens stopped the sensitive original and created this protected prompt:\n\n${protectedPrompt}\n\nReview it before submitting. Open the local PonoLens dashboard for detected details.`
      : `PonoLens blocked this action: ${analysis.headline}. ${analysis.recommendation} Open the local PonoLens dashboard to inspect detected details.`;
    if (harness === "windsurf") {
      process.stderr.write(`${reason}\n`);
      process.exitCode = 2;
    } else if (harness === "cursor") {
      process.stdout.write(JSON.stringify({ continue: false, user_message: reason }));
    } else if (event.hookEvent === "UserPromptSubmit") {
      process.stdout.write(JSON.stringify({ decision: "block", reason }));
    } else
    if (harness === "codex") {
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: reason,
        },
        systemMessage: reason,
      }));
    } else {
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: reason,
        },
        decision: "block",
        reason,
      }));
    }
  } else if (harness === "cursor") process.stdout.write(JSON.stringify({ continue: true }));
} catch (error) {
  // A security hook must fail visibly but must not print the raw event.
  process.stderr.write(`PonoLens could not inspect this action: ${error.message}\n`);
  process.exitCode = 1;
}
