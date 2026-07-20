import { closeSync, existsSync, fstatSync, openSync, readSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { analyzeEvent, redactEventForStorage } from "../risk-engine.mjs";
import { normalizeHookEvent, shouldRecordEvent } from "./event-normalizer.mjs";

const MAX_TAIL_BYTES = 8 * 1024 * 1024;
const RECENT_WINDOW_MS = 30 * 60 * 1000;
const SEEN_SETTING = "codex_session_observer_seen";

function sessionFiles(root, output = []) {
  if (!existsSync(root)) return output;
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) sessionFiles(path, output);
    else if (entry.isFile() && entry.name.endsWith(".jsonl")) output.push(path);
  }
  return output;
}

function recentSessions(root) {
  const cutoff = Date.now() - (2 * 60 * 60 * 1000);
  return sessionFiles(root)
    .map((path) => ({ path, modified: statSync(path).mtimeMs }))
    .filter((file) => file.modified >= cutoff)
    .sort((a, b) => b.modified - a.modified)
    .slice(0, 5)
    .map((file) => file.path);
}

function readFrom(path, requestedStart) {
  const descriptor = openSync(path, "r");
  try {
    const size = fstatSync(descriptor).size;
    const initial = requestedStart === undefined;
    const start = initial ? Math.max(0, size - MAX_TAIL_BYTES) : Math.min(requestedStart, size);
    const buffer = Buffer.alloc(size - start);
    readSync(descriptor, buffer, 0, buffer.length, start);
    const text = buffer.toString("utf8");
    return { text: initial && start ? text.slice(text.indexOf("\n") + 1) : text, size };
  } finally {
    closeSync(descriptor);
  }
}

function parseArguments(value) {
  if (typeof value !== "string") return value || {};
  try { return JSON.parse(value); } catch { return { value }; }
}

function promptText(content) {
  if (!Array.isArray(content)) return "";
  return content.filter((item) => item?.type === "input_text").map((item) => item.text).join("\n").trim();
}

export class CodexSessionObserver {
  constructor(store, getPolicy, sessionsRoot = join(homedir(), ".codex", "sessions")) {
    this.store = store;
    this.getPolicy = getPolicy;
    this.sessionsRoot = sessionsRoot;
    this.seen = new Set(store.getSetting(SEEN_SETTING, []));
    this.offsets = new Map();
    this.metadata = new Map();
    this.lastSync = 0;
  }

  sync() {
    if (Date.now() - this.lastSync < 750) return 0;
    this.lastSync = Date.now();
    let added = 0;
    let seenChanged = false;
    for (const path of recentSessions(this.sessionsRoot)) {
      const chunk = readFrom(path, this.offsets.get(path));
      this.offsets.set(path, chunk.size);
      const records = chunk.text.split("\n").filter(Boolean).flatMap((line) => {
        try { return [JSON.parse(line)]; } catch { return []; }
      });
      const discoveredMetadata = [...records].reverse().find((record) => record.type === "session_meta")?.payload;
      if (discoveredMetadata) this.metadata.set(path, discoveredMetadata);
      const metadata = this.metadata.get(path) || {};
      for (const record of records) {
        const timestamp = Date.parse(record.timestamp || "");
        if (!timestamp || Date.now() - timestamp > RECENT_WINDOW_MS) continue;
        const payload = record.payload || {};
        const key = `${metadata.session_id || path}:${record.timestamp}:${payload.id || payload.call_id || payload.client_id || payload.type || record.type}`;
        if (this.seen.has(key) || record.type !== "response_item") continue;
        let event;
        if (payload.type === "message" && payload.role === "user") {
          const prompt = promptText(payload.content);
          if (!prompt) continue;
          event = normalizeHookEvent({ session_id: metadata.session_id, hook_event_name: "UserPromptSubmit", prompt, cwd: metadata.cwd }, "codex");
        } else if (payload.type === "function_call" || payload.type === "custom_tool_call") {
          const input = parseArguments(payload.type === "custom_tool_call" ? payload.input : payload.arguments);
          if (typeof input.value === "string" && !input.command) input.command = input.value;
          if (typeof input.cmd === "string" && !input.command) input.command = input.cmd;
          const toolName = payload.name === "exec" ? "Codex action" : payload.name;
          event = normalizeHookEvent({ session_id: metadata.session_id, hook_event_name: "PreToolUse", tool_name: toolName, tool_input: input, cwd: input.workdir || metadata.cwd }, "codex");
        } else {
          continue;
        }
        event.createdAt = record.timestamp;
        event.observedVia = "local Codex session";
        const policy = this.getPolicy();
        const analysis = analyzeEvent(event, policy);
        if (shouldRecordEvent(event, policy)) {
          this.store.add(redactEventForStorage(event, policy), analysis);
          added += 1;
        }
        this.seen.add(key);
        seenChanged = true;
      }
    }
    if (seenChanged) this.store.setSetting(SEEN_SETTING, [...this.seen].slice(-1000));
    return added;
  }
}
