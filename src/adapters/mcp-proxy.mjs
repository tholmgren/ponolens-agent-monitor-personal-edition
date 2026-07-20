#!/usr/bin/env node
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { analyzeEvent, redactEventForStorage } from "../risk-engine.mjs";
import { EventStore } from "../store.mjs";
import { normalizeMcpCall } from "./event-normalizer.mjs";
import { DEFAULT_POLICY, normalizePolicy } from "../policy.mjs";

const separator = process.argv.indexOf("--");
const harnessFlag = process.argv.indexOf("--harness");
const harness = harnessFlag >= 0 ? process.argv[harnessFlag + 1] : "cursor";
const upstreamCommand = separator >= 0 ? process.argv[separator + 1] : null;
const upstreamArgs = separator >= 0 ? process.argv.slice(separator + 2) : [];

if (!upstreamCommand) {
  process.stderr.write("Usage: mcp-proxy.mjs --harness cursor -- <upstream-command> [args...]\n");
  process.exit(2);
}

const dataDir = process.env.PONOLENS_DATA_DIR || join(homedir(), ".ponolens");
const store = new EventStore(join(dataDir, "ponolens.db"));
const upstream = spawn(upstreamCommand, upstreamArgs, { stdio: ["pipe", "pipe", "inherit"], env: process.env });

let inputBuffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  inputBuffer += chunk;
  let newline;
  while ((newline = inputBuffer.indexOf("\n")) >= 0) {
    const line = inputBuffer.slice(0, newline);
    inputBuffer = inputBuffer.slice(newline + 1);
    if (!line.trim()) continue;
    inspectAndForward(line);
  }
});

function inspectAndForward(line) {
  let message;
  try { message = JSON.parse(line); } catch { upstream.stdin.write(`${line}\n`); return; }

  if (message.method === "tools/call") {
    const event = normalizeMcpCall(message, harness);
    const policy = normalizePolicy(store.getSetting("protection_policy", DEFAULT_POLICY));
    const analysis = analyzeEvent(event, policy);
    store.add(redactEventForStorage(event, policy), analysis);
    if (analysis.decision === "blocked") {
      process.stdout.write(`${JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        error: { code: -32001, message: `PonoLens blocked this action: ${analysis.headline}`, data: { recommendation: analysis.recommendation } },
      })}\n`);
      return;
    }
  }
  upstream.stdin.write(`${line}\n`);
}

upstream.stdout.pipe(process.stdout);
upstream.on("exit", (code, signal) => process.exit(signal ? 1 : (code ?? 0)));
process.on("SIGTERM", () => upstream.kill("SIGTERM"));
process.on("SIGINT", () => upstream.kill("SIGINT"));
