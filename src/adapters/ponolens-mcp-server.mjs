#!/usr/bin/env node
import readline from "node:readline";

const lines = readline.createInterface({ input: process.stdin });
lines.on("line", (line) => {
  let request;
  try { request = JSON.parse(line); } catch { return; }
  let result = {};
  if (request.method === "initialize") {
    result = { protocolVersion: request.params?.protocolVersion || "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "ponolens", version: "0.1.0" } };
  } else if (request.method === "tools/list") {
    result = { tools: [{ name: "ponolens_status", description: "Reports whether the local PonoLens MCP connection is active.", inputSchema: { type: "object", properties: {} } }] };
  } else if (request.method === "tools/call") {
    result = { content: [{ type: "text", text: "PonoLens is active locally. No external data was sent." }] };
  }
  if (request.id !== undefined) process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: request.id, result })}\n`);
});
