import { execFileSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { harnessFor } from "../../public/product-config.js";

const OUTBOUND_COMMAND = /\b(curl|wget|scp|rsync|nc|netcat|gh\s+api|git\s+push|npm\s+publish)\b/i;
const REPO_ARCHIVE = /\b(git\s+bundle|tar\s+[^\n]*(?:\.git|--exclude)|zip\s+[^\n]*(?:\.git|\.env))\b/i;
const SENSITIVE_PATH = /(?:^|[\s'"/])(?:\.env(?:\.[\w.-]+)?|\.git|\.ssh|\.aws|credentials|secrets?)(?:[\s'"/]|$)/i;

function countFiles(root, max = 5000) {
  let count = 0;
  const stack = [root];
  while (stack.length && count < max) {
    const directory = stack.pop();
    let entries = [];
    try { entries = readdirSync(directory, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (entry.name === "node_modules") continue;
      if (entry.isDirectory()) stack.push(join(directory, entry.name));
      else count += 1;
      if (count >= max) break;
    }
  }
  return count;
}

function gitTrackedCount(cwd) {
  try {
    return execFileSync("git", ["ls-files"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim().split("\n").filter(Boolean).length;
  } catch {
    return countFiles(cwd);
  }
}

function hostnameFromTarget(target) {
  const value = String(target || "").replace(/^["']|["',;}\\]+$/g, "");
  if (!value) return null;
  try { return new URL(value).hostname; } catch {}
  const scpHost = value.match(/^(?:[^@\s]+@)?([\w.-]+):[^/]/)?.[1];
  return scpHost || null;
}

function gitPushDestination(text, cwd) {
  const value = String(text);
  if (!/\bgit\s+push\b/i.test(value)) return null;
  const match = value.match(/\bgit\s+push(?:\s+(?:--[\w-]+(?:=[^\s]+)?|-[A-Za-z]+))*\s+([^\s'"\\,;}]+)/i);
  const remote = match?.[1] || "origin";
  const directHost = hostnameFromTarget(remote);
  if (directHost) return directHost;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(remote)) return null;
  try {
    const remoteUrl = execFileSync("git", ["remote", "get-url", remote], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return hostnameFromTarget(remoteUrl);
  } catch { return null; }
}

function commandDestination(text, cwd) {
  const value = String(text);
  const gitDestination = gitPushDestination(value, cwd);
  if (gitDestination) return gitDestination;
  if (/\bgh\s+api\b/i.test(value)) return "api.github.com";
  if (/\bnpm\s+publish\b/i.test(value)) {
    try {
      const registry = execFileSync("npm", ["config", "get", "registry"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      return hostnameFromTarget(registry) || "registry.npmjs.org";
    } catch { return "registry.npmjs.org"; }
  }
  const url = value.match(/https?:\/\/[^\s'"}]+/i)?.[0];
  if (url) return hostnameFromTarget(url) || url;
  const remoteTarget = value.match(/\b(?:scp|rsync)\b[^\n]*?\s+(?:[^@\s]+@)?([\w.-]+):[^\s]+/i)?.[1];
  if (remoteTarget) return remoteTarget;
  const socketHost = value.match(/\b(?:nc|netcat)\s+(?:-[A-Za-z]+\s+)*(?:[^\s]+\s+)*?([\w.-]+)\s+\d+\b/i)?.[1];
  if (socketHost) return socketHost;
  return value.match(/(?:@|--host\s+)([\w.-]+)/)?.[1] ?? "Unresolved external destination";
}

function destinationFromText(text, cwd) {
  return commandDestination(text, cwd);
}

export function normalizeHookEvent(raw, harness) {
  const windsurfPrompt = raw.agent_action_name === "pre_user_prompt" ? raw.tool_info?.user_prompt : null;
  const prompt = typeof raw.prompt === "string" ? raw.prompt : windsurfPrompt;
  const isPrompt = raw.hook_event_name === "UserPromptSubmit" || typeof prompt === "string";
  if (isPrompt) {
    const destination = harnessFor(harness)?.modelDestination || "Model provider";
    return {
      harness,
      sessionId: raw.session_id ?? raw.sessionId ?? raw.conversation_id ?? raw.trajectory_id ?? raw.execution_id ?? "unknown",
      action: "prompt",
      source: "Your prompt",
      destination,
      destinationTrust: "trusted",
      repoFileCount: 0,
      sentFileCount: 0,
      includesGitHistory: false,
      files: [],
      content: prompt,
      command: "",
      toolName: "UserPromptSubmit",
      cwd: raw.cwd || raw.tool_info?.cwd || raw.workspace_roots?.[0] || process.cwd(),
      hookEvent: raw.hook_event_name ?? raw.agent_action_name ?? "UserPromptSubmit",
    };
  }
  const toolName = raw.tool_name ?? raw.toolName ?? raw.tool_info?.mcp_tool_name ?? raw.agent_action_name ?? "unknown-tool";
  const input = raw.tool_input ?? raw.toolInput ?? raw.tool_info ?? {};
  const serialized = JSON.stringify(input);
  const command = typeof input.command === "string"
    ? input.command
    : typeof input.command_line === "string"
      ? input.command_line
      : typeof input.cmd === "string"
        ? input.cmd
        : "";
  const cwd = raw.cwd || input.cwd || input.workdir || process.cwd();
  const windsurfMcp = raw.agent_action_name === "pre_mcp_tool_use";
  const outbound = windsurfMcp || OUTBOUND_COMMAND.test(command) || /(?:send|upload|post|message|email|share|publish)/i.test(toolName);
  const repoArchive = REPO_ARCHIVE.test(command);
  const sensitive = SENSITIVE_PATH.test(command) || SENSITIVE_PATH.test(serialized);
  const trackedCount = repoArchive ? gitTrackedCount(cwd) : 0;
  const candidateDestination = windsurfMcp ? `MCP server: ${input.mcp_server_name || "unknown"}` : outbound ? destinationFromText(`${command} ${serialized}`, cwd) : null;
  const localDestination = candidateDestination && /^(localhost|127(?:\.\d{1,3}){3}|::1)$/i.test(candidateDestination);
  const destination = localDestination ? null : candidateDestination;

  return {
    harness,
    sessionId: raw.session_id ?? raw.sessionId ?? raw.trajectory_id ?? raw.execution_id ?? "unknown",
    action: outbound && !localDestination ? "network" : command ? "command" : "tool_call",
    source: repoArchive ? `Git repository: ${basename(cwd)}` : sensitive ? "Sensitive local data" : toolName,
    destination,
    destinationTrust: destination ? "unknown" : "local",
    repoFileCount: trackedCount,
    sentFileCount: 0,
    repositoryOperation: repoArchive,
    includesGitHistory: /\.git|git\s+bundle/i.test(`${command} ${serialized}`),
    files: sensitive ? [String(command || serialized).match(SENSITIVE_PATH)?.[0]?.trim() || "sensitive path"] : [],
    content: serialized,
    command,
    toolName,
    cwd,
    hookEvent: raw.hook_event_name ?? raw.hookEventName ?? raw.agent_action_name,
  };
}

export function shouldRecordEvent(event, policy = {}) {
  if (event.action !== "command") return true;
  return policy.commandMonitoring === true;
}

export function normalizeMcpCall(message, harness) {
  const params = message.params ?? {};
  const args = params.arguments ?? {};
  return normalizeHookEvent({
    session_id: `mcp-${process.pid}`,
    hook_event_name: "PreToolUse",
    tool_name: `mcp__${params.name ?? "unknown"}`,
    tool_input: args,
    cwd: process.cwd(),
  }, harness);
}
