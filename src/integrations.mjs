import { execFileSync, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { HARNESS_CATALOG, PRODUCT_DEFAULTS, collectorUrl } from "../public/product-config.js";

const DEFINITIONS = Object.fromEntries(Object.values(HARNESS_CATALOG).filter((harness) => harness.integration !== false).map((harness) => [harness.id, {
  ...harness,
  config: harness.projectConfig,
  userConfig: join(homedir(), harness.userConfig),
  hookConfig: harness.hookConfig,
  userHookConfig: harness.hookConfig ? join(homedir(), harness.hookConfig) : undefined,
  legacyUserConfig: harness.legacyUserConfig ? join(homedir(), harness.legacyUserConfig) : undefined,
  applicationPaths: (harness.applicationNames || []).flatMap((name) => [join("/Applications", name), join(homedir(), "Applications", name)]),
}]));

function commandPath(commands, applicationPaths = []) {
  for (const command of commands) {
    try {
      const path = execFileSync("which", [command], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      if (path) return path;
    } catch { /* try the next command */ }
  }
  const application = applicationPaths.find((path) => path && existsSync(path));
  if (application) return application;
  return null;
}

export function detectIntegrations(root) {
  return Object.entries(DEFINITIONS).map(([id, definition]) => {
    const path = commandPath(definition.commands, definition.applicationPaths);
    const configPath = join(root, definition.config);
    const cursorHookPath = id === "cursor" ? join(root, definition.hookConfig) : null;
    const configured = id === "cursor"
      ? hasPonoLensConfiguration(cursorHookPath, id, "hook")
      : hasPonoLensConfiguration(configPath, id);
    const globalConfigured = id === "cursor"
      ? hasPonoLensConfiguration(definition.userHookConfig, id, "hook")
      : hasPonoLensConfiguration(definition.userConfig, id)
        || (definition.legacyUserConfig ? hasPonoLensConfiguration(definition.legacyUserConfig, id) : false);
    const mcpConfigured = id === "cursor" && (hasPonoLensConfiguration(configPath, id, "mcp") || hasPonoLensConfiguration(definition.userConfig, id, "mcp"));
    const monitoring = Boolean(path) && (globalConfigured || configured);
    return {
      id,
      name: definition.name,
      installed: Boolean(path),
      detected: Boolean(path),
      executable: path,
      configured,
      globalConfigured,
      monitoring,
      status: monitoring ? (globalConfigured ? "protected" : "project") : (globalConfigured || configured) ? "configured_missing" : mcpConfigured ? "limited" : path ? "detected" : "available",
      coverage: !path && (globalConfigured || configured)
        ? `${definition.name} hooks are configured, but its command-line harness is not detected${id === "claude-code" ? "; Claude Desktop chats do not use Claude Code hooks" : ""}`
        : id === "codex" && (globalConfigured || configured)
        ? `Task prompts and tool actions · ${globalConfigured ? "new tasks in all projects" : "new tasks in this project"} · side chats are not exposed by Codex`
        : globalConfigured ? `${definition.coverage} · new chats in all projects` : configured ? `${definition.coverage} · new chats in this project` : mcpConfigured ? "MCP tools only — enable prompt monitoring" : path ? "Installed — connect PonoLens" : "Not detected on PATH",
      configPath,
      userConfigPath: definition.userConfig,
      hookConfigPath: cursorHookPath,
      userHookConfigPath: definition.userHookConfig,
      mcpConfigured,
    };
  });
}

function readJson(path) {
  if (!existsSync(path)) return {};
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { throw new Error(`Cannot safely update invalid JSON: ${path}`); }
}

function hasPonoLensConfiguration(path, id, kind = "hook") {
  if (!existsSync(path)) return false;
  const text = readFileSync(path, "utf8");
  if (id === "cursor") return kind === "mcp" ? text.includes('"ponolens"') : text.includes("ponolens-hook.mjs") || (text.includes("src/adapters/hook.mjs") && text.includes(" cursor"));
  if (id === "windsurf") return text.includes("ponolens-windsurf-hook.mjs") || (text.includes("src/adapters/hook.mjs") && text.includes(" windsurf"));
  return text.includes("src/adapters/hook.mjs") && text.includes(` ${id === "codex" ? "codex" : "claude-code"}`);
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
}

export function connectIntegration(root, id, scope = "project", bridgeDataDir = join(homedir(), ".ponolens"), collectorBaseUrl = collectorUrl(PRODUCT_DEFAULTS.port)) {
  const definition = DEFINITIONS[id];
  if (!definition) throw new Error("Unknown harness");
  const path = scope === "global" ? definition.userConfig : join(root, definition.config);
  if (scope === "global") {
    if (id === "cursor") {
      const config = readJson(path);
      config.mcpServers ??= {};
      config.mcpServers.ponolens = cursorServer(root);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
      writeCursorHooks(definition.userHookConfig, root, collectorBaseUrl);
    } else if (id === "windsurf") {
      writeDevinHooks(path, root, bridgeDataDir, collectorBaseUrl);
      if (definition.legacyUserConfig) writeWindsurfHooks(definition.legacyUserConfig, root, bridgeDataDir, collectorBaseUrl);
    } else {
      const config = readJson(path);
      config.hooks ??= {};
      config.hooks.PreToolUse ??= [];
      config.hooks.UserPromptSubmit ??= [];
      if (!JSON.stringify(config.hooks.PreToolUse).includes("src/adapters/hook.mjs")) config.hooks.PreToolUse.push(hookGroup(root, id, "PreToolUse"));
      if (!JSON.stringify(config.hooks.UserPromptSubmit).includes("src/adapters/hook.mjs")) config.hooks.UserPromptSubmit.push(hookGroup(root, id, "UserPromptSubmit"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
    }
    return { connected: true, alreadyConfigured: false, configPath: id === "cursor" ? definition.userHookConfig : path, scope };
  }

  if (id === "cursor") {
    const config = readJson(path);
    config.mcpServers ??= {};
    config.mcpServers.ponolens = cursorServer(root);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
    writeCursorHooks(join(root, definition.hookConfig), root, collectorBaseUrl);
    return { connected: true, alreadyConfigured: false, configPath: join(root, definition.hookConfig), scope };
  }

  if (id === "windsurf") {
    writeWindsurfHooks(path, root, bridgeDataDir, collectorBaseUrl);
    return { connected: true, alreadyConfigured: false, configPath: path, scope };
  }

  if (existsSync(path)) return { connected: true, alreadyConfigured: true, configPath: path, scope };

  if (id === "codex") {
    writeJson(path, {
      description: "PonoLens observes local Codex tool use and blocks critical privacy risks.",
      hooks: {
        PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: 'node "$(git rev-parse --show-toplevel)/src/adapters/hook.mjs" codex', timeout: 10, statusMessage: "PonoLens is checking this action" }] }],
        UserPromptSubmit: [{ hooks: [{ type: "command", command: 'node "$(git rev-parse --show-toplevel)/src/adapters/hook.mjs" codex', timeout: 10, statusMessage: "PonoLens is checking this prompt" }] }],
      },
    });
  } else if (id === "claude-code") {
    writeJson(path, {
      hooks: {
        PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/src/adapters/hook.mjs" claude-code', timeout: 10, statusMessage: "PonoLens is checking this action" }] }],
        UserPromptSubmit: [{ hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/src/adapters/hook.mjs" claude-code', timeout: 10, statusMessage: "PonoLens is checking this prompt" }] }],
      },
    });
  }
  return { connected: true, alreadyConfigured: false, configPath: path, scope };
}

function hookGroup(root, id, eventName) {
  const harness = id === "codex" ? "codex" : "claude-code";
  return {
    ...(eventName === "PreToolUse" ? { matcher: "*" } : {}),
    hooks: [{
      type: "command",
      command: `node ${JSON.stringify(join(root, "src/adapters/hook.mjs"))} ${harness}`,
      timeout: 10,
      statusMessage: "PonoLens is checking this action",
    }],
  };
}

function cursorServer(root) {
  return {
    command: "node",
    args: [join(root, "src/adapters/mcp-proxy.mjs"), "--harness", "cursor", "--", "node", join(root, "src/adapters/ponolens-mcp-server.mjs")],
  };
}

function writeCursorHooks(path, root, collectorBaseUrl) {
  const config = readJson(path);
  config.version ??= 1;
  config.hooks ??= {};
  const bridgePath = join(dirname(path), "ponolens-hook.mjs");
  writeCursorBridge(bridgePath, collectorBaseUrl);
  const command = `node ${JSON.stringify(bridgePath)}`;
  for (const eventName of ["beforeSubmitPrompt", "preToolUse", "postToolUse"]) {
    config.hooks[eventName] ??= [];
    config.hooks[eventName] = config.hooks[eventName].filter((hook) => !String(hook?.command || "").includes("src/adapters/hook.mjs") && !String(hook?.command || "").includes("ponolens-hook.mjs"));
    config.hooks[eventName].push({ command });
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function writeCursorBridge(path, collectorBaseUrl) {
  const source = `#!/usr/bin/env node
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
try {
  const response = await fetch(${JSON.stringify(`${collectorBaseUrl}/api/hooks/cursor`)}, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: Buffer.concat(chunks),
    signal: AbortSignal.timeout(9000),
  });
  if (!response.ok) throw new Error("PonoLens collector unavailable");
  process.stdout.write(await response.text());
} catch (error) {
  process.stderr.write("PonoLens could not inspect this Cursor action: " + error.message + "\\n");
  process.stdout.write(JSON.stringify({ continue: false, user_message: "PonoLens is unavailable, so this action was stopped because it could not be inspected. Start PonoLens and try again." }));
}
`;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, source, "utf8");
}

function writeWindsurfHooks(path, root, bridgeDataDir, collectorBaseUrl) {
  const config = readJson(path);
  config.hooks ??= {};
  const bridgePath = join(bridgeDataDir, "hooks/ponolens-windsurf-hook.mjs");
  writeWindsurfBridge(bridgePath, collectorBaseUrl);
  const command = `node ${JSON.stringify(bridgePath)}`;
  for (const eventName of ["pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"]) {
    config.hooks[eventName] ??= [];
    config.hooks[eventName] = config.hooks[eventName].filter((hook) => !String(hook?.command || "").includes("src/adapters/hook.mjs") && !String(hook?.command || "").includes("ponolens-windsurf-hook.mjs"));
    config.hooks[eventName].push({ command, show_output: eventName !== "pre_user_prompt" });
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function writeWindsurfBridge(path, collectorBaseUrl) {
  const source = `#!/usr/bin/env node
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
try {
  const response = await fetch(${JSON.stringify(`${collectorBaseUrl}/api/hooks/windsurf`)}, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: Buffer.concat(chunks),
    signal: AbortSignal.timeout(9000),
  });
  if (!response.ok) throw new Error("PonoLens collector unavailable");
  const result = await response.json();
  if (result.blocked) {
    process.stderr.write(String(result.reason || "PonoLens blocked this action") + "\\n");
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write("PonoLens could not inspect this Windsurf action: " + error.message + "\\n");
  process.stderr.write("This action was stopped because PonoLens could not inspect it. Start PonoLens and try again.\\n");
  process.exitCode = 2;
}
`;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, source, "utf8");
}

function writeDevinHooks(path, root, bridgeDataDir, collectorBaseUrl) {
  const config = readJson(path);
  config.version ??= 1;
  config.hooks ??= {};
  for (const legacyName of ["pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"]) {
    if (!Array.isArray(config.hooks[legacyName])) continue;
    config.hooks[legacyName] = config.hooks[legacyName].filter((hook) => !JSON.stringify(hook).includes("src/adapters/hook.mjs") || !JSON.stringify(hook).includes(" windsurf"));
    if (config.hooks[legacyName].length === 0) delete config.hooks[legacyName];
  }
  const bridgePath = join(bridgeDataDir, "hooks/ponolens-windsurf-hook.mjs");
  writeWindsurfBridge(bridgePath, collectorBaseUrl);
  const command = `node ${JSON.stringify(bridgePath)}`;
  const definitions = [
    ["UserPromptSubmit", false],
    ["PreToolUse", true],
  ];
  for (const [eventName, matchTools] of definitions) {
    config.hooks[eventName] ??= [];
    config.hooks[eventName] = config.hooks[eventName].filter((group) => !JSON.stringify(group).includes("src/adapters/hook.mjs") && !JSON.stringify(group).includes("ponolens-windsurf-hook.mjs"));
    config.hooks[eventName].push({
      ...(matchTools ? { matcher: "*" } : {}),
      hooks: [{
        type: "command",
        command,
        timeout: 10,
        statusMessage: eventName === "UserPromptSubmit" ? "PonoLens is checking this prompt" : "PonoLens is checking this action",
      }],
    });
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function runHookBridge(path, input, timeout = 10_000) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), timeout);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => { clearTimeout(timer); resolve({ status: null, stdout, stderr: stderr || error.message }); });
    child.on("close", (status) => { clearTimeout(timer); resolve({ status, stdout, stderr }); });
    child.stdin.end(input);
  });
}

export async function testIntegration(root, id, dataDir) {
  if (!DEFINITIONS[id]) throw new Error("Unknown harness");
  if (id === "cursor") {
    const projectHooks = join(root, ".cursor/hooks.json");
    const hooks = hasPonoLensConfiguration(DEFINITIONS[id].userHookConfig, "cursor", "hook")
      ? DEFINITIONS[id].userHookConfig
      : projectHooks;
    if (!hasPonoLensConfiguration(hooks, "cursor", "hook")) {
      return { ok: false, message: "Cursor prompt hooks are not configured. Enable Cursor for this project or system-wide first." };
    }
    const bridge = join(dirname(hooks), "ponolens-hook.mjs");
    if (!existsSync(bridge)) return { ok: false, message: "Cursor's PonoLens hook bridge is missing. Enable the integration again to repair it." };
    const input = JSON.stringify({
      hook_event_name: "beforeSubmitPrompt",
      conversation_id: `dashboard-test-${Date.now()}`,
      workspace_roots: [root],
      prompt: "Harmless PonoLens connection test",
    });
    const result = await runHookBridge(bridge, input);
    let response = null;
    try { response = JSON.parse(result.stdout || ""); } catch { /* report the invalid bridge response below */ }
    const ok = result.status === 0 && !result.stderr?.trim() && response && typeof response.continue === "boolean";
    return {
      ok,
      message: ok
        ? "Cursor prompt hook reached the live PonoLens collector successfully. Fully quit and reopen Cursor only after changing hook configuration."
        : "Cursor's hook is configured but could not reach the PonoLens collector. Restart PonoLens, then test again.",
      error: result.stderr?.trim() || (!response ? "The Cursor hook returned an invalid response." : null),
    };
  }
  const harness = id;
  const input = JSON.stringify(id === "windsurf" ? {
    agent_action_name: "pre_run_command",
    trajectory_id: `dashboard-test-${Date.now()}`,
    tool_info: { command_line: "git status", cwd: root },
  } : {
    session_id: `dashboard-test-${Date.now()}`,
    cwd: root,
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "git status" },
  });
  const result = spawnSync(process.execPath, [join(root, "src/adapters/hook.mjs"), harness], {
    input,
    encoding: "utf8",
    timeout: 10_000,
    env: { ...process.env, PONOLENS_DATA_DIR: dataDir },
  });
  return { ok: result.status === 0, message: result.status === 0 ? `${DEFINITIONS[id].name} adapter responded successfully. Ordinary command receipts are retained only when Experimental command monitoring is enabled.` : "Adapter test failed.", error: result.stderr?.trim() || null };
}

export function sampleIntegrationEvent(root, id) {
  const definition = DEFINITIONS[id];
  if (!definition) throw new Error("Unknown harness");
  return {
    harness: id,
    action: "prompt",
    hookEvent: "ponolens_synthetic_demo",
    source: "PonoLens judge demo · synthetic",
    destination: `Simulated ${definition.modelDestination || `${definition.name} provider`}`,
    destinationTrust: "unknown",
    content: "Synthetic demo only: draft a follow-up for demo patient Alex Example, patient ID DEMO-001, email alex@example.invalid, with high blood pressure.",
    details: {
      synthetic: true,
      generatedBy: "PonoLens judge demo",
      notice: "No prompt was sent to this harness or model provider by this test.",
      cwd: root,
    },
  };
}
