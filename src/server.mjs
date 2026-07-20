import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { analyzeEvent, redactContent, redactEventForStorage, restoreTokens, tokenizeContent } from "./risk-engine.mjs";
import { EventStore } from "./store.mjs";
import { DEFAULT_POLICY, normalizePolicy } from "./policy.mjs";
import { connectIntegration, detectIntegrations, testIntegration } from "./integrations.mjs";
import { CodexSessionObserver } from "./adapters/codex-session-observer.mjs";
import { normalizeHookEvent, shouldRecordEvent } from "./adapters/event-normalizer.mjs";
import { ollamaMetrics, ollamaPromptText, rewriteOllamaPrompt } from "./ollama-gateway.mjs";
import { isPathInside, readJsonBody, SECURITY_HEADERS } from "./http-security.mjs";
import { TokenVault } from "./token-vault.mjs";
import { eventsCsv, eventsPdf } from "./report-export.mjs";
import { HARNESS_CATALOG, PRODUCT_DEFAULTS, PROVIDER_CATALOG, collectorUrl, featureEnabled } from "../public/product-config.js";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const publicDir = join(root, "public");
const dataDir = process.env.PONOLENS_DATA_DIR || join(homedir(), ".ponolens");
const port = Number(process.env.PORT || PRODUCT_DEFAULTS.port);
const collectorBaseUrl = collectorUrl(port, process.env.PONOLENS_COLLECTOR_URL);
const store = new EventStore(join(dataDir, "ponolens.db"));
const getPolicy = () => normalizePolicy(store.getSetting("protection_policy", DEFAULT_POLICY));
store.migrateUnredactedOutboundPrompts(analyzeEvent, redactContent, getPolicy());
store.correctLocalClassifications();
const codexObserver = new CodexSessionObserver(store, getPolicy);
const roundTrips = new TokenVault();
const ROUND_TRIP_TTL_MS = 30 * 60 * 1000;
const DEFAULT_LLM_SETTINGS = { ...PROVIDER_CATALOG.defaultSettings };
const WEB_APPS = Object.fromEntries(PROVIDER_CATALOG.webApps.map((provider) => [provider.id, provider.url]));
const PROVIDER_IDS = new Set(PROVIDER_CATALOG.modes.map((provider) => provider.id));
const OLLAMA_PROVIDER = PROVIDER_CATALOG.modes.find((provider) => provider.id === "ollama");
const ollamaBaseUrl = String(process.env.PONOLENS_OLLAMA_URL || OLLAMA_PROVIDER.apiBaseUrl).replace(/\/$/, "");
const OPENAI_PROVIDER = PROVIDER_CATALOG.modes.find((provider) => provider.id === "openai");
const KEYCHAIN_SERVICE = "com.ponolens.openai-api-key";
const KEYCHAIN_ACCOUNT = "ponolens";
const LOCAL_REQUEST_HEADER = "x-ponolens-request";
const getLlmSettings = () => ({ ...DEFAULT_LLM_SETTINGS, ...store.getSetting("llm_settings", DEFAULT_LLM_SETTINGS) });
const getRetentionDays = () => Math.max(1, Math.min(PRODUCT_DEFAULTS.retentionMaxDays, Number(store.getSetting("retention_days", PRODUCT_DEFAULTS.retentionDays)) || PRODUCT_DEFAULTS.retentionDays));
let lastRetentionPrune = 0;

function applyRetention() {
  if (Date.now() - lastRetentionPrune < 3600000) return 0;
  lastRetentionPrune = Date.now();
  return store.pruneOlderThan(getRetentionDays());
}

function keychainApiKey() {
  if (process.platform !== "darwin") return "";
  const result = spawnSync("/usr/bin/security", ["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE, "-w"], { encoding: "utf8", timeout: 5000 });
  return result.status === 0 ? result.stdout.trim() : "";
}

function openaiApiKey() { return process.env.OPENAI_API_KEY || keychainApiKey(); }
function openaiCredentialStatus() { return process.env.OPENAI_API_KEY ? "environment" : keychainApiKey() ? "keychain" : "none"; }

async function ollamaModels() {
  try {
    const result = await fetch(`${ollamaBaseUrl}/api/tags`, { signal: AbortSignal.timeout(1800) });
    if (!result.ok) throw new Error("Ollama did not respond");
    const data = await result.json();
    return { running: true, models: (data.models || []).map((item) => ({ name: item.name, size: item.size, modifiedAt: item.modified_at })), gatewayUrl: `${collectorBaseUrl}/ollama` };
  } catch { return { running: false, models: [], gatewayUrl: `${collectorBaseUrl}/ollama` }; }
}

function ollamaInstalled() {
  const result = spawnSync("which", ["ollama"], { encoding: "utf8", timeout: 3000 });
  return result.status === 0 && Boolean(result.stdout.trim());
}

function ollamaGatewayIntegration(ollama) {
  const installed = ollama.running || ollamaInstalled();
  return {
    id: "ollama-gateway",
    name: "Ollama Gateway",
    installed,
    detected: installed,
    configured: true,
    globalConfigured: true,
    monitoring: ollama.running,
    status: ollama.running ? "protected" : installed ? "detected" : "available",
    coverage: `Report Only, Redact, and Block for traffic sent to ${ollama.gatewayUrl}`,
    gateway: true,
    gatewayUrl: ollama.gatewayUrl,
    running: ollama.running,
  };
}

async function integrationSnapshot() {
  const ollama = await ollamaModels();
  const integrations = featureEnabled("ollamaGateway") ? [...detectIntegrations(root), ollamaGatewayIntegration(ollama)] : detectIntegrations(root);
  return integrations.map((item) => {
    const definition = HARNESS_CATALOG[item.id];
    const lastEvent = store.latestForHarness(definition?.matchTerms || [item.id]);
    const intercepts = definition?.promptInterception === "block_redact";
    const limitation = item.id === "codex"
      ? "Codex side chats cannot be reliably blocked. Experimental command reports cover only task hooks and observable local-session tool calls, not unrelated Terminal activity."
      : item.id === "claude-code"
        ? "Claude Desktop is not covered. Experimental command reports require Claude Code PreToolUse payloads and a new CLI session after hook installation."
        : item.id === "cursor"
          ? "Coverage depends on Cursor hooks. Command detail varies by Cursor version/tool; unexposed commands and background traffic are invisible."
          : "Experimental command reports use Windsurf/Devin pre-command or pre-tool events; activity that bypasses those hooks is invisible.";
    return {
      ...item,
      hookConfigured: Boolean(item.globalConfigured || item.configured),
      reachable: Boolean(item.installed && item.monitoring),
      promptCoverage: definition?.coverage || item.coverage,
      capabilities: { report: true, commandReport: true, redact: Boolean(intercepts), block: Boolean(intercepts) },
      limitation,
      lastEvent: lastEvent ? { id: lastEvent.id, createdAt: lastEvent.createdAt, decision: lastEvent.decision } : null,
    };
  });
}

function responseText(data) {
  if (typeof data.output_text === "string") return data.output_text;
  return (data.output || []).flatMap((item) => item.content || []).filter((item) => item.type === "output_text").map((item) => item.text).join("\n");
}

const mime = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

function json(response, status, body) {
  response.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  response.end(JSON.stringify(body));
}

function jsonDownload(response, filename, body) {
  response.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", "Content-Disposition": `attachment; filename="${filename}"`, "Cache-Control": "no-store" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function localDateBoundary(value, end = false) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return "";
  const date = new Date(`${value}T${end ? "23:59:59.999" : "00:00:00.000"}`);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function localCalendarDay(value) {
  const date = new Date(value);
  const pad = (number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function allowedLocalOrigins() {
  return new Set([
    `http://${PRODUCT_DEFAULTS.host}:${port}`,
    `http://localhost:${port}`,
  ]);
}

function validateLocalRequest(request) {
  const host = String(request.headers.host || "").toLowerCase();
  const allowedHosts = new Set([`${PRODUCT_DEFAULTS.host}:${port}`, `localhost:${port}`]);
  if (!allowedHosts.has(host)) return { status: 421, error: "Invalid local Host header" };

  const origin = request.headers.origin;
  if (origin && !allowedLocalOrigins().has(origin)) return { status: 403, error: "Cross-origin requests are not allowed" };
  if (request.headers["sec-fetch-site"] === "cross-site") return { status: 403, error: "Cross-site requests are not allowed" };

  const requestPath = String(request.url || "").split("?", 1)[0];
  const protectedApiRequest = requestPath.startsWith("/api/") && !requestPath.startsWith("/api/hooks/");
  if (protectedApiRequest && request.headers[LOCAL_REQUEST_HEADER] !== "PonoLens-Local") {
    return { status: 403, error: "Missing PonoLens local request header" };
  }
  return null;
}

function ollamaError(response, status, message) {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  response.end(JSON.stringify({ error: message }));
}

function gatewayEvent(body, endpoint, content, stream) {
  return {
    harness: "ollama-gateway",
    action: "prompt",
    source: "App using PonoLens Ollama Gateway",
    destination: "Ollama on this device",
    destinationTrust: "trusted",
    hookEvent: "gateway",
    content,
    details: { observedVia: "PonoLens Ollama Gateway", endpoint: `/api/${endpoint}`, model: String(body.model || "unknown"), stream: Boolean(stream), preSend: true },
  };
}

async function proxyOllama(request, response, url) {
  if (!url.pathname.startsWith("/ollama/")) return false;
  if (!featureEnabled("ollamaGateway")) {
    ollamaError(response, 404, "The PonoLens Ollama Gateway is currently disabled");
    return true;
  }
  const endpoint = url.pathname.slice("/ollama/api/".length);
  if (request.method === "GET" && url.pathname === "/ollama/api/tags") {
    let upstream;
    try { upstream = await fetch(`${ollamaBaseUrl}/api/tags`, { signal: AbortSignal.timeout(10000) }); }
    catch { ollamaError(response, 502, "PonoLens could not reach the local Ollama service"); return true; }
    const payload = Buffer.from(await upstream.arrayBuffer());
    response.writeHead(upstream.status, { "Content-Type": upstream.headers.get("content-type") || "application/json" });
    response.end(payload);
    return true;
  }
  if (request.method !== "POST" || !["chat", "generate"].includes(endpoint)) {
    ollamaError(response, 404, "PonoLens Ollama Gateway supports only GET /api/tags, POST /api/chat, and POST /api/generate");
    return true;
  }

  const body = await readJsonBody(request);
  const content = ollamaPromptText(body, endpoint);
  if (!content.trim()) {
    ollamaError(response, 400, `A text ${endpoint === "chat" ? "message" : "prompt"} is required`);
    return true;
  }
  const stream = body.stream !== false;
  const policy = getPolicy();
  const event = gatewayEvent(body, endpoint, content, stream);
  const analysis = analyzeEvent(event, policy);
  const action = analysis.policyResult?.action || "warn";

  if (analysis.decision === "blocked" && action === "block") {
    store.add(redactEventForStorage(event, policy), analysis);
    ollamaError(response, 403, `PonoLens blocked this Ollama request: ${analysis.headline}`);
    return true;
  }
  if (analysis.decision === "blocked" && action === "redact" && stream) {
    analysis.recommendation = "Set stream:false so PonoLens can redact the complete request before forwarding it, or use Report Only for transparent streaming.";
    store.add(redactEventForStorage(event, policy), analysis);
    ollamaError(response, 409, "PonoLens detected protected information. Redacted Ollama requests currently require stream:false");
    return true;
  }

  const forwardedBody = action === "redact" && analysis.policyResult?.sensitiveDetected
    ? rewriteOllamaPrompt(body, endpoint, (value) => redactContent(value, policy))
    : body;
  let upstream;
  try {
    upstream = await fetch(`${ollamaBaseUrl}/api/${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(forwardedBody),
      signal: AbortSignal.timeout(120000),
    });
  } catch {
    ollamaError(response, 502, "PonoLens could not reach the local Ollama service");
    return true;
  }
  const contentType = upstream.headers.get("content-type") || (stream ? "application/x-ndjson" : "application/json");
  if (stream && upstream.ok) {
    store.add(redactEventForStorage({ ...event, details: { ...event.details, gatewayAction: action, responseMetricsAvailable: false } }, policy), analysis);
    response.writeHead(upstream.status, { "Content-Type": contentType, "Cache-Control": "no-store" });
    for await (const chunk of upstream.body || []) response.write(chunk);
    response.end();
    return true;
  }

  const payload = Buffer.from(await upstream.arrayBuffer());
  let metrics = {};
  try { metrics = ollamaMetrics(JSON.parse(payload.toString("utf8"))); } catch { /* preserve upstream response unchanged */ }
  store.add(redactEventForStorage({ ...event, details: { ...event.details, gatewayAction: action, ...metrics } }, policy), analysis);
  response.writeHead(upstream.status, { "Content-Type": contentType, "Cache-Control": "no-store" });
  response.end(payload);
  return true;
}

const server = createServer(async (request, response) => {
  try {
    const rejected = validateLocalRequest(request);
    if (rejected) return json(response, rejected.status, { error: rejected.error });
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await proxyOllama(request, response, url)) return;
    const hookMatch = url.pathname.match(/^\/api\/hooks\/(cursor|windsurf)$/);
    if (request.method === "POST" && hookMatch) {
      const raw = await readJsonBody(request);
      const event = normalizeHookEvent(raw, hookMatch[1]);
      const policy = getPolicy();
      const analysis = analyzeEvent(event, policy);
      if (shouldRecordEvent(event, policy)) store.add(redactEventForStorage(event, policy), analysis);
      if (analysis.decision === "blocked") {
        const reason = `PonoLens blocked this action: ${analysis.headline}. ${analysis.recommendation}`;
        if (hookMatch[1] === "windsurf") return json(response, 200, { blocked: true, reason });
        return json(response, 200, { continue: false, user_message: reason });
      }
      if (hookMatch[1] === "windsurf") return json(response, 200, { blocked: false });
      return json(response, 200, { continue: true });
    }

    if (request.method === "GET" && url.pathname === "/api/state") {
      applyRetention();
      codexObserver.sync();
      const events = store.list().map((event) => ({ ...event, mitigation: store.getSetting(`event_mitigation_${event.id}`, null) }));
      return json(response, 200, {
        events,
        stats: store.stats(),
        integrations: await integrationSnapshot(),
        privacy: { storage: "Local SQLite", path: join(dataDir, "ponolens.db"), cloudSync: false, rawRetention: false },
        policy: getPolicy(),
        retention: { days: getRetentionDays() },
      });
    }

    if (request.method === "GET" && url.pathname === "/api/events") {
      applyRetention();
      const limit = Math.max(1, Math.min(PRODUCT_DEFAULTS.activityPageSize, Number(url.searchParams.get("limit")) || PRODUCT_DEFAULTS.activityPageSize));
      const offset = Math.max(0, Number(url.searchParams.get("offset")) || 0);
      const requestedFilter = String(url.searchParams.get("filter") || "all");
      const filter = ["all", "protected", "risks", "blocked", "review", "prompts", "commands"].includes(requestedFilter) ? requestedFilter : "all";
      const harness = Object.values(HARNESS_CATALOG).find((item) => item.filter === String(url.searchParams.get("harness") || ""));
      const search = String(url.searchParams.get("search") || "").trim().slice(0, 120);
      const from = localDateBoundary(String(url.searchParams.get("from") || ""));
      const to = localDateBoundary(String(url.searchParams.get("to") || ""), true);
      const query = { filter, harnessTerms: harness?.matchTerms || [], search, from, to };
      const result = store.listFiltered({ ...query, limit, offset });
      const insightEvents = store.listFiltered({ ...query, limit: Math.min(result.total, 5000), offset: 0 }).events;
      const byDay = Object.entries(insightEvents.reduce((days, event) => { const day = localCalendarDay(event.createdAt); days[day] = (days[day] || 0) + 1; return days; }, {})).sort(([a], [b]) => b.localeCompare(a)).slice(0, 7).map(([date, count]) => ({ date, count }));
      const repeatedRisks = Object.entries(insightEvents.filter((event) => event.decision !== "allowed").reduce((items, event) => { items[event.summary] = (items[event.summary] || 0) + 1; return items; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([summary, count]) => ({ summary, count }));
      return json(response, 200, { events: result.events, pagination: { limit, offset, total: result.total, filter, harness: harness?.filter || "all" }, insights: { byDay, repeatedRisks, analyzed: insightEvents.length, capped: result.total > insightEvents.length } });
    }

    if (request.method === "GET" && url.pathname === "/api/events/export") {
      applyRetention();
      const requestedFilter = String(url.searchParams.get("filter") || "all");
      const filter = ["all", "protected", "risks", "blocked", "review", "prompts", "commands"].includes(requestedFilter) ? requestedFilter : "all";
      const harness = Object.values(HARNESS_CATALOG).find((item) => item.filter === String(url.searchParams.get("harness") || ""));
      const search = String(url.searchParams.get("search") || "").trim().slice(0, 120);
      const result = store.listFiltered({ filter, harnessTerms: harness?.matchTerms || [], search, from: localDateBoundary(String(url.searchParams.get("from") || "")), to: localDateBoundary(String(url.searchParams.get("to") || ""), true), limit: 10000, offset: 0 });
      const format = url.searchParams.get("format") === "pdf" ? "pdf" : "csv";
      const payload = format === "pdf" ? eventsPdf(result.events) : Buffer.from(eventsCsv(result.events));
      response.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": format === "pdf" ? "application/pdf" : "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="ponolens-redacted-report.${format}"`, "Cache-Control": "no-store", "X-PonoLens-Export-Limit": "10000" });
      response.end(payload); return;
    }

    const integrationMatch = url.pathname.match(/^\/api\/integrations\/([^/]+)\/(connect|test)$/);
    if (request.method === "POST" && integrationMatch) {
      const [, id, operation] = integrationMatch;
      const body = await readJsonBody(request);
      if (id === "ollama-gateway") {
        if (!featureEnabled("ollamaGateway")) return json(response, 404, { error: "The PonoLens Ollama Gateway is currently disabled" });
        if (operation !== "test") return json(response, 400, { error: "The Ollama Gateway is built into PonoLens and does not require installation" });
        const ollama = await ollamaModels();
        return json(response, 200, { ok: ollama.running, message: ollama.running ? `Ollama Gateway reached ${ollama.models.length} installed model${ollama.models.length === 1 ? "" : "s"}.` : "PonoLens could not reach Ollama. Start Ollama and test again.", integrations: [...detectIntegrations(root), ollamaGatewayIntegration(ollama)] });
      }
      const result = operation === "connect" ? connectIntegration(root, id, body.scope || "project", dataDir, collectorBaseUrl) : testIntegration(root, id, dataDir);
      return json(response, 200, { ...result, integrations: await integrationSnapshot() });
    }

    if (request.method === "PUT" && url.pathname === "/api/policy") {
      const policy = normalizePolicy(await readJsonBody(request));
      store.setSetting("protection_policy", policy);
      return json(response, 200, { policy });
    }

    if (request.method === "GET" && url.pathname === "/api/policy/export") {
      const policy = getPolicy();
      return jsonDownload(response, "ponolens-policy-template.json", {
        format: "ponolens-policy-template-v1",
        exportedAt: new Date().toISOString(),
        notice: "User-authored labels, raw protected values, dictionary entries, and regular-expression patterns are intentionally excluded.",
        policy: {
          presets: policy.presets,
          commandMonitoring: policy.commandMonitoring,
          categoryActions: policy.categoryActions,
          trustedDestinations: policy.trustedDestinations,
          thresholds: policy.thresholds,
          customValues: (policy.customValues || []).map((item) => ({ category: item.category || "custom", labelExcluded: true, valueExcluded: true })),
          dictionaries: (policy.dictionaries || []).map((item) => ({ category: item.category, entryCount: item.values?.length || 0, labelExcluded: true, valuesExcluded: true })),
          regexRules: (policy.regexRules || []).map((item) => ({ category: item.category, labelExcluded: true, patternExcluded: true })),
        },
      });
    }

    if (request.method === "DELETE" && url.pathname === "/api/local-data") {
      const body = await readJsonBody(request);
      if (body.confirmation !== "DELETE ALL LOCAL DATA") return json(response, 400, { error: "Type DELETE ALL LOCAL DATA to confirm" });
      roundTrips.clear();
      store.clearAll();
      return json(response, 200, { deleted: true, note: "Audit events, policies, protected values, and local settings were deleted. Keychain credentials were not changed." });
    }

    if (request.method === "PUT" && url.pathname === "/api/retention") {
      const body = await readJsonBody(request);
      const days = Math.max(1, Math.min(PRODUCT_DEFAULTS.retentionMaxDays, Math.round(Number(body.days) || PRODUCT_DEFAULTS.retentionDays)));
      store.setSetting("retention_days", days);
      lastRetentionPrune = 0;
      const deleted = applyRetention();
      return json(response, 200, { retention: { days }, deleted });
    }

    if (request.method === "GET" && url.pathname === "/api/llm-settings") {
      return json(response, 200, { settings: getLlmSettings(), ollama: await ollamaModels(), openaiConfigured: Boolean(openaiApiKey()), openaiCredentialSource: openaiCredentialStatus(), webApps: WEB_APPS });
    }

    if (request.method === "PUT" && url.pathname === "/api/llm-settings") {
      const body = await readJsonBody(request);
      const settings = { provider: PROVIDER_IDS.has(body.provider) ? body.provider : DEFAULT_LLM_SETTINGS.provider, model: String(body.model || "").slice(0, 120), webApp: WEB_APPS[body.webApp] ? body.webApp : DEFAULT_LLM_SETTINGS.webApp };
      store.setSetting("llm_settings", settings);
      return json(response, 200, { settings, ollama: await ollamaModels(), openaiConfigured: Boolean(openaiApiKey()), openaiCredentialSource: openaiCredentialStatus(), webApps: WEB_APPS });
    }

    if (request.method === "PUT" && url.pathname === "/api/llm-credentials/openai") {
      const body = await readJsonBody(request);
      const apiKey = String(body.apiKey || "").trim();
      if (!apiKey || apiKey.length > 500) return json(response, 400, { error: "Enter a valid API key" });
      if (process.platform !== "darwin") return json(response, 501, { error: "Secure API-key storage is currently available through macOS Keychain" });
      const result = spawnSync("/usr/bin/security", ["add-generic-password", "-U", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE, "-l", "PonoLens OpenAI API Key", "-w", apiKey], { encoding: "utf8", timeout: 10000 });
      if (result.status !== 0) return json(response, 500, { error: "PonoLens could not save the key in macOS Keychain" });
      return json(response, 200, { configured: true, source: process.env.OPENAI_API_KEY ? "environment" : "keychain" });
    }

    if (request.method === "DELETE" && url.pathname === "/api/llm-credentials/openai") {
      if (process.platform === "darwin") spawnSync("/usr/bin/security", ["delete-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE], { encoding: "utf8", timeout: 10000 });
      return json(response, 200, { configured: Boolean(process.env.OPENAI_API_KEY), source: process.env.OPENAI_API_KEY ? "environment" : "none" });
    }

    if (request.method === "POST" && url.pathname === "/api/events") {
      const event = await readJsonBody(request);
      if (!event.harness || !event.action) return json(response, 400, { error: "harness and action are required" });
      const policy = getPolicy();
      const analysis = analyzeEvent(event, policy);
      if (!shouldRecordEvent(event, policy)) return json(response, 202, { recorded: false, reason: "Experimental command monitoring is off" });
      return json(response, 201, store.add(redactEventForStorage(event, policy), analysis));
    }

    if (request.method === "POST" && url.pathname === "/api/safe-prompt") {
      const body = await readJsonBody(request);
      if (typeof body.content !== "string" || !body.content.trim()) return json(response, 400, { error: "Enter a prompt to check" });
      const policy = getPolicy();
      const tokenVault = body.locallyScanned ? { tokenized: body.content, mapping: {} } : tokenizeContent(body.content, policy);
      const input = {
        harness: "Safe Prompt",
        action: "prompt",
        source: "PonoLens safe composer",
        destination: null,
        hookEvent: "UserPromptSubmit",
        content: body.content,
        details: { observedVia: "PonoLens safe composer", preSend: true },
      };
      const analysis = analyzeEvent(input, policy);
      if (body.locallyScanned && Array.isArray(body.clientFindings) && body.clientFindings.length) {
        const safeFindings = body.clientFindings.slice(0, 50).map((item) => ({ category: String(item.category || "Protected").slice(0, 40), type: String(item.type || "information").slice(0, 80), count: Math.max(1, Math.min(100, Number(item.count) || 1)), action: item.action === "retained_warning" ? "retained_warning" : "tokenized" }));
        const removed = safeFindings.filter((item) => item.action === "tokenized");
        const retained = safeFindings.filter((item) => item.action === "retained_warning");
        analysis.score = Math.max(analysis.score, 55);
        analysis.severity = "high";
        analysis.decision = "approval_required";
        analysis.headline = "Protected information was removed in your browser";
        analysis.explanation = `${removed.length ? `The browser removed ${removed.map((item) => `${item.count} ${item.type}`).join(", ")}.` : "No direct identifiers were removed."} ${retained.length ? `It retained ${retained.map((item) => item.type).join(", ")} for usefulness; review these sensitive topics before continuing.` : ""} Original identifier values were not sent to PonoLens.`;
        analysis.recommendation = "Review both the removed identifiers and retained sensitive topics. Continue only when the remaining context is appropriate for your approved provider.";
        analysis.findings.custom = safeFindings.map((item) => ({ type: `${item.category}: ${item.type} (${item.action === "retained_warning" ? "retained" : "removed"})`, count: item.count }));
      }
      const event = store.add(redactEventForStorage({ ...input, content: body.content }, policy), analysis);
      const roundTripId = randomUUID();
      const expiresAt = new Date(Date.now() + ROUND_TRIP_TTL_MS).toISOString();
      roundTrips.set(roundTripId, { mapping: tokenVault.mapping, tokenizedPrompt: tokenVault.tokenized, expiresAt: Date.parse(expiresAt) });
      return json(response, 200, { event, roundTripId, expiresAt, tokenizedPrompt: tokenVault.tokenized });
    }

    if (request.method === "POST" && url.pathname === "/api/safe-prompt/send") {
      const body = await readJsonBody(request);
      const vault = roundTrips.get(body.roundTripId);
      if (!vault || vault.expiresAt < Date.now()) return json(response, 410, { error: "This local token vault expired. Check the prompt again." });
      const providerController = new AbortController();
      response.on("close", () => { if (!response.writableEnded) providerController.abort(); });
      const providerSignal = AbortSignal.any([providerController.signal, AbortSignal.timeout(120000)]);
      let settings = getLlmSettings();
      if (settings.provider === "ollama" && !settings.model) {
        const available = await ollamaModels();
        if (available.models[0]?.name) {
          settings = { ...settings, model: available.models[0].name };
          store.setSetting("llm_settings", settings);
        }
      }
      if (settings.provider === "webapp") return json(response, 200, { manual: true, prompt: vault.tokenizedPrompt, url: WEB_APPS[settings.webApp], provider: settings.webApp });
      if (!settings.model) return json(response, 400, { error: "Select a default model in Settings first" });
      let reply;
      if (settings.provider === "ollama") {
        const result = await fetch(`${ollamaBaseUrl}/api/generate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ model: settings.model, prompt: vault.tokenizedPrompt, stream: false }), signal: providerSignal });
        const data = await result.json();
        if (!result.ok) return json(response, 502, { error: data.error || "Ollama request failed" });
        reply = data.response;
      } else {
        const apiKey = openaiApiKey();
        if (!apiKey) return json(response, 400, { error: "Add an OpenAI API key in Settings first" });
        const result = await fetch(OPENAI_PROVIDER.endpoint, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ model: settings.model, input: vault.tokenizedPrompt, store: false }), signal: providerSignal });
        const data = await result.json();
        if (!result.ok) return json(response, 502, { error: data.error?.message || "OpenAI request failed" });
        reply = responseText(data);
      }
      const restored = restoreTokens(reply, vault.mapping);
      roundTrips.delete(body.roundTripId);
      return json(response, 200, { manual: false, tokenizedReply: reply, restored, vaultDeleted: true, provider: settings.provider, model: settings.model });
    }

    if (request.method === "POST" && url.pathname === "/api/safe-prompt/restore") {
      const body = await readJsonBody(request);
      const vault = roundTrips.get(body.roundTripId);
      if (!vault || vault.expiresAt < Date.now()) {
        if (body.roundTripId) roundTrips.delete(body.roundTripId);
        return json(response, 410, { error: "This local token vault expired. Check the original prompt again to start a new round trip." });
      }
      if (typeof body.content !== "string") return json(response, 400, { error: "Paste the model reply first" });
      const restored = restoreTokens(body.content, vault.mapping);
      roundTrips.delete(body.roundTripId);
      return json(response, 200, { restored, vaultDeleted: true, note: "Reidentified locally. Do not paste this result back into an unapproved AI service." });
    }

    if (request.method === "POST" && url.pathname.match(/^\/api\/events\/\d+\/decision$/)) {
      const id = Number(url.pathname.split("/")[3]);
      const body = await readJsonBody(request);
      const event = store.get(id);
      if (!event) return json(response, 404, { error: "Event not found" });
      const previous = store.getSetting(`event_mitigation_${id}`, { actions: {} });
      const mitigation = { actions: { ...(previous.actions || {}), [body.decision]: new Date().toISOString() } };
      store.setSetting(`event_mitigation_${id}`, mitigation);
      return json(response, 200, { ...event, mitigation, note: "Recorded locally as mitigation. This does not undo a completed transmission or determine legal compliance." });
    }

    const requestedAsset = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    const filePath = resolve(publicDir, requestedAsset);
    if (!isPathInside(publicDir, filePath)) return json(response, 403, { error: "Forbidden" });
    const content = await readFile(filePath);
    response.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": mime[extname(filePath)] || "application/octet-stream", "Cache-Control": "no-store" });
    response.end(content);
  } catch (error) {
    if (response.destroyed || response.writableEnded) return;
    if (error.code === "ENOENT") return json(response, 404, { error: "Not found" });
    if (error.statusCode) return json(response, error.statusCode, { error: error.message });
    console.error(error);
    json(response, 500, { error: "PonoLens could not process this request" });
  }
});

// Keep stalled or incomplete local clients from occupying the guard service.
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;

server.listen(port, PRODUCT_DEFAULTS.host, () => {
  console.log(`PonoLens is running at ${collectorBaseUrl}`);
  console.log(`Local data: ${join(dataDir, "ponolens.db")}`);
});
