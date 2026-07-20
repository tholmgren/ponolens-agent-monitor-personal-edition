export const PRODUCT_DEFAULTS = Object.freeze({
  host: "127.0.0.1",
  port: 4317,
  retentionDays: 180,
  retentionMaxDays: 3650,
  activityPreviewLimit: 20,
  activityPageSize: 100,
  pollIntervalMs: 2000,
  thresholds: Object.freeze({ largeTransferPercent: 30, entireRepoPercent: 80, minimumRepoFiles: 10, medium: 20, high: 45, critical: 70 }),
  thresholdBounds: Object.freeze({
    largeTransferPercent: Object.freeze({ min: 1, max: 99 }),
    entireRepoPercent: Object.freeze({ min: 2, max: 100 }),
    minimumRepoFiles: Object.freeze({ min: 1, max: 10000 }),
    medium: Object.freeze({ min: 1, max: 98 }),
    high: Object.freeze({ min: 2, max: 99 }),
    critical: Object.freeze({ min: 3, max: 100 }),
  }),
  trustedDestinations: Object.freeze(["api.openai.com", "api.anthropic.com", "github.com"]),
});

export const FEATURE_FLAGS = Object.freeze({
  // Prototype retained for later testing. Native Ollama macOS chats cannot be
  // inspected merely by detecting port 11434, so do not advertise gateway coverage.
  ollamaGateway: false,
});

export const PROVIDER_CATALOG = Object.freeze({
  modes: Object.freeze([
    { id: "ollama", label: "Ollama · local", description: "Installed models running on this computer", apiBaseUrl: "http://127.0.0.1:11434" },
    { id: "openai", label: "OpenAI API", description: "Direct API with tokenized prompts", defaultModel: "gpt-5.4", endpoint: "https://api.openai.com/v1/responses" },
    { id: "webapp", label: "Web app", description: "Copy the prompt and open a selected website" },
  ]),
  defaultSettings: Object.freeze({ provider: "ollama", model: "", webApp: "chatgpt" }),
  webApps: Object.freeze([
    { id: "chatgpt", label: "ChatGPT", url: "https://chatgpt.com/" },
    { id: "claude", label: "Claude", url: "https://claude.ai/new" },
    { id: "gemini", label: "Gemini", url: "https://gemini.google.com/app" },
    { id: "kimi", label: "Kimi", url: "https://www.kimi.com/" },
  ]),
});

export const PROTECTION_CATEGORIES = Object.freeze([
  Object.freeze({ id: "secrets", label: "Secrets and access keys", shortLabel: "Secrets & access keys", findingLabel: "Secrets & access keys", description: "API keys, high-entropy credentials, passwords, private keys, and credential files", defaultEnabled: true }),
  Object.freeze({ id: "contact", label: "Personal & contact information", shortLabel: "Personal & contact", findingLabel: "Contact information", description: "Names, addresses, birth dates, identity documents, contact details, IP addresses, and device identifiers", defaultEnabled: true }),
  Object.freeze({ id: "healthcare", label: "Healthcare information", shortLabel: "Healthcare", findingLabel: "Healthcare information", description: "Medical records, health-plan members, providers, patients, and medical-device identifiers", defaultEnabled: false }),
  Object.freeze({ id: "legal", label: "Legal information", shortLabel: "Legal", findingLabel: "Legal information", description: "Privilege markers, matter, case, claim, and docket identifiers", defaultEnabled: false }),
  Object.freeze({ id: "financial", label: "Financial information", shortLabel: "Financial", findingLabel: "Financial information", description: "Social Security, validated payment cards, bank accounts, routing numbers, and IBANs", defaultEnabled: false }),
  Object.freeze({ id: "custom", label: "Custom rules and dictionaries", shortLabel: "Custom rules & dictionaries", findingLabel: "Custom protected values", description: "Organization-defined exact values, dictionaries, and regular-expression rules", defaultEnabled: false, preset: false }),
]);

export const PROTECTION_CATEGORY_IDS = Object.freeze(PROTECTION_CATEGORIES.map((category) => category.id));

export const HARNESS_CATALOG = Object.freeze({
  "ollama-gateway": Object.freeze({ id: "ollama-gateway", name: "Ollama Gateway", mark: "OL", filter: "ollama", modelDestination: "Ollama on this device", matchTerms: ["ollama gateway", "ollama-gateway"], commands: [], coverage: "Requests explicitly routed through the local PonoLens gateway", promptInterception: "block_redact", promptHookEvents: ["gateway"], integration: false, feature: "ollamaGateway" }),
  codex: Object.freeze({ id: "codex", name: "Codex", mark: "CO", filter: "codex", modelDestination: "OpenAI", matchTerms: ["codex"], commands: ["codex"], projectConfig: ".codex/hooks.json", userConfig: ".codex/hooks.json", coverage: "Pre-action tool hook", promptInterception: "observe", promptHookEvents: [] }),
  "claude-code": Object.freeze({ id: "claude-code", name: "Claude Code", mark: "CL", filter: "claude", modelDestination: "Anthropic", matchTerms: ["claude"], commands: ["claude"], projectConfig: ".claude/settings.json", userConfig: ".claude/settings.json", coverage: "Pre-action tool hook", promptInterception: "block_redact", promptHookEvents: ["UserPromptSubmit"] }),
  cursor: Object.freeze({ id: "cursor", name: "Cursor", mark: "CU", filter: "cursor", modelDestination: "Cursor model provider", matchTerms: ["cursor"], commands: ["cursor"], applicationNames: ["Cursor.app"], projectConfig: ".cursor/mcp.json", userConfig: ".cursor/mcp.json", hookConfig: ".cursor/hooks.json", coverage: "Submitted prompts and agent actions", promptInterception: "block_redact", promptHookEvents: ["beforeSubmitPrompt"] }),
  windsurf: Object.freeze({ id: "windsurf", name: "Windsurf", mark: "WS", filter: "windsurf", modelDestination: "Windsurf model provider", matchTerms: ["windsurf", "devin"], commands: ["windsurf", "devin-desktop", "devin"], applicationNames: ["Windsurf.app", "Devin Desktop.app", "Devin.app"], projectConfig: ".windsurf/hooks.json", userConfig: ".config/devin/config.json", legacyUserConfig: ".codeium/windsurf/hooks.json", coverage: "Cascade prompts, file access, commands, and MCP tools", promptInterception: "block_redact", promptHookEvents: ["pre_user_prompt", "UserPromptSubmit"] }),
});

export function harnessFor(value) {
  const normalized = String(value || "").toLowerCase();
  return Object.values(HARNESS_CATALOG).find((harness) => harness.matchTerms.some((term) => normalized.includes(term))) || null;
}

export function harnessCanInterceptPrompt(value, hookEvent) {
  const harness = harnessFor(value);
  return harness?.promptInterception === "block_redact" && harness.promptHookEvents.includes(String(hookEvent || ""));
}

export function featureEnabled(name) {
  return FEATURE_FLAGS[name] !== false;
}

export function collectorUrl(port = PRODUCT_DEFAULTS.port, override = "") {
  return String(override || `http://${PRODUCT_DEFAULTS.host}:${port}`).replace(/\/$/, "");
}
