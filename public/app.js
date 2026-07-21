import { scanContent } from "./detectors.js";
import { HARNESS_CATALOG, PRODUCT_DEFAULTS, PROTECTION_CATEGORIES, PROVIDER_CATALOG, featureEnabled, harnessFor } from "./product-config.js";

const state = { events: [], selected: null, activityFilter: "all", trailFilter: "all", trailHarness: "all", trailOffset: 0, openIntegration: null, roundTripId: null, localTokenMapping: {}, draftAliases: {}, localVaultTimer: null, localScan: null, originalFindings: [], promptCopied: false, webAppReady: false, llmController: null, llmTimer: null, llmSettings: null, llmSaveTimer: null, llmSaveVersion: 0, openaiKeyEditing: false, policyDirty: false, policySaveTimer: null, policySaveVersion: 0, toastTimer: null, toastOnClose: null, policy: { presets: {}, customValues: [] } };
const $ = (selector) => document.querySelector(selector);
const APPEARANCE_KEY = "ponolens-appearance";
const THRESHOLD_INPUTS = Object.freeze([
  ["threshold-large", "largeTransferPercent"], ["threshold-entire", "entireRepoPercent"], ["threshold-files", "minimumRepoFiles"],
  ["threshold-medium", "medium"], ["threshold-high", "high"], ["threshold-critical", "critical"],
]);
const SAFE_PROMPT_TIPS = Object.freeze({
  1: Object.freeze([
    Object.freeze({ title: "Help PonoLens recognize names", body: "Name detection uses context. “Joe Doe” alone may be missed; “Patient: Joe Doe”, “Client: Joe Doe”, or “Employee: Joe Doe” is more likely to be tokenized." }),
    Object.freeze({ title: "Protect names that must never be missed", body: "Add an exact person, client, patient, or organization name under Pono Guard → Your protected values. Exact protected values are checked locally." }),
    Object.freeze({ title: "Describe the task without unnecessary identifiers", body: "Include only the information the AI needs. Generic roles such as “the patient” or “the client” are safer than a real name when identity is not required." }),
  ]),
  2: Object.freeze([
    Object.freeze({ title: "Review every replacement", body: "Confirm that identifiers became clear role-based placeholders and that the remaining text still gives the AI enough context to help." }),
    Object.freeze({ title: "Warnings may remain on purpose", body: "A health condition or legal topic can remain when removing it would destroy the task. Decide whether the remaining narrative is appropriate for your provider." }),
    Object.freeze({ title: "Edited drafts are checked again", body: "You can revise this draft. PonoLens rescans your changes before creating the final tokenized prompt." }),
  ]),
  3: Object.freeze([
    Object.freeze({ title: "Only the tokenized prompt should leave", body: "Review the final prompt before copying or sending it. The local token mapping must stay in PonoLens." }),
    Object.freeze({ title: "Web apps use copy and paste", body: "PonoLens can open the selected website, but it does not put prompt text in the URL or control the provider’s composer." }),
    Object.freeze({ title: "Use an approved provider", body: "Tokenization reduces direct disclosure but does not make every remaining narrative anonymous or automatically compliant." }),
  ]),
  4: Object.freeze([
    Object.freeze({ title: "Keep placeholder tokens unchanged", body: "The reply must preserve tokens such as [[PATIENT_1]] so PonoLens can restore the correct local values." }),
    Object.freeze({ title: "The restored result is sensitive again", body: "After restoration, handle the result under the same privacy and security rules as the original information." }),
    Object.freeze({ title: "Temporary mappings expire", body: "Restore the reply before the local token vault expires. Start a new prompt if the mapping is no longer available." }),
  ]),
});
const ADVANCED_GUARD_HELP = Object.freeze({
  actions: Object.freeze({
    title: "Action by category",
    intro: "Choose what PonoLens should do when each type of protected information is detected. Changes apply automatically to new activity.",
    items: Object.freeze([
      Object.freeze({ name: "Protection category", impact: "Each row controls one category, such as secrets, personal information, healthcare, legal, financial, or custom rules. Categories can use different actions." }),
      Object.freeze({ name: "Report Only · Stable", impact: "Allows the activity to continue and creates a redacted privacy receipt. It provides visibility but does not prevent transmission." }),
      Object.freeze({ name: "Redact · Experimental", impact: "At a supported pre-submit hook, stops the original protected prompt and provides a tokenized version for review. Unsupported or post-submit activity can only be reported." }),
      Object.freeze({ name: "Block · Experimental", impact: "At a supported pre-submit hook, stops a matching prompt before the harness processes it. It is not available for every harness or chat surface." }),
    ]),
  }),
  destinations: Object.freeze({
    title: "Trusted destinations",
    intro: "Identify provider hostnames your organization expects agents to contact. Enter one hostname per line without a path or prompt data.",
    items: Object.freeze([
      Object.freeze({ name: "Approved destination hostnames", impact: "A hostname also covers its subdomains. For example, an approved example.com entry includes api.example.com." }),
      Object.freeze({ name: "Risk impact", impact: "A trusted match removes the untrusted-destination score from new events, which can reduce warnings caused only by an unfamiliar destination." }),
      Object.freeze({ name: "What trust does not do", impact: "Trust never disables sensitive-data detection or category actions. A prompt containing protected information can still be reported, redacted, or blocked." }),
    ]),
  }),
  thresholds: Object.freeze({
    title: "Risk thresholds",
    intro: "Thresholds tune when repository transfers add risk and how total event scores are labeled. Lower values create more warnings; higher values create fewer warnings.",
    items: Object.freeze([
      Object.freeze({ name: "Large transfer %", impact: "The percentage of project files that adds a large-transfer risk score when the minimum file count is also met." }),
      Object.freeze({ name: "Entire project %", impact: "The percentage treated as an entire-project upload. Lowering it makes the strongest repository-transfer warning trigger sooner." }),
      Object.freeze({ name: "Minimum project files", impact: "Prevents very small projects from being classified by percentage alone. Raising it excludes more small repositories from transfer scoring." }),
      Object.freeze({ name: "Review score", impact: "The minimum total score labeled medium risk and shown for review. Sensitive command receipts are raised to at least this score." }),
      Object.freeze({ name: "High score", impact: "The minimum total score labeled high risk. Depending on the active policy and hook coverage, high-risk activity may require approval." }),
      Object.freeze({ name: "Critical score", impact: "The minimum total score labeled critical. At a supported enforcement point, critical activity can be blocked." }),
    ]),
  }),
  dictionaries: Object.freeze({
    title: "Organization dictionaries",
    intro: "Create local exact-match lists for identifiers PonoLens cannot reliably infer, such as client names, internal codes, project names, or patient identifiers.",
    items: Object.freeze([
      Object.freeze({ name: "Dictionary name", impact: "A local label that helps administrators recognize the list. It does not affect matching." }),
      Object.freeze({ name: "Protection category", impact: "Determines which category action and receipt label apply when a listed value is detected." }),
      Object.freeze({ name: "Protected values", impact: "Enter one exact value per line. More entries expand detection coverage but broad or common words can create false positives." }),
      Object.freeze({ name: "Storage and removal", impact: "Values remain in the local policy database and are excluded from safe policy exports. Removing a dictionary stops it from matching new activity." }),
    ]),
  }),
  regex: Object.freeze({
    title: "Custom regular-expression rules",
    intro: "Add constrained local patterns for consistent identifier formats. Test with fictional examples before relying on a new rule.",
    items: Object.freeze([
      Object.freeze({ name: "Rule name", impact: "A local description shown in policy management. It does not change how the pattern matches." }),
      Object.freeze({ name: "Protection category", impact: "Controls the action and category label used when the pattern finds a match." }),
      Object.freeze({ name: "Safe pattern", impact: "Defines the format to detect. The safety subset rejects groups, alternation, backreferences, unbounded quantifiers, and excessive ranges to reduce performance risk." }),
      Object.freeze({ name: "Flags", impact: "Use i for case-insensitive matching and g to find multiple occurrences. Removing i makes letter case significant and can reduce matches." }),
      Object.freeze({ name: "Detection impact", impact: "A pattern that is too broad can flag ordinary text; one that is too narrow can miss variants. New rules apply automatically after they are added." }),
    ]),
  }),
});

function getAppearance() {
  try {
    const saved = JSON.parse(localStorage.getItem(APPEARANCE_KEY) || "null") || {};
    return {
      theme: ["light", "dark"].includes(saved.theme) ? saved.theme : "light",
      fontSize: ["small", "regular", "large"].includes(saved.fontSize) ? saved.fontSize : "regular",
    };
  } catch {
    return { theme: "light", fontSize: "regular" };
  }
}

function applyAppearance(appearance, announce = false) {
  document.documentElement.dataset.theme = appearance.theme;
  document.documentElement.dataset.fontSize = appearance.fontSize;
  document.querySelector(`[name="theme"][value="${appearance.theme}"]`).checked = true;
  document.querySelector(`[name="font-size"][value="${appearance.fontSize}"]`).checked = true;
  document.querySelector('meta[name="theme-color"]').content = appearance.theme === "dark" ? "#07110e" : "#07110f";
  localStorage.setItem(APPEARANCE_KEY, JSON.stringify(appearance));
  if (announce) $("#appearance-status").textContent = `${appearance.theme === "dark" ? "Dark" : "Light"} theme · ${appearance.fontSize} text · saved`;
}

function openSection(view) {
  const targets = { live: "main-content", safe: "safe-prompt", trail: "activity-history", policies: "protection-settings", advanced: "advanced-guard", faq: "faq-section", settings: "appearance-settings" };
  document.body.classList.toggle("settings-view", view === "settings");
  document.body.classList.toggle("safe-prompt-view", view === "safe");
  document.body.classList.toggle("advanced-view", view === "advanced");
  document.body.classList.toggle("faq-view", view === "faq");
  document.body.classList.toggle("trail-view", view === "trail");
  const target = document.getElementById(targets[view] || "main-content");
  target?.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  closeMobileMenu();
}

function setMobileMenu(open) {
  document.body.classList.toggle("nav-open", open);
  $("#mobile-menu-button").setAttribute("aria-expanded", String(open));
  $("#mobile-menu-button").setAttribute("aria-label", open ? "Close navigation menu" : "Open navigation menu");
  $("#nav-backdrop").hidden = !open;
  if (open) document.querySelector(".nav-item.active")?.focus();
}

function closeMobileMenu() { setMobileMenu(false); }

applyAppearance(getAppearance());

async function request(path, options) {
  const headers = new Headers(options?.headers || {});
  headers.set("X-PonoLens-Request", "PonoLens-Local");
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const error = new Error((await response.json()).error || "Request failed");
    error.status = response.status;
    throw error;
  }
  return response.json();
}

async function downloadLocalFile(path, fallbackName) {
  const response = await fetch(path, { headers: { "X-PonoLens-Request": "PonoLens-Local" } });
  if (!response.ok) throw new Error((await response.json()).error || "Download failed");
  const blobUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = (response.headers.get("content-disposition")?.match(/filename="([^"]+)"/) || [])[1] || fallbackName;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

function closeHarnessToast() {
  clearTimeout(state.toastTimer);
  state.toastTimer = null;
  $("#harness-toast").hidden = true;
  const onClose = state.toastOnClose;
  state.toastOnClose = null;
  onClose?.();
}

function showHarnessToast({ title, message, tone = "success", actionLabel = "", actionUrl = "", sticky = false, onClose = null }) {
  const toast = $("#harness-toast");
  clearTimeout(state.toastTimer);
  if (!toast.hidden && state.toastOnClose) {
    const previousOnClose = state.toastOnClose;
    state.toastOnClose = null;
    previousOnClose();
  }
  state.toastOnClose = onClose;
  toast.className = `harness-toast ${tone}`;
  toast.setAttribute("role", tone === "error" ? "alert" : "status");
  $("#harness-toast-title").textContent = title;
  $("#harness-toast-message").textContent = message;
  $(".harness-toast-icon").textContent = tone === "error" ? "!" : tone === "warning" ? "?" : "✓";
  const action = $("#harness-toast-action");
  action.hidden = !actionLabel || !actionUrl;
  action.textContent = actionLabel;
  action.href = actionUrl || "#";
  toast.hidden = false;
  state.toastTimer = sticky ? null : setTimeout(closeHarnessToast, 8000);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

function initializeProductCatalog() {
  const harnesses = Object.values(HARNESS_CATALOG).filter((harness) => !harness.feature || featureEnabled(harness.feature));
  const supportedHarnesses = harnesses.filter((harness) => harness.integration !== false).map((harness) => harness.name).join(", ");
  const interceptingHarnesses = harnesses.filter((harness) => harness.promptInterception === "block_redact").map((harness) => harness.name).join(", ");
  const fixedFilters = [
    ["all", "All activity"], ["protected", "Protected information"], ["risks", "Risks explained"], ["blocked", "Unsafe actions stopped"],
    ["review", "Needs review"], ["prompts", "Prompts"], ["commands", "Agent commands · Experimental"],
  ];
  const activityFilterOptions = [...fixedFilters, ...harnesses.map((harness) => [harness.filter, harness.name])]
    .map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("");
  $("#activity-filter").innerHTML = activityFilterOptions;
  $("#trail-filter").innerHTML = fixedFilters.map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("");
  $("#trail-harness-filter").innerHTML = `<option value="all">All harnesses</option>${harnesses.map((harness) => `<option value="${escapeHtml(harness.filter)}">${escapeHtml(harness.name)}</option>`).join("")}`;
  const providerChoices = PROVIDER_CATALOG.modes.map((provider) => `<label class="choice-card"><input type="radio" name="llm-provider" value="${escapeHtml(provider.id)}" /><strong>${escapeHtml(provider.label)}</strong><small>${escapeHtml(provider.description)}</small></label>`).join("");
  $(".provider-choices").innerHTML = providerChoices;
  const quickDescriptions = { ollama: "Uses a model installed on this computer", openai: "Uses the API key configured in Settings", webapp: "Copies the protected prompt for manual use" };
  $(".quick-provider-choices").innerHTML = PROVIDER_CATALOG.modes.map((provider) => `<label><input type="radio" name="quick-provider" value="${escapeHtml(provider.id)}" /><span><strong>${escapeHtml(provider.label)}${provider.id === "webapp" ? " · manual" : ""}</strong><small>${escapeHtml(quickDescriptions[provider.id])}</small></span></label>`).join("");
  const webOptions = PROVIDER_CATALOG.webApps.map((provider) => `<option value="${escapeHtml(provider.id)}">${escapeHtml(provider.label)}</option>`).join("");
  $("#webapp").innerHTML = webOptions;
  $("#quick-webapp").innerHTML = webOptions;
  const openaiDefault = PROVIDER_CATALOG.modes.find((provider) => provider.id === "openai")?.defaultModel || "";
  $("#openai-model").value = openaiDefault;
  $("#openai-model").placeholder = openaiDefault ? `e.g. ${openaiDefault}` : "Model name";
  $("#quick-openai-model").value = openaiDefault;
  document.querySelectorAll("[data-default-retention]").forEach((element) => { element.textContent = PRODUCT_DEFAULTS.retentionDays; });
  document.querySelectorAll("[data-default-port]").forEach((element) => { element.textContent = PRODUCT_DEFAULTS.port; });
  document.querySelectorAll("[data-supported-harnesses]").forEach((element) => { element.textContent = supportedHarnesses; });
  document.querySelectorAll("[data-intercepting-harnesses]").forEach((element) => { element.textContent = interceptingHarnesses; });
  $("#trusted-destinations").placeholder = PRODUCT_DEFAULTS.trustedDestinations.join("\n");
  $("#common-protections").innerHTML = PROTECTION_CATEGORIES.filter((category) => category.preset !== false).map((category) => `<label class="switch-row"><span><strong>${escapeHtml(category.label)}</strong><small>${escapeHtml(category.description)}</small></span><input type="checkbox" name="${escapeHtml(category.id)}" /><i></i></label>`).join("");
  $("#retention-days").value = PRODUCT_DEFAULTS.retentionDays;
  $("#retention-days").max = PRODUCT_DEFAULTS.retentionMaxDays;
  for (const [id, key] of THRESHOLD_INPUTS) {
    const bounds = PRODUCT_DEFAULTS.thresholdBounds[key];
    $(`#${id}`).min = bounds.min;
    $(`#${id}`).max = bounds.max;
  }
  $("#trail-newer").textContent = `← Newer ${PRODUCT_DEFAULTS.activityPageSize}`;
  $("#trail-older").textContent = `Older ${PRODUCT_DEFAULTS.activityPageSize} →`;
}

initializeProductCatalog();

function renderSafeTip(container, requestedIndex = 0) {
  const tips = SAFE_PROMPT_TIPS[container.dataset.safeTips] || [];
  const index = ((requestedIndex % tips.length) + tips.length) % tips.length;
  const tip = tips[index];
  container.dataset.tipIndex = String(index);
  container.innerHTML = `<aside class="safe-tip-card" aria-label="Helpful Safe Prompt tip"><div class="safe-tip-copy" aria-live="polite"><strong>Helpful tip · ${escapeHtml(tip.title)}</strong><span>${escapeHtml(tip.body)}</span></div><div class="safe-tip-controls"><button type="button" data-tip-delta="-1" aria-label="Previous tip">‹</button><span class="safe-tip-position">${index + 1} / ${tips.length}</span><button type="button" data-tip-delta="1" aria-label="Next tip">›</button></div></aside>`;
}

document.querySelectorAll("[data-safe-tips]").forEach((container) => {
  renderSafeTip(container);
  container.addEventListener("click", (event) => {
    const button = event.target.closest("[data-tip-delta]");
    if (button) renderSafeTip(container, Number(container.dataset.tipIndex) + Number(button.dataset.tipDelta));
  });
});

function openAdvancedHelp(topic) {
  const help = ADVANCED_GUARD_HELP[topic];
  if (!help) return;
  $("#advanced-help-title").textContent = help.title;
  $("#advanced-help-intro").textContent = help.intro;
  $("#advanced-help-content").innerHTML = help.items.map((item) => `<section class="advanced-help-item"><strong>${escapeHtml(item.name)}</strong><p>${escapeHtml(item.impact)}</p></section>`).join("");
  $("#advanced-help-dialog").showModal();
}

function localPromptScan(content) { return scanContent(content, state.policy); }

function restoreLocally(content) {
  let restored = String(content || "");
  for (const [token, value] of Object.entries(state.localTokenMapping)) restored = restored.split(token).join(value);
  return restored;
}

function friendlyTokenName(token) {
  const match = token.match(/^\[\[([A-Z0-9_]+)_(\d+)\]\]$/);
  if (!match) return token;
  const names = { PATIENT_NAME: "Patient", EMAIL_ADDRESS: "Email", PATIENT_IDENTIFIER: "Patient ID", SOCIAL_SECURITY_NUMBER: "SSN", PHONE_NUMBER: "Phone", PAYMENT_CARD_NUMBER: "Payment card", BANK_ROUTING_NUMBER: "Routing number", MATTER_IDENTIFIER: "Matter ID", API_KEY: "API key" };
  return `[${names[match[1]] || match[1].toLowerCase().replaceAll("_", " ")} ${match[2]}]`;
}

function refreshDraftAliases(mapping) {
  for (const token of Object.keys(mapping)) state.draftAliases[token] ||= friendlyTokenName(token);
}

function tokenizedToDraft(content) {
  let draft = String(content || "");
  for (const [token, alias] of Object.entries(state.draftAliases)) draft = draft.split(token).join(alias);
  return draft;
}

function draftToTokenized(content) {
  let tokenized = String(content || "");
  for (const [token, alias] of Object.entries(state.draftAliases)) tokenized = tokenized.split(alias).join(token);
  return tokenized;
}

function showLlmProgress() {
  const started = Date.now();
  $("#llm-progress-status").textContent = "Sending only the tokenized prompt to the configured model…";
  $("#llm-elapsed").textContent = "0:00";
  clearInterval(state.llmTimer);
  state.llmTimer = setInterval(() => {
    const seconds = Math.floor((Date.now() - started) / 1000);
    $("#llm-elapsed").textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
    if (seconds >= 5) $("#llm-progress-status").textContent = "The model is generating its response locally. Larger Ollama models can take longer.";
  }, 250);
  $("#llm-progress-dialog").showModal();
}

function closeLlmProgress() {
  clearInterval(state.llmTimer);
  state.llmTimer = null;
  if ($("#llm-progress-dialog").open) $("#llm-progress-dialog").close();
}

function updateLocalScan() {
  state.localScan = localPromptScan($("#safe-prompt-text").value);
  state.localTokenMapping = state.localScan.mapping;
  $("#sanitized-preview").value = state.localScan.tokenized;
  $("#local-findings").innerHTML = state.localScan.findings.length
    ? state.localScan.findings.map((item) => `<span class="finding-chip ${item.action === "retained_warning" ? "retained" : "removed"}"><strong>${escapeHtml(item.category)}</strong>${escapeHtml(item.type)} · ${item.count}<em>${item.action === "retained_warning" ? "Retained · review" : "Removed"}</em></span>`).join("")
    : `<span class="empty-values">No configured identifiers detected. This does not guarantee the text is non-sensitive.</span>`;
  $("#local-scan-result").classList.toggle("has-findings", state.localScan.findings.length > 0);
  const removed = state.localScan.findings.filter((item) => item.action === "tokenized").length;
  const retained = state.localScan.findings.filter((item) => item.action === "retained_warning").length;
  $("#local-scan-result").querySelector("strong").textContent = state.localScan.findings.length ? `${removed} identifier type${removed === 1 ? "" : "s"} removed · ${retained} sensitive topic${retained === 1 ? "" : "s"} retained` : "No configured identifiers detected locally";
}

function showSafeStep(step) {
  $("#safe-prompt-form").hidden = step !== 1;
  $("#round-trip-panel").hidden = step === 1;
  $("#safe-draft-step").hidden = step !== 2;
  $("#safe-copy-step").hidden = step !== 3;
  $("#safe-reply-step").hidden = step !== 4;
  document.querySelectorAll("[data-safe-step-indicator]").forEach((item) => {
    const number = Number(item.dataset.safeStepIndicator);
    item.classList.toggle("current", number === step);
    item.classList.toggle("complete", number < step);
  });
  $(step === 1 ? "#safe-prompt-text" : step === 2 ? "#sanitized-preview" : step === 3 ? "#tokenized-prompt" : "#model-reply").focus();
}

function resetSafePrompt() {
  const roundTripId = state.roundTripId;
  state.llmController?.abort();
  state.llmController = null;
  closeLlmProgress();
  clearTimeout(state.localVaultTimer);
  state.localVaultTimer = null;
  if (!$("#harness-toast").hidden) closeHarnessToast();
  state.roundTripId = null;
  state.localTokenMapping = {};
  state.draftAliases = {};
  state.localScan = null;
  state.originalFindings = [];
  state.promptCopied = false;
  state.webAppReady = false;
  for (const selector of ["#safe-prompt-text", "#sanitized-preview", "#tokenized-prompt", "#model-reply", "#restored-reply"]) $(selector).value = "";
  $("#restored-step").hidden = true;
  $("#local-findings").innerHTML = "";
  $("#local-scan-result").classList.remove("has-findings");
  $("#local-scan-result").querySelector("strong").textContent = "Local browser scan ready";
  $("#safe-prompt-status").textContent = "New prompt ready. Nothing has been sent.";
  $("#round-trip-status").textContent = "";
  updateSafeSendActions();
  document.querySelectorAll("[data-safe-tips]").forEach((container) => renderSafeTip(container));
  showSafeStep(1);
  if (roundTripId) request("/api/safe-prompt", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ roundTripId }) }).catch(() => {
    $("#safe-prompt-status").textContent = "The prompt was cleared here. Its expired server-memory token vault will be discarded automatically.";
  });
}

function renderStats(stats) {
  const items = [
    [Number(stats.total).toLocaleString(), "Actions checked", ""],
    [Number(stats.risks).toLocaleString(), "Risks explained", "risks"],
    [Number(stats.blocked).toLocaleString(), "Unsafe actions stopped", "blocked"],
    ["Local", "Where logs live", ""],
  ];
  $("#stats").innerHTML = items.map(([value, label, review]) => review
    ? `<button type="button" class="stat stat-button ${review}" data-summary="${review}"><strong>${escapeHtml(value)}</strong><small>${escapeHtml(label)}</small><span>Review items →</span></button>`
    : `<div class="stat"><strong>${escapeHtml(value)}</strong><small>${escapeHtml(label)}</small></div>`).join("");
  document.querySelectorAll("[data-summary]").forEach((button) => button.addEventListener("click", () => openSummary(button.dataset.summary)));
}

function renderIntegrations(integrations) {
  const visible = integrations.filter((item) => !HARNESS_CATALOG[item.id]?.feature || featureEnabled(HARNESS_CATALOG[item.id].feature));
  const monitoring = visible.filter((item) => item.monitoring).length;
  $("#monitored-count").textContent = monitoring;
  if (!visible.length) {
    const supported = Object.values(HARNESS_CATALOG).map((harness) => harness.name).join(", ");
    $("#integrations").innerHTML = `<div class="integration"><div class="integration-icon">?</div><div><strong>No supported harnesses detected</strong><small>Install ${escapeHtml(supported)}, then scan again.</small></div></div>`;
    return;
  }
  const yesNo = (value) => `<span class="coverage-value ${value ? "yes" : "no"}">${value ? "Yes" : "No"}</span>`;
  $("#integrations").innerHTML = visible.map((item) => `
    <details class="integration" data-integration-id="${escapeHtml(item.id)}" ${state.openIntegration === item.id ? "open" : ""}>
      <summary><span class="integration-icon">${escapeHtml(harnessFor(item.id)?.mark || item.name.slice(0, 2).toUpperCase())}</span><span class="integration-summary-copy"><strong>${escapeHtml(item.name)}</strong><small>${item.monitoring ? "Monitoring enabled · Test Harness available" : item.installed ? "Installed, not fully protected" : "Not detected"}${item.lastEvent ? ` · Last event ${new Date(item.lastEvent.createdAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}` : " · No events yet"}</small></span><span class="integration-summary-meta"><span class="scope-badge ${item.monitoring ? (item.globalConfigured ? "global" : "project") : "detected"}">${item.monitoring ? (item.globalConfigured ? "System-wide" : "This project") : item.hookConfigured ? "Configured only" : item.installed ? "Detected" : "Unavailable"}</span><span class="integration-chevron" aria-hidden="true"></span></span></summary>
      <div class="coverage-grid">
        <div><span>Installed</span>${yesNo(item.installed)}</div><div><span>Hook configured</span>${yesNo(item.hookConfigured)}</div><div><span>Currently reachable</span>${yesNo(item.reachable)}</div>
        <div class="coverage-wide"><span>Prompt coverage</span><strong>${escapeHtml(item.promptCoverage || item.coverage)}</strong></div>
        <div class="coverage-wide"><span>Capabilities</span><div class="capability-list"><i class="${item.capabilities?.report ? "on" : "off"}">Report</i><i class="${item.capabilities?.commandReport ? "on" : "off"}">Commands · Experimental</i><i class="${item.capabilities?.redact ? "on" : "off"}">Redact</i><i class="${item.capabilities?.block ? "on" : "off"}">Block</i></div></div>
        <div class="coverage-wide"><span>Known limitations</span><strong>${escapeHtml(item.limitation || "Coverage depends on events exposed by this harness.")}</strong></div>
        <div class="coverage-wide"><span>Last event received</span><strong>${item.lastEvent ? `${new Date(item.lastEvent.createdAt).toLocaleString()} · event #${item.lastEvent.id}` : "No event received yet"}</strong></div>
      </div>
      ${item.monitoring ? `<div class="judge-test-panel"><span class="label">TEST HARNESS</span><strong>Verify the connection or preview Pono Trail</strong><small>The test event creates one clearly labeled synthetic receipt with fictional data. It does not send a prompt to ${escapeHtml(item.name)} or a model provider.</small><div class="integration-actions"><button class="mini-button" data-test-agent="${item.id}">Test connection</button><button class="mini-button demo" data-sample-agent="${item.id}">Test event</button></div></div>` : item.installed ? `<div class="integration-actions"><button class="mini-button connect" data-connect-agent="${item.id}" data-scope="global">Enable system-wide</button></div>` : ""}
      <div class="integration-result" id="integration-result-${item.id}">${escapeHtml(item.monitoring ? "PonoLens is receiving supported activity from this harness." : item.hookConfigured ? "Hook configuration exists, but the compatible harness is not currently reachable." : item.installed ? "Install the PonoLens hook to begin coverage." : "Install this harness, then scan again.")}</div>
    </details>`).join("");
  document.querySelectorAll("[data-connect-agent]").forEach((button) => button.addEventListener("click", () => integrationAction(button.dataset.connectAgent, "connect", button, button.dataset.scope)));
  document.querySelectorAll("[data-test-agent]").forEach((button) => button.addEventListener("click", () => integrationAction(button.dataset.testAgent, "test", button)));
  document.querySelectorAll("[data-sample-agent]").forEach((button) => button.addEventListener("click", () => integrationAction(button.dataset.sampleAgent, "sample", button)));
  document.querySelectorAll("#integrations details").forEach((details) => details.addEventListener("toggle", () => {
    const id = details.dataset.integrationId;
    if (details.open) {
      state.openIntegration = id;
      document.querySelectorAll("#integrations details[open]").forEach((other) => { if (other !== details) other.open = false; });
    } else if (state.openIntegration === id) state.openIntegration = null;
  }));
}

async function integrationAction(id, action, button, scope = "project") {
  const actionLabels = { connect: ["Enabling…", "Enable system-wide"], test: ["Testing…", "Test connection"], sample: ["Creating event…", "Test event"] };
  button.disabled = true;
  button.textContent = actionLabels[action]?.[0] || "Working…";
  try {
    const result = await request(`/api/integrations/${id}/${action}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scope }) });
    renderIntegrations(result.integrations);
    const message = $("#integration-result-" + id);
    if (message) message.textContent = result.message || (result.alreadyConfigured ? "Already connected" : "Added. Restart the harness to load PonoLens.");
    if (action === "test") showHarnessToast({
      title: result.ok ? "Connection test passed" : "Connection needs attention",
      message: result.message || (result.ok ? "PonoLens reached this harness connection." : "PonoLens could not verify this harness connection."),
      tone: result.ok ? "success" : "warning",
    });
    if (action === "sample") showHarnessToast({
      title: "Test event created",
      message: result.message || "The synthetic receipt is now available in Pono Trail under Needs Review.",
    });
    if ((action === "test" || action === "sample") && result.ok) await refreshDashboard();
  } catch (error) {
    button.disabled = false;
    button.textContent = actionLabels[action]?.[1] || "Try again";
    const message = $("#integration-result-" + id);
    const errorMessage = action === "sample" && error.status === 404
      ? "Test event is unavailable because the local PonoLens service is out of date. Restart PonoLens, refresh this page, and try again."
      : error.message;
    if (message) message.textContent = errorMessage;
    if (action === "test" || action === "sample") showHarnessToast({ title: action === "sample" ? "Test event failed" : "Connection test failed", message: errorMessage, tone: "error" });
  }
}

function renderFlow(event) {
  if (!event) return;
  const synthetic = isSyntheticEvent(event);
  const risk = ["critical", "high"].includes(event.severity) ? "risky" : "";
  const routeState = event.decision === "blocked" ? "blocked" : event.decision === "approval_required" ? "review" : "expected";
  const workingFolder = event.details?.cwd || event.details?.workingDirectory || "";
  const folderName = workingFolder ? workingFolder.split(/[\\/]/).filter(Boolean).at(-1) : "";
  const sourceDetail = folderName
    ? `In ${folderName}`
    : `${escapeHtml(event.details?.sentFileCount || 1)} file${event.details?.sentFileCount === 1 ? "" : "s"}`;
  const destinationStatus = synthetic
    ? "Synthetic demo · no transmission"
    : !event.destination
    ? "No external destination"
    : event.decision === "blocked"
      ? "Stopped before execution"
      : event.action === "prompt"
        ? "Prompt submitted to provider"
        : event.action === "network"
          ? "Outbound request observed"
          : "Tool call allowed";
  $("#flow").className = `flow-map flow-${routeState}`;
  $("#flow").innerHTML = `
    <div class="flow-node ${risk}" ${workingFolder ? `title="${escapeHtml(workingFolder)}"` : ""}><strong>${escapeHtml(event.source || "Local project")}</strong><small>${escapeHtml(sourceDetail)}</small>${folderName ? `<span class="path-hint">${escapeHtml(workingFolder)}</span>` : ""}</div>
    <div class="flow-arrow"></div>
    <div class="flow-node"><strong>${escapeHtml(event.harness)}</strong><small>AI coding agent</small></div>
    <div class="flow-arrow"></div>
    <div class="flow-node ${risk}"><strong>${escapeHtml(event.destination || "Stayed on this device")}</strong><small>${destinationStatus}</small></div>`;
}

function isSyntheticEvent(event) {
  return event.details?.details?.synthetic === true || String(event.source || "").includes("judge demo · synthetic");
}

function displayEvent(event) {
  if (isSyntheticEvent(event)) return {
    title: event.summary || `Synthetic judge demo · ${harnessIdentity(event.harness).label}`,
    explanation: event.explanation || "This fictional receipt was generated locally. No prompt was sent to a harness or model provider.",
  };
  if (event.action === "command") {
    const categories = protectedCategories(event).join(", ");
    return {
      title: categories ? `Command includes sensitive information: ${categories}` : "Agent command observed",
      explanation: categories
        ? `PonoLens stored only a redacted command preview. This report-only receipt needs review.`
        : event.explanation,
    };
  }
  if (event.action !== "prompt" || !event.destination) return { title: event.summary, explanation: event.explanation };
  if (event.decision === "blocked") {
    return {
      title: `PonoLens blocked a protected prompt to ${event.destination}`,
      explanation: `The original prompt was not sent. ${event.explanation}`,
    };
  }
  if (event.decision !== "allowed") {
    return {
      title: `A prompt sent to ${event.destination} includes protected information`,
      explanation: `This prompt left your device. ${event.explanation}`,
    };
  }
  if (hasProtectedInformation(event)) {
    const categories = protectedCategories(event).join(", ");
    const codexObserved = String(event.harness || "").toLowerCase() === "codex";
    const identity = harnessIdentity(event.harness);
    return {
      title: `Sensitive information detected and sent${categories ? `: ${categories}` : ""}`,
      explanation: codexObserved
        ? `PonoLens detected ${categories || "protected information"} after submission. Codex prompts cannot be blocked here; use Safe Prompt before sending.`
        : `PonoLens detected ${categories || "protected information"}. ${identity.label} can block enabled categories at supported pre-submit hooks.`,
    };
  }
  return {
    title: `Your prompt was submitted to ${event.destination}`,
    explanation: `The text you entered left this device for processing by ${event.destination}. PonoLens observed the submission, but cannot confirm the provider's storage or retention.`,
  };
}

function renderActivity(events) {
  events = events.filter((event) => matchesActivityFilter(event));
  $("#show-more-activity").hidden = events.length <= PRODUCT_DEFAULTS.activityPreviewLimit;
  if (!events.length) {
    $("#activity").innerHTML = `<div class="activity-empty"><h3>No matching activity</h3><p>Choose another filter or continue using an agent.</p></div>`;
    return;
  }
  $("#activity").innerHTML = events.slice(0, PRODUCT_DEFAULTS.activityPreviewLimit).map((event) => {
    const display = displayEvent(event);
    const identity = harnessIdentity(event.harness);
    return `
    <button type="button" class="activity-item ${event.action === "prompt" ? "prompt-event" : ""} ${hasProtectedInformation(event) ? "protected-event" : ""} ${event.decision === "blocked" ? "blocked-event" : ""}" data-id="${event.id}" aria-label="View activity ${event.id}: ${escapeHtml(display.title)}">
      <div class="activity-dot ${event.severity}">${event.decision === "blocked" ? "!" : hasProtectedInformation(event) ? "?" : event.severity === "low" ? "✓" : "?"}</div>
      <div><h3>${escapeHtml(display.title)}</h3><p>${escapeHtml(display.explanation)}</p></div>
      <div class="activity-meta"><span class="harness-mark harness-${identity.className}" aria-hidden="true">${escapeHtml(identity.mark)}</span><span><strong>${escapeHtml(identity.label)}</strong><time>${new Date(event.createdAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</time></span></div>
    </button>`;
  }).join("");
  document.querySelectorAll(".activity-item[data-id]").forEach((item) => item.addEventListener("click", () => openWarning(Number(item.dataset.id))));
}

function trailQueryParams(offset = 0) { return new URLSearchParams({ limit: PRODUCT_DEFAULTS.activityPageSize, offset, filter: state.trailFilter, harness: state.trailHarness, search: $("#trail-search").value.trim(), from: $("#trail-date-from").value, to: $("#trail-date-to").value }); }

async function openTrail(offset = 0) {
  openSection("trail");
  $("#trail-page-status").textContent = "Loading retained activity…";
  const params = trailQueryParams(offset);
  const data = await request(`/api/events?${params}`);
  state.trailOffset = offset;
  const { total, limit } = data.pagination;
  const start = total ? offset + 1 : 0;
  const end = Math.min(offset + data.events.length, total);
  const visibleEvents = data.events;
  const filterLabel = $("#trail-filter").selectedOptions[0]?.textContent || "All activity";
  $("#trail-page-status").textContent = `Showing ${start}–${end} of ${total} ${state.trailFilter === "all" ? "retained" : filterLabel.toLowerCase()} event${total === 1 ? "" : "s"} · newest first`;
  $("#trail-events").innerHTML = visibleEvents.length ? visibleEvents.map((event) => {
    const display = displayEvent(event);
    const identity = harnessIdentity(event.harness);
    return `<button type="button" class="activity-item trail-event ${event.action === "prompt" ? "prompt-event" : ""} ${hasProtectedInformation(event) ? "protected-event" : ""} ${event.decision === "blocked" ? "blocked-event" : ""}" data-trail-event="${event.id}" aria-label="View activity ${event.id}: ${escapeHtml(display.title)}"><div class="activity-dot ${event.severity}">${event.decision === "blocked" ? "!" : hasProtectedInformation(event) ? "?" : event.severity === "low" ? "✓" : "?"}</div><div><h3>${escapeHtml(display.title)}</h3><p>${escapeHtml(display.explanation)}</p></div><div class="activity-meta"><span class="harness-mark harness-${identity.className}" aria-hidden="true">${escapeHtml(identity.mark)}</span><span><strong>${escapeHtml(identity.label)}</strong><time title="${escapeHtml(new Date(event.createdAt).toLocaleString())}">${new Date(event.createdAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</time></span></div></button>`;
  }).join("") : `<div class="activity-empty"><h3>${state.trailFilter === "all" ? "No retained events" : "No matching activity on this page"}</h3><p>${state.trailFilter === "all" ? "New activity will appear here." : "Choose another filter or use Older/Newer to check another page."}</p></div>`;
  $("#trail-newer").disabled = offset === 0;
  $("#trail-older").disabled = offset + limit >= total;
  const dayItems = data.insights?.byDay || [], repeats = data.insights?.repeatedRisks || [];
  $("#trail-insights").innerHTML = `<article><span>Recent daily activity</span>${dayItems.length ? dayItems.map((item) => `<div><strong>${escapeHtml(new Date(`${item.date}T12:00:00`).toLocaleDateString([], { month: "short", day: "numeric" }))}</strong><b>${item.count}</b></div>`).join("") : `<p>No matching activity.</p>`}</article><article><span>Repeated risks</span>${repeats.length ? repeats.map((item) => `<div><strong>${escapeHtml(item.summary)}</strong><b>${item.count}</b></div>`).join("") : `<p>No repeated risks in this result.</p>`}</article>${data.insights?.capped ? `<small>Insights use the newest ${data.insights.analyzed.toLocaleString()} matching events.</small>` : ""}`;
  document.querySelectorAll("[data-trail-event]").forEach((button) => button.addEventListener("click", () => {
    const event = data.events.find((item) => item.id === Number(button.dataset.trailEvent));
    if (event && !state.events.some((item) => item.id === event.id)) state.events.push(event);
    openWarning(Number(button.dataset.trailEvent));
  }));
}

function hasProtectedInformation(event) {
  const findings = event.details?.analysis?.findings || {};
  return ["secrets", "personal", "regulated", "custom"].some((key) => findings[key]?.length);
}

function categoryForRegulatedFinding(finding) {
  if (finding.category) return finding.category;
  const type = String(finding.type || "").toLowerCase();
  if (/privilege|legal|matter/.test(type)) return "legal";
  if (/social security|payment|bank|routing|financial/.test(type)) return "financial";
  return "healthcare";
}

function detectedFindings(event) {
  const findings = event.details?.analysis?.findings || {};
  const categoryLabel = (id) => PROTECTION_CATEGORIES.find((category) => category.id === id)?.findingLabel || "Protected information";
  return [
    ...(findings.secrets || []).map((finding) => ({ ...finding, category: "secrets", categoryLabel: categoryLabel("secrets") })),
    ...(findings.personal || []).map((finding) => ({ ...finding, category: "contact", categoryLabel: categoryLabel("contact") })),
    ...(findings.regulated || []).map((finding) => {
      const category = categoryForRegulatedFinding(finding);
      return { ...finding, category, categoryLabel: categoryLabel(category) };
    }),
    ...(findings.custom || []).map((finding) => ({ ...finding, category: "custom", categoryLabel: categoryLabel("custom") })),
  ];
}

function protectedCategories(event) {
  return [...new Set(detectedFindings(event).map((finding) => finding.categoryLabel))];
}

function harnessIdentity(harness) {
  const value = String(harness || "Agent");
  const matched = harnessFor(value);
  if (matched) return { label: matched.name, mark: matched.mark, className: matched.filter };
  return { label: value, mark: value.replace(/[^a-z0-9]/gi, "").slice(0, 2).toUpperCase() || "AI", className: "agent" };
}

function matchesActivityFilter(event, filter = state.activityFilter) {
  const harnessFilter = Object.values(HARNESS_CATALOG).find((harness) => harness.filter === filter);
  if (harnessFilter) return harnessFor(event.harness)?.id === harnessFilter.id;
  switch (filter) {
    case "protected": return hasProtectedInformation(event);
    case "risks": return ["critical", "high"].includes(event.severity);
    case "blocked": return event.decision === "blocked";
    case "review": return event.decision === "approval_required"
      || (Boolean(event.destination) && event.decision !== "blocked" && hasProtectedInformation(event));
    case "prompts": return event.action === "prompt";
    case "commands": return event.action === "command" || (event.action === "network" && Boolean(event.details?.command));
    default: return true;
  }
}

async function openSummary(type) {
  $("#summary-eyebrow").textContent = type === "blocked" ? "PONO GUARD" : "PLAIN-LANGUAGE REVIEW";
  $("#summary-title").textContent = type === "blocked" ? "Unsafe actions stopped" : "Risks explained";
  $("#summary-copy").textContent = type === "blocked"
    ? "These actions were stopped before execution. Select an item to review what was detected and the redacted details retained locally."
    : "These are the highest-risk events currently retained in your local audit log. Select an item for its explanation and technical details.";
  $("#summary-events").innerHTML = `<div class="activity-empty"><h3>Loading retained events…</h3></div>`;
  $("#summary-dialog").showModal();
  let events = [];
  try {
    const filter = type === "blocked" ? "blocked" : "risks";
    const data = await request(`/api/events?limit=${PRODUCT_DEFAULTS.activityPageSize}&offset=0&filter=${filter}&harness=all&search=&from=&to=`);
    events = data.events || [];
    for (const event of events) if (!state.events.some((item) => item.id === event.id)) state.events.push(event);
  } catch (error) {
    $("#summary-events").innerHTML = `<div class="activity-empty"><h3>Could not load retained events</h3><p>${escapeHtml(error.message)}</p></div>`;
    return;
  }
  $("#summary-events").innerHTML = events.length ? events.map((event) => {
    const display = displayEvent(event);
    return `<button type="button" class="summary-event ${hasProtectedInformation(event) ? "protected" : ""} ${event.decision === "blocked" ? "blocked" : ""}" data-summary-event="${event.id}"><span class="activity-dot ${event.severity}">${event.decision === "blocked" ? "!" : "?"}</span><span><strong>${escapeHtml(display.title)}</strong><small>${escapeHtml(event.harness)} · ${new Date(event.createdAt).toLocaleString()}</small><em>${escapeHtml(display.explanation)}</em></span><b aria-hidden="true">›</b></button>`;
  }).join("") : `<div class="activity-empty"><h3>No items to review</h3><p>New qualifying events will appear here.</p></div>`;
  document.querySelectorAll("[data-summary-event]").forEach((button) => button.addEventListener("click", () => {
    $("#summary-dialog").close();
    openWarning(Number(button.dataset.summaryEvent));
  }));
}

function renderPolicy(policy, force = false) {
  if (state.policyDirty && !force) return;
  state.policy = policy;
  const baseCategoryAction = policy.mode === "redact" ? "redact" : policy.mode === "block_critical" ? "block" : "warn";
  const categoryActions = Object.values(policy.categoryActions || {});
  const customCategoryActions = categoryActions.some((action) => action && action !== baseCategoryAction);
  const customGuardMode = $("#custom-guard-mode");
  customGuardMode.hidden = !customCategoryActions;
  const guardMode = document.querySelector(`[name="guard-mode"][value="${customCategoryActions ? "custom" : policy.mode || "observe"}"]`);
  if (guardMode) guardMode.checked = true;
  const commandMonitoring = document.querySelector('[name="command-monitoring"]');
  if (commandMonitoring) commandMonitoring.checked = policy.commandMonitoring === true;
  for (const name of PROTECTION_CATEGORIES.filter((category) => category.preset !== false).map((category) => category.id)) {
    const input = document.querySelector(`[name="${name}"]`);
    if (input) input.checked = Boolean(policy.presets?.[name]);
  }
  const values = policy.customValues ?? [];
  $("#custom-values").innerHTML = values.length
    ? values.map((item, index) => `<span class="custom-chip"><strong>${escapeHtml(item.label || "Private value")}</strong>: ${escapeHtml(maskValue(item.value))}<button type="button" data-remove-value="${index}" aria-label="Remove">×</button></span>`).join("")
    : `<span class="empty-values">No custom values yet.</span>`;
  document.querySelectorAll("[data-remove-value]").forEach((button) => button.addEventListener("click", () => {
    state.policy.customValues.splice(Number(button.dataset.removeValue), 1);
    renderPolicy(state.policy, true);
    schedulePolicySave();
  }));
  renderAdvancedPolicy(policy);
}

const policyCategories = Object.fromEntries(PROTECTION_CATEGORIES.map((category) => [category.id, category.shortLabel]));
function categoryOptions(selected = "custom") { return Object.entries(policyCategories).map(([value, label]) => `<option value="${value}" ${value === selected ? "selected" : ""}>${label}</option>`).join(""); }
function renderAdvancedPolicy(policy) {
  if (!$("#advanced-policy-form")) return;
  $("#category-actions").innerHTML = Object.entries(policyCategories).map(([category, label]) => `<label class="category-action-row"><span><strong>${label}</strong><small>Choose what happens when this category is found.</small></span><select data-category-action="${category}"><option value="warn">Report Only · Stable</option><option value="redact">Redact · Experimental</option><option value="block">Block · Experimental</option></select></label>`).join("");
  document.querySelectorAll("[data-category-action]").forEach((select) => { select.value = policy.categoryActions?.[select.dataset.categoryAction] || (policy.mode === "observe" ? "warn" : policy.mode === "redact" ? "redact" : "block"); select.addEventListener("change", schedulePolicySave); });
  $("#trusted-destinations").value = (policy.trustedDestinations || []).join("\n");
  const thresholds = { ...PRODUCT_DEFAULTS.thresholds, ...(policy.thresholds || {}) };
  for (const [id, key] of THRESHOLD_INPUTS) $(`#${id}`).value = thresholds[key];
  $("#dictionary-category").innerHTML = categoryOptions(); $("#regex-category").innerHTML = categoryOptions();
  $("#dictionary-list").innerHTML = (policy.dictionaries || []).map((item, index) => `<div class="advanced-item"><span><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(policyCategories[item.category] || "Custom")} · ${(item.values || []).length} values</small></span><button type="button" data-remove-dictionary="${index}" aria-label="Remove ${escapeHtml(item.label)}">Remove</button></div>`).join("") || `<span class="empty-values">No organization dictionaries yet.</span>`;
  $("#regex-list").innerHTML = (policy.regexRules || []).map((item, index) => `<div class="advanced-item"><span><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(policyCategories[item.category] || "Custom")} · /${escapeHtml(item.pattern)}/${escapeHtml(item.flags)}</small></span><button type="button" data-remove-regex="${index}" aria-label="Remove ${escapeHtml(item.label)}">Remove</button></div>`).join("") || `<span class="empty-values">No custom regular-expression rules yet.</span>`;
  document.querySelectorAll("[data-remove-dictionary]").forEach((button) => button.addEventListener("click", () => { state.policy.dictionaries.splice(Number(button.dataset.removeDictionary), 1); renderAdvancedPolicy(state.policy); schedulePolicySave(); }));
  document.querySelectorAll("[data-remove-regex]").forEach((button) => button.addEventListener("click", () => { state.policy.regexRules.splice(Number(button.dataset.removeRegex), 1); renderAdvancedPolicy(state.policy); schedulePolicySave(); }));
}

function maskValue(value) {
  const text = String(value ?? "");
  if (text.length <= 3) return "•••";
  return `${text.slice(0, 2)}${"•".repeat(Math.min(text.length - 2, 8))}`;
}

function markPolicyChanged() {
  state.policyDirty = true;
  $("#policy-status").textContent = "Unsaved changes";
  $("#policy-status").classList.add("saving");
  $("#advanced-status").textContent = "Unsaved changes";
}

function currentPolicyFromForm() {
  const policy = {
    ...state.policy,
    mode: document.querySelector('[name="guard-mode"]:checked')?.value === "custom"
      ? state.policy.mode || "observe"
      : document.querySelector('[name="guard-mode"]:checked')?.value || "observe",
    commandMonitoring: document.querySelector('[name="command-monitoring"]')?.checked === true,
    presets: {
      ...state.policy.presets,
      secrets: document.querySelector('[name="secrets"]').checked,
      contact: document.querySelector('[name="contact"]').checked,
      healthcare: document.querySelector('[name="healthcare"]').checked,
      legal: document.querySelector('[name="legal"]').checked,
      financial: document.querySelector('[name="financial"]').checked,
    },
  };
  if ($("#trusted-destinations")) {
    policy.trustedDestinations = $("#trusted-destinations").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
    policy.categoryActions = Object.fromEntries([...document.querySelectorAll("[data-category-action]")].map((select) => [select.dataset.categoryAction, select.value]));
    policy.thresholds = Object.fromEntries(THRESHOLD_INPUTS.map(([id, key]) => [key, Number($(`#${id}`).value)]));
  }
  return policy;
}

function schedulePolicySave() {
  markPolicyChanged();
  const version = ++state.policySaveVersion;
  clearTimeout(state.policySaveTimer);
  state.policySaveTimer = setTimeout(() => savePolicy(version), 250);
}

async function savePolicy(version = ++state.policySaveVersion) {
  const status = $("#policy-status");
  state.policy = currentPolicyFromForm();
  const requestedCommandMonitoring = state.policy.commandMonitoring === true;
  status.textContent = "Saving…";
  status.classList.add("saving");
  try {
    const result = await request("/api/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(state.policy),
    });
    if (version !== state.policySaveVersion) return;
    if (requestedCommandMonitoring && result.policy?.commandMonitoring !== true) {
      throw new Error("Restart PonoLens to enable Agent command monitoring, then try again.");
    }
    state.policyDirty = false;
    renderPolicy(result.policy, true);
    status.textContent = "Saved locally";
    status.classList.remove("saving");
    $("#advanced-status").textContent = "Saved locally";
  } catch (error) {
    if (version !== state.policySaveVersion) return;
    status.textContent = `Could not save: ${error.message}`;
    status.classList.add("saving");
  }
}

function openWarning(id) {
  const event = state.events.find((candidate) => candidate.id === id);
  if (!event) return;
  state.selected = event;
  const display = displayEvent(event);
  const blocked = event.decision === "blocked";
  const detected = detectedFindings(event);
  const synthetic = isSyntheticEvent(event);
  const sent = Boolean(event.destination) && !blocked && !synthetic;
  const codexObserved = event.action === "prompt" && String(event.harness || "").toLowerCase() === "codex";
  const identity = harnessIdentity(event.harness);
  const review = event.decision === "approval_required" || (sent && detected.length > 0);
  $("#warning-dialog").className = blocked ? "event-blocked" : review ? "event-review" : "event-allowed";
  $("#warning-status").textContent = synthetic ? "Synthetic judge demo · Needs review" : blocked ? "Pono Guard stopped this" : review ? (sent ? "Sensitive information sent" : "Needs review") : "Allowed activity";
  $("#warning-status").className = `eyebrow ${blocked ? "danger-text" : review ? "review-text" : "safe-text"}`;
  $("#warning-symbol").textContent = blocked ? "!" : review ? "?" : "✓";
  $("#warning-title").textContent = display.title;
  $("#warning-explanation").textContent = display.explanation;
  $("#warning-source").textContent = event.source || "Your device";
  $("#warning-destination").textContent = synthetic ? `${event.destination || "Simulated destination"} · no transmission` : event.destination || "Stayed on this device";
  $("#warning-recommendation").textContent = codexObserved && detected.length
    ? "This Codex prompt was already sent. Use Safe Prompt to remove identifiers before submitting a future prompt."
    : review && sent ? `Review what was sent. ${identity.label} can block enabled categories at supported pre-submit hooks.` : event.recommendation;
  $("#detected-box").classList.toggle("has-findings", detected.length > 0);
  $("#detected-note").textContent = detected.length
    ? `PonoLens inspected the original ${event.action === "prompt" ? "prompt" : "action"} locally and found ${detected.reduce((total, finding) => total + Number(finding.count || 0), 0)} protected item${detected.reduce((total, finding) => total + Number(finding.count || 0), 0) === 1 ? "" : "s"} before creating the redacted audit record.`
    : "PonoLens inspected the original content locally before creating the audit record.";
  $("#detected-details").innerHTML = detected.length
    ? detected.map((finding) => `<div class="finding-row"><span><b>${escapeHtml(finding.categoryLabel)}</b>${escapeHtml(finding.type)}</span><strong>${escapeHtml(finding.count)}</strong>${finding.samples?.length ? `<small>${finding.samples.map(escapeHtml).join(", ")}</small>` : ""}</div>`).join("")
    : `<span class="empty-values">No protected values detected.</span>`;
  const preview = String(event.action === "command" ? event.details.command : event.details.content || "").slice(0, 500);
  $("#redacted-preview").textContent = preview || "No content preview was retained.";
  const redactedPromptAvailable = event.action === "prompt" && event.decision === "blocked" && Boolean(event.details.content);
  $("#copy-redacted").hidden = !redactedPromptAvailable;
  $("#copy-redacted").dataset.eventId = redactedPromptAvailable ? String(event.id) : "";
  $("#copy-redacted").textContent = "Copy redacted prompt";
  $("#event-timing").textContent = synthetic
    ? "Generated locally for demonstration. No harness or model-provider transmission occurred."
    : event.decision === "blocked"
    ? "Stopped before execution. No transmission was observed."
    : sent
      ? `Observed after submission to ${event.destination}. This receipt cannot undo a completed transmission.`
      : "Observed locally. PonoLens found no external destination for this action.";
  const categories = protectedCategories(event);
  $("#guard-followup").hidden = !(sent && detected.length > 0);
  $("#guard-followup strong").textContent = codexObserved ? "Protect your next Codex prompt" : "Prevent this type of information from being sent next time";
  $("#guard-followup-copy").textContent = codexObserved
    ? `Codex does not expose side-chat prompts early enough for Pono Guard to block them. Use Safe Prompt first${categories.length ? ` for: ${categories.join(", ")}` : ""}.`
    : categories.length ? `Review or enable: ${categories.join(", ")}.` : "Review your protection categories.";
  $("#change-guard-settings").textContent = codexObserved ? "Open Safe Prompt" : "Change Pono Guard settings";
  $("#change-guard-settings").dataset.action = codexObserved ? "safe" : "policies";
  $("#change-guard-settings").dataset.category = detected[0]?.category || "";
  const needsResponse = sent && detected.length > 0;
  $("#incident-response").hidden = !needsResponse;
  const mitigationEntries = Object.entries(event.mitigation?.actions || {});
  $("#mitigation-status").textContent = mitigationEntries.length
    ? `${mitigationEntries.map(([action, time]) => `${action === "source_deleted" ? "Source deletion" : "Incident report"} marked ${new Date(time).toLocaleString()}`).join(" · ")}. This is mitigation, not proof of compliance.`
    : "No mitigation has been recorded in PonoLens.";
  $("#technical-details").textContent = JSON.stringify({
    id: event.id,
    observedAt: event.createdAt,
    harness: event.harness,
    action: event.action,
    source: event.source,
    destination: event.destination || "local device",
    score: event.score,
    decision: event.decision,
    policyResult: event.details.analysis.policyResult,
    findings: event.details.analysis.findings,
    ...(event.details.command ? { redactedCommandPreview: event.details.command } : {}),
  }, null, 2);
  $("#warning-actions").hidden = false;
  $("#warning-dialog").showModal();
}

async function load() {
  const [data, llm] = await Promise.all([request("/api/state"), request("/api/llm-settings")]);
  applyDashboardState(data);
  renderLlmSettings(llm);
}

function renderLlmSettings(data) {
  const previousProvider = state.llmSettings?.settings?.provider;
  const settings = data.settings;
  state.llmSettings = data;
  if (previousProvider && previousProvider !== settings.provider) state.webAppReady = false;
  document.querySelector(`[name="llm-provider"][value="${settings.provider}"]`).checked = true;
  const models = data.ollama.models || [];
  $("#ollama-model").innerHTML = models.length ? models.map((item) => `<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}</option>`).join("") : `<option value="">No installed models found</option>`;
  if (settings.model && models.some((item) => item.name === settings.model)) $("#ollama-model").value = settings.model;
  if (settings.provider === "openai" && settings.model) $("#openai-model").value = settings.model;
  $("#webapp").value = settings.webApp || "chatgpt";
  $("#ollama-status").textContent = data.ollama.running ? `${models.length} installed model${models.length === 1 ? "" : "s"} found` : "Ollama is not running. Install/start it, then refresh.";
  $("#ollama-gateway-url").textContent = data.ollama.gatewayUrl;
  $("#ollama-gateway-status").textContent = data.ollama.running
    ? "Ready. Configure a compatible app to use this URL instead of calling Ollama directly."
    : "Gateway available, but the Ollama service is not currently reachable.";
  $(".ollama-gateway-card").hidden = !featureEnabled("ollamaGateway");
  document.querySelectorAll('[data-feature="ollamaGateway"]').forEach((element) => { element.hidden = !featureEnabled("ollamaGateway"); });
  const keyConfigured = Boolean(data.openaiConfigured);
  const environmentKey = data.openaiCredentialSource === "environment";
  $("#openai-key-entry").hidden = keyConfigured && !state.openaiKeyEditing;
  $("#openai-key-saved").hidden = !keyConfigured || state.openaiKeyEditing;
  $("#cancel-openai-key").hidden = !keyConfigured || !state.openaiKeyEditing;
  $("#save-openai-key").textContent = keyConfigured ? "Save replacement" : "Save key";
  $("#openai-key-source").textContent = environmentKey ? "Provided by the OPENAI_API_KEY environment variable." : "Stored securely in macOS Keychain.";
  $("#replace-openai-key").disabled = environmentKey;
  $("#remove-openai-key").disabled = environmentKey;
  $("#replace-openai-key").title = environmentKey ? "Replace OPENAI_API_KEY in the environment where PonoLens starts." : "";
  $("#remove-openai-key").title = environmentKey ? "Environment variables cannot be removed from PonoLens." : "";
  $("#openai-status").textContent = keyConfigured
    ? environmentKey ? "The environment key is active. Change or remove it where PonoLens is launched." : "The saved key is never displayed or stored in SQLite."
    : "Add a key to use OpenAI API with Safe Prompt.";
  const webNames = Object.fromEntries(PROVIDER_CATALOG.webApps.map((provider) => [provider.id, provider.label]));
  const openaiDefault = PROVIDER_CATALOG.modes.find((provider) => provider.id === "openai")?.defaultModel || "";
  $("#send-provider-summary").textContent = settings.provider === "ollama"
    ? `Ollama · ${settings.model || data.ollama.models[0]?.name || "No model installed"}`
    : settings.provider === "openai"
      ? `OpenAI API · ${settings.model || openaiDefault}`
      : `${webNames[settings.webApp] || settings.webApp} · manual copy and paste`;
  updateSafeSendActions();
  updateProviderRows();
}

function updateSafeSendActions() {
  const provider = state.llmSettings?.settings?.provider;
  const webAppSelected = provider === "webapp";
  const automaticProvider = provider === "ollama" || provider === "openai";
  $("#send-default-llm").hidden = webAppSelected;
  $("#send-default-llm").textContent = automaticProvider ? "Continue" : "Send to default LLM";
  $("#copy-tokenized").className = webAppSelected ? "primary-button" : "secondary-button";
  $("#next-to-reply").textContent = webAppSelected ? "Next" : "Next: paste reply";
  $("#next-to-reply").hidden = automaticProvider || (webAppSelected && !state.webAppReady);
}

function updateQuickProviderRows() {
  const provider = document.querySelector('[name="quick-provider"]:checked')?.value || "ollama";
  $("#quick-ollama-row").hidden = provider !== "ollama";
  $("#quick-openai-row").hidden = provider !== "openai";
  $("#quick-webapp-row").hidden = provider !== "webapp";
}

async function openProviderDialog() {
  const data = await request("/api/llm-settings");
  const { settings } = data;
  document.querySelector(`[name="quick-provider"][value="${settings.provider}"]`).checked = true;
  $("#quick-ollama-model").innerHTML = data.ollama.models.length
    ? data.ollama.models.map((item) => `<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}</option>`).join("")
    : `<option value="">No installed models found</option>`;
  if (settings.model && data.ollama.models.some((item) => item.name === settings.model)) $("#quick-ollama-model").value = settings.model;
  $("#quick-openai-model").value = settings.provider === "openai" && settings.model ? settings.model : (PROVIDER_CATALOG.modes.find((provider) => provider.id === "openai")?.defaultModel || "");
  $("#quick-webapp").value = settings.webApp || "chatgpt";
  $("#quick-provider-status").textContent = data.ollama.running ? `${data.ollama.models.length} local Ollama model${data.ollama.models.length === 1 ? "" : "s"} available.` : "Ollama is not currently running.";
  updateQuickProviderRows();
  $("#provider-dialog").showModal();
}

function updateProviderRows() {
  const provider = document.querySelector('[name="llm-provider"]:checked')?.value || "ollama";
  $("#ollama-model-row").hidden = provider !== "ollama";
  $("#openai-model-row").hidden = provider !== "openai";
  $("#webapp-row").hidden = provider !== "webapp";
}

async function saveDefaultLlm(version) {
  const provider = document.querySelector('[name="llm-provider"]:checked')?.value || "webapp";
  const model = provider === "ollama" ? $("#ollama-model").value : provider === "openai" ? $("#openai-model").value.trim() : "";
  const status = $("#llm-settings-status");
  status.textContent = "Saving automatically…";
  try {
    const data = await request("/api/llm-settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider, model, webApp: $("#webapp").value }) });
    if (version !== state.llmSaveVersion) return;
    renderLlmSettings(data);
    status.textContent = "Default model saved locally.";
  } catch (error) {
    if (version === state.llmSaveVersion) status.textContent = `Could not save automatically: ${error.message}`;
  }
}

function scheduleDefaultLlmSave(delay = 0) {
  clearTimeout(state.llmSaveTimer);
  const version = ++state.llmSaveVersion;
  state.llmSaveTimer = setTimeout(() => saveDefaultLlm(version), delay);
}

function applyDashboardState(data) {
  state.events = data.events;
  renderPolicy(data.policy);
  renderStats(data.stats);
  renderIntegrations(data.integrations);
  renderActivity(data.events);
  renderFlow(data.events[0]);
  if (data.retention) $("#retention-days").value = data.retention.days;
  const status = $("#activity-live-status");
  status.className = "live-status connected";
  status.textContent = data.events[0]
    ? `Live · event #${data.events[0].id} · ${new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}`
    : "Live · waiting for activity";
}

async function refreshDashboard() {
  try {
    applyDashboardState(await request("/api/state"));
  } catch (error) {
    const status = $("#activity-live-status");
    status.className = "live-status disconnected";
    status.textContent = "Collector disconnected";
    throw error;
  }
}

$("#detect-agents").addEventListener("click", async () => {
  const button = $("#detect-agents");
  button.textContent = "Scanning…";
  const data = await request("/api/state");
  renderIntegrations(data.integrations);
  button.textContent = "Scan again";
});

$("#rescan-header").addEventListener("click", () => $("#detect-agents").click());

$("#add-custom").addEventListener("click", () => {
  const label = $("#custom-label").value.trim();
  const value = $("#custom-value").value.trim();
  if (!value) return $("#custom-value").focus();
  state.policy.customValues.push({ label: label || "Private value", value });
  $("#custom-label").value = "";
  $("#custom-value").value = "";
  renderPolicy(state.policy, true);
  schedulePolicySave();
});

for (const name of PROTECTION_CATEGORIES.filter((category) => category.preset !== false).map((category) => category.id)) {
  document.querySelector(`[name="${name}"]`).addEventListener("change", schedulePolicySave);
}
document.querySelector('[name="command-monitoring"]').addEventListener("change", schedulePolicySave);
$("#custom-guard-mode").addEventListener("click", (event) => {
  event.preventDefault();
  openSection("advanced");
});
document.querySelectorAll('[name="guard-mode"]').forEach((input) => input.addEventListener("change", () => {
  if (input.value === "custom") {
    openSection("advanced");
    return;
  }
  const action = input.value === "observe" ? "warn" : input.value === "redact" ? "redact" : "block";
  document.querySelectorAll("[data-category-action]").forEach((select) => { select.value = action; });
  schedulePolicySave();
}));

$("#policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await savePolicy();
});

document.querySelectorAll(".nav-item[data-view]").forEach((button) => button.addEventListener("click", () => button.dataset.view === "trail" ? openTrail(0) : openSection(button.dataset.view)));
document.querySelectorAll("[data-open-view]").forEach((button) => button.addEventListener("click", () => openSection(button.dataset.openView)));
document.querySelectorAll("[data-advanced-help]").forEach((button) => button.addEventListener("click", () => openAdvancedHelp(button.dataset.advancedHelp)));
document.querySelectorAll(".advanced-help-close").forEach((button) => button.addEventListener("click", () => $("#advanced-help-dialog").close()));
for (const id of ["trusted-destinations","threshold-large","threshold-entire","threshold-files","threshold-medium","threshold-high","threshold-critical"]) $(`#${id}`).addEventListener("change", schedulePolicySave);
$("#add-dictionary").addEventListener("click", () => {
  const label = $("#dictionary-label").value.trim(), values = $("#dictionary-values").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  if (!values.length) return $("#dictionary-values").focus();
  state.policy.dictionaries ||= []; state.policy.dictionaries.push({ label: label || "Dictionary", category: $("#dictionary-category").value, values });
  $("#dictionary-label").value = ""; $("#dictionary-values").value = ""; renderAdvancedPolicy(state.policy); schedulePolicySave();
});
$("#add-regex").addEventListener("click", () => {
  const label = $("#regex-label").value.trim(), pattern = $("#regex-pattern").value.trim(), flags = $("#regex-flags").value.trim() || "gi";
  $("#regex-error").textContent = "";
  try { if (!pattern || /[()|]/.test(pattern) || /\\[1-9]|(^|[^\\])[*+]|\{\d+,\}/.test(pattern) || [...pattern.matchAll(/\{(\d+)(?:,(\d+))?\}/g)].some((match) => Number(match[1]) > Number(match[2] ?? match[1]) || Number(match[2] ?? match[1]) > 1000)) throw new Error("Use the safe subset: no groups, alternation, backreferences, or unbounded quantifiers. Bounded ranges may not exceed 1,000."); new RegExp(pattern, flags); } catch (error) { $("#regex-error").textContent = error.message; return; }
  state.policy.regexRules ||= []; state.policy.regexRules.push({ label: label || "Custom rule", category: $("#regex-category").value, pattern, flags });
  $("#regex-label").value = ""; $("#regex-pattern").value = ""; renderAdvancedPolicy(state.policy); schedulePolicySave();
});
$("#mobile-menu-button").addEventListener("click", () => setMobileMenu(!document.body.classList.contains("nav-open")));
$("#nav-backdrop").addEventListener("click", closeMobileMenu);
$("#activity-filter").addEventListener("change", (event) => {
  state.activityFilter = event.target.value;
  const isHarness = Object.values(HARNESS_CATALOG).some((item) => item.filter === event.target.value);
  state.trailFilter = isHarness ? "all" : event.target.value;
  state.trailHarness = isHarness ? event.target.value : "all";
  $("#trail-filter").value = state.trailFilter;
  $("#trail-harness-filter").value = state.trailHarness;
  openTrail(0);
});
$("#trail-filters").addEventListener("submit", (event) => { event.preventDefault(); state.trailFilter = $("#trail-filter").value; state.trailHarness = $("#trail-harness-filter").value; openTrail(0); });
$("#reset-trail-filters").addEventListener("click", () => { state.trailFilter = "all"; state.trailHarness = "all"; $("#trail-filter").value = "all"; $("#trail-harness-filter").value = "all"; $("#trail-search").value = ""; $("#trail-date-from").value = ""; $("#trail-date-to").value = ""; openTrail(0); });
for (const format of ["csv", "pdf"]) $(`#export-trail-${format}`).addEventListener("click", async () => {
  const button = $(`#export-trail-${format}`), original = button.textContent; button.disabled = true; button.textContent = "Preparing…";
  try { const params = trailQueryParams(0); params.set("format", format); await downloadLocalFile(`/api/events/export?${params}`, `ponolens-redacted-report.${format}`); }
  catch (error) { $("#trail-page-status").textContent = error.message; }
  finally { button.disabled = false; button.textContent = original; }
});
$("#show-more-activity").addEventListener("click", () => openTrail(0));
$("#close-trail").addEventListener("click", () => openSection("live"));
$("#trail-newer").addEventListener("click", () => openTrail(Math.max(0, state.trailOffset - PRODUCT_DEFAULTS.activityPageSize)));
$("#trail-older").addEventListener("click", () => openTrail(state.trailOffset + PRODUCT_DEFAULTS.activityPageSize));
$(".settings-button").addEventListener("click", () => openSection("settings"));
$("#close-settings").addEventListener("click", () => openSection("live"));
$("#export-policy").addEventListener("click", async () => {
  const status = $("#data-management-status"); status.textContent = "Preparing a safe policy template…";
  try { await downloadLocalFile("/api/policy/export", "ponolens-policy-template.json"); status.textContent = "Exported without user-authored labels, exact protected values, dictionary entries, or regex patterns."; }
  catch (error) { status.textContent = error.message; }
});
$("#open-delete-data").addEventListener("click", () => { $("#delete-data-confirmation").value = ""; $("#confirm-delete-data").disabled = true; $("#delete-data-dialog").showModal(); $("#delete-data-confirmation").focus(); });
document.querySelectorAll(".delete-data-close").forEach((button) => button.addEventListener("click", () => $("#delete-data-dialog").close()));
$("#delete-data-confirmation").addEventListener("input", (event) => { $("#confirm-delete-data").disabled = event.target.value !== "DELETE ALL LOCAL DATA"; });
$("#confirm-delete-data").addEventListener("click", async () => {
  const button = $("#confirm-delete-data"); button.disabled = true;
  try {
    const result = await request("/api/local-data", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmation: $("#delete-data-confirmation").value }) });
    $("#delete-data-dialog").close(); $("#data-management-status").textContent = result.note; await load();
  } catch (error) { $("#data-management-status").textContent = error.message; button.disabled = false; }
});
$("#close-safe-prompt").addEventListener("click", () => openSection("live"));
$("#safe-prompt-form").addEventListener("submit", (event) => {
  event.preventDefault();
  updateLocalScan();
  state.originalFindings = [...state.localScan.findings];
  state.draftAliases = {};
  refreshDraftAliases(state.localTokenMapping);
  $("#sanitized-preview").value = tokenizedToDraft(state.localScan.tokenized);
  $("#safe-prompt-status").textContent = "Draft created locally. Review it before continuing.";
  $("#round-trip-status").textContent = "Edit the safe draft if needed, then check it again.";
  showSafeStep(2);
});
$("#check-safe-draft").addEventListener("click", async () => {
  const visibleDraft = $("#sanitized-preview").value.trim();
  if (!visibleDraft) return $("#round-trip-status").textContent = "Enter a safe draft before continuing.";
  const draft = draftToTokenized(visibleDraft);
  const additional = localPromptScan(draft);
  state.localTokenMapping = { ...state.localTokenMapping, ...additional.mapping };
  refreshDraftAliases(additional.mapping);
  if (additional.tokenized !== draft) {
    $("#sanitized-preview").value = tokenizedToDraft(additional.tokenized);
    $("#round-trip-status").textContent = "Additional identifiers were found and removed. Review the updated draft, then check it again.";
    return;
  }
  const findings = [...state.originalFindings, ...additional.findings.filter((item) => item.action === "retained_warning")];
  $("#round-trip-status").textContent = "Creating the final tokenized prompt…";
  try {
    const result = await request("/api/safe-prompt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: draft, locallyScanned: true, clientFindings: findings }),
    });
    state.roundTripId = result.roundTripId;
    clearTimeout(state.localVaultTimer);
    state.localVaultTimer = setTimeout(() => {
      state.localTokenMapping = {};
      state.roundTripId = null;
      $("#round-trip-status").textContent = "The browser-memory token vault expired. Check the prompt again to restart.";
    }, Math.max(0, Date.parse(result.expiresAt) - Date.now()));
    $("#tokenized-prompt").value = result.tokenizedPrompt;
    $("#model-reply").value = "";
    $("#restored-reply").value = "";
    $("#restored-step").hidden = true;
    state.promptCopied = false;
    state.webAppReady = false;
    updateSafeSendActions();
    showSafeStep(3);
    $("#round-trip-status").textContent = `The identifier mapping stays only in this browser's memory. The sanitized prompt expires at ${new Date(result.expiresAt).toLocaleTimeString()}.`;
    state.events.unshift(result.event);
    await refreshDashboard();
    $("#safe-prompt").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  } catch (error) {
    $("#round-trip-status").textContent = error.message;
  }
});
$("#copy-tokenized").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#tokenized-prompt").value);
  state.promptCopied = true;
  const settings = state.llmSettings?.settings;
  if (settings?.provider === "webapp") {
    const webApp = PROVIDER_CATALOG.webApps.find((provider) => provider.id === settings.webApp) || PROVIDER_CATALOG.webApps[0];
    $("#round-trip-status").textContent = `Protected prompt copied. Launch ${webApp.label}, paste it there, then return to continue.`;
    showHarnessToast({
      title: "Protected prompt copied",
      message: "Only the tokenized prompt was copied. The local identifier mapping stayed in PonoLens.",
      actionLabel: `Launch ${webApp.label}`,
      actionUrl: webApp.url,
      sticky: true,
      onClose: () => {
        state.webAppReady = true;
        updateSafeSendActions();
        $("#round-trip-status").textContent = `When you have a reply from ${webApp.label}, select Next and paste it into PonoLens.`;
      },
    });
    return;
  }
  $("#round-trip-status").textContent = "Protected prompt copied. The local token mapping was not copied.";
});
$("#send-default-llm").addEventListener("click", async () => {
  const status = $("#round-trip-status");
  if (!state.roundTripId) return status.textContent = "The local token vault expired. Return to the draft and prepare it again.";
  status.textContent = "Sending the tokenized prompt to the default model…";
  state.llmController = new AbortController();
  showLlmProgress();
  try {
    const result = await request("/api/safe-prompt/send", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ roundTripId: state.roundTripId }), signal: state.llmController.signal });
    if (result.manual) {
      await navigator.clipboard.writeText(result.prompt);
      state.promptCopied = true;
      showSafeStep(4);
      status.textContent = `${result.provider} is a web app, so the protected prompt was copied instead of submitted. Paste it there, then paste its reply below.`;
      closeLlmProgress();
      return;
    }
    $("#model-reply").value = result.tokenizedReply;
    state.roundTripId = null;
    showSafeStep(4);
    status.textContent = `Reply received from ${result.model}. Review it, then reinsert protected data locally.`;
    closeLlmProgress();
  } catch (error) {
    closeLlmProgress();
    status.textContent = error.name === "AbortError" ? "The model request was canceled." : error.message;
  } finally { state.llmController = null; }
});
$("#change-send-provider").addEventListener("click", openProviderDialog);
document.querySelectorAll('[name="quick-provider"]').forEach((input) => input.addEventListener("change", updateQuickProviderRows));
$(".provider-close").addEventListener("click", () => $("#provider-dialog").close());
$("#cancel-provider-change").addEventListener("click", () => $("#provider-dialog").close());
$("#save-provider-change").addEventListener("click", async () => {
  const provider = document.querySelector('[name="quick-provider"]:checked').value;
  const model = provider === "ollama" ? $("#quick-ollama-model").value : provider === "openai" ? $("#quick-openai-model").value.trim() : "";
  if (provider !== "webapp" && !model) return $("#quick-provider-status").textContent = "Select a model before continuing.";
  $("#quick-provider-status").textContent = "Saving selection…";
  try {
    const data = await request("/api/llm-settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider, model, webApp: $("#quick-webapp").value }) });
    renderLlmSettings(data);
    $("#provider-dialog").close();
    $("#round-trip-status").textContent = `Default LLM changed to ${$("#send-provider-summary").textContent}. Your current prompt is unchanged.`;
  } catch (error) { $("#quick-provider-status").textContent = error.message; }
});
$("#cancel-llm-request").addEventListener("click", () => {
  $("#llm-progress-status").textContent = "Canceling the model request…";
  $("#cancel-llm-request").disabled = true;
  state.llmController?.abort();
  setTimeout(() => { $("#cancel-llm-request").disabled = false; }, 500);
});
$("#next-to-reply").addEventListener("click", () => {
  if (!state.promptCopied) return $("#round-trip-status").textContent = "Copy the protected prompt before continuing.";
  showSafeStep(4);
  $("#round-trip-status").textContent = "Paste the AI provider's reply below. Nothing is submitted automatically.";
});
$("#back-to-create").addEventListener("click", () => showSafeStep(1));
$("#back-to-draft").addEventListener("click", () => showSafeStep(2));
$("#back-to-copy").addEventListener("click", () => showSafeStep(3));
document.querySelectorAll(".safe-prompt-reset").forEach((button) => button.addEventListener("click", resetSafePrompt));
$("#restore-reply").addEventListener("click", () => {
  const status = $("#round-trip-status");
  if (!$("#model-reply").value.trim()) return status.textContent = "Paste the model reply first.";
  $("#restored-reply").value = restoreLocally($("#model-reply").value);
  state.localTokenMapping = {};
  clearTimeout(state.localVaultTimer);
  $("#restored-step").hidden = false;
  state.roundTripId = null;
  status.textContent = "Protected values were reinserted in this browser. The temporary mapping has been deleted.";
});
$("#copy-restored").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#restored-reply").value);
  $("#round-trip-status").textContent = "Restored result copied. Treat it as sensitive information.";
});
$("#appearance-form").addEventListener("change", () => applyAppearance({
  theme: document.querySelector('[name="theme"]:checked').value,
  fontSize: document.querySelector('[name="font-size"]:checked').value,
}, true));
document.querySelectorAll('[name="llm-provider"]').forEach((input) => input.addEventListener("change", () => {
  updateProviderRows();
  scheduleDefaultLlmSave();
}));
$("#ollama-model").addEventListener("change", () => scheduleDefaultLlmSave());
$("#webapp").addEventListener("change", () => scheduleDefaultLlmSave());
$("#openai-model").addEventListener("input", () => scheduleDefaultLlmSave(500));
$("#openai-model").addEventListener("change", () => scheduleDefaultLlmSave());
$("#refresh-models").addEventListener("click", async () => renderLlmSettings(await request("/api/llm-settings")));
$("#save-openai-key").addEventListener("click", async () => {
  const input = $("#openai-api-key");
  if (!input.value.trim()) return $("#openai-status").textContent = "Enter an API key first.";
  $("#openai-status").textContent = "Saving securely…";
  try {
    await request("/api/llm-credentials/openai", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ apiKey: input.value }) });
    input.value = "";
    state.openaiKeyEditing = false;
    renderLlmSettings(await request("/api/llm-settings"));
  } catch (error) { $("#openai-status").textContent = error.message; }
});
$("#replace-openai-key").addEventListener("click", () => {
  state.openaiKeyEditing = true;
  renderLlmSettings(state.llmSettings);
  $("#openai-api-key").focus();
});
$("#cancel-openai-key").addEventListener("click", () => {
  state.openaiKeyEditing = false;
  $("#openai-api-key").value = "";
  renderLlmSettings(state.llmSettings);
});
$("#remove-openai-key").addEventListener("click", async () => {
  await request("/api/llm-credentials/openai", { method: "DELETE" });
  state.openaiKeyEditing = false;
  renderLlmSettings(await request("/api/llm-settings"));
});
$("#save-retention").addEventListener("click", async () => {
  const days = Number($("#retention-days").value);
  if (!Number.isInteger(days) || days < 1 || days > PRODUCT_DEFAULTS.retentionMaxDays) return $("#retention-status").textContent = `Enter between 1 and ${PRODUCT_DEFAULTS.retentionMaxDays.toLocaleString()} days.`;
  const result = await request("/api/retention", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ days }) });
  $("#retention-days").value = result.retention.days;
  $("#retention-status").textContent = result.deleted ? `Saved. ${result.deleted} expired event${result.deleted === 1 ? "" : "s"} deleted.` : "Retention saved locally.";
  await refreshDashboard();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.body.classList.contains("nav-open")) closeMobileMenu();
  if ((event.metaKey || event.ctrlKey) && event.key === ",") {
    event.preventDefault();
    openSection("settings");
  }
});

$("#harness-toast-close").addEventListener("click", closeHarnessToast);

$(".dialog-close").addEventListener("click", () => $("#warning-dialog").close());
$(".summary-close").addEventListener("click", () => $("#summary-dialog").close());
$("#summary-done").addEventListener("click", () => $("#summary-dialog").close());
$("#receipt-close").addEventListener("click", () => $("#warning-dialog").close());
$("#change-guard-settings").addEventListener("click", () => {
  const category = $("#change-guard-settings").dataset.category;
  const action = $("#change-guard-settings").dataset.action;
  $("#warning-dialog").close();
  if (action === "safe") {
    openSection("safe");
    $("#safe-prompt-text")?.focus();
    return;
  }
  openSection("policies");
  const input = category && category !== "custom" ? document.querySelector(`[name="${category}"]`) : $("#custom-label");
  input?.focus();
});
$("#copy-redacted").addEventListener("click", async () => {
  const event = state.events.find((candidate) => candidate.id === Number($("#copy-redacted").dataset.eventId));
  if (!event?.details.content) return;
  try {
    await navigator.clipboard.writeText(event.details.content);
    $("#copy-redacted").textContent = "Copied — review before sending";
  } catch {
    $("#copy-redacted").textContent = "Copy unavailable — use the preview";
  }
});
document.querySelectorAll("[data-mitigation]").forEach((button) => button.addEventListener("click", async () => {
  if (!state.selected) return;
  button.disabled = true;
  try {
    const result = await request(`/api/events/${state.selected.id}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision: button.dataset.mitigation }),
    });
    state.selected.mitigation = result.mitigation;
    const stored = state.events.find((event) => event.id === state.selected.id);
    if (stored) stored.mitigation = result.mitigation;
    $("#mitigation-status").textContent = `${button.dataset.mitigation === "source_deleted" ? "Source deletion" : "Incident report"} recorded locally. This is mitigation, not proof of compliance.`;
  } finally {
    button.disabled = false;
  }
}));

load().catch((error) => {
  $("#activity").innerHTML = `<div class="activity-item"><div class="activity-dot high">!</div><div><h3>PonoLens could not start</h3><p>${escapeHtml(error.message)}</p></div></div>`;
});

async function pollDashboard() {
  if (document.hidden) return;
  try {
    await refreshDashboard();
  } catch { /* status is visible; the next poll will retry */ }
}

setInterval(pollDashboard, PRODUCT_DEFAULTS.pollIntervalMs);
document.addEventListener("visibilitychange", () => { if (!document.hidden) pollDashboard(); });
window.addEventListener("focus", pollDashboard);
