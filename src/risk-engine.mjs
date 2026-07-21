import { createHash } from "node:crypto";
import { matchesFor, policyDefinitions, replaceWith } from "../public/detectors.js";
import { PRODUCT_DEFAULTS, harnessCanInterceptPrompt, harnessFor } from "../public/product-config.js";


const HIGH_RISK_FILES = /(^|\/)(?:\.env(?:\..*)?|\.ssh|\.aws|credentials|secrets?)(?:$|\/)/i;
const HISTORY_FILES = /(^|\/)\.git(?:$|\/)/i;


function countMatches(text, definitions) {
  const findings = [];
  for (const definition of definitions) {
    const matches = matchesFor(text, definition).map((match) => match[0]);
    if (matches.length) findings.push({
      type: definition.type,
      count: matches.length,
      ...(definition.category ? { category: definition.category } : {}),
      ...(definition.type === "email address" ? { samples: [...new Set(matches.map(maskEmail))].slice(0, 3) } : {}),
    });
  }
  return findings;
}

function maskEmail(value) {
  const [local, domain] = String(value).split("@");
  if (!domain) return "[masked email]";
  return `${local.slice(0, 1)}${"•".repeat(Math.max(3, Math.min(local.length - 1, 8)))}@${domain}`;
}

export function fingerprint(value) {
  return createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

export function redactEventForStorage(event, policy = {}) {
  const sanitize = (value) => {
    if (typeof value === "string") return redactContent(value, policy);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitize(item)]));
    return value;
  };
  return sanitize(event);
}


export function analyzeEvent(input, policy = {}) {
  const files = Array.isArray(input.files) ? input.files : [];
  const content = String(input.content ?? "");
  const repoFileCount = Number(input.repoFileCount ?? files.length ?? 0);
  const sentFileCount = Number(input.sentFileCount ?? files.length ?? 0);
  const percentOfRepo = repoFileCount > 0 ? Math.round((sentFileCount / repoFileCount) * 100) : 0;
  const detected = countMatches(content, policyDefinitions(policy, true));
  const secrets = detected.filter((finding) => finding.category === "secrets");
  const personal = detected.filter((finding) => finding.category === "contact");
  const regulated = detected.filter((finding) => ["healthcare", "legal", "financial"].includes(finding.category));
  const custom = detected.filter((finding) => finding.category === "custom");
  const enforcedSecrets = policy.presets?.secrets === false ? [] : secrets;
  const enforcedPersonal = policy.presets?.contact === false ? [] : personal;
  const enforcedRegulated = regulated.filter((finding) => policy.presets?.[finding.category] === true);
  const sensitiveFiles = files.filter((file) => HIGH_RISK_FILES.test(file));
  const includesGitHistory = Boolean(input.includesGitHistory) || files.some((file) => HISTORY_FILES.test(file));
  const destinationText = String(input.destination || "").toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const destinationTrusted = input.destinationTrust === "trusted" || (policy.trustedDestinations || []).some((trusted) => destinationText === trusted || destinationText.endsWith(`.${trusted}`));
  const externalTransfer = input.action === "network" || Boolean(input.destination);
  const commandReceipt = input.action === "command" && Boolean(input.command);

  let score = 0;
  const reasons = [];

  const thresholds = { ...PRODUCT_DEFAULTS.thresholds, ...(policy.thresholds || {}) };
  if (externalTransfer && percentOfRepo >= thresholds.entireRepoPercent && repoFileCount >= thresholds.minimumRepoFiles) {
    score += 55;
    reasons.push(`The agent is sending ${percentOfRepo}% of the project (${sentFileCount} of ${repoFileCount} files).`);
  } else if (externalTransfer && percentOfRepo >= thresholds.largeTransferPercent && repoFileCount >= thresholds.minimumRepoFiles) {
    score += 30;
    reasons.push(`The agent is sending a large part of the project (${sentFileCount} of ${repoFileCount} files).`);
  }

  if (externalTransfer && includesGitHistory) {
    score += 25;
    reasons.push("The upload includes Git history, which can contain files or secrets deleted long ago.");
  }
  if (externalTransfer && sensitiveFiles.length) {
    score += 30;
    reasons.push(`Sensitive files are included: ${sensitiveFiles.slice(0, 3).join(", ")}.`);
  }
  if (externalTransfer && enforcedSecrets.length) {
    score += 35;
    reasons.push(`Possible ${enforcedSecrets.map((item) => item.type).join(" and ")} detected.`);
  }
  if (externalTransfer && enforcedPersonal.length) {
    score += 20;
    reasons.push(`Personal information detected: ${enforcedPersonal.map((item) => `${item.count} ${item.type}${item.count === 1 ? "" : "es"}`).join(", ")}.`);
  }
  if (externalTransfer && enforcedRegulated.length) {
    score += 35;
    reasons.push(`Protected information detected: ${enforcedRegulated.map((item) => item.type).join(", ")}.`);
  }
  if (externalTransfer && custom.length) {
    score += 35;
    reasons.push(`A value you marked as private was detected: ${custom.map((item) => item.type).join(", ")}.`);
  }
  if (externalTransfer && !destinationTrusted) {
    score += 15;
    score = Math.max(score, thresholds.medium);
    reasons.push("The destination is not on your trusted list.");
  }

  const sensitiveDetected = secrets.length > 0 || personal.length > 0 || regulated.length > 0 || custom.length > 0;
  if (commandReceipt && sensitiveDetected) {
    score = Math.max(score, thresholds.medium);
    const categories = [secrets.length && "secrets or credentials", personal.length && "personal information", regulated.length && "regulated information", custom.length && "a locally protected value"].filter(Boolean);
    reasons.push(`The command contains ${categories.join(", ")}. PonoLens stored only a redacted preview.`);
  }

  score = Math.min(score, 100);
  const severity = score >= thresholds.critical ? "critical" : score >= thresholds.high ? "high" : score >= thresholds.medium ? "medium" : "low";
  const unfamiliarPersonalTransfer = externalTransfer && !destinationTrusted && (enforcedPersonal.length > 0 || enforcedRegulated.length > 0 || custom.length > 0);
  const protectedTransfer = externalTransfer && (enforcedRegulated.length > 0 || custom.length > 0);
  const untrustedHistoryTransfer = externalTransfer && !destinationTrusted && includesGitHistory;
  const normalizedHarness = String(input.harness || "").toLowerCase();
  const harness = harnessFor(normalizedHarness);
  const promptCanBeBlocked = input.action === "prompt" && harnessCanInterceptPrompt(normalizedHarness, input.hookEvent);
  const enabledFindings = [...enforcedSecrets, ...enforcedPersonal, ...enforcedRegulated, ...custom];
  const categoryAction = (category) => policy.categoryActions?.[category] || (policy.mode === "observe" ? "warn" : policy.mode === "redact" ? "redact" : "block");
  const requestedActions = enabledFindings.map((finding) => categoryAction(finding.category));
  const protectionAction = requestedActions.includes("block") ? "block" : requestedActions.includes("redact") ? "redact" : "warn";
  const preSubmitProtectedPrompt = promptCanBeBlocked && enabledFindings.length > 0 && protectionAction !== "warn";
  const enforcementEnabled = policy.mode !== "observe" || requestedActions.some((action) => action !== "warn");
  const observedPrompt = input.action === "prompt" && Boolean(input.destination) && !promptCanBeBlocked;
  const decision = commandReceipt
    ? sensitiveDetected ? "approval_required" : "allowed"
    : enforcementEnabled && !observedPrompt && (preSubmitProtectedPrompt || severity === "critical" || untrustedHistoryTransfer)
    ? "blocked"
    : externalTransfer && !destinationTrusted
      ? "approval_required"
      : !enforcementEnabled || observedPrompt
        ? "allowed"
        : severity === "high" || unfamiliarPersonalTransfer || protectedTransfer
          ? "approval_required"
      : "allowed";

  let headline = "Activity looks normal";
  if (commandReceipt) headline = sensitiveDetected ? "This command includes sensitive information" : "Agent command observed";
  if (input.action === "prompt" && input.destination) headline = `Your prompt was submitted to ${input.destination}`;
  if (percentOfRepo >= thresholds.entireRepoPercent && externalTransfer) headline = "This agent is uploading your entire project";
  else if (untrustedHistoryTransfer) headline = "This agent is uploading your project's Git history";
  else if (externalTransfer && enforcedSecrets.length) headline = "This action may expose a password or secret key";
  else if (externalTransfer && enforcedRegulated.length) headline = "This action includes protected information";
  else if (externalTransfer && custom.length) headline = "This action includes information you marked as private";
  else if (externalTransfer && enforcedPersonal.length) headline = "This action includes personal information";
  else if (externalTransfer && (secrets.length || personal.length || regulated.length)) headline = "Sensitive information was detected and sent";
  else if (severity === "high") headline = "This agent is sending more data than expected";
  else if (severity === "medium") headline = "Review this action before it continues";

  const recommendation = commandReceipt && sensitiveDetected
    ? "Review the redacted command receipt. PonoLens did not block this command; remove sensitive arguments before running a similar command again."
    : commandReceipt
      ? "No sensitive information was detected. Review the command if this agent action was unexpected."
    : decision === "blocked"
    ? preSubmitProtectedPrompt
      ? protectionAction === "redact"
        ? "The sensitive original was not sent. Review the protected prompt, then copy and submit it after confirming the meaning is still correct."
        : "The original prompt was not sent. Review the redacted preview, copy it into your agent, and submit only after confirming the meaning is still correct."
      : includesGitHistory
      ? "Keep this blocked. Share only the files required for the task, and remove secrets and Git history."
      : "Keep this blocked. Remove the protected information or choose a trusted destination before trying again."
    : observedPrompt && sensitiveDetected
      ? harness?.id === "codex"
        ? "Codex prompts cannot be blocked by PonoLens before submission. Use Safe Prompt to remove identifiers before sending your next Codex prompt."
        : "This prompt was observed after submission. Use Safe Prompt to remove identifiers before sending similar prompts."
    : promptCanBeBlocked && sensitiveDetected && protectionAction === "warn"
      ? `Update your Pono Guard settings to redact or block similar ${harness?.name || "agent"} prompts before submission.`
    : preSubmitProtectedPrompt && sensitiveDetected
      ? `Update your Pono Guard settings to block similar ${harness?.name || "agent"} prompts before submission.`
    : decision === "approval_required"
      ? "Check the destination and remove unnecessary information before allowing this action."
      : "No action is required. You can inspect the details if this activity was unexpected.";

  return {
    score,
    severity,
    decision,
    headline,
    explanation: reasons.join(" ") || (commandReceipt
      ? "PonoLens observed this agent command and stored a redacted command preview locally. No external destination was identified."
      : externalTransfer && (secrets.length || personal.length || regulated.length)
      ? "PonoLens detected sensitive information, but its categories were not enabled for blocking when this prompt was submitted."
      : !externalTransfer && (secrets.length || personal.length || regulated.length || custom.length)
      ? "Protected information was present in this local action, but PonoLens observed no external destination."
      : input.action === "prompt" && input.destination
      ? `The text you entered left this device for processing by ${input.destination}. PonoLens observed the submission, but cannot confirm the provider's storage or retention.`
      : "PonoLens found no unusual data movement."),
    recommendation,
    policyResult: {
      mode: policy.mode === "redact" ? "redact" : enforcementEnabled ? "block_critical" : "observe",
      sensitiveDetected,
      enforcement: decision === "blocked" ? "blocked" : "allowed",
      action: protectionAction,
      reason: observedPrompt && sensitiveDetected
        ? String(input.harness || "").toLowerCase() === "codex"
          ? "Codex does not expose this prompt to PonoLens early enough to block it; the transmission was observed after submission."
          : "This transmission was observed after submission and could not be blocked."
        : commandReceipt
          ? "Experimental command monitoring is report-only; the command was observed and its stored preview was redacted."
        : decision === "blocked"
        ? "Current Pono Guard settings require this prompt to be blocked."
        : sensitiveDetected && externalTransfer
          ? "Current Pono Guard settings allowed this action."
          : "No configured Pono Guard condition required blocking.",
    },
    interception: {
      capable: promptCanBeBlocked,
      timing: promptCanBeBlocked ? "before_submission" : input.action === "prompt" && input.destination ? "after_submission" : "not_applicable",
    },
    findings: { secrets, personal, regulated, custom, sensitiveFiles, includesGitHistory, percentOfRepo },
  };
}

export function redactContent(content, policy = {}) {
  let redacted = String(content ?? "");
  for (const definition of policyDefinitions(policy, true)) redacted = replaceWith(redacted, definition, () => `[REDACTED ${definition.type.toUpperCase()}]`);
  for (const item of policy.customValues ?? []) {
    if (!item?.value) continue;
    const escaped = String(item.value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    redacted = redacted.replace(new RegExp(escaped, "gi"), `[REDACTED ${(item.label || "CUSTOM VALUE").toUpperCase()}]`);
  }
  return redacted;
}

export function tokenizeContent(content, policy = {}) {
  let tokenized = String(content ?? "");
  const mapping = {};
  const counts = new Map();
  const definitions = policyDefinitions(policy);
  for (const definition of definitions) {
    tokenized = replaceWith(tokenized, definition, (value) => {
      const key = definition.type.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
      const number = (counts.get(key) || 0) + 1;
      counts.set(key, number);
      const token = `[[${key}_${number}]]`;
      mapping[token] = value;
      return token;
    });
  }
  for (const item of policy.customValues ?? []) {
    if (!item?.value) continue;
    const escaped = String(item.value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    tokenized = tokenized.replace(new RegExp(escaped, "gi"), (value) => {
      const key = String(item.label || "CUSTOM_VALUE").toUpperCase().replace(/[^A-Z0-9]+/g, "_");
      const number = (counts.get(key) || 0) + 1;
      counts.set(key, number);
      const token = `[[${key}_${number}]]`;
      mapping[token] = value;
      return token;
    });
  }
  return { tokenized, mapping };
}

export function restoreTokens(content, mapping = {}) {
  let restored = String(content ?? "");
  for (const [token, value] of Object.entries(mapping)) restored = restored.split(token).join(String(value));
  return restored;
}
