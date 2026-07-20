import test from "node:test";
import assert from "node:assert/strict";
import { analyzeEvent, redactContent, restoreTokens, tokenizeContent } from "../src/risk-engine.mjs";
import { normalizePolicy } from "../src/policy.mjs";
import { scanContent } from "../public/detectors.js";

test("blocks an excessive repository upload and explains it plainly", () => {
  const result = analyzeEvent({
    harness: "cursor",
    action: "network",
    repoFileCount: 100,
    sentFileCount: 100,
    destination: "unknown.example",
    destinationTrust: "unknown",
    includesGitHistory: true,
    files: [".git/objects", ".env"],
  });

  assert.equal(result.decision, "blocked");
  assert.equal(result.severity, "critical");
  assert.match(result.headline, /entire project/i);
  assert.match(result.explanation, /Git history/i);
});

test("allows a narrow, trusted source-code request", () => {
  const result = analyzeEvent({
    harness: "codex",
    action: "tool_call",
    repoFileCount: 500,
    sentFileCount: 1,
    destination: "OpenAI",
    destinationTrust: "trusted",
    files: ["src/Button.tsx"],
    content: "export const Button = () => null;",
  });

  assert.equal(result.decision, "allowed");
  assert.equal(result.severity, "low");
});

test("does not treat a local tool call as an external transfer", () => {
  const result = analyzeEvent({
    harness: "codex",
    action: "tool_call",
    source: "Bash",
    destination: null,
    destinationTrust: "local",
    content: "{\"command\":\"git status\"}",
  });

  assert.equal(result.score, 0);
  assert.equal(result.decision, "allowed");
  assert.equal(result.explanation, "PonoLens found no unusual data movement.");
});

test("detects then redacts common personal data and secrets", () => {
  const content = "Email me at person@example.com with sk-example1234567890";
  const result = analyzeEvent({ harness: "claude-code", action: "network", destination: "example.com", content });
  const redacted = redactContent(content);

  assert.ok(result.findings.personal.length > 0);
  assert.ok(result.findings.secrets.length > 0);
  assert.equal(result.decision, "blocked");
  assert.doesNotMatch(redacted, /person@example\.com/);
  assert.doesNotMatch(redacted, /sk-example/);
});

test("detects and redacts disabled categories without enforcing a block", () => {
  const content = "Email person@example.com with sk-example1234567890";
  const policy = { presets: { secrets: false, contact: false } };
  const result = analyzeEvent({ harness: "cursor", action: "prompt", destination: "Cursor model provider", content, hookEvent: "beforeSubmitPrompt" }, policy);
  const redacted = redactContent(content, policy);
  assert.equal(result.findings.personal.length, 1);
  assert.equal(result.findings.secrets.length, 1);
  assert.equal(result.decision, "allowed");
  assert.doesNotMatch(redacted, /person@example\.com|sk-example/);
});

test("applies healthcare and custom protected-value policies", () => {
  const policy = {
    presets: { healthcare: true },
    customValues: [{ label: "Patient name", value: "Jane Example" }],
  };
  const content = "Patient Jane Example has MRN: ABC-12345";
  const result = analyzeEvent({ harness: "cursor", action: "network", destination: "unknown.example", content }, policy);
  const redacted = redactContent(content, policy);

  assert.equal(result.decision, "blocked");
  assert.match(result.headline, /protected information/i);
  assert.equal(result.findings.custom[0].type, "Patient name");
  assert.match(redacted, /REDACTED PATIENT NAME/);
  assert.match(redacted, /REDACTED MEDICAL RECORD NUMBER/);
  assert.doesNotMatch(redacted, /Jane Example|ABC-12345/i);
});

test("flags realistic healthcare details in a prompt sent to a trusted model provider", () => {
  const content = "Patient: Jane Example\nDOB: 04/12/1980\nDiagnosis: Type 2 diabetes\nMedication: metformin 500mg\nTreatment: follow-up bloodwork";
  const result = analyzeEvent({
    harness: "codex",
    action: "prompt",
    destination: "OpenAI",
    destinationTrust: "trusted",
    content,
  }, { presets: { healthcare: true } });
  const redacted = redactContent(content, { presets: { healthcare: true } });

  assert.equal(result.decision, "allowed");
  assert.equal(result.interception.timing, "after_submission");
  assert.match(result.recommendation, /use Safe Prompt/i);
  assert.ok(result.findings.regulated.some((finding) => finding.type === "date of birth"));
  assert.ok(result.findings.regulated.some((finding) => finding.type === "diagnosis"));
  assert.ok(result.findings.regulated.some((finding) => finding.type === "medication information"));
  assert.doesNotMatch(redacted, /04\/12\/1980|Type 2 diabetes|metformin 500mg/i);
});

test("flags plain-language health conditions and email in a letter request", () => {
  const content = "Draft a letter to Tim at tim.holmgreng@gmail.com about his IBS and high blood pressure.";
  const result = analyzeEvent({
    harness: "codex",
    action: "prompt",
    destination: "OpenAI",
    destinationTrust: "trusted",
    content,
  }, { presets: { healthcare: true } });

  assert.equal(result.decision, "allowed");
  assert.equal(result.interception.capable, false);
  assert.match(result.recommendation, /Codex prompts cannot be blocked/i);
  assert.ok(result.findings.personal.some((finding) => finding.type === "email address"));
  assert.match(result.findings.personal.find((finding) => finding.type === "email address").samples[0], /^t.+@gmail\.com$/);
  assert.doesNotMatch(result.findings.personal.find((finding) => finding.type === "email address").samples[0], /tim\.holmgreng/);
  assert.equal(result.findings.regulated.find((finding) => finding.type === "health condition").count, 2);
});

test("does not require review when protected text appears only in a local action", () => {
  const result = analyzeEvent({
    harness: "codex",
    action: "tool_call",
    destination: null,
    destinationTrust: "local",
    content: "Email tim.holmgreng@gmail.com about IBS treatment",
  }, { presets: { healthcare: true } });

  assert.equal(result.score, 0);
  assert.equal(result.decision, "allowed");
  assert.match(result.explanation, /local action/i);
});

test("warns that Codex prompts are observed after submission and recommends Safe Prompt", () => {
  const content = "Email person@example.com about their high blood pressure";
  const event = {
    harness: "codex",
    action: "prompt",
    hookEvent: "UserPromptSubmit",
    destination: "OpenAI",
    destinationTrust: "trusted",
    content,
  };
  const policy = { presets: { healthcare: true } };
  const result = analyzeEvent(event, policy);
  const redacted = redactContent(content, policy);

  assert.equal(result.decision, "allowed");
  assert.equal(result.interception.capable, false);
  assert.equal(result.interception.timing, "after_submission");
  assert.match(result.recommendation, /cannot be blocked.*safe prompt/i);
  assert.match(result.policyResult.reason, /does not expose.*early enough/i);
  assert.doesNotMatch(redacted, /person@example\.com|high blood pressure/i);
  assert.match(redacted, /REDACTED EMAIL ADDRESS/);
});

test("allows and logs a protected Cursor prompt when Pono Guard is in observe mode", () => {
  const result = analyzeEvent({
    harness: "cursor",
    action: "prompt",
    hookEvent: "beforeSubmitPrompt",
    destination: "Cursor model provider",
    destinationTrust: "trusted",
    content: "Email person@example.com about their high blood pressure",
  }, { presets: { contact: true, healthcare: true }, mode: "observe" });

  assert.equal(result.decision, "allowed");
  assert.equal(result.policyResult.enforcement, "allowed");
  assert.match(result.policyResult.reason, /settings allowed this action/i);
  assert.match(result.recommendation, /update your Pono Guard settings/i);
});

test("redact mode stops a protected prompt and produces a sanitized copy", () => {
  const content = "Email patient@example.com about high blood pressure";
  const policy = { presets: { contact: true, healthcare: true }, mode: "redact" };
  for (const event of [
    { harness: "cursor", hookEvent: "beforeSubmitPrompt", destination: "Cursor model provider" },
    { harness: "claude-code", hookEvent: "UserPromptSubmit", destination: "Anthropic" },
    { harness: "windsurf", hookEvent: "pre_user_prompt", destination: "Windsurf model provider" },
  ]) {
    const result = analyzeEvent({ ...event, action: "prompt", destinationTrust: "trusted", content }, policy);
    assert.equal(result.decision, "blocked");
    assert.equal(result.policyResult.action, "redact");
    assert.match(result.recommendation, /protected prompt/i);
  }
  const sanitized = redactContent(content, policy);
  assert.doesNotMatch(sanitized, /patient@example\.com|high blood pressure/i);
  assert.match(sanitized, /REDACTED EMAIL ADDRESS/);
});

test("blocks a protected Claude Code prompt before submission", () => {
  const result = analyzeEvent({
    harness: "claude-code",
    action: "prompt",
    hookEvent: "UserPromptSubmit",
    destination: "Anthropic",
    destinationTrust: "trusted",
    content: "Email patient@example.com about their high blood pressure",
  }, { presets: { contact: true, healthcare: true }, mode: "block_critical" });

  assert.equal(result.decision, "blocked");
  assert.equal(result.interception.capable, true);
  assert.equal(result.interception.timing, "before_submission");
  assert.match(result.recommendation, /original prompt was not sent/i);
});

test("blocks a protected Windsurf prompt before Cascade processes it", () => {
  const result = analyzeEvent({
    harness: "windsurf", action: "prompt", hookEvent: "pre_user_prompt",
    destination: "Windsurf model provider", destinationTrust: "trusted",
    content: "Email patient@example.com about high blood pressure",
  }, { presets: { contact: true, healthcare: true }, mode: "block_critical" });
  assert.equal(result.decision, "blocked");
  assert.equal(result.interception.capable, true);
  assert.equal(result.interception.timing, "before_submission");
});

test("blocks a protected prompt from Devin's current UserPromptSubmit hook", () => {
  const result = analyzeEvent({
    harness: "windsurf", action: "prompt", hookEvent: "UserPromptSubmit",
    destination: "Windsurf model provider", destinationTrust: "trusted",
    content: "Email patient@example.com about high blood pressure",
  }, { presets: { contact: true, healthcare: true }, mode: "block_critical" });
  assert.equal(result.decision, "blocked");
  assert.equal(result.interception.capable, true);
});

test("detects and redacts a contextual patient name and patient identifier", () => {
  const policy = { presets: { healthcare: true, financial: true }, customValues: [] };
  const input = {
    harness: "Safe Prompt", action: "prompt", hookEvent: "UserPromptSubmit",
    destination: "Selected AI provider",
    content: "write to my patient Tim Holmgren with IBS. Patient: 001-222 and social security 123-33-3234",
  };
  const result = analyzeEvent(input, policy);
  const redacted = redactContent(input.content, policy);
  assert.equal(result.decision, "allowed");
  assert.match(redacted, /\[REDACTED PATIENT NAME\]/);
  assert.match(redacted, /\[REDACTED PATIENT OR INSURANCE IDENTIFIER\]/);
  assert.doesNotMatch(redacted, /Tim Holmgren|001-222/);
});

test("tokenizes protected values and restores an LLM reply locally", () => {
  const policy = { presets: { healthcare: true }, customValues: [] };
  const { tokenized, mapping } = tokenizeContent("Email Jane at jane@example.com about IBS", policy);
  assert.doesNotMatch(tokenized, /jane@example.com|IBS/);
  const reply = `Draft for ${Object.keys(mapping).join(" and ")}`;
  const restored = restoreTokens(reply, mapping);
  assert.match(restored, /jane@example.com/);
  assert.match(restored, /IBS/);
});

test("detects expanded personal, identity, device, and international identifiers", () => {
  const content = [
    "Name: Jamie Rivera", "Address: 123 Palm Street", "DOB: 04/12/1980",
    "Passport number: X1234567", "Driver license: H12345678",
    "IP address: 192.168.1.42", "IMEI: 490154203237518", "National ID: DE-123456789",
  ].join("\n");
  const result = analyzeEvent({ harness: "cursor", action: "prompt", hookEvent: "beforeSubmitPrompt", destination: "Cursor model provider", content }, { presets: { contact: true } });
  const types = result.findings.personal.map((finding) => finding.type);
  for (const expected of ["person name", "postal address", "date of birth", "passport number", "driver license number", "IP address", "device identifier", "international personal identifier"]) assert.ok(types.includes(expected), expected);
  assert.equal(result.decision, "blocked");
});

test("validates payment cards, routing numbers, IBANs, and ignores invalid lookalikes", () => {
  const valid = "Card 4111 1111 1111 1111 routing: 021000021 account number: 123456789 IBAN GB82 WEST 1234 5698 7654 32";
  const invalid = "Card 4111 1111 1111 1112 routing: 021000022 IP 999.999.1.1";
  const policy = { presets: { financial: true, contact: true } };
  const validResult = analyzeEvent({ action: "network", destination: "example.test", content: valid }, policy);
  const invalidResult = analyzeEvent({ action: "network", destination: "example.test", content: invalid }, policy);
  assert.ok(validResult.findings.regulated.some((item) => item.type === "payment card number"));
  assert.ok(validResult.findings.regulated.some((item) => item.type === "bank routing number"));
  assert.ok(validResult.findings.regulated.some((item) => item.type === "bank account number"));
  assert.ok(validResult.findings.regulated.some((item) => item.type === "IBAN"));
  assert.ok(!invalidResult.findings.regulated.some((item) => item.type === "payment card number"));
  assert.ok(!invalidResult.findings.regulated.some((item) => item.type === "bank routing number"));
  assert.ok(!invalidResult.findings.personal.some((item) => item.type === "IP address"));
});

test("detects additional medical, legal, and high-entropy credential formats", () => {
  const content = "Medicare ID: 1EG4TE5MK73 NPI: 1234567890 UDI: (01)12345678901234 Docket No: 24-CV-00991 privileged and confidential api_key=K8pQ2zL9xR4vN7mT6cW1";
  const policy = { presets: { secrets: true, healthcare: true, legal: true } };
  const result = analyzeEvent({ action: "network", destination: "example.test", content }, policy);
  assert.ok(result.findings.secrets.some((item) => item.type === "cloud or service credential"));
  assert.ok(result.findings.regulated.some((item) => item.type === "health plan beneficiary number"));
  assert.ok(result.findings.regulated.some((item) => item.type === "provider medical identifier"));
  assert.ok(result.findings.regulated.some((item) => item.type === "medical device identifier"));
  assert.ok(result.findings.regulated.some((item) => item.type === "legal matter identifier"));
  assert.ok(result.findings.regulated.some((item) => item.type === "legal privilege marker"));
});

test("uses the same detector catalog for server analysis and browser Safe Prompt", () => {
  const policy = normalizePolicy({ presets: { contact: true, financial: true } });
  const content = "Email jane@example.com card 4111 1111 1111 1111";
  const analysis = analyzeEvent({ action: "network", destination: "example.test", content }, policy);
  const browser = scanContent(content, policy);
  const serverTypes = [...analysis.findings.personal, ...analysis.findings.regulated].map((item) => item.type);
  const browserTypes = browser.findings.map((item) => item.type);
  assert.ok(serverTypes.includes("email address") && browserTypes.includes("email address"));
  assert.ok(serverTypes.includes("payment card number") && browserTypes.includes("payment card number"));
});

test("normalizes and applies advanced destinations, actions, dictionaries, regex, and thresholds", () => {
  const policy = normalizePolicy({
    presets: { contact: true }, categoryActions: { contact: "warn", custom: "block" },
    trustedDestinations: ["trusted.example"], thresholds: { medium: 10, high: 30, critical: 60 },
    dictionaries: [{ label: "Client list", category: "custom", values: ["Project Koa"] }],
    regexRules: [{ label: "Matter format", category: "custom", pattern: "MAT-[0-9]{4}", flags: "gi" }],
  });
  const trusted = analyzeEvent({ harness: "cursor", action: "prompt", hookEvent: "beforeSubmitPrompt", destination: "api.trusted.example", content: "person@example.com" }, policy);
  assert.equal(trusted.decision, "allowed");
  const blocked = analyzeEvent({ harness: "cursor", action: "prompt", hookEvent: "beforeSubmitPrompt", destination: "other.example", content: "Project Koa MAT-2042" }, policy);
  assert.equal(blocked.decision, "blocked");
  assert.ok(blocked.findings.custom.length >= 2);
});

test("rejects unsafe or invalid custom regex rules", () => {
  const policy = normalizePolicy({ regexRules: [{ label: "unsafe", pattern: "(a+)+" }, { label: "backref", pattern: "(a)\\1" }, { label: "valid", pattern: "CASE-[0-9]{1,12}" }] });
  assert.equal(policy.regexRules.length, 1);
  assert.equal(policy.regexRules[0].label, "valid");
});

test("rejects ambiguous-alternation ReDoS rules while allowing bounded identifier patterns", () => {
  const policy = normalizePolicy({ regexRules: [
    { label: "unsafe", category: "custom", pattern: "(a|aa)+$", flags: "g" },
    { label: "adjacent", category: "custom", pattern: "a+a+$", flags: "g" },
    { label: "oversized", category: "custom", pattern: "ID-[0-9]{1,5000}", flags: "g" },
    { label: "matter", category: "legal", pattern: "MAT-[0-9]{4,8}", flags: "gi" },
  ] });
  assert.deepEqual(policy.regexRules.map((rule) => rule.label), ["matter"]);
});
