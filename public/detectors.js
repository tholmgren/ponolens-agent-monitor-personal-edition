const digits = (value) => String(value).replace(/\D/g, "");
const validators = {
  paymentCard(value) { const number = digits(value); if (number.length < 13 || number.length > 19 || /^(\d)\1+$/.test(number)) return false; let sum = 0, alternate = false; for (let i = number.length - 1; i >= 0; i--) { let n = Number(number[i]); if (alternate && (n *= 2) > 9) n -= 9; sum += n; alternate = !alternate; } return sum % 10 === 0; },
  aba(value) { const number = digits(value).slice(-9); return number.length === 9 && [...number].reduce((sum, n, i) => sum + Number(n) * [3, 7, 1][i % 3], 0) % 10 === 0; },
  ipv4(value) { const match = String(value).match(/(?:\d{1,3}\.){3}\d{1,3}/); return Boolean(match && match[0].split(".").every((part) => Number(part) <= 255)); },
  iban(value) { const iban = String(value).replace(/\s/g, "").toUpperCase(); if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return false; let remainder = 0; for (const char of iban.slice(4) + iban.slice(0, 4)) for (const n of (/[A-Z]/.test(char) ? String(char.charCodeAt(0) - 55) : char)) remainder = (remainder * 10 + Number(n)) % 97; return remainder === 1; },
  entropy(value) { const candidate = String(value).split(/[=:]/).at(-1).replace(/["'\s]/g, ""); if (candidate.length < 16) return false; const counts = new Map(); for (const char of candidate) counts.set(char, (counts.get(char) || 0) + 1); return [...counts.values()].reduce((sum, count) => { const p = count / candidate.length; return sum - p * Math.log2(p); }, 0) >= 3.5; },
};

export const DETECTOR_CATALOG = [
  ["secrets", "API key", /\b(?:sk-(?:proj-|live-)?|xox[baprs]-?|gh[pousr]_|github_pat_|AKIA|ASIA|AIza|pk_(?:live|test)_|rk_(?:live|test)_|sq0atp-|SG\.)[-_A-Za-z0-9.]{12,}\b/g],
  ["secrets", "cloud or service credential", /\b(?:aws_(?:access_key_id|secret_access_key)|api[_ -]?key|access[_ -]?token|client[_ -]?secret|secret[_ -]?key)\s*[=:]\s*["']?[A-Za-z0-9_+/.=-]{16,}["']?/gi, "entropy"],
  ["secrets", "private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi], ["secrets", "password", /\b(?:password|passwd|pwd)\s*[=:]\s*[^\s,;]{6,}/gi],
  ["contact", "email address", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi], ["contact", "phone number", /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g],
  ["contact", "person name", /\b(?:full name|customer name|client name|employee name|name)\s*[:=-]\s*[A-Z][A-Za-z'’-]{1,30}(?:\s+[A-Z][A-Za-z'’-]{1,30}){1,3}\b/gi],
  ["contact", "postal address", /\b(?:address|street address|mailing address)\s*[:=-]\s*\d{1,6}\s+[A-Za-z0-9.'’ -]{2,60}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b[^\n,]*/gi],
  ["contact", "date of birth", /\b(?:DOB|date of birth|birth date|born)\s*[:=-]?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|[A-Z][a-z]+\s+\d{1,2},?\s+\d{4})\b/gi],
  ["contact", "passport number", /\bpassport(?: number| no\.?| #)?\s*[:=-]\s*[A-Z0-9]{6,12}\b/gi], ["contact", "driver license number", /\b(?:driver'?s? licen[cs]e|DL)(?: number| no\.?| #)?\s*[:=-]\s*[A-Z0-9-]{5,20}\b/gi],
  ["contact", "IP address", /\b(?:IP(?:v4)?(?: address)?\s*[:=-]\s*)?(?:\d{1,3}\.){3}\d{1,3}\b/gi, "ipv4"], ["contact", "device identifier", /\b(?:device id|advertising id|IDFA|GAID|IMEI|serial number)\s*[:=-]\s*(?:[A-F0-9]{8}-[A-F0-9-]{12,}|\d{15}|[A-Z0-9-]{8,40})\b/gi],
  ["contact", "international personal identifier", /\b(?:national id|tax id|identity number|identification number)\s*[:=-]\s*[A-Z0-9][A-Z0-9 .-]{5,24}\b/gi],
  ["healthcare", "medical record number", /\b(?:MRN|medical record(?: number)?)[\s:#-]*[A-Z0-9-]{5,}\b/gi], ["healthcare", "patient or insurance identifier", /\b(?:member|policy)[\s_-]*(?:id|number)[\s:#-]*[A-Z0-9-]{5,}\b|\bpatient(?:[\s_-]*(?:id|number))?[\s:#-]+[A-Z0-9]*\d[A-Z0-9-]{3,}\b/gi],
  ["healthcare", "date of birth", /\b(?:DOB|date of birth|birth date)[\s:#-]*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|[A-Z][a-z]+\s+\d{1,2},?\s+\d{4})\b/gi],
  ["healthcare", "health plan beneficiary number", /\b(?:Medicare|Medicaid|health plan|beneficiary)(?:\s+(?:ID|number|identifier))?\s*[:#=-]\s*[A-Z0-9-]{5,20}\b/gi], ["healthcare", "provider medical identifier", /\b(?:NPI|DEA number)\s*[:#=-]\s*[A-Z0-9]{7,12}\b/gi], ["healthcare", "medical device identifier", /\b(?:UDI|medical device (?:ID|identifier)|implant serial)\s*[:#=-]\s*[A-Z0-9().-]{6,40}\b/gi],
  ["healthcare", "patient name", /\b(?:my\s+patient|patient\s+name|patient(?!\s*(?:id|identifier|number)\b))[\s:#-]+[A-Z][A-Za-z'’-]{1,30}(?:\s+[A-Z][A-Za-z'’-]{1,30}){1,3}\b/g], ["healthcare", "diagnosis", /\b(?:diagnosis|diagnosed with|medical condition)[\s:#-]+[^\n.;]{3,80}/gi], ["healthcare", "medication information", /\b(?:medication|prescription|prescribed)[\s:#-]+[^\n.;]{3,80}/gi], ["healthcare", "treatment information", /\b(?:treatment|procedure|care plan)[\s:#-]+[^\n.;]{3,80}/gi],
  ["healthcare", "health condition", /\b(?:IBS|irritable bowel syndrome|high (?:blood )?pressure|hypertension|diabetes|cancer|HIV|AIDS|pregnan(?:cy|t)|depression|anxiety disorder|asthma)\b/gi, null, false],
  ["legal", "legal privilege marker", /\b(?:attorney[- ]client privileged|privileged and confidential|attorney work product|work product|common interest privilege|without prejudice)\b/gi, null, false], ["legal", "legal matter identifier", /\b(?:matter|case|docket|claim)[\s_-]*(?:id|number|no\.?|#)?[\s:#-]*[A-Z0-9][A-Z0-9./-]{3,}\b/gi],
  ["financial", "Social Security number", /\b\d{3}-\d{2}-\d{4}\b/g], ["financial", "payment card number", /\b(?:\d[ -]*?){13,19}\b/g, "paymentCard"], ["financial", "bank routing number", /\b(?:routing|ABA)(?: number)?[\s:#=-]*\d{9}\b/gi, "aba"], ["financial", "bank account number", /\b(?:bank )?account(?: number| no\.?| #)?[\s:#=-]*\d{6,17}\b/gi], ["financial", "IBAN", /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b/g, "iban"],
].map(([category, type, pattern, validator, tokenize = true]) => ({ category, type, pattern, validate: validator ? validators[validator] : null, tokenize }));

export function matchesFor(text, definition) { const flags = definition.pattern.flags.includes("g") ? definition.pattern.flags : `${definition.pattern.flags}g`; return [...String(text).matchAll(new RegExp(definition.pattern.source, flags))].filter((m) => !definition.validate || definition.validate(m[0])); }
export function replaceWith(text, definition, replacer) { const flags = definition.pattern.flags.includes("g") ? definition.pattern.flags : `${definition.pattern.flags}g`; return String(text).replace(new RegExp(definition.pattern.source, flags), (value) => definition.validate && !definition.validate(value) ? value : replacer(value)); }
export function isSafeCustomRegexSource(source) {
  source = String(source || "");
  if (!source || source.length > 200) return false;
  // Custom rules intentionally use a linear, group-free subset. JavaScript RegExp
  // has no execution timeout, so expressive grouping/alternation is not safe here.
  if (/[()|]/.test(source) || /\\[1-9]|(^|[^\\])[*+]|\{\d+,\}/.test(source)) return false;
  for (const match of source.matchAll(/\{(\d+)(?:,(\d+))?\}/g)) {
    const lower = Number(match[1]), upper = Number(match[2] ?? match[1]);
    if (lower > upper || upper > 1000) return false;
  }
  try { new RegExp(source); return true; } catch { return false; }
}
export function safeRegexRule(rule) { const source = String(rule?.pattern || ""); if (!isSafeCustomRegexSource(source)) return null; try { return new RegExp(source, String(rule.flags || "gi").replace(/[^gimsuy]/g, "")); } catch { return null; } }
export function policyDefinitions(policy = {}, includeDisabled = false) {
  const definitions = DETECTOR_CATALOG.filter((d) => includeDisabled || policy.presets?.[d.category] !== false);
  for (const item of policy.customValues || []) if (item?.value) definitions.push({ category: item.category || "custom", type: item.label || "Protected value", pattern: new RegExp(String(item.value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), tokenize: true });
  for (const dictionary of policy.dictionaries || []) for (const value of dictionary.values || []) if (value) definitions.push({ category: dictionary.category || "custom", type: dictionary.label || "Dictionary value", pattern: new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), tokenize: true });
  for (const rule of policy.regexRules || []) { const pattern = safeRegexRule(rule); if (pattern) definitions.push({ category: rule.category || "custom", type: rule.label || "Custom rule", pattern, tokenize: true }); }
  return definitions;
}

export function scanContent(content, policy = {}) {
  let tokenized = String(content || "");
  const mapping = {}, findings = [], counts = new Map();
  for (const match of tokenized.matchAll(/\[\[([A-Z0-9_]+)_(\d+)\]\]/g)) counts.set(match[1], Math.max(counts.get(match[1]) || 0, Number(match[2])));
  for (const definition of policyDefinitions(policy)) {
    let count = 0;
    if (definition.tokenize === false) count = matchesFor(tokenized, definition).length;
    else tokenized = replaceWith(tokenized, definition, (value) => { count++; const key = definition.type.toUpperCase().replace(/[^A-Z0-9]+/g, "_"); const number = (counts.get(key) || 0) + 1; counts.set(key, number); const token = `[[${key}_${number}]]`; mapping[token] = value; return token; });
    if (count) findings.push({ category: definition.category, type: definition.type, count, action: definition.tokenize === false ? "retained_warning" : "tokenized" });
  }
  return { tokenized, mapping, findings };
}
