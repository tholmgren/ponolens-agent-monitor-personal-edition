import { PRODUCT_DEFAULTS, PROTECTION_CATEGORIES, PROTECTION_CATEGORY_IDS } from "../public/product-config.js";
import { isSafeCustomRegexSource } from "../public/detectors.js";

export const DEFAULT_POLICY = Object.freeze({
  presets: Object.fromEntries(PROTECTION_CATEGORIES.filter((category) => category.preset !== false).map((category) => [category.id, category.defaultEnabled])),
  customValues: [],
  trustedDestinations: [...PRODUCT_DEFAULTS.trustedDestinations],
  thresholds: { ...PRODUCT_DEFAULTS.thresholds },
  categoryActions: {},
  dictionaries: [],
  regexRules: [],
  commandMonitoring: false,
  mode: "observe",
});

export function normalizePolicy(input = {}) {
  const customValues = Array.isArray(input.customValues)
    ? input.customValues
      .map((item) => ({ label: String(item?.label ?? "").trim().slice(0, 80), value: String(item?.value ?? "").trim().slice(0, 500) }))
      .filter((item) => item.value)
      .slice(0, 100)
    : [];
  return {
    presets: {
      ...DEFAULT_POLICY.presets,
      ...(input.presets ?? {}),
    },
    customValues,
    trustedDestinations: [...new Set((Array.isArray(input.trustedDestinations) ? input.trustedDestinations : DEFAULT_POLICY.trustedDestinations).map((value) => String(value).trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "")).filter(Boolean))].slice(0, 100),
    thresholds: {
      ...Object.fromEntries(Object.entries(PRODUCT_DEFAULTS.thresholds).map(([key, fallback]) => {
        const bounds = PRODUCT_DEFAULTS.thresholdBounds[key];
        return [key, bounded(input.thresholds?.[key], bounds.min, bounds.max, fallback)];
      })),
    },
    categoryActions: Object.fromEntries(PROTECTION_CATEGORY_IDS.map((category) => [category, ["warn", "redact", "block"].includes(input.categoryActions?.[category]) ? input.categoryActions[category] : ""]).filter(([, value]) => value)),
    dictionaries: (Array.isArray(input.dictionaries) ? input.dictionaries : []).slice(0, 50).map((item) => ({ label: String(item?.label || "Dictionary").slice(0, 80), category: allowedCategory(item?.category), values: [...new Set((Array.isArray(item?.values) ? item.values : String(item?.values || "").split(/\r?\n/)).map((value) => String(value).trim()).filter(Boolean))].slice(0, 500) })),
    regexRules: (Array.isArray(input.regexRules) ? input.regexRules : []).slice(0, 50).map((item) => ({ label: String(item?.label || "Custom rule").slice(0, 80), category: allowedCategory(item?.category), pattern: String(item?.pattern || "").slice(0, 200), flags: String(item?.flags || "gi").replace(/[^gimsuy]/g, "").slice(0, 6) })).filter((item) => item.pattern && safePattern(item.pattern)),
    commandMonitoring: input.commandMonitoring === true,
    mode: ["observe", "redact", "block_critical"].includes(input.mode) ? input.mode : DEFAULT_POLICY.mode,
  };
}

function bounded(value, min, max, fallback) { const number = Math.round(Number(value)); return Number.isFinite(number) ? Math.max(min, Math.min(max, number)) : fallback; }
function allowedCategory(value) { return PROTECTION_CATEGORY_IDS.includes(value) ? value : "custom"; }
function safePattern(source) { return isSafeCustomRegexSource(source); }
