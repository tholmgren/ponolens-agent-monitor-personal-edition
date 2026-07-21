import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export class EventStore {
  constructor(path) {
    const directory = dirname(path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    restrictPermissions(directory, 0o700);
    this.db = new DatabaseSync(path);
    const version = Number(this.db.prepare("PRAGMA user_version").get().user_version || 0);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        harness TEXT NOT NULL,
        action TEXT NOT NULL,
        source TEXT,
        destination TEXT,
        destination_trust TEXT,
        summary TEXT NOT NULL,
        severity TEXT NOT NULL,
        score INTEGER NOT NULL,
        decision TEXT NOT NULL,
        explanation TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        details_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    if (version < 1) this.db.exec("PRAGMA user_version = 1");
    restrictPermissions(path, 0o600);
    restrictPermissions(`${path}-wal`, 0o600);
    restrictPermissions(`${path}-shm`, 0o600);
    this.insert = this.db.prepare(`
      INSERT INTO events (
        created_at, harness, action, source, destination, destination_trust,
        summary, severity, score, decision, explanation, recommendation, details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
  }

  add(event, analysis) {
    const result = this.insert.run(
      event.createdAt ?? new Date().toISOString(),
      event.harness,
      event.action,
      event.source ?? null,
      event.destination ?? null,
      event.destinationTrust ?? "unknown",
      analysis.headline,
      analysis.severity,
      analysis.score,
      analysis.decision,
      analysis.explanation,
      analysis.recommendation,
      JSON.stringify({ ...event, analysis })
    );
    return this.get(Number(result.lastInsertRowid));
  }

  get(id) {
    const row = this.db.prepare("SELECT * FROM events WHERE id = ?").get(id);
    return row ? normalize(row) : null;
  }

  deleteSynthetic(id) {
    const event = this.get(id);
    if (!event || event.details?.details?.synthetic !== true) return false;
    return Number(this.db.prepare("DELETE FROM events WHERE id = ?").run(id).changes || 0) === 1;
  }

  list(limit = 100, offset = 0) {
    return this.db.prepare("SELECT * FROM events ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?").all(limit, offset).map(normalize);
  }

  listFiltered({ filter = "all", harnessTerms = [], search = "", from = "", to = "", limit = 100, offset = 0 } = {}) {
    const protectedData = `(details_json LIKE '%"secrets":[{%' OR details_json LIKE '%"personal":[{%' OR details_json LIKE '%"regulated":[{%' OR details_json LIKE '%"custom":[{%')`;
    const conditions = [];
    const parameters = [];
    if (harnessTerms.length) {
      conditions.push(`(${harnessTerms.map(() => "LOWER(harness) LIKE ?").join(" OR ")})`);
      parameters.push(...harnessTerms.map((term) => `%${String(term).toLowerCase()}%`));
    }
    if (filter === "protected") conditions.push(protectedData);
    else if (filter === "risks") conditions.push("severity IN ('critical', 'high')");
    else if (filter === "blocked") conditions.push("decision = 'blocked'");
    else if (filter === "review") conditions.push(`(decision = 'approval_required' OR (destination IS NOT NULL AND decision <> 'blocked' AND ${protectedData}))`);
    else if (filter === "prompts") conditions.push("action = 'prompt'");
    else if (filter === "commands") conditions.push("action IN ('command', 'network') AND details_json LIKE '%\"command\":%'");
    if (from) { conditions.push("created_at >= ?"); parameters.push(from); }
    if (to) { conditions.push("created_at <= ?"); parameters.push(to); }
    if (search) {
      const term = `%${String(search).toLowerCase()}%`;
      conditions.push("(LOWER(summary) LIKE ? OR LOWER(explanation) LIKE ? OR LOWER(harness) LIKE ? OR LOWER(COALESCE(source,'')) LIKE ? OR LOWER(COALESCE(destination,'')) LIKE ?)");
      parameters.push(term, term, term, term, term);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const total = Number(this.db.prepare(`SELECT COUNT(*) AS total FROM events ${where}`).get(...parameters).total || 0);
    const events = this.db.prepare(`SELECT * FROM events ${where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`).all(...parameters, limit, offset).map(normalize);
    return { events, total };
  }

  count() {
    return Number(this.db.prepare("SELECT COUNT(*) AS total FROM events").get().total || 0);
  }

  latestForHarness(matchTerms = []) {
    if (!matchTerms.length) return null;
    const where = matchTerms.map(() => "LOWER(harness) LIKE ?").join(" OR ");
    const row = this.db.prepare(`SELECT * FROM events WHERE ${where} ORDER BY created_at DESC, id DESC LIMIT 1`).get(...matchTerms.map((term) => `%${String(term).toLowerCase()}%`));
    return row ? normalize(row) : null;
  }

  pruneOlderThan(days) {
    const cutoff = new Date(Date.now() - Number(days) * 86400000).toISOString();
    return Number(this.db.prepare("DELETE FROM events WHERE created_at < ?").run(cutoff).changes || 0);
  }

  stats() {
    const totals = this.db.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN decision = 'blocked' THEN 1 ELSE 0 END) AS blocked,
        SUM(CASE WHEN decision = 'approval_required' THEN 1 ELSE 0 END) AS approvals,
        SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS risks
      FROM events
    `).get();
    return Object.fromEntries(Object.entries(totals).map(([key, value]) => [key, Number(value ?? 0)]));
  }

  getSetting(key, fallback = null) {
    const row = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
    if (!row) return fallback;
    try { return JSON.parse(row.value); } catch { return fallback; }
  }

  setSetting(key, value) {
    this.db.prepare(`
      INSERT INTO settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(key, JSON.stringify(value));
    return value;
  }

  clear() {
    this.db.exec("DELETE FROM events");
  }

  clearAll() {
    this.db.exec("BEGIN IMMEDIATE; DELETE FROM events; DELETE FROM settings; COMMIT;");
  }

  integrityCheck() {
    return this.db.prepare("PRAGMA quick_check").all().every((row) => Object.values(row).includes("ok"));
  }

  reanalyze(analyzer, policy) {
    const rows = this.db.prepare("SELECT id, details_json FROM events").all();
    const update = this.db.prepare(`
      UPDATE events SET summary = ?, severity = ?, score = ?, decision = ?, explanation = ?, recommendation = ?, details_json = ?
      WHERE id = ?
    `);
    for (const row of rows) {
      const details = JSON.parse(row.details_json);
      const analysis = analyzer(details, policy);
      update.run(
        analysis.headline,
        analysis.severity,
        analysis.score,
        analysis.decision,
        analysis.explanation,
        analysis.recommendation,
        JSON.stringify({ ...details, analysis }),
        row.id,
      );
    }
  }

  correctLocalClassifications() {
    const rows = this.db.prepare("SELECT id, details_json FROM events WHERE destination IS NULL").all();
    const update = this.db.prepare(`
      UPDATE events SET summary = ?, severity = 'low', score = 0, decision = 'allowed', explanation = ?, recommendation = ?, details_json = ?
      WHERE id = ?
    `);
    for (const row of rows) {
      const details = JSON.parse(row.details_json);
      const findings = details.analysis?.findings || {};
      const hasProtectedData = ["secrets", "personal", "regulated", "custom"].some((name) => findings[name]?.length);
      const analysis = {
        ...details.analysis,
        score: 0,
        severity: "low",
        decision: "allowed",
        headline: "Activity looks normal",
        explanation: hasProtectedData
          ? "Protected information was present in this local action, but PonoLens observed no external destination."
          : "PonoLens found no unusual data movement.",
        recommendation: "No action is required. This action stayed on your device.",
      };
      update.run(analysis.headline, analysis.explanation, analysis.recommendation, JSON.stringify({ ...details, analysis }), row.id);
    }
  }

  migrateUnredactedOutboundPrompts(analyze, redact, policy) {
    const rows = this.db.prepare("SELECT id, details_json FROM events WHERE destination IS NOT NULL").all();
    const update = this.db.prepare(`
      UPDATE events SET summary = ?, severity = ?, score = ?, decision = ?, explanation = ?, recommendation = ?, details_json = ?
      WHERE id = ?
    `);
    let migrated = 0;
    for (const row of rows) {
      const details = JSON.parse(row.details_json);
      if (details.action !== "prompt" || typeof details.content !== "string") continue;
      const redactedContent = redact(details.content, policy);
      if (redactedContent === details.content) continue;
      const fresh = analyze(details, policy);
      const previous = details.analysis || {};
      const findings = {};
      for (const key of ["secrets", "personal", "regulated", "custom"]) {
        const merged = new Map();
        for (const finding of [...(previous.findings?.[key] || []), ...(fresh.findings?.[key] || [])]) {
          const existing = merged.get(finding.type) || {};
          merged.set(finding.type, { ...existing, ...finding, count: Math.max(Number(existing.count || 0), Number(finding.count || 0)) });
        }
        findings[key] = [...merged.values()];
      }
      Object.assign(findings, {
        sensitiveFiles: fresh.findings?.sensitiveFiles || previous.findings?.sensitiveFiles || [],
        includesGitHistory: fresh.findings?.includesGitHistory || previous.findings?.includesGitHistory || false,
        percentOfRepo: fresh.findings?.percentOfRepo || previous.findings?.percentOfRepo || 0,
      });
      const analysis = { ...fresh, ...previous, findings };
      const safeDetails = { ...details, content: redactedContent, analysis };
      update.run(analysis.headline, analysis.severity, analysis.score, analysis.decision, analysis.explanation, analysis.recommendation, JSON.stringify(safeDetails), row.id);
      migrated += 1;
    }
    return migrated;
  }
}

function restrictPermissions(path, mode) {
  if (process.platform === "win32" || !existsSync(path)) return;
  chmodSync(path, mode);
}

function normalize(row) {
  return {
    id: row.id,
    createdAt: row.created_at,
    harness: row.harness,
    action: row.action,
    source: row.source,
    destination: row.destination,
    destinationTrust: row.destination_trust,
    summary: row.summary,
    severity: row.severity,
    score: row.score,
    decision: row.decision,
    explanation: row.explanation,
    recommendation: row.recommendation,
    details: JSON.parse(row.details_json),
  };
}
