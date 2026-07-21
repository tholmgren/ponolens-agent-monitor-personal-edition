import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

function securelyEqual(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function bearerToken(request) {
  return String(request.headers.authorization || "").match(/^Bearer\s+([^\s]+)$/i)?.[1] || "";
}

export function cookieValue(request, name) {
  for (const part of String(request.headers.cookie || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0 && part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return "";
}

export class LocalDashboardAuth {
  constructor(tokenPath, { ttlMs = 12 * 60 * 60 * 1000, maxSessions = 32 } = {}) {
    this.ttlMs = ttlMs;
    this.maxSessions = maxSessions;
    this.sessions = new Map();
    mkdirSync(dirname(tokenPath), { recursive: true, mode: 0o700 });
    try { this.installToken = readFileSync(tokenPath, "utf8").trim(); } catch { this.installToken = ""; }
    if (this.installToken.length < 40) {
      this.installToken = randomBytes(32).toString("base64url");
      writeFileSync(tokenPath, `${this.installToken}\n`, { mode: 0o600 });
    }
    chmodSync(tokenPath, 0o600);
  }

  createSession(token, now = Date.now()) {
    if (!securelyEqual(token, this.installToken)) return null;
    this.sweep(now);
    while (this.sessions.size >= this.maxSessions) this.sessions.delete(this.sessions.keys().next().value);
    const session = { id: randomBytes(32).toString("base64url"), expiresAt: now + this.ttlMs };
    this.sessions.set(session.id, session.expiresAt);
    return session;
  }

  hasSession(id, now = Date.now()) {
    this.sweep(now);
    return (this.sessions.get(String(id || "")) || 0) > now;
  }

  sweep(now = Date.now()) {
    for (const [id, expiry] of this.sessions) if (expiry <= now) this.sessions.delete(id);
  }

  cookie(session) {
    const maxAge = Math.max(1, Math.floor((session.expiresAt - Date.now()) / 1000));
    return `ponolens_session=${session.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
  }

  accessUrl(baseUrl) { return `${baseUrl}/#access=${this.installToken}`; }
}
