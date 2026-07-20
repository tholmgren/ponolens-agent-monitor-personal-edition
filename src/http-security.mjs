export const MAX_JSON_BODY_BYTES = 1024 * 1024;
import { isAbsolute, relative, sep } from "node:path";
export const SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
});

export async function readJsonBody(request, limit = MAX_JSON_BODY_BYTES) {
  const declared = Number(request.headers?.["content-length"] || 0);
  if (Number.isFinite(declared) && declared > limit) throw httpError(413, "Request body is too large");
  const chunks = [];
  let received = 0;
  for await (const chunk of request) {
    received += chunk.length;
    if (received > limit) throw httpError(413, "Request body is too large");
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); }
  catch { throw httpError(400, "Request body must be valid JSON"); }
}

function httpError(statusCode, message) { return Object.assign(new Error(message), { statusCode }); }

export function isPathInside(root, candidate) {
  const value = relative(root, candidate);
  return Boolean(value) && !isAbsolute(value) && value !== ".." && !value.startsWith(`..${sep}`) && !value.split(sep).some((part) => part.startsWith("."));
}
