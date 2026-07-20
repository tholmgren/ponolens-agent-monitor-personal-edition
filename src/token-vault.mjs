export class TokenVault {
  constructor({ maxEntries = 100, maxBytes = 8 * 1024 * 1024, sweepIntervalMs = 60_000 } = {}) {
    this.entries = new Map();
    this.maxEntries = maxEntries;
    this.maxBytes = maxBytes;
    this.totalBytes = 0;
    this.timer = setInterval(() => this.sweep(), sweepIntervalMs);
    this.timer.unref?.();
  }

  set(id, value) {
    this.sweep();
    const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
    if (bytes > this.maxBytes) throw Object.assign(new Error("Safe Prompt token vault is too large"), { statusCode: 413 });
    while (this.entries.size >= this.maxEntries || (this.entries.size && this.totalBytes + bytes > this.maxBytes)) this.delete(this.entries.keys().next().value);
    this.entries.set(id, { value, bytes });
    this.totalBytes += bytes;
    return this;
  }

  get(id) {
    const entry = this.entries.get(id);
    if (!entry) return undefined;
    if (entry.value.expiresAt < Date.now()) { this.delete(id); return undefined; }
    return entry.value;
  }

  delete(id) {
    const entry = this.entries.get(id);
    if (!entry) return false;
    this.totalBytes -= entry.bytes;
    this.entries.delete(id);
    return true;
  }

  sweep(now = Date.now()) {
    for (const [id, entry] of this.entries) if (entry.value.expiresAt < now) this.delete(id);
  }

  clear() {
    this.entries.clear();
    this.totalBytes = 0;
  }

  get size() { return this.entries.size; }
}
