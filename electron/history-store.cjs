const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

function createHistoryStore(rootDir) {
  const dir = path.join(rootDir, "history");
  const legacyFile = path.join(dir, "runs.json");
  const databaseFile = path.join(dir, "ducktest.sqlite");
  fs.mkdirSync(dir, { recursive: true });
  const database = new DatabaseSync(databaseFile);
  database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS runs (
      id TEXT PRIMARY KEY,
      saved_at TEXT NOT NULL,
      type TEXT,
      target TEXT,
      summary_json TEXT NOT NULL,
      payload_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_runs_saved_at ON runs(saved_at DESC);
    CREATE TABLE IF NOT EXISTS app_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      level TEXT NOT NULL,
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT,
      message TEXT NOT NULL,
      detail_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_logs_created_at ON app_logs(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_logs_category ON app_logs(category, created_at DESC);
  `);
  const parseJson = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };
  const rowToRun = (row) => parseJson(row?.payload_json, null);
  const store = {
    save(record) {
      const item = { id: record.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, savedAt: new Date().toISOString(), ...record };
      database.prepare(`INSERT OR REPLACE INTO runs (id, saved_at, type, target, summary_json, payload_json) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(item.id, item.savedAt, item.type || "", item.target || "", JSON.stringify(item.summary || {}), JSON.stringify(item));
      database.prepare(`DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY saved_at DESC LIMIT 200)`).run();
      return item;
    },
    list(limit = 50) {
      const safeLimit = Math.max(1, Math.min(200, Number(limit) || 50));
      return database.prepare(`SELECT payload_json FROM runs ORDER BY saved_at DESC LIMIT ?`).all(safeLimit).map(rowToRun).filter(Boolean);
    },
    get(id) { return rowToRun(database.prepare(`SELECT payload_json FROM runs WHERE id = ?`).get(String(id || ""))); },
    clear() { database.exec("DELETE FROM runs"); return true; },
    log(entry = {}) {
      const item = {
        createdAt: entry.createdAt || new Date().toISOString(),
        level: ["INFO", "WARN", "ERROR"].includes(entry.level) ? entry.level : "INFO",
        category: String(entry.category || "system").slice(0, 60),
        action: String(entry.action || "event").slice(0, 80),
        target: String(entry.target || "").slice(0, 500),
        message: String(entry.message || "已記錄事件").slice(0, 2000),
        detail: entry.detail || {},
      };
      const result = database.prepare(`INSERT INTO app_logs (created_at, level, category, action, target, message, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(item.createdAt, item.level, item.category, item.action, item.target, item.message, JSON.stringify(item.detail));
      database.prepare(`DELETE FROM app_logs WHERE id NOT IN (SELECT id FROM app_logs ORDER BY id DESC LIMIT 10000)`).run();
      return { id: Number(result.lastInsertRowid), ...item };
    },
    logs(options = {}) {
      const conditions = [];
      const values = [];
      if (["INFO", "WARN", "ERROR"].includes(options.level)) { conditions.push("level = ?"); values.push(options.level); }
      if (options.category) { conditions.push("category = ?"); values.push(String(options.category).slice(0, 60)); }
      if (options.search) { conditions.push("(message LIKE ? OR target LIKE ? OR action LIKE ?)"); const value = `%${String(options.search).slice(0, 100)}%`; values.push(value, value, value); }
      const limit = Math.max(1, Math.min(1000, Number(options.limit) || 200));
      const rows = database.prepare(`SELECT * FROM app_logs ${conditions.length ? `WHERE ${conditions.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ?`).all(...values, limit);
      return rows.map((row) => ({ id: row.id, createdAt: row.created_at, level: row.level, category: row.category, action: row.action, target: row.target, message: row.message, detail: parseJson(row.detail_json, {}) }));
    },
    clearLogs() { database.exec("DELETE FROM app_logs"); return true; },
    databaseInfo() {
      return { path: databaseFile, runCount: Number(database.prepare("SELECT COUNT(*) count FROM runs").get().count), logCount: Number(database.prepare("SELECT COUNT(*) count FROM app_logs").get().count) };
    },
    close() { database.close(); },
  };
  if (database.prepare("SELECT COUNT(*) count FROM runs").get().count === 0 && fs.existsSync(legacyFile)) {
    const legacy = parseJson(fs.readFileSync(legacyFile, "utf8"), []);
    if (Array.isArray(legacy)) legacy.slice(0, 200).reverse().forEach((record) => store.save(record));
    store.log({ category: "database", action: "migration", message: `已將 ${legacy.length} 筆舊版 JSON 歷史搬移至 SQLite。` });
  }
  return store;
}

function compareRuns(left, right) {
  const metric = (label, a, b, unit = "") => ({ label, before: Number(a) || 0, after: Number(b) || 0, delta: Number(((Number(b) || 0) - (Number(a) || 0)).toFixed(2)), unit });
  const a = left?.summary || left || {};
  const b = right?.summary || right || {};
  return {
    target: right?.target || left?.target || "",
    metrics: [
      metric("Requests / second", a.requestsPerSecond, b.requestsPerSecond, "req/s"),
      metric("P95 latency", left?.latencyMs?.p95, right?.latencyMs?.p95, "ms"),
      metric("Failure rate", a.failureRate, b.failureRate, "%"),
      metric("Completed requests", a.completed, b.completed, "req"),
      metric("Availability", a.availability, b.availability, "%"),
    ],
  };
}

module.exports = { createHistoryStore, compareRuns };
