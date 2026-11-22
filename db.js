// db.js — all storage lives here (SQLite, built into Node 22.13+)
import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes } from "node:crypto";

export const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const ZERO = "0".repeat(64);
const sha256 = s => createHash("sha256").update(s).digest("hex");

export const db = new DatabaseSync(process.env.DB_PATH || "chat.db");
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    name_lc TEXT NOT NULL UNIQUE,
    skeleton TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    created INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    text TEXT NOT NULL,
    ts INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS chain (
    idx INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
  );
`);

function tx(fn) {
  db.exec("BEGIN IMMEDIATE");
  try { const r = fn(); db.exec("COMMIT"); return r; }
  catch (e) { db.exec("ROLLBACK"); throw e; }
}

/* ---------- hash-chained audit ledger (no passwords in here, only who registered and when) ---------- */
const blockHash = (idx, ts, type, data, prev) => sha256(JSON.stringify([idx, ts, type, data, prev]));

function appendBlock(type, obj) {
  const last = db.prepare("SELECT idx, hash FROM chain ORDER BY idx DESC LIMIT 1").get();
  const idx = last ? last.idx + 1 : 0, prev = last ? last.hash : ZERO, ts = Date.now(), data = JSON.stringify(obj);
  db.prepare("INSERT INTO chain (idx, ts, type, data, prev_hash, hash) VALUES (?,?,?,?,?,?)")
    .run(idx, ts, type, data, prev, blockHash(idx, ts, type, data, prev));
}

export function verifyChain() {
  const rows = db.prepare("SELECT * FROM chain ORDER BY idx").all();
  for (let i = 0; i < rows.length; i++) {
    const b = rows[i];
    if (b.idx !== i || b.prev_hash !== (i ? rows[i - 1].hash : ZERO)) return { ok: false, badIndex: i };
    if (blockHash(b.idx, b.ts, b.type, b.data, b.prev_hash) !== b.hash) return { ok: false, badIndex: i };
  }
  return { ok: true, blocks: rows.length };
}

if (!db.prepare("SELECT 1 FROM chain LIMIT 1").get()) appendBlock("genesis", {});

/* ---------- users ---------- */
export const allSkeletons = () => db.prepare("SELECT skeleton FROM users").all().map(r => r.skeleton);
export const getUser = nameLc => db.prepare("SELECT * FROM users WHERE name_lc = ?").get(nameLc);

export function createUser({ name, skeleton, pwHash }) {
  return tx(() => {
    const r = db.prepare("INSERT INTO users (name, name_lc, skeleton, pw_hash, created) VALUES (?,?,?,?,?)")
      .run(name, name.toLowerCase(), skeleton, pwHash, Date.now());
    const id = Number(r.lastInsertRowid);
    appendBlock("register", { userId: id, name, skeleton });
    return id;
  });
}

/* ---------- sessions (only a hash of the token is stored) ---------- */
export function createSession(userId) {
  const token = randomBytes(32).toString("base64url");
  db.prepare("INSERT INTO sessions (token_hash, user_id, expires) VALUES (?,?,?)").run(sha256(token), userId, Date.now() + SESSION_MS);
  return token;
}
export function sessionUser(token) {
  if (!token) return null;
  return db.prepare(`SELECT u.id, u.name, s.token_hash FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token_hash = ? AND s.expires > ?`).get(sha256(token), Date.now()) || null;
}
export const deleteSession = token => db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sha256(token));
export const purgeSessions = () => db.prepare("DELETE FROM sessions WHERE expires <= ?").run(Date.now());

/* ---------- messages ---------- */
export function addMessage(userId, text) {
  const ts = Date.now();
  const r = db.prepare("INSERT INTO messages (user_id, text, ts) VALUES (?,?,?)").run(userId, text, ts);
  return { id: Number(r.lastInsertRowid), ts };
}
export const recentMessages = (n = 100) =>
  db.prepare(`SELECT m.id, u.name AS user, m.text, m.ts FROM messages m JOIN users u ON u.id = m.user_id
              ORDER BY m.id DESC LIMIT ?`).all(n).reverse();