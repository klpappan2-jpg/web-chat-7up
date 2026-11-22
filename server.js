// server.js — web server: pages, signup/login/logout, security headers
import express from "express";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as store from "./db.js";
import { hashPassword, verifyPassword, checkName, skeleton } from "./security.js";
import { attachRealtime, COOKIE, parseCookies } from "./realtime.js";

const PROD = process.env.NODE_ENV === "production";
const PORT = process.env.PORT || 3000;
const here = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const server = createServer(app);
const wss = attachRealtime(server);

if (PROD) app.set("trust proxy", 1);   // hosting platforms sit behind a proxy; needed for correct client IPs
app.disable("x-powered-by");

/* ---------- security headers ---------- */
app.use((req, res, next) => {
  const host = /^[a-z0-9.-]+(:\d+)?$/i.test(req.headers.host || "") ? req.headers.host : "";
  res.set({
    "Content-Security-Policy":
          `default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' ws://${host} wss://${host}; ` +
      `frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...(PROD && { "Strict-Transport-Security": "max-age=31536000" })
  });
  next();
});
app.use(express.json({ limit: "2kb" }));

/* ---------- helpers ---------- */
function limiter(max, windowMs) {
  const hits = new Map();
  setInterval(() => hits.clear(), windowMs).unref();
  return (req, res, next) => {
    const n = (hits.get(req.ip) || 0) + 1;
    hits.set(req.ip, n);
    if (n > max) return res.status(429).json({ error: "Too many attempts. Try again in a minute." });
    next();
  };
}
const authLimit = limiter(10, 60_000);

const cookieOpts = { httpOnly: true, sameSite: "strict", secure: PROD, path: "/" };
const startSession = (res, userId) => res.cookie(COOKIE, store.createSession(userId), { ...cookieOpts, maxAge: store.SESSION_MS });

function requireLogin(req, res, next) {
  const user = store.sessionUser(parseCookies(req.headers.cookie)[COOKIE]);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  req.user = user;
  next();
}

/* ---------- API ---------- */
app.post("/api/register", authLimit, async (req, res) => {
  const { name, password } = req.body ?? {};
  if (typeof name !== "string" || typeof password !== "string") return res.status(400).json({ error: "Name and password are required" });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: "Password must be 8–128 characters" });

  const clean = name.trim();
  const early = checkName(clean, store.allSkeletons());
  if (early) return res.status(400).json({ error: early });

  const pwHash = await hashPassword(password);

  // Check again right before saving: someone else may have signed up while we were hashing.
  // There is no "await" between this check and the insert, so no one can slip in between.
  const late = checkName(clean, store.allSkeletons());
  if (late) return res.status(409).json({ error: late });

  let id;
  try { id = store.createUser({ name: clean, skeleton: skeleton(clean), pwHash }); }
  catch { return res.status(409).json({ error: "That name is taken or too similar to an existing one" }); }

  startSession(res, id);
  res.json({ ok: true, name: clean });
});

app.post("/api/login", authLimit, async (req, res) => {
  const { name, password } = req.body ?? {};
  if (typeof name !== "string" || typeof password !== "string" || password.length > 128)
    return res.status(400).json({ error: "Name and password are required" });

  const user = store.getUser(name.trim().toLowerCase());
  const ok = await verifyPassword(password, user?.pw_hash);   // runs even for unknown names (same timing)
  if (!user || !ok) return res.status(401).json({ error: "Wrong name or password" });

  startSession(res, user.id);
  res.json({ ok: true, name: user.name });
});

app.post("/api/logout", (req, res) => {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  const user = store.sessionUser(token);
  if (user) {
    store.deleteSession(token);
    for (const ws of wss.clients) if (ws.tokenHash === user.token_hash) ws.close(1000, "logged out");
  }
  res.clearCookie(COOKIE, cookieOpts);
  res.json({ ok: true });
});

app.get("/api/me", requireLogin, (req, res) => res.json({ name: req.user.name }));

/* ---------- pages ---------- */
app.get("/", (req, res) => res.redirect("/login.html"));
app.use(express.static(path.join(here, "public")));
app.use((err, req, res, next) => res.status(err.status || 500).json({ error: "Bad request" }));

/* ---------- start ---------- */
const v = store.verifyChain();
console.log(v.ok ? `User ledger OK (${v.blocks} blocks)` : `WARNING: user ledger was tampered with at block ${v.badIndex}`);
setInterval(() => store.purgeSessions(), 60 * 60 * 1000).unref();
server.listen(PORT, () => console.log(`Chat running at http://localhost:${PORT}`));