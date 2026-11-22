// realtime.js — WebSocket chat: login check, origin check, broadcasting
import { WebSocketServer } from "ws";
import * as store from "./db.js";

export const COOKIE = "sid";
export const parseCookies = header => Object.fromEntries(
  (header || "").split(";").map(p => p.trim().split("=")).filter(p => p[0]).map(([k, ...v]) => [k, v.join("=")])
);

const MAX_LEN = 500;     // characters per message
const MIN_GAP_MS = 500;  // anti-spam: one message per half second per connection

export function attachRealtime(server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 4096 });

  const send = (ws, obj) => { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); };
  const broadcast = obj => wss.clients.forEach(ws => send(ws, obj));
  const online = () => [...new Set([...wss.clients].map(ws => ws.user.name))];

  // Every socket must come from a logged-in user AND from a page served by this same site.
  server.on("upgrade", (req, socket, head) => {
    const reject = (code, text) => { socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
    if (req.url !== "/ws") return reject(404, "Not Found");

    let originHost = "";
    try { originHost = new URL(req.headers.origin).host; } catch {}
    if (originHost !== req.headers.host) return reject(403, "Forbidden");   // blocks cross-site WebSocket hijacking

    const user = store.sessionUser(parseCookies(req.headers.cookie)[COOKIE]);
    if (!user) return reject(401, "Unauthorized");

    wss.handleUpgrade(req, socket, head, ws => {
      ws.user = user;
      ws.tokenHash = user.token_hash;
      wss.emit("connection", ws, req);
    });
  });

  wss.on("connection", ws => {
    ws.isAlive = true;
    ws.lastMsg = 0;
    ws.on("pong", () => { ws.isAlive = true; });
    ws.on("error", () => {});

    send(ws, { type: "history", messages: store.recentMessages(100) });
    broadcast({ type: "presence", online: online() });

    ws.on("message", raw => {
      let data;
      try { data = JSON.parse(raw.toString()); } catch { return; }
      if (data?.type !== "msg" || typeof data.text !== "string") return;

      const text = data.text.trim();
      if (!text || text.length > MAX_LEN) return;

      const now = Date.now();
      if (now - ws.lastMsg < MIN_GAP_MS) return send(ws, { type: "error", error: "You’re sending too fast" });
      ws.lastMsg = now;

      const { id, ts } = store.addMessage(ws.user.id, text);
      // The sender's name comes from the session, never from anything the client sends.
      broadcast({ type: "msg", id, user: ws.user.name, text, ts });
    });

    ws.on("close", () => broadcast({ type: "presence", online: online() }));
  });

  // Drop dead connections every 30 seconds
  setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      ws.ping();
    }
  }, 30_000).unref();

  return wss;
}