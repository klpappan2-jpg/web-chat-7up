const $ = id => document.getElementById(id);
const MAX_SHOWN = 200;
let me = "", ws = null, messages = [];

const hue = s => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };

function setStatus(text) {
  $("status").style.display = text ? "block" : "none";
  $("status").textContent = text;
}

function renderMembers(names) {
  const box = $("members");
  box.textContent = "";
  names.forEach(n => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = n;                                   // textContent = no HTML injection
    chip.style.background = `hsl(${hue(n)} 55% 42%)`;
    box.appendChild(chip);
  });
}

function renderMsgs() {
  const box = $("msgs");
  box.textContent = "";
  if (messages.length === 0) {
    const e = document.createElement("div");
    e.className = "empty";
    e.textContent = "No messages yet. Say hello!";
    box.appendChild(e);
    return;
  }
  messages.forEach(m => {
    const bubble = document.createElement("div");
    bubble.className = "m" + (m.user === me ? " me" : "");
    if (m.user !== me) {
      const who = document.createElement("div");
      who.className = "who";
      who.textContent = m.user;
      bubble.appendChild(who);
    }
    const body = document.createElement("div");
    body.textContent = m.text;
    const time = document.createElement("div");
    time.className = "time";
    time.textContent = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    bubble.append(body, time);
    box.appendChild(bubble);
  });
  box.scrollTop = box.scrollHeight;
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => setStatus("");
  ws.onmessage = e => {
    let d; try { d = JSON.parse(e.data); } catch { return; }
    if (d.type === "history") { messages = d.messages; renderMsgs(); }
    else if (d.type === "msg") { messages.push(d); if (messages.length > MAX_SHOWN) messages.shift(); renderMsgs(); }
    else if (d.type === "presence") renderMembers(d.online);
    else if (d.type === "error") setStatus(d.error);
  };
  ws.onclose = async () => {
    setStatus("Disconnected. Reconnecting…");
    await new Promise(r => setTimeout(r, 2000));
    const r = await fetch("/api/me").catch(() => null);
    if (r && r.status === 401) return location.replace("login.html");   // session ended
    connect();
  };
}

$("form").addEventListener("submit", e => {
  e.preventDefault();
  const text = $("text").value.trim();
  if (!text || !ws || ws.readyState !== 1) return;
  ws.send(JSON.stringify({ type: "msg", text }));            // server adds the sender name and time
  $("text").value = "";
});

$("logout").onclick = async () => {
  if (ws) ws.onclose = null;
  await fetch("/api/logout", { method: "POST" }).catch(() => {});
  location.href = "login.html";
};

(async function init() {
  const r = await fetch("/api/me").catch(() => null);
  if (!r || !r.ok) return location.replace("login.html");
  me = (await r.json()).name;
  $("who").textContent = me;
  connect();
  $("text").focus();
})();