const $ = id => document.getElementById(id);
let mode = "up";   // "up" = sign up, "in" = log in

async function api(path, body) {
  try {
    const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, ...data } : { ok: false, error: data.error || "Something went wrong" };
  } catch {
    return { ok: false, error: "Can’t reach the server" };
  }
}

// Already logged in? Skip the form.
fetch("/api/me").then(r => { if (r.ok) location.replace("chat.html"); });

function setMode(m) {
  mode = m;
  $("tabUp").classList.toggle("on", m === "up");
  $("tabIn").classList.toggle("on", m === "in");
  $("go").textContent = m === "up" ? "Create account" : "Log in";
  $("pass").autocomplete = m === "up" ? "new-password" : "current-password";
  $("msg").textContent = "";
}
$("tabUp").onclick = () => setMode("up");
$("tabIn").onclick = () => setMode("in");

async function submit() {
  $("go").disabled = true;
  $("msg").textContent = "";
  const result = await api(mode === "up" ? "/api/register" : "/api/login", { name: $("name").value, password: $("pass").value });
  if (result.ok) location.href = "chat.html";
  else { $("msg").textContent = result.error; $("go").disabled = false; }
}
$("go").onclick = submit;
["name", "pass"].forEach(id => $(id).addEventListener("keydown", e => { if (e.key === "Enter") submit(); }));