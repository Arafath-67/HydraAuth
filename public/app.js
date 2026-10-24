// app.js
// Access token kept only in memory -- never localStorage/sessionStorage,
// so a successful XSS can't trivially read it off disk.
let accessToken = null;

const logEl = document.getElementById("log");

function logEntry(method, path, status, body) {
  const entry = document.createElement("div");
  entry.className = "entry " + (status >= 200 && status < 300 ? "ok" : "err");

  const head = document.createElement("div");
  head.className = "entry-head";
  head.innerHTML =
    '<span class="method">' + method + '</span>' +
    '<span class="path">' + path + '</span>' +
    '<span class="status">' + status + '</span>' +
    '<span class="time">' + new Date().toLocaleTimeString() + '</span>';

  const pre = document.createElement("pre");
  pre.textContent = typeof body === "string" ? body : JSON.stringify(body, null, 2);

  entry.appendChild(head);
  entry.appendChild(pre);
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
}

function getCookie(name) {
  const m = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return m ? m[2] : null;
}

async function call(method, path, opts) {
  const r = await fetch(path, { method, ...opts });
  let data;
  try { data = await r.json(); } catch { data = { note: "(no JSON body)" }; }
  logEntry(method, path, r.status, data);
  return data;
}

async function register() {
  const username = document.getElementById("reg-user").value;
  const password = document.getElementById("reg-pass").value;
  await call("POST", "/auth/register", {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

async function login() {
  const username = document.getElementById("login-user").value;
  const password = document.getElementById("login-pass").value;
  const data = await call("POST", "/auth/login", {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (data.accessToken) accessToken = data.accessToken;
}

async function getSecret() {
  await call("GET", "/secret", {
    headers: { Authorization: "Bearer " + accessToken },
  });
}

async function refresh() {
  const data = await call("POST", "/auth/refresh", {
    headers: { "X-CSRF-Token": getCookie("csrf_token") || "" },
  });
  if (data.accessToken) accessToken = data.accessToken;
}

async function logout() {
  await call("POST", "/auth/logout", {
    headers: { "X-CSRF-Token": getCookie("csrf_token") || "" },
  });
  accessToken = null;
}

document.getElementById("btn-register").addEventListener("click", register);
document.getElementById("btn-login").addEventListener("click", login);
document.getElementById("btn-secret").addEventListener("click", getSecret);
document.getElementById("btn-refresh").addEventListener("click", refresh);
document.getElementById("btn-logout").addEventListener("click", logout);