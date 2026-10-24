// app.js
// Access token kept only in memory -- never localStorage/sessionStorage,
// so a successful XSS can't trivially read it off disk.
let accessToken = null;

function out(x) {
  document.getElementById("out").textContent =
    typeof x === "string" ? x : JSON.stringify(x, null, 2);
}

function getCookie(name) {
  const m = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return m ? m[2] : null;
}

async function register() {
  const username = document.getElementById("reg-user").value;
  const password = document.getElementById("reg-pass").value;
  const r = await fetch("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  out(await r.json());
}

async function login() {
  const username = document.getElementById("login-user").value;
  const password = document.getElementById("login-pass").value;
  const r = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await r.json();
  if (data.accessToken) accessToken = data.accessToken;
  out(data);
}

async function getSecret() {
  const r = await fetch("/secret", {
    headers: { Authorization: "Bearer " + accessToken },
  });
  out(await r.json());
}

async function refresh() {
  const r = await fetch("/auth/refresh", {
    method: "POST",
    headers: { "X-CSRF-Token": getCookie("csrf_token") || "" },
  });
  const data = await r.json();
  if (data.accessToken) accessToken = data.accessToken;
  out(data);
}

async function logout() {
  const r = await fetch("/auth/logout", {
    method: "POST",
    headers: { "X-CSRF-Token": getCookie("csrf_token") || "" },
  });
  accessToken = null;
  out(await r.json());
}

document.getElementById("btn-register").addEventListener("click", register);
document.getElementById("btn-login").addEventListener("click", login);
document.getElementById("btn-secret").addEventListener("click", getSecret);
document.getElementById("btn-refresh").addEventListener("click", refresh);
document.getElementById("btn-logout").addEventListener("click", logout);