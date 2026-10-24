// db.js
// A tiny file-backed "database" so this project has zero native dependencies
// (no node-gyp / compiled modules to fight with). Good enough for a learning lab.
// Swap this for real Postgres/MySQL once you move past the lab stage.

const fs = require("fs");
const path = require("path");

const DB_PATH = path.join(__dirname, "data", "db.json");

function load() {
  if (!fs.existsSync(DB_PATH)) {
    const initial = { users: [], refreshTokens: [], secrets: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}

function save(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// No-op here — the Postgres version (db.pg.js) uses init() to create tables.
// Kept so server.js can call db.init() the same way regardless of backend.
async function init() {}

// --- Users ---
function findUserByUsername(username) {
  const data = load();
  return data.users.find(
    (u) => u.username.toLowerCase() === String(username).toLowerCase()
  );
}

function findUserById(id) {
  const data = load();
  return data.users.find((u) => u.id === id);
}

function createUser(user) {
  const data = load();
  data.users.push(user);
  save(data);
  return user;
}

function updateUser(id, patch) {
  const data = load();
  const idx = data.users.findIndex((u) => u.id === id);
  if (idx === -1) return null;
  data.users[idx] = { ...data.users[idx], ...patch };
  save(data);
  return data.users[idx];
}

// --- Refresh tokens (stored hashed, rotated on every use) ---
function storeRefreshToken(entry) {
  const data = load();
  data.refreshTokens.push(entry);
  save(data);
}

function findRefreshToken(tokenHash) {
  const data = load();
  return data.refreshTokens.find((t) => t.tokenHash === tokenHash);
}

function revokeRefreshToken(tokenHash) {
  const data = load();
  const idx = data.refreshTokens.findIndex((t) => t.tokenHash === tokenHash);
  if (idx !== -1) data.refreshTokens[idx].revoked = true;
  save(data);
}

function revokeAllRefreshTokensForUser(userId) {
  const data = load();
  data.refreshTokens.forEach((t) => {
    if (t.userId === userId) t.revoked = true;
  });
  save(data);
}

// --- Secrets (the protected resource each user "owns") ---
function createSecret(secret) {
  const data = load();
  data.secrets.push(secret);
  save(data);
  return secret;
}

function findSecretByUserId(userId) {
  const data = load();
  return data.secrets.find((s) => s.userId === userId);
}

module.exports = {
  init,
  findUserByUsername,
  findUserById,
  createUser,
  updateUser,
  storeRefreshToken,
  findRefreshToken,
  revokeRefreshToken,
  revokeAllRefreshTokensForUser,
  createSecret,
  findSecretByUserId,
};