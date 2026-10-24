// db.pg.js
// PostgreSQL-backed version of db.js — use this in production (Render, etc.)
// so data survives restarts/redeploys. Same function names/shapes as the
// JSON-file version, but every function is now async.

const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

async function init() {
  const schema = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
  await pool.query(schema);
}

function rowToUser(r) {
  if (!r) return null;
  return {
    id: r.id,
    username: r.username,
    passwordHash: r.password_hash,
    failedAttempts: r.failed_attempts,
    lockUntil: r.lock_until ? Number(r.lock_until) : null,
    createdAt: Number(r.created_at),
  };
}

// --- Users ---
async function findUserByUsername(username) {
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE LOWER(username) = LOWER($1)",
    [username]
  );
  return rowToUser(rows[0]);
}

async function findUserById(id) {
  const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
  return rowToUser(rows[0]);
}

async function createUser(user) {
  await pool.query(
    `INSERT INTO users (id, username, password_hash, failed_attempts, lock_until, created_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [user.id, user.username, user.passwordHash, user.failedAttempts || 0, user.lockUntil, user.createdAt]
  );
  return user;
}

async function updateUser(id, patch) {
  const existing = await findUserById(id);
  if (!existing) return null;
  const merged = { ...existing, ...patch };
  await pool.query(
    `UPDATE users SET failed_attempts = $1, lock_until = $2 WHERE id = $3`,
    [merged.failedAttempts, merged.lockUntil, id]
  );
  return merged;
}

// --- Refresh tokens ---
async function storeRefreshToken(entry) {
  await pool.query(
    `INSERT INTO refresh_tokens (token_hash, user_id, created_at, expires_at, revoked)
     VALUES ($1, $2, $3, $4, $5)`,
    [entry.tokenHash, entry.userId, entry.createdAt, entry.expiresAt, entry.revoked]
  );
}

async function findRefreshToken(tokenHash) {
  const { rows } = await pool.query(
    "SELECT * FROM refresh_tokens WHERE token_hash = $1",
    [tokenHash]
  );
  if (!rows[0]) return null;
  const r = rows[0];
  return {
    tokenHash: r.token_hash,
    userId: r.user_id,
    createdAt: Number(r.created_at),
    expiresAt: Number(r.expires_at),
    revoked: r.revoked,
  };
}

async function revokeRefreshToken(tokenHash) {
  await pool.query("UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1", [tokenHash]);
}

async function revokeAllRefreshTokensForUser(userId) {
  await pool.query("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1", [userId]);
}

// --- Secrets ---
async function createSecret(secret) {
  await pool.query(
    "INSERT INTO secrets (id, user_id, data) VALUES ($1, $2, $3)",
    [secret.id, secret.userId, secret.data]
  );
  return secret;
}

async function findSecretByUserId(userId) {
  const { rows } = await pool.query("SELECT * FROM secrets WHERE user_id = $1", [userId]);
  if (!rows[0]) return null;
  return { id: rows[0].id, userId: rows[0].user_id, data: rows[0].data };
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