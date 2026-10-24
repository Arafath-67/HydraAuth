// server.js
require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

// Uses PostgreSQL in production (Render sets DATABASE_URL automatically when
// you attach a Postgres database) and falls back to the local JSON-file
// store otherwise, so plain `npm start` still works with zero setup.
const db = process.env.DATABASE_URL ? require("./db.pg") : require("./db");
const { requireAuth } = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

if (!ACCESS_SECRET || !REFRESH_SECRET || ACCESS_SECRET.startsWith("changeme")) {
  console.error("Set real JWT_ACCESS_SECRET / JWT_REFRESH_SECRET in .env before running.");
  process.exit(1);
}

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 min

// ---------- helpers ----------

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function issueAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username },
    ACCESS_SECRET,
    {
      algorithm: "HS256",
      expiresIn: ACCESS_TOKEN_TTL,
      issuer: "secure-login-lab",
      audience: "secure-login-lab-client",
      jwtid: crypto.randomUUID(),
    }
  );
}

async function issueRefreshToken(user) {
  const raw = crypto.randomBytes(48).toString("hex");
  const tokenHash = hashToken(raw);
  await db.storeRefreshToken({
    tokenHash,
    userId: user.id,
    createdAt: Date.now(),
    expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
    revoked: false,
  });
  return raw;
}

function setAuthCookies(res, refreshRaw) {
  res.cookie("refresh_token", refreshRaw, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: REFRESH_TOKEN_TTL_MS,
    path: "/auth/refresh",
  });

  // CSRF token: readable by JS (not httpOnly) so the frontend can echo it
  // back in a header on state-changing requests (double-submit pattern).
  const csrfToken = crypto.randomBytes(24).toString("hex");
  res.cookie("csrf_token", csrfToken, {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: REFRESH_TOKEN_TTL_MS,
  });
}

function requireCsrf(req, res, next) {
  const cookieToken = req.cookies["csrf_token"];
  const headerToken = req.headers["x-csrf-token"];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: "CSRF validation failed" });
  }
  next();
}

function isValidUsername(u) {
  return typeof u === "string" && /^[a-zA-Z0-9_]{3,32}$/.test(u);
}

function isValidPassword(p) {
  return typeof p === "string" && p.length >= 10 && p.length <= 256;
}

// ---------- rate limiting ----------

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // per IP — the per-account lockout below is the real defense
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, slow down." },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- routes ----------

app.post("/auth/register", registerLimiter, async (req, res) => {
  const { username, password } = req.body || {};

  if (!isValidUsername(username)) {
    return res.status(400).json({ error: "Username must be 3-32 chars: letters, numbers, underscore." });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: "Password must be at least 10 characters." });
  }
  if (await db.findUserByUsername(username)) {
    // Same message as success-adjacent errors elsewhere would be nice too,
    // but username-exists checks on registration are a smaller leak than
    // on login — this is a reasonable, intentional design tradeoff to probe.
    return res.status(409).json({ error: "Username already taken." });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordHash,
    failedAttempts: 0,
    lockUntil: null,
    createdAt: Date.now(),
  };
  await db.createUser(user);
  await db.createSecret({
    id: crypto.randomUUID(),
    userId: user.id,
    data: `This is ${username}'s private secret. Only a valid access token for this exact user can read it.`,
  });

  res.status(201).json({ message: "Registered. You can now log in." });
});

app.post("/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!isValidUsername(username) || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid request." });
  }

  const user = await db.findUserByUsername(username);

  // Constant-shape response + dummy hash compare when user doesn't exist,
  // so response timing/shape doesn't trivially confirm username existence.
  const dummyHash = "$2a$12$CwTycUXWue0Thq9StjUM0uJ8gCK.gMPy.fOwBX8kg2oe7IJKhC.1e";
  const compareTarget = user ? user.passwordHash : dummyHash;

  if (user && user.lockUntil && user.lockUntil > Date.now()) {
    return res.status(423).json({ error: "Account temporarily locked. Try again later." });
  }

  const valid = await bcrypt.compare(password, compareTarget);

  if (!user || !valid) {
    if (user) {
      const attempts = (user.failedAttempts || 0) + 1;
      const patch = { failedAttempts: attempts };
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        patch.lockUntil = Date.now() + LOCK_DURATION_MS;
        patch.failedAttempts = 0;
      }
      await db.updateUser(user.id, patch);
    }
    return res.status(401).json({ error: "Invalid username or password." });
  }

  await db.updateUser(user.id, { failedAttempts: 0, lockUntil: null });

  const accessToken = issueAccessToken(user);
  const refreshRaw = await issueRefreshToken(user);
  setAuthCookies(res, refreshRaw);

  res.json({ accessToken, expiresIn: ACCESS_TOKEN_TTL });
});

app.post("/auth/refresh", requireCsrf, async (req, res) => {
  const raw = req.cookies["refresh_token"];
  if (!raw) return res.status(401).json({ error: "No refresh token." });

  const tokenHash = hashToken(raw);
  const stored = await db.findRefreshToken(tokenHash);

  if (!stored || stored.revoked || stored.expiresAt < Date.now()) {
    // Reuse of an already-rotated/revoked token is a strong signal of theft.
    // If we can identify the user, nuke every refresh token they have.
    if (stored) await db.revokeAllRefreshTokensForUser(stored.userId);
    return res.status(401).json({ error: "Refresh token invalid. Please log in again." });
  }

  const user = await db.findUserById(stored.userId);
  if (!user) return res.status(401).json({ error: "Refresh token invalid." });

  // Rotate: revoke the old one, issue a brand new one.
  await db.revokeRefreshToken(tokenHash);
  const newRefreshRaw = await issueRefreshToken(user);
  setAuthCookies(res, newRefreshRaw);

  const accessToken = issueAccessToken(user);
  res.json({ accessToken, expiresIn: ACCESS_TOKEN_TTL });
});

app.post("/auth/logout", requireCsrf, async (req, res) => {
  const raw = req.cookies["refresh_token"];
  if (raw) await db.revokeRefreshToken(hashToken(raw));
  res.clearCookie("refresh_token", { path: "/auth/refresh" });
  res.clearCookie("csrf_token");
  res.json({ message: "Logged out." });
});

// The protected resource. Note: userId comes ONLY from the verified JWT
// (req.user.id), never from a URL/body param — that's the IDOR defense.
app.get("/secret", requireAuth, async (req, res) => {
  const secret = await db.findSecretByUserId(req.user.id);
  res.json({ secret: secret ? secret.data : null });
});

(async () => {
  await db.init(); // creates tables on Postgres; no-op on the JSON-file backend
  app.listen(PORT, () => {
    console.log(`secure-login-lab running on http://localhost:${PORT}`);
  });
})();