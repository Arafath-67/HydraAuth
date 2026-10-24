// middleware/auth.js
const jwt = require("jsonwebtoken");

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

function requireAuth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }
  const token = header.slice("Bearer ".length);

  try {
    // IMPORTANT: algorithms is explicitly pinned. Never trust the `alg`
    // claim inside the token itself — that's what lets an attacker switch
    // to "none" or try to get the server to verify an RS256 token with the
    // public key treated as an HMAC secret.
    const payload = jwt.verify(token, ACCESS_SECRET, {
      algorithms: ["HS256"],
      issuer: "secure-login-lab",
      audience: "secure-login-lab-client",
    });
    req.user = { id: payload.sub, username: payload.username };
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = { requireAuth };