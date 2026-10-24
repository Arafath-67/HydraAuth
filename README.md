# secure-login-lab

A login system built with modern defenses already in place — your job is to
find a real way through, then patch what you find, then try again.

## What's already hardened

- Passwords hashed with bcrypt (cost 12), never stored/logged in plaintext
- Short-lived JWT access tokens (15 min), algorithm pinned server-side
  (defends against `alg: none` / algorithm-confusion attacks)
- Refresh tokens: random 384-bit value, stored server-side only as a SHA-256
  hash, **rotated on every use**, with reuse detection (if an old/revoked
  refresh token is replayed, every refresh token for that user is revoked)
- CSRF protection via double-submit cookie pattern on state-changing routes
- Per-account lockout after 5 failed logins (15 min), plus per-IP rate
  limiting on login/register
- Login response shape/timing doesn't trivially confirm whether a username
  exists (dummy bcrypt compare runs even for unknown usernames)
- `/secret` derives the owner strictly from the verified JWT's `sub` claim —
  never from a client-supplied ID — as the IDOR defense
- `helmet` for baseline secure headers; cookies are `httpOnly`, `sameSite:
  strict`, and `secure` in production

## Setup

```bash
cd secure-login-lab
npm install
cp .env.example .env
# edit .env and put in real random secrets:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
npm start
```

Visit `http://localhost:3000`.

## Deploying to Render (free)

This repo includes `render.yaml`, so Render can set up both the web service
and a free Postgres database in one go, and the app auto-detects
`DATABASE_URL` and switches from the local JSON-file store to Postgres.

1. Push this folder to a GitHub repo.
2. Go to [render.com](https://render.com) → New → **Blueprint** → connect
   the repo. Render reads `render.yaml` and provisions:
   - a free web service (auto-generates `JWT_ACCESS_SECRET` /
     `JWT_REFRESH_SECRET` for you)
   - a free Postgres database, wired in via `DATABASE_URL`
3. Deploy. On first boot the app runs `schema.sql` automatically to create
   the tables.
4. Visit the `.onrender.com` URL Render gives you — it's served over HTTPS
   automatically.

**Free tier notes to know going in:**
- The web service spins down after 15 minutes of no traffic and takes
  ~1 minute to wake back up on the next request — expected, not a bug.
- You get 750 free instance-hours/month, which comfortably covers one
  always-available-ish hobby service.
- Free Postgres **data persists** across restarts (unlike the JSON-file
  version), but Render's free Postgres database **expires 30 days after
  creation** (14-day grace period to upgrade before it's deleted). Fine for
  this lab — just don't treat it as permanent storage.

## How to use this as a training loop

1. Register two users (Alice, Bob) and confirm `/secret` only ever returns
   the logged-in user's own data.
2. Try to break it. Don't just run the classic playbook (plain SQLi,
   no-hash password, obvious XSS) — those don't apply here. Focus on the
   categories below instead.
3. When you find something real, write down: what broke, why the existing
   defense didn't catch it, and the fix. Patch it yourself before asking me
   to check your reasoning.
4. Re-run your own exploit against the patched version to confirm it's
   actually closed, not just hidden.

## Attack surface to probe (no solutions given — that's the exercise)

- **JWT handling**: token tampering, claim manipulation, expiry/replay
  behavior, what happens with a malformed or resigned token
- **Refresh token flow**: concurrent refresh requests (race conditions),
  what happens if a token is used twice, cookie scoping (`path`)
- **CSRF**: does every state-changing route actually enforce it? Check all
  of them, not just the obvious one
- **Rate limiting / lockout**: is the limit keyed in a way that's easy to
  route around? Does the lockout logic have an edge case at the boundary?
- **IDOR / authorization**: are there any routes you could add later that
  might accidentally trust a client-supplied ID instead of the token?
- **Registration race conditions**: what happens if two requests to
  register the same username land at nearly the same time?
- **Information leakage**: error messages, response timing, HTTP headers —
  anything that narrows down valid usernames or internal state
- **Session/token lifecycle**: logout, token revocation on password change
  (not yet implemented — is that a gap?), what happens to old access tokens
  after logout

Good places to sharpen technique in parallel: **PortSwigger Web Security
Academy** (free, has live labs for JWT attacks, race conditions, and auth
bypass) and reading real CVE writeups for auth libraries.

Test only against this local instance — never against systems you don't own
or have explicit permission to test.