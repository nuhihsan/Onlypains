// OnlyPains Worker (Cloudflare): accounts, cloud sync and the feedback relay, in one place.
//
// Bindings (Worker > Settings > Bindings):
//   DB          D1 database "onlypains"
// Variables (Worker > Settings > Variables and Secrets, type "Text"):
//   GOOGLE_CLIENT_ID  the OAuth client id from Google Cloud (see worker/README.md)
// Secrets (Worker > Settings > Variables and Secrets, type "Secret"):
//   BOT_TOKEN   the token BotFather gave you
//   CHAT_ID     your own Telegram chat id
//
// Routes
//   POST /feedback        { type, msg, name }               (old "POST /" still works)
//   POST /auth/signup     { username, password }  -> { token, username }
//   POST /auth/login      { username, password }  -> { token, username }
//   POST /auth/logout     Bearer token
//   POST /auth/password   Bearer token, { old, new }   (old can be empty if the account has no password yet)
//   POST /auth/google     { credential } -> { token, username }; with a Bearer token it links Google to that account
//   POST /auth/google-redirect   form post from Google's own sign-in page (no popup, works on iPhone);
//                                 sends the user back to the app with a one-time login in the address #fragment
//   POST /sync            Bearer token, { since, changes: [{ path, data, t, del }] } -> { now, changes }
//
// Passwords are never stored: only a salted PBKDF2-SHA256 hash. Login tokens are stored as SHA-256 hashes.

const ALLOWED_ORIGINS = ["https://nuhihsan.github.io"];
const APP_URL = "https://nuhihsan.github.io/Onlypains/";
const TYPES = ["Bug", "Idea", "Other"];
const PBKDF2_ITER = 100000;           // the most Workers allow
const MAX_DOC = 200000;               // bytes per synced document
const MAX_CHANGES = 500;              // per sync request
const MAX_PULL = 2000;                // rows returned per sync

const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
async function hashPw(pw, saltHex){
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER }, key, 256));
}
function safeEq(a, b){ if(a.length !== b.length) return false; let d = 0; for(let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
const cleanUser = u => String(u || "").trim().toLowerCase();
const validUser = u => /^[a-z0-9_]{3,20}$/.test(u);
const validPath = p => typeof p === "string" && p.length <= 200 && /^[A-Za-z0-9_\-\/.]+$/.test(p) && !p.includes("..");

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const allowed = ALLOWED_ORIGINS.includes(origin);
    const cors = {
      "Access-Control-Allow-Origin": allowed ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    };
    const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });
    // Google's sign-in page posts here directly (from accounts.google.com), so it skips the app-origin check.
    // Safe because the Google token itself is checked: signed by Google, made for our client id, not expired.
    if (req.method === "POST" && new URL(req.url).pathname.replace(/\/+$/, "") === "/auth/google-redirect") return googleRedirect(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST" || !allowed) return reply(403, { ok: false, error: "not allowed" });

    const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
    let b = {};
    try { b = await req.json(); } catch (e) { return reply(400, { ok: false, error: "bad request" }); }

    try {
      if (path === "/" || path === "/feedback") return await feedback(b, req, env, reply);
      if (!env.DB) return reply(500, { ok: false, error: "database not connected" });
      if (path === "/auth/signup") return await signup(b, env, reply);
      if (path === "/auth/login") return await login(b, env, reply);
      if (path === "/auth/google") return await google(b, req, env, reply);
      const who = await authed(req, env);
      if (!who) return reply(401, { ok: false, error: "signed out" });
      if (path === "/auth/logout") { await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(who.th).run(); return reply(200, { ok: true }); }
      if (path === "/auth/password") return await changePw(b, who, env, reply);
      if (path === "/sync") return await sync(b, who, env, reply);
      return reply(404, { ok: false, error: "not found" });
    } catch (e) {
      return reply(500, { ok: false, error: "server error" });
    }
  }
};

async function authed(req, env){
  const m = (req.headers.get("Authorization") || "").match(/^Bearer ([a-f0-9]{64})$/);
  if (!m || !env.DB) return null;
  const th = await sha256(m[1]);
  const row = await env.DB.prepare("SELECT s.user_id, u.username, s.last_used FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?").bind(th).first();
  if (!row) return null;
  const now = Date.now();
  if (now - row.last_used > 86400000) await env.DB.prepare("UPDATE sessions SET last_used = ? WHERE token_hash = ?").bind(now, th).run();
  return { id: row.user_id, username: row.username, th };
}
async function newSession(userId, env){
  const token = randHex(32), now = Date.now();
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, created, last_used) VALUES (?, ?, ?, ?)").bind(await sha256(token), userId, now, now).run();
  return token;
}
async function signup(b, env, reply){
  const u = cleanUser(b.username), pw = String(b.password || "");
  if (!validUser(u)) return reply(400, { ok: false, error: "Username: 3 to 20 letters, numbers or _" });
  if (pw.length < 8 || pw.length > 200) return reply(400, { ok: false, error: "Password needs at least 8 characters" });
  if (await env.DB.prepare("SELECT 1 FROM users WHERE username = ?").bind(u).first()) return reply(409, { ok: false, error: "That username is taken" });
  const salt = randHex(16), ph = await hashPw(pw, salt);
  const r = await env.DB.prepare("INSERT INTO users (username, pass_hash, salt, created) VALUES (?, ?, ?, ?)").bind(u, ph, salt, Date.now()).run();
  return reply(200, { ok: true, token: await newSession(r.meta.last_row_id, env), username: u });
}
async function login(b, env, reply){
  const u = cleanUser(b.username), pw = String(b.password || ""), now = Date.now();
  const lock = await env.DB.prepare("SELECT n, until FROM login_fails WHERE username = ?").bind(u).first();
  if (lock && lock.until > now) return reply(429, { ok: false, error: "Too many tries. Wait 15 minutes and try again." });
  const row = await env.DB.prepare("SELECT id, pass_hash, salt FROM users WHERE username = ?").bind(u).first();
  const ok = row && row.salt && safeEq(await hashPw(pw, row.salt), row.pass_hash);
  if (!ok) {
    const n = (lock ? lock.n : 0) + 1;
    await env.DB.prepare("INSERT INTO login_fails (username, n, until) VALUES (?, ?, ?) ON CONFLICT(username) DO UPDATE SET n = excluded.n, until = excluded.until")
      .bind(u, n >= 5 ? 0 : n, n >= 5 ? now + 15 * 60000 : 0).run();
    return reply(401, { ok: false, error: "Wrong username or password" });
  }
  if (lock) await env.DB.prepare("DELETE FROM login_fails WHERE username = ?").bind(u).run();
  return reply(200, { ok: true, token: await newSession(row.id, env), username: u });
}
async function changePw(b, who, env, reply){
  const row = await env.DB.prepare("SELECT pass_hash, salt FROM users WHERE id = ?").bind(who.id).first();
  if (!row || (row.salt && !safeEq(await hashPw(String(b.old || ""), row.salt), row.pass_hash))) return reply(401, { ok: false, error: "Current password is wrong" });
  const pw = String(b.new || "");
  if (pw.length < 8 || pw.length > 200) return reply(400, { ok: false, error: "Password needs at least 8 characters" });
  const salt = randHex(16);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?").bind(await hashPw(pw, salt), salt, who.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?").bind(who.id, who.th)   // sign out other devices
  ]);
  return reply(200, { ok: true });
}

// Last write wins per document, by the time the change was made on the phone (t).
// st is the server's own clock, used only to hand back "what changed since you last asked".
async function sync(b, who, env, reply){
  const changes = Array.isArray(b.changes) ? b.changes.slice(0, MAX_CHANGES) : [];
  const since = Number(b.since) || 0;
  let st = Date.now();
  const stmts = [];
  for (const c of changes) {
    if (!c || !validPath(c.path) || !(Number(c.t) > 0)) continue;
    const del = c.del ? 1 : 0, data = del ? null : JSON.stringify(c.data ?? null);
    if (data && data.length > MAX_DOC) continue;
    stmts.push(env.DB.prepare(
      `INSERT INTO docs (user_id, path, data, t, st, del) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id, path) DO UPDATE SET data = excluded.data, t = excluded.t, st = excluded.st, del = excluded.del WHERE excluded.t > docs.t`
    ).bind(who.id, c.path, data, Math.floor(Number(c.t)), st++, del));
  }
  for (let i = 0; i < stmts.length; i += 100) await env.DB.batch(stmts.slice(i, i + 100));
  const rows = (await env.DB.prepare("SELECT path, data, t, st, del FROM docs WHERE user_id = ? AND st > ? ORDER BY st LIMIT ?").bind(who.id, since, MAX_PULL).all()).results || [];
  // also send back the server copy of anything we just refused (an older edit), so the phone catches up
  const got = new Set(rows.map(r => r.path)), pushed = [...new Set(changes.filter(c => c && validPath(c.path)).map(c => c.path))].filter(p => !got.has(p));
  const extra = [];
  for (let i = 0; i < pushed.length; i += 90) {
    const part = pushed.slice(i, i + 90);
    const r = await env.DB.prepare(`SELECT path, data, t, st, del FROM docs WHERE user_id = ? AND path IN (${part.map(() => "?").join(",")})`).bind(who.id, ...part).all();
    extra.push(...(r.results || []));
  }
  const conv = r => ({ path: r.path, t: r.t, del: !!r.del, data: r.del ? null : JSON.parse(r.data) });
  const out = [...rows.map(conv), ...extra.map(conv)];
  const now = rows.length ? rows[rows.length - 1].st : since;
  const info = await env.DB.prepare("SELECT salt, google_sub, email FROM users WHERE id = ?").bind(who.id).first();
  return reply(200, { ok: true, now, more: rows.length === MAX_PULL, changes: out, username: who.username,
    hasPassword: !!(info && info.salt), google: info && info.google_sub ? (info.email || "linked") : null });
}

async function feedback(b, req, env, reply){
  if (!env.BOT_TOKEN || !env.CHAT_ID) return reply(500, { ok: false, error: "worker not set up" });
  if (b && b.website) return reply(200, { ok: true }); // honeypot field that only bots fill in
  const type = TYPES.includes(b.type) ? b.type : "Other";
  const msg = String(b.msg || "").trim().slice(0, 2000);
  const name = String(b.name || "").trim().slice(0, 40) || "anonymous";
  if (!msg) return reply(400, { ok: false, error: "empty message" });
  const who = await authed(req, env).catch(() => null);
  const ver = String(b.version || "").slice(0, 12);
  const text = `OnlyPains feedback: ${type}\n\n${msg}\n\nFrom: ${name}${who ? ` (account: ${who.username})` : " (not signed in)"}${ver ? `\nApp: v${ver}` : ""}`;
  const tg = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: env.CHAT_ID, text, disable_web_page_preview: true })
  });
  return tg.ok ? reply(200, { ok: true }) : reply(502, { ok: false, error: "telegram refused the message" });
}

// ---------- Sign in with Google ----------
// The app gets a signed ID token from Google; we check Google's signature, that it was made for our
// client id, and that it hasn't expired. Nothing else from Google is stored except the account id and email.
let jwks = null, jwksAt = 0;
async function googleKeys(){
  if (jwks && Date.now() - jwksAt < 3600000) return jwks;
  const r = await fetch("https://www.googleapis.com/oauth2/v3/certs");
  if (!r.ok) throw new Error("google keys");
  jwks = (await r.json()).keys; jwksAt = Date.now(); return jwks;
}
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
async function verifyGoogle(token, clientId){
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  let head, body;
  try { head = JSON.parse(new TextDecoder().decode(b64u(parts[0]))); body = JSON.parse(new TextDecoder().decode(b64u(parts[1]))); } catch (e) { return null; }
  if (head.alg !== "RS256") return null;
  const jwk = (await googleKeys()).find(k => k.kid === head.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64u(parts[2]), enc.encode(parts[0] + "." + parts[1]));
  const now = Date.now() / 1000;
  if (!ok || body.aud !== clientId || !["accounts.google.com", "https://accounts.google.com"].includes(body.iss) || !(body.exp > now) || !body.sub) return null;
  if (body.email && body.email_verified === false) return null;
  return body;
}
async function google(b, req, env, reply){
  if (!env.GOOGLE_CLIENT_ID) return reply(500, { ok: false, error: "Google sign-in isn't set up yet" });
  const g = await verifyGoogle(b.credential, env.GOOGLE_CLIENT_ID);
  if (!g) return reply(401, { ok: false, error: "Google sign-in didn't go through. Try again." });
  const email = String(g.email || "").toLowerCase().slice(0, 200);
  const owner = await env.DB.prepare("SELECT id, username FROM users WHERE google_sub = ?").bind(g.sub).first();
  const who = await authed(req, env);
  if (who) { // link Google to the signed-in account
    if (owner && owner.id !== who.id) return reply(409, { ok: false, error: `That Google account is already used by ${owner.username}` });
    await env.DB.prepare("UPDATE users SET google_sub = ?, email = ? WHERE id = ?").bind(g.sub, email, who.id).run();
    return reply(200, { ok: true, linked: true, username: who.username, google: email });
  }
  const r = await googleAccount(g, env);
  return reply(200, { ok: true, token: r.token, username: r.username, created: !!r.created });
}

async function googleRedirect(req, env){
  const back = frag => Response.redirect(APP_URL + "#" + new URLSearchParams(frag).toString(), 303);
  try {
    if (!env.DB || !env.GOOGLE_CLIENT_ID) return back({ gerr: "Google sign-in isn't set up yet" });
    const form = await req.formData();
    const g = await verifyGoogle(form.get("credential"), env.GOOGLE_CLIENT_ID);
    if (!g) return back({ gerr: "Google sign-in didn't go through. Try again." });
    const r = await googleAccount(g, env);
    return back({ gtoken: r.token, guser: r.username, gnew: r.created ? "1" : "0" });
  } catch (e) { return back({ gerr: "Google sign-in didn't go through. Try again." }); }
}
// find the account for this Google user, or make one
async function googleAccount(g, env){
  const email = String(g.email || "").toLowerCase().slice(0, 200);
  const owner = await env.DB.prepare("SELECT id, username FROM users WHERE google_sub = ?").bind(g.sub).first();
  if (owner) return { token: await newSession(owner.id, env), username: owner.username };
  let base = (email.split("@")[0] || "user").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 16);
  if (base.length < 3) base = (base + "user").slice(0, 16);
  let u = base;
  for (let i = 0; i < 50 && await env.DB.prepare("SELECT 1 FROM users WHERE username = ?").bind(u).first(); i++) u = base + Math.floor(10 + Math.random() * 990);
  const r = await env.DB.prepare("INSERT INTO users (username, pass_hash, salt, created, google_sub, email) VALUES (?, '', '', ?, ?, ?)").bind(u, Date.now(), g.sub, email).run();
  return { token: await newSession(r.meta.last_row_id, env), username: u, created: true };
}
