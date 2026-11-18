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
//   POST /social/...      Bearer token. Friends, groups, feed and profiles (see "Friends and groups" below)
//   POST /group/...       Bearer token. Create, join, view and leave groups
//   POST /social/notifs   Bearer token. Your notifications (friend requests, accepted, declined, group joins)
//   POST /push/...        Bearer token. Phone notifications: key, subscribe, unsubscribe
//   POST /social/5ha      Bearer token. Give or take back a 5HA (kudos) on a friend's workout, run or achievement
//   POST /social/avatar   Bearer token. Set or remove your profile photo
//   GET  /a/<key>         A profile photo. The key is random and only handed to friends and group-mates
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
  async fetch(req, env, ctx) {
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
    if (req.method === "GET" && /^\/a\/[a-f0-9]{32}$/.test(new URL(req.url).pathname)) return avatarImage(new URL(req.url).pathname.slice(3), env);
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
      if (path.startsWith("/social/") || path.startsWith("/group/") || path.startsWith("/push/")) return await social(path, b, who, env, reply, ctx);
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

// ---------- Friends and groups ----------
// Each phone publishes a small summary of its own stats (recent workouts and runs, PRs, streak, weekly totals).
// Friends and group-mates only ever see that summary, never the raw log, and only the parts the owner shares:
// lifts and runs are shared by default, body weight is off by default, food is never shared.
// Tables are created automatically the first time any of this is used.
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const newCode = () => [...crypto.getRandomValues(new Uint8Array(8))].map(x => CODE_CHARS[x % CODE_CHARS.length]).join("");
const cleanCode = c => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
const MAX_SUMMARY = 40000, MAX_PENDING = 30, MAX_OWNED_GROUPS = 10, MAX_GROUP_SIZE = 50, MAX_GROUPS = 20;
const DEFAULT_SHARE = { lifts: true, runs: true, body: false };

let socialReady = false;
async function ensureSocial(env){
  if (socialReady) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS social (user_id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, share TEXT NOT NULL DEFAULT '{}', summary TEXT, pub INTEGER NOT NULL DEFAULT 0)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS friend_reqs (from_id INTEGER NOT NULL, to_id INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (from_id, to_id))"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS friend_reqs_to ON friend_reqs(to_id)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS friends (a INTEGER NOT NULL, b INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (a, b))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS grp (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE, owner INTEGER NOT NULL, created INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS grp_members (grp_id INTEGER NOT NULL, user_id INTEGER NOT NULL, joined INTEGER NOT NULL, PRIMARY KEY (grp_id, user_id))"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS grp_members_user ON grp_members(user_id)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS notifs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL, actor TEXT, grp_id INTEGER, grp_name TEXT, created INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS notifs_user ON notifs(user_id, id)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, user_id INTEGER NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created INTEGER NOT NULL)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS push_subs_user ON push_subs(user_id)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS app_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS kudos (owner_id INTEGER NOT NULL, item TEXT NOT NULL, giver_id INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (owner_id, item, giver_id))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS avatars (user_id INTEGER PRIMARY KEY, k TEXT NOT NULL UNIQUE, data TEXT NOT NULL, updated INTEGER NOT NULL)")
  ]);
  socialReady = true;
}
async function mySocial(id, env){
  let row = await env.DB.prepare("SELECT code, share FROM social WHERE user_id = ?").bind(id).first();
  for (let i = 0; !row && i < 5; i++) {
    try { await env.DB.prepare("INSERT INTO social (user_id, code) VALUES (?, ?)").bind(id, newCode()).run(); } catch (e) {}
    row = await env.DB.prepare("SELECT code, share FROM social WHERE user_id = ?").bind(id).first();
  }
  return { code: row.code, share: shareOf(row.share) };
}
function shareOf(text){ try { return Object.assign({}, DEFAULT_SHARE, JSON.parse(text || "{}")); } catch (e) { return Object.assign({}, DEFAULT_SHARE); } }
// strip whatever the owner isn't sharing
function visible(summaryText, shareText, self){
  let s; try { s = JSON.parse(summaryText || "null"); } catch (e) { return null; }
  if (!s || typeof s !== "object") return null;
  const sh = self ? { lifts: true, runs: true, body: true } : shareOf(shareText);
  const t = s.totals || {}, o = { at: s.at || 0, share: sh, totals: {}, weeks: {} };
  if (sh.lifts) { o.lifts = s.lifts || null; o.streak = s.streak || null; o.totals.sessions = t.sessions; o.totals.volume = t.volume; }
  if (sh.runs) { o.runs = s.runs || null; o.totals.runKm = t.runKm; }
  if (sh.body) o.body = s.body || null;
  for (const [w, v] of Object.entries(s.weeks || {})) if (v) o.weeks[w] = { s: sh.lifts ? v.s : null, vol: sh.lifts ? v.vol : null, km: sh.runs ? v.km : null };
  return o;
}
// everyone this user may see: friends plus anyone in a group with them
async function circle(id, env){
  const r = await env.DB.prepare(
    `SELECT b AS id FROM friends WHERE a = ?1
     UNION SELECT m2.user_id AS id FROM grp_members m1 JOIN grp_members m2 ON m1.grp_id = m2.grp_id WHERE m1.user_id = ?1 AND m2.user_id != ?1`
  ).bind(id).all();
  return (r.results || []).map(x => x.id);
}
async function canSee(viewer, target, env){
  if (viewer === target) return true;
  const r = await env.DB.prepare(
    `SELECT 1 FROM friends WHERE a = ?1 AND b = ?2
     UNION SELECT 1 FROM grp_members m1 JOIN grp_members m2 ON m1.grp_id = m2.grp_id WHERE m1.user_id = ?1 AND m2.user_id = ?2 LIMIT 1`
  ).bind(viewer, target).first();
  return !!r;
}
async function summariesOf(ids, env){
  const out = [];
  for (let i = 0; i < ids.length; i += 90) {
    const part = ids.slice(i, i + 90);
    const r = await env.DB.prepare(`SELECT u.id, u.username, s.summary, s.share, a.k AS av FROM users u LEFT JOIN social s ON s.user_id = u.id LEFT JOIN avatars a ON a.user_id = u.id WHERE u.id IN (${part.map(() => "?").join(",")})`).bind(...part).all();
    out.push(...(r.results || []));
  }
  return out;
}
const userByName = (u, env) => env.DB.prepare("SELECT id, username FROM users WHERE username = ?").bind(cleanUser(u)).first();

async function social(path, b, who, env, reply, ctx){
  await ensureSocial(env);
  const me = who.id, now = Date.now();
  const bad = msg => reply(400, { ok: false, error: msg });

  if (path === "/social/me") {
    const mine = await mySocial(me, env);
    const [fr, inc, out, gr, un, av] = await Promise.all([
      env.DB.prepare("SELECT u.username, s.pub, a.k AS av FROM friends f JOIN users u ON u.id = f.b LEFT JOIN social s ON s.user_id = f.b LEFT JOIN avatars a ON a.user_id = f.b WHERE f.a = ? ORDER BY u.username").bind(me).all(),
      env.DB.prepare("SELECT u.username FROM friend_reqs r JOIN users u ON u.id = r.from_id WHERE r.to_id = ? ORDER BY r.created DESC").bind(me).all(),
      env.DB.prepare("SELECT u.username FROM friend_reqs r JOIN users u ON u.id = r.to_id WHERE r.from_id = ? ORDER BY r.created DESC").bind(me).all(),
      env.DB.prepare("SELECT g.id, g.name, g.code, g.owner, (SELECT COUNT(*) FROM grp_members x WHERE x.grp_id = g.id) AS n FROM grp_members m JOIN grp g ON g.id = m.grp_id WHERE m.user_id = ? ORDER BY g.name").bind(me).all(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM notifs WHERE user_id = ? AND read = 0").bind(me).first(),
      env.DB.prepare("SELECT k FROM avatars WHERE user_id = ?").bind(me).first()
    ]);
    return reply(200, { ok: true, username: who.username, code: mine.code, share: mine.share, unread: un ? un.n : 0, avatar: av ? av.k : null,
      friends: (fr.results || []).map(r => ({ username: r.username, active: r.pub || 0, avatar: r.av || null })),
      incoming: (inc.results || []).map(r => r.username), outgoing: (out.results || []).map(r => r.username),
      groups: (gr.results || []).map(g => ({ id: g.id, name: g.name, code: g.code, owner: g.owner === me, members: g.n })) });
  }

  if (path === "/social/share") {
    const sh = { lifts: !!b.lifts, runs: !!b.runs, body: !!b.body };
    await mySocial(me, env);
    await env.DB.prepare("UPDATE social SET share = ? WHERE user_id = ?").bind(JSON.stringify(sh), me).run();
    return reply(200, { ok: true, share: sh });
  }

  if (path === "/social/publish") {
    const text = JSON.stringify(b.summary ?? null);
    if (!b.summary || typeof b.summary !== "object" || text.length > MAX_SUMMARY) return bad("Summary too big");
    await mySocial(me, env);
    await env.DB.prepare("UPDATE social SET summary = ?, pub = ? WHERE user_id = ?").bind(text, now, me).run();
    return reply(200, { ok: true });
  }

  if (path === "/social/add") {
    const code = cleanCode(b.code);
    if (code.length < 6) return bad("That code looks too short. Codes are 8 letters and numbers.");
    const row = await env.DB.prepare("SELECT s.user_id AS id, u.username FROM social s JOIN users u ON u.id = s.user_id WHERE s.code = ?").bind(code).first();
    if (!row) return reply(404, { ok: false, error: "No one has that friend code. Check it and try again." });
    if (row.id === me) return bad("That's your own code. Send it to a friend instead.");
    if (await env.DB.prepare("SELECT 1 FROM friends WHERE a = ? AND b = ?").bind(me, row.id).first()) return reply(200, { ok: true, status: "friends", username: row.username });
    if (await env.DB.prepare("SELECT 1 FROM friend_reqs WHERE from_id = ? AND to_id = ?").bind(row.id, me).first()) {
      await makeFriends(me, row.id, env); // they already asked you
      await markReqHandled(me, row.username, env);
      await notify(env, ctx, [row.id], "accepted", { actor: who.username });
      return reply(200, { ok: true, status: "friends", username: row.username });
    }
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM friend_reqs WHERE from_id = ?").bind(me).first();
    if (n && n.n >= MAX_PENDING) return bad("You have too many requests waiting. Cancel some first.");
    const ins = await env.DB.prepare("INSERT OR IGNORE INTO friend_reqs (from_id, to_id, created) VALUES (?, ?, ?)").bind(me, row.id, now).run();
    if (ins.meta && ins.meta.changes) await notify(env, ctx, [row.id], "req", { actor: who.username }); // not again for a repeat tap
    return reply(200, { ok: true, status: "sent", username: row.username });
  }

  if (path === "/social/respond") {
    const u = await userByName(b.username, env);
    if (!u || !(await env.DB.prepare("SELECT 1 FROM friend_reqs WHERE from_id = ? AND to_id = ?").bind(u.id, me).first())) return reply(404, { ok: false, error: "That request is gone." });
    if (b.accept) await makeFriends(me, u.id, env);
    else await env.DB.prepare("DELETE FROM friend_reqs WHERE from_id = ? AND to_id = ?").bind(u.id, me).run();
    await markReqHandled(me, u.username, env);
    await notify(env, ctx, [u.id], b.accept ? "accepted" : "declined", { actor: who.username });
    return reply(200, { ok: true });
  }

  if (path === "/social/remove") { // unfriend, or cancel a request either way
    const u = await userByName(b.username, env);
    if (u) await env.DB.batch([
      env.DB.prepare("DELETE FROM friends WHERE (a = ?1 AND b = ?2) OR (a = ?2 AND b = ?1)").bind(me, u.id),
      env.DB.prepare("DELETE FROM friend_reqs WHERE (from_id = ?1 AND to_id = ?2) OR (from_id = ?2 AND to_id = ?1)").bind(me, u.id)
    ]);
    return reply(200, { ok: true });
  }

  if (path === "/social/profile") {
    const u = await userByName(b.username, env);
    if (!u || !(await canSee(me, u.id, env))) return reply(404, { ok: false, error: "You can only see friends and people in your groups." });
    const row = await env.DB.prepare("SELECT s.summary, s.share, a.k AS av FROM social s LEFT JOIN avatars a ON a.user_id = s.user_id WHERE s.user_id = ?").bind(u.id).first();
    const friend = !!(await env.DB.prepare("SELECT 1 FROM friends WHERE a = ? AND b = ?").bind(me, u.id).first());
    return reply(200, { ok: true, username: u.username, self: u.id === me, friend, avatar: row ? row.av || null : null, summary: row ? visible(row.summary, row.share, u.id === me) : null });
  }

  if (path === "/social/feed") {
    const ids = [me, ...(await circle(me, env))].slice(0, 500);
    const cutoff = String(b.from || "").match(/^\d{4}-\d{2}-\d{2}$/) ? b.from : "0000";
    const items = [], idOf = {};
    for (const r of await summariesOf(ids, env)) {
      const s = visible(r.summary, r.share, r.id === me);
      if (!s) continue;
      idOf[r.username] = r.id;
      const base = { user: r.username, self: r.id === me, avatar: r.av || null };
      for (const w of (s.lifts && s.lifts.recent) || []) if (w && w.date >= cutoff) items.push(Object.assign({ kind: "lift" }, base, w, { key: w.sid ? "l:" + w.sid : null }));
      for (const w of (s.runs && s.runs.recent) || []) if (w && w.date >= cutoff) items.push(Object.assign({ kind: "run" }, base, w, { key: w.rid ? "r:" + w.rid : null }));
      for (const a of [...((s.lifts && s.lifts.ach) || []), ...((s.runs && s.runs.ach) || [])]) if (a && a.date >= cutoff) items.push(Object.assign({ kind: "ach" }, base, a, { key: "a:" + a.id, ts: 0 }));
    }
    items.sort((x, y) => String(y.date).localeCompare(String(x.date)) || (y.ts || 0) - (x.ts || 0));
    const top = items.slice(0, 80);
    // 5HA counts, who gave them, and whether you did
    const owners = [...new Set(top.map(i => idOf[i.user]))], k5 = {};
    for (let i = 0; i < owners.length; i += 90) {
      const part = owners.slice(i, i + 90);
      const r = await env.DB.prepare(`SELECT k.owner_id, k.item, k.giver_id, u.username FROM kudos k JOIN users u ON u.id = k.giver_id WHERE k.owner_id IN (${part.map(() => "?").join(",")}) ORDER BY k.created`).bind(...part).all();
      for (const x of r.results || []) (k5[x.owner_id + "|" + x.item] ||= []).push(x);
    }
    for (const it of top) {
      const l = it.key ? k5[idOf[it.user] + "|" + it.key] || [] : [];
      it.fha = { n: l.length, mine: l.some(x => x.giver_id === me), names: l.map(x => x.giver_id === me ? "You" : x.username).slice(-4) };
    }
    return reply(200, { ok: true, items: top });
  }

  if (path === "/social/notifs") {
    await env.DB.prepare("DELETE FROM notifs WHERE user_id = ? AND created < ?").bind(me, now - 30 * 86400000).run();
    const r = await env.DB.prepare(
      `SELECT n.id, n.kind, n.actor, n.grp_id, n.grp_name, n.created, n.read, (SELECT a.k FROM avatars a JOIN users u ON u.id = a.user_id WHERE u.username = n.actor) AS av,
         CASE WHEN n.kind = 'req' THEN EXISTS (SELECT 1 FROM friend_reqs q JOIN users u ON u.id = q.from_id WHERE q.to_id = n.user_id AND u.username = n.actor) ELSE 0 END AS pending
       FROM notifs n WHERE n.user_id = ? ORDER BY n.id DESC LIMIT 50`).bind(me).all();
    const list = (r.results || []).map(n => ({ id: n.id, kind: n.kind, actor: n.actor, avatar: n.av || null, group: n.grp_id ? { id: n.grp_id, name: n.grp_name } : null, label: n.kind === "5ha" ? n.grp_name : null, at: n.created, read: !!n.read, pending: !!n.pending }));
    return reply(200, { ok: true, items: list, unread: list.filter(n => !n.read).length });
  }
  if (path === "/social/notifs-read") {
    await env.DB.prepare("UPDATE notifs SET read = 1 WHERE user_id = ? AND read = 0").bind(me).run();
    return reply(200, { ok: true });
  }
  if (path === "/social/5ha") {
    const u = await userByName(b.user, env), item = String(b.item || "");
    if (!u || !/^[lra]:[A-Za-z0-9_:.\-]{1,60}$/.test(item)) return bad("Can't find that.");
    if (u.id === me) return bad("You can't 5HA yourself.");
    if (!(await canSee(me, u.id, env))) return reply(404, { ok: false, error: "You can only 5HA friends and people in your groups." });
    if (b.on) {
      const ins = await env.DB.prepare("INSERT OR IGNORE INTO kudos (owner_id, item, giver_id, created) VALUES (?, ?, ?, ?)").bind(u.id, item, me, now).run();
      const label = String(b.label || "").slice(0, 60);
      const seen = await env.DB.prepare("SELECT 1 FROM notifs WHERE user_id = ? AND kind = '5ha' AND actor = ? AND grp_name IS ? AND created > ?").bind(u.id, who.username, label || null, now - 86400000).first();
      if (ins.meta && ins.meta.changes && !seen) await notify(env, ctx, [u.id], "5ha", { actor: who.username, label }); // once a day per item, however many taps
    } else await env.DB.prepare("DELETE FROM kudos WHERE owner_id = ? AND item = ? AND giver_id = ?").bind(u.id, item, me).run();
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM kudos WHERE owner_id = ? AND item = ?").bind(u.id, item).first();
    return reply(200, { ok: true, n: n ? n.n : 0, mine: !!b.on });
  }
  if (path === "/social/avatar") {
    if (b.remove) { await env.DB.prepare("DELETE FROM avatars WHERE user_id = ?").bind(me).run(); return reply(200, { ok: true, avatar: null }); }
    const m = String(b.data || "").match(/^data:image\/(jpeg|webp|png);base64,([A-Za-z0-9+\/=]+)$/);
    if (!m || m[2].length > 80000) return bad("That photo didn't work. Try another one.");
    const k = randHex(16);
    await env.DB.prepare("INSERT INTO avatars (user_id, k, data, updated) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET k = excluded.k, data = excluded.data, updated = excluded.updated").bind(me, k, b.data, now).run();
    return reply(200, { ok: true, avatar: k });
  }
  if (path === "/push/key") return reply(200, { ok: true, key: (await vapidKeys(env)).pub });
  if (path === "/push/subscribe") {
    const ep = String(b.endpoint || ""), k = b.keys || {};
    if (!PUSH_HOSTS.test(ep) || ep.length > 1000 || !/^[A-Za-z0-9_-]{80,100}$/.test(String(k.p256dh || "")) || !/^[A-Za-z0-9_-]{16,30}$/.test(String(k.auth || ""))) return bad("That phone can't take notifications.");
    await env.DB.prepare("INSERT OR REPLACE INTO push_subs (endpoint, user_id, p256dh, auth, created) VALUES (?, ?, ?, ?, ?)").bind(ep, me, k.p256dh, k.auth, now).run();
    await env.DB.prepare("DELETE FROM push_subs WHERE user_id = ? AND endpoint NOT IN (SELECT endpoint FROM push_subs WHERE user_id = ? ORDER BY created DESC LIMIT 10)").bind(me, me).run();
    return reply(200, { ok: true });
  }
  if (path === "/push/unsubscribe") {
    await env.DB.prepare("DELETE FROM push_subs WHERE endpoint = ? AND user_id = ?").bind(String(b.endpoint || ""), me).run();
    return reply(200, { ok: true });
  }
  if (path === "/push/test") {
    await notify(env, ctx, [me], "test", { actor: who.username });
    return reply(200, { ok: true });
  }

  if (path === "/group/create") {
    const name = String(b.name || "").trim().replace(/\s+/g, " ").slice(0, 30);
    if (name.length < 2) return bad("Give the group a name.");
    const own = await env.DB.prepare("SELECT COUNT(*) AS n FROM grp WHERE owner = ?").bind(me).first();
    if (own && own.n >= MAX_OWNED_GROUPS) return bad(`You can make up to ${MAX_OWNED_GROUPS} groups.`);
    let id = null;
    for (let i = 0; !id && i < 5; i++) {
      try { id = (await env.DB.prepare("INSERT INTO grp (name, code, owner, created) VALUES (?, ?, ?, ?)").bind(name, newCode(), me, now).run()).meta.last_row_id; } catch (e) {}
    }
    if (!id) return reply(500, { ok: false, error: "Couldn't make the group. Try again." });
    await env.DB.prepare("INSERT INTO grp_members (grp_id, user_id, joined) VALUES (?, ?, ?)").bind(id, me, now).run();
    return reply(200, { ok: true, id });
  }

  if (path === "/group/join") {
    const code = cleanCode(b.code);
    const g = code.length >= 6 && await env.DB.prepare("SELECT id, name FROM grp WHERE code = ?").bind(code).first();
    if (!g) return reply(404, { ok: false, error: "No group has that code. Check it and try again." });
    if (await env.DB.prepare("SELECT 1 FROM grp_members WHERE grp_id = ? AND user_id = ?").bind(g.id, me).first()) return reply(200, { ok: true, id: g.id, name: g.name, already: true });
    const [size, mine] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS n FROM grp_members WHERE grp_id = ?").bind(g.id).first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM grp_members WHERE user_id = ?").bind(me).first()]);
    if (size && size.n >= MAX_GROUP_SIZE) return bad("That group is full.");
    if (mine && mine.n >= MAX_GROUPS) return bad(`You can be in up to ${MAX_GROUPS} groups.`);
    await env.DB.prepare("INSERT INTO grp_members (grp_id, user_id, joined) VALUES (?, ?, ?)").bind(g.id, me, now).run();
    const others = ((await env.DB.prepare("SELECT user_id FROM grp_members WHERE grp_id = ? AND user_id != ?").bind(g.id, me).all()).results || []).map(r => r.user_id);
    await notify(env, ctx, others, "joined", { actor: who.username, grpId: g.id, grpName: g.name });
    return reply(200, { ok: true, id: g.id, name: g.name });
  }

  // everything below needs you to be in the group
  const gid = Number(b.id) || 0;
  const g = await env.DB.prepare("SELECT g.id, g.name, g.code, g.owner FROM grp g JOIN grp_members m ON m.grp_id = g.id AND m.user_id = ? WHERE g.id = ?").bind(me, gid).first();
  if (!g) return reply(404, { ok: false, error: "You're not in that group." });
  const isOwner = g.owner === me;

  if (path === "/group/view") {
    const r = await env.DB.prepare("SELECT u.id, u.username, s.summary, s.share, m.joined, a.k AS av FROM grp_members m JOIN users u ON u.id = m.user_id LEFT JOIN social s ON s.user_id = u.id LEFT JOIN avatars a ON a.user_id = u.id WHERE m.grp_id = ? ORDER BY m.joined").bind(g.id).all();
    const week = String(b.week || "");
    const members = (r.results || []).map(x => {
      const s = visible(x.summary, x.share, x.id === me);
      return { username: x.username, self: x.id === me, owner: x.id === g.owner, published: !!s, avatar: x.av || null,
        week: s && s.weeks[week] || null, streak: s && s.streak ? s.streak.cur : null, share: s ? s.share : null };
    });
    return reply(200, { ok: true, id: g.id, name: g.name, code: g.code, owner: isOwner, members });
  }
  if (path === "/group/leave") {
    await env.DB.prepare("DELETE FROM grp_members WHERE grp_id = ? AND user_id = ?").bind(g.id, me).run();
    const next = await env.DB.prepare("SELECT user_id FROM grp_members WHERE grp_id = ? ORDER BY joined LIMIT 1").bind(g.id).first();
    if (!next) await env.DB.prepare("DELETE FROM grp WHERE id = ?").bind(g.id).run();          // last one out
    else if (isOwner) await env.DB.prepare("UPDATE grp SET owner = ? WHERE id = ?").bind(next.user_id, g.id).run(); // hand it on
    return reply(200, { ok: true });
  }
  if (!isOwner) return reply(403, { ok: false, error: "Only the group's owner can do that." });
  if (path === "/group/kick") {
    const u = await userByName(b.username, env);
    if (!u || u.id === me) return bad("Pick someone else.");
    await env.DB.prepare("DELETE FROM grp_members WHERE grp_id = ? AND user_id = ?").bind(g.id, u.id).run();
    return reply(200, { ok: true });
  }
  if (path === "/group/newcode") {
    for (let i = 0; i < 5; i++) {
      const c = newCode();
      try { await env.DB.prepare("UPDATE grp SET code = ? WHERE id = ?").bind(c, g.id).run(); return reply(200, { ok: true, code: c }); } catch (e) {}
    }
    return reply(500, { ok: false, error: "Try again." });
  }
  if (path === "/group/rename") {
    const name = String(b.name || "").trim().replace(/\s+/g, " ").slice(0, 30);
    if (name.length < 2) return bad("Give the group a name.");
    await env.DB.prepare("UPDATE grp SET name = ? WHERE id = ?").bind(name, g.id).run();
    return reply(200, { ok: true });
  }
  return reply(404, { ok: false, error: "not found" });
}
async function makeFriends(x, y, env){
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO friends (a, b, created) VALUES (?, ?, ?)").bind(x, y, now),
    env.DB.prepare("INSERT OR IGNORE INTO friends (a, b, created) VALUES (?, ?, ?)").bind(y, x, now),
    env.DB.prepare("DELETE FROM friend_reqs WHERE (from_id = ?1 AND to_id = ?2) OR (from_id = ?2 AND to_id = ?1)").bind(x, y)
  ]);
}

// ---------- Notifications ----------
// Every notification is kept for 30 days for the bell in the app, and also sent as a phone notification
// to any phone that switched them on. Phone notifications use the standard Web Push protocol (RFC 8291 + VAPID).
// The VAPID signing key is made once and kept in D1, so there's nothing to set up.
const PUSH_HOSTS = /^https:\/\/([a-z0-9-]+\.)*(fcm\.googleapis\.com|android\.googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)\//i;
function notifText(kind, d){
  if (kind === "req") return `${d.actor} sent you a friend request`;
  if (kind === "accepted") return `${d.actor} accepted your friend request`;
  if (kind === "declined") return `${d.actor} declined your friend request`;
  if (kind === "joined") return `${d.actor} joined ${d.grpName}`;
  if (kind === "5ha") return `${d.actor} gave you 5HA${d.label ? " for " + d.label : ""}`;
  if (kind === "test") return "Notifications are on. You'll hear about friend requests and group joins here.";
  return "Something new on OnlyPains";
}
async function notify(env, ctx, userIds, kind, d){
  if (!userIds.length) return;
  const now = Date.now();
  if (kind !== "test") await env.DB.batch(userIds.map(u => env.DB.prepare("INSERT INTO notifs (user_id, kind, actor, grp_id, grp_name, created) VALUES (?, ?, ?, ?, ?, ?)").bind(u, kind, d.actor || null, d.grpId || null, d.grpName || d.label || null, now)));
  const msg = { title: "OnlyPains", body: notifText(kind, d), url: APP_URL + "#notifs", tag: `${kind}-${d.actor || ""}-${d.grpId || ""}` };
  const p = pushTo(env, userIds, msg).catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(p); else await p;
}
async function markReqHandled(me, actor, env){
  await env.DB.prepare("UPDATE notifs SET read = 1 WHERE user_id = ? AND kind = 'req' AND actor = ?").bind(me, actor).run();
}
async function pushTo(env, userIds, msg){
  const subs = [];
  for (let i = 0; i < userIds.length; i += 90) {
    const part = userIds.slice(i, i + 90);
    const r = await env.DB.prepare(`SELECT endpoint, p256dh, auth FROM push_subs WHERE user_id IN (${part.map(() => "?").join(",")})`).bind(...part).all();
    subs.push(...(r.results || []));
  }
  if (!subs.length) return;
  const vapid = await vapidKeys(env);
  await Promise.all(subs.map(async sub => {
    try {
      const r = await sendPush(vapid, sub, msg);
      if (r.status === 404 || r.status === 410) await env.DB.prepare("DELETE FROM push_subs WHERE endpoint = ?").bind(sub.endpoint).run(); // phone unsubscribed
    } catch (e) {}
  }));
}
const b64uEnc = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const cat = (...arrs) => { const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };
let vapidCache = null;
async function vapidKeys(env){
  if (vapidCache) return vapidCache;
  let row = await env.DB.prepare("SELECT v FROM app_kv WHERE k = 'vapid'").first();
  if (!row) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const v = JSON.stringify({ pub: b64uEnc(await crypto.subtle.exportKey("raw", kp.publicKey)), jwk: await crypto.subtle.exportKey("jwk", kp.privateKey) });
    await env.DB.prepare("INSERT OR IGNORE INTO app_kv (k, v) VALUES ('vapid', ?)").bind(v).run();
    row = await env.DB.prepare("SELECT v FROM app_kv WHERE k = 'vapid'").first();
  }
  const v = JSON.parse(row.v);
  vapidCache = { pub: v.pub, key: await crypto.subtle.importKey("jwk", v.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]) };
  return vapidCache;
}
async function vapidJwt(vapid, aud){
  const head = b64uEnc(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64uEnc(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: APP_URL })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, vapid.key, enc.encode(head + "." + body));
  return head + "." + body + "." + b64uEnc(sig);
}
async function hkdf(salt, ikm, info, len){
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
// encrypt for one phone (aes128gcm, RFC 8291) and hand it to that phone's push service
async function sendPush(vapid, sub, msg){
  const ua = b64u(sub.p256dh), auth = b64u(sub.auth);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(enc.encode("WebPush: info\0"), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, cat(enc.encode(JSON.stringify(msg)), new Uint8Array([2]))));
  const head = new Uint8Array(21 + asPub.length);
  head.set(salt, 0); new DataView(head.buffer).setUint32(16, 4096); head[20] = asPub.length; head.set(asPub, 21);
  return fetch(sub.endpoint, { method: "POST", body: cat(head, ct), headers: {
    "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": "86400", "Urgency": "normal",
    "Authorization": `vapid t=${await vapidJwt(vapid, new URL(sub.endpoint).origin)}, k=${vapid.pub}` } });
}

// ---------- Profile photos ----------
// Shrunk to 256 px on the phone before upload. Served by a random key that changes with every new photo,
// so it can be cached for good and only people who were handed the key (friends, group-mates) can load it.
async function avatarImage(k, env){
  if (!env.DB) return new Response("", { status: 404 });
  let row = null;
  try { row = await env.DB.prepare("SELECT data FROM avatars WHERE k = ?").bind(k).first(); } catch (e) {}
  const m = row && String(row.data).match(/^data:(image\/[a-z]+);base64,(.+)$/);
  if (!m) return new Response("", { status: 404 });
  return new Response(b64u(m[2].replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")), { headers: {
    "Content-Type": m[1], "Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff", "Access-Control-Allow-Origin": "*" } });
}
