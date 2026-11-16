// OnlyPains feedback relay (Cloudflare Worker).
// Receives feedback from the app and forwards it to your Telegram via your bot.
// The bot token never appears in the app: it lives here as a secret.
//
// Secrets to add in Cloudflare (Worker > Settings > Variables and Secrets, type "Secret"):
//   BOT_TOKEN  the token BotFather gave you
//   CHAT_ID    your own Telegram chat id (see worker/README.md)

const ALLOWED_ORIGINS = ["https://nuhihsan.github.io"];
const TYPES = ["Bug", "Idea", "Other"];

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const allowed = ALLOWED_ORIGINS.includes(origin);
    const cors = {
      "Access-Control-Allow-Origin": allowed ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin"
    };
    const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST" || !allowed) return reply(403, { ok: false, error: "not allowed" });
    if (!env.BOT_TOKEN || !env.CHAT_ID) return reply(500, { ok: false, error: "worker not set up" });

    let b;
    try { b = await req.json(); } catch (e) { return reply(400, { ok: false, error: "bad request" }); }
    if (b && b.website) return reply(200, { ok: true }); // honeypot field that only bots fill in

    const type = TYPES.includes(b.type) ? b.type : "Other";
    const msg = String(b.msg || "").trim().slice(0, 2000);
    const name = String(b.name || "").trim().slice(0, 40) || "anonymous";
    if (!msg) return reply(400, { ok: false, error: "empty message" });

    const text = `OnlyPains feedback: ${type}\n\n${msg}\n\nFrom: ${name}`;
    const tg = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.CHAT_ID, text, disable_web_page_preview: true })
    });
    return tg.ok ? reply(200, { ok: true }) : reply(502, { ok: false, error: "telegram refused the message" });
  }
};
