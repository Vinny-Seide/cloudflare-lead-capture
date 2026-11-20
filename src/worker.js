// Lead capture and tap analytics for digital business cards, on Cloudflare Workers + D1.
//
// Routes
//   GET  /card/:id        card page view, logged to D1, then served from static assets
//   GET  /card/:id.vcf    contact save, logged to D1, then served from static assets
//   POST /lead            "share your info" form: Turnstile check, validation, rate limit, D1, Teams alert
//   GET  /stats           JSON summary for the last N days, behind Cloudflare Access
//
// Bindings (wrangler.toml): DB (D1), ASSETS (static files)
// Variables: CARDS, SITE_HOSTNAME, ACCESS_TEAM_DOMAIN, ACCESS_AUD, STATS_ALLOWLIST
// Secrets (wrangler secret put): TURNSTILE_SECRET, TEAMS_WEBHOOK_URL, IP_HASH_SALT

const BOT_UA = /bot|crawl|spider|slurp|preview|facebookexternalhit|linkedinbot|whatsapp|skypeuripreview|curl|wget|python|headless|monitor|uptime/i;
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
  "trashmail.com", "yopmail.com", "sharklasers.com", "getnada.com", "maildrop.cc"
]);
const DUPLICATE_WINDOW_MS = 10 * 60 * 1000;
const LEADS_PER_IP_PER_HOUR = 3;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const cardIds = (env) => new Set(String(env.CARDS || "").split(",").map((s) => s.trim()).filter(Boolean));

// Strip control characters and cap length.
const clean = (value, max) => String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function deviceType(userAgent) {
  if (/iphone|ipad/i.test(userAgent)) return "ios";
  if (/android/i.test(userAgent)) return "android";
  if (/mac os|windows|linux|cros/i.test(userAgent)) return "desktop";
  return "other";
}

// ---------------------------------------------------------------------------
// Tap logging
// ---------------------------------------------------------------------------

export function parseCardPath(pathname, env) {
  const m = pathname.match(/^\/card\/([a-z0-9-]+?)(\.vcf|\.html|\/)?$/i);
  if (!m) return null;
  const card = m[1].toLowerCase();
  if (!cardIds(env).has(card)) return null;
  return { card, event: m[2] === ".vcf" ? "save" : "view" };
}

export async function logTap(request, url, env, hit) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua || BOT_UA.test(ua)) return { logged: false, reason: "bot" };
  // Browsers prefetching a link are not real visits.
  if (request.headers.get("purpose") === "prefetch" || request.headers.get("sec-purpose")) return { logged: false, reason: "prefetch" };

  let src = clean(url.searchParams.get("src"), 40).toLowerCase().replace(/[^a-z0-9_-]/g, "");
  if (!src) {
    const ref = request.headers.get("referer") || "";
    let refHost = "";
    try { refHost = ref ? new URL(ref).hostname : ""; } catch { refHost = "invalid"; }
    src = !ref ? "direct" : refHost === url.hostname ? "site" : "referral";
  }
  const cf = request.cf || {};
  const now = new Date();
  const device = deviceType(ua);

  // A refresh within the window is still stored, but only the first one sends an alert.
  const dup = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM taps WHERE card = ?1 AND event = ?2 AND src = ?3 AND device = ?4 AND IFNULL(city,'') = ?5 AND ts > ?6"
  ).bind(hit.card, hit.event, src, device, cf.city || "", new Date(now.getTime() - DUPLICATE_WINDOW_MS).toISOString()).first();

  await env.DB.prepare(
    "INSERT INTO taps (ts, card, event, src, device, country, region, city) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
  ).bind(now.toISOString(), hit.card, hit.event, src, device, cf.country || null, cf.regionCode || null, cf.city || null).run();

  if (!dup || !dup.n) {
    const where = [cf.city, cf.regionCode, cf.country].filter(Boolean).join(", ") || "Unknown location";
    await notifyTeams(env, `${hit.event === "save" ? "Contact saved" : "Card opened"}: ${hit.card}`, [
      ["Source", src], ["Where", where], ["Device", device], ["When (UTC)", now.toISOString()]
    ]);
  }
  return { logged: true, src, device };
}

// ---------------------------------------------------------------------------
// Lead form
// ---------------------------------------------------------------------------

async function verifyTurnstile(env, token, ip) {
  const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: clean(token, 2048) });
  if (ip) body.set("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    const result = await r.json();
    return result.success === true && (!env.SITE_HOSTNAME || result.hostname === env.SITE_HOSTNAME);
  } catch {
    return false;
  }
}

export async function submitLead(request, env, ctx) {
  if (!env.TURNSTILE_SECRET || !env.IP_HASH_SALT) return json({ ok: false, error: "unavailable" }, 503);

  let b;
  try { b = await request.json(); } catch { return json({ ok: false, error: "bad_request" }, 400); }

  // Honeypot field: real visitors never fill it. Report success so bots don't adapt.
  if (clean(b.website, 100)) return json({ ok: true });

  const card = cardIds(env).has(b.card) ? b.card : "team";
  const name = clean(b.name, 100);
  const email = clean(b.email, 160).toLowerCase();
  const phone = clean(b.phone, 40);
  const company = clean(b.company, 120);
  const note = clean(b.note, 1000);
  const src = clean(b.src, 40).toLowerCase().replace(/[^a-z0-9_-]/g, "") || "card";

  if (name.length < 2) return json({ ok: false, error: "name" }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(email) || DISPOSABLE_DOMAINS.has(email.split("@")[1])) return json({ ok: false, error: "email" }, 400);
  if (phone && phone.replace(/\D/g, "").length < 10) return json({ ok: false, error: "phone" }, 400);

  const ip = request.headers.get("cf-connecting-ip") || "";
  if (!(await verifyTurnstile(env, b.token, ip))) return json({ ok: false, error: "captcha" }, 403);

  // Raw IPs are never stored. A salted hash is enough to rate-limit.
  const ipKey = (await sha256Hex(`${env.IP_HASH_SALT}|${ip}`)).slice(0, 24);
  const now = new Date();
  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM leads WHERE ip_key = ?1 AND ts > ?2")
    .bind(ipKey, new Date(now.getTime() - 3600000).toISOString()).first();
  if (recent && recent.n >= LEADS_PER_IP_PER_HOUR) return json({ ok: false, error: "rate_limited" }, 429);

  const cf = request.cf || {};
  await env.DB.prepare(
    "INSERT INTO leads (ts, card, src, name, email, phone, company, note, city, region, ip_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
  ).bind(now.toISOString(), card, src, name, email, phone || null, company || null, note || null, cf.city || null, cf.regionCode || null, ipKey).run();

  const alert = notifyTeams(env, `New lead: ${name}`, [
    ["Email", email], ["Phone", phone || "-"], ["Company", company || "-"], ["Card", card], ["Source", src], ["Note", note || "-"]
  ]);
  if (ctx && ctx.waitUntil) ctx.waitUntil(alert); else await alert;

  return json({ ok: true, first: name.split(/\s+/)[0] });
}

// ---------------------------------------------------------------------------
// Teams alert (Teams Workflows "When a Teams webhook request is received")
// ---------------------------------------------------------------------------

export async function notifyTeams(env, title, facts) {
  if (!env.TEAMS_WEBHOOK_URL) return;
  const card = {
    type: "message",
    attachments: [{
      contentType: "application/vnd.microsoft.card.adaptive",
      content: {
        $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
        type: "AdaptiveCard",
        version: "1.4",
        body: [
          { type: "TextBlock", text: title, weight: "Bolder", size: "Medium", wrap: true },
          { type: "FactSet", facts: facts.map(([t, v]) => ({ title: t, value: String(v) })) }
        ]
      }
    }]
  };
  try {
    const r = await fetch(env.TEAMS_WEBHOOK_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(card) });
    if (!r.ok) console.error(JSON.stringify({ teams_webhook_status: r.status }));
  } catch (e) {
    console.error(JSON.stringify({ teams_webhook_error: String(e && e.message || e) }));
  }
}

// ---------------------------------------------------------------------------
// Stats, behind Cloudflare Access. The Access JWT is verified here too, so the
// endpoint stays closed even if the Access policy is removed by mistake.
// ---------------------------------------------------------------------------

const b64urlToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

export async function verifyAccessJwt(request, env, fetchImpl = fetch) {
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  } catch { return null; }
  if (header.alg !== "RS256") return null;

  const certs = await (await fetchImpl(`https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`)).json();
  const jwk = (certs.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlToBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!ok) return null;

  const now = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(env.ACCESS_AUD) || payload.exp < now || payload.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;

  const allow = String(env.STATS_ALLOWLIST || "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
  const email = String(payload.email || "").toLowerCase();
  return allow.includes(email) ? email : null;
}

export async function stats(request, env) {
  const user = await verifyAccessJwt(request, env);
  if (!user) return json({ error: "forbidden" }, 403);

  const days = Math.min(Math.max(parseInt(new URL(request.url).searchParams.get("days"), 10) || 30, 1), 365);
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const q = (sql, ...args) => env.DB.prepare(sql).bind(...args).all().then((r) => r.results || []);

  const [byCard, bySource, byDay, byCity, leads] = await Promise.all([
    q("SELECT card, SUM(event = 'view') AS views, SUM(event = 'save') AS saves FROM taps WHERE ts >= ?1 GROUP BY card", since),
    q("SELECT src, COUNT(*) AS n FROM taps WHERE ts >= ?1 AND event = 'view' GROUP BY src ORDER BY n DESC", since),
    q("SELECT substr(ts, 1, 10) AS day, SUM(event = 'view') AS views, SUM(event = 'save') AS saves FROM taps WHERE ts >= ?1 GROUP BY day ORDER BY day", since),
    q("SELECT IFNULL(city, 'Unknown') AS city, IFNULL(region, '') AS region, COUNT(*) AS n FROM taps WHERE ts >= ?1 GROUP BY city, region ORDER BY n DESC LIMIT 10", since),
    q("SELECT COUNT(*) AS n FROM leads WHERE ts >= ?1", since)
  ]);
  return json({ days, viewer: user, byCard, bySource, byDay, byCity, leads: leads[0] ? leads[0].n : 0 });
}

// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/lead") {
      return request.method === "POST" ? submitLead(request, env, ctx) : json({ error: "method_not_allowed" }, 405);
    }
    if (url.pathname === "/stats" && request.method === "GET") return stats(request, env);

    if (request.method === "GET") {
      const hit = parseCardPath(url.pathname, env);
      // Logging runs after the response is sent, and a logging failure never breaks the page.
      if (hit && ctx && ctx.waitUntil) ctx.waitUntil(logTap(request, url, env, hit).catch((e) => console.error(String(e))));
    }
    return env.ASSETS.fetch(request);
  }
};
