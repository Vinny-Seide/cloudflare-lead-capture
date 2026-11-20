// Runs the Worker logic against a real SQLite database (node:sqlite) shaped like D1.
// Run: node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import worker, { parseCardPath, logTap, submitLead, verifyAccessJwt } from "../src/worker.js";

function fakeD1() {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync(new URL("../schema.sql", import.meta.url), "utf8"));
  return {
    raw: db,
    prepare(sql) {
      let args = [];
      const stmt = {
        bind(...a) { args = a; return stmt; },
        async first() { return db.prepare(sql.replace(/\?(\d+)/g, "?")).get(...args) ?? null; },
        async all() { return { results: db.prepare(sql.replace(/\?(\d+)/g, "?")).all(...args) }; },
        async run() { return db.prepare(sql.replace(/\?(\d+)/g, "?")).run(...args); }
      };
      return stmt;
    }
  };
}

function makeEnv(overrides = {}) {
  return {
    DB: fakeD1(),
    CARDS: "alex,team",
    SITE_HOSTNAME: "example.com",
    TURNSTILE_SECRET: "test-secret",
    IP_HASH_SALT: "test-salt",
    TEAMS_WEBHOOK_URL: "https://teams.example/webhook",
    ASSETS: { fetch: async () => new Response("asset") },
    ...overrides
  };
}

// Records outbound calls and fakes Turnstile and Teams.
function mockFetch({ turnstileOk = true, hostname = "example.com" } = {}) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: init && init.body });
    if (String(url).includes("turnstile")) return new Response(JSON.stringify({ success: turnstileOk, hostname }));
    return new Response("ok");
  };
  return calls;
}

const browserUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15";
const req = (url, init = {}) => new Request(url, init);

test("card paths are recognized only for configured cards", () => {
  const env = makeEnv();
  assert.deepEqual(parseCardPath("/card/alex", env), { card: "alex", event: "view" });
  assert.deepEqual(parseCardPath("/card/alex.vcf", env), { card: "alex", event: "save" });
  assert.equal(parseCardPath("/card/unknown", env), null);
  assert.equal(parseCardPath("/about", env), null);
});

test("bots are not logged; real visits are, and a quick refresh does not alert twice", async () => {
  const env = makeEnv();
  const calls = mockFetch();
  const url = new URL("https://example.com/card/alex?src=nfc");
  const hit = { card: "alex", event: "view" };

  const bot = await logTap(req(url, { headers: { "user-agent": "LinkedInBot/1.0" } }), url, env, hit);
  assert.equal(bot.logged, false);

  await logTap(req(url, { headers: { "user-agent": browserUA } }), url, env, hit);
  await logTap(req(url, { headers: { "user-agent": browserUA } }), url, env, hit);
  const rows = env.DB.raw.prepare("SELECT card, event, src, device FROM taps").all();
  assert.equal(rows.length, 2);
  assert.deepEqual({ ...rows[0] }, { card: "alex", event: "view", src: "nfc", device: "ios" });
  assert.equal(calls.filter((c) => c.url.includes("teams")).length, 1);
});

test("a malformed referer does not throw", async () => {
  const env = makeEnv();
  mockFetch();
  const url = new URL("https://example.com/card/alex");
  const r = await logTap(req(url, { headers: { "user-agent": browserUA, referer: "not a url" } }), url, env, { card: "alex", event: "view" });
  assert.equal(r.src, "referral");
});

const leadReq = (body, ip = "203.0.113.7") => req("https://example.com/lead", {
  method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(body)
});
const good = { card: "alex", name: "Jordan Lee", email: "jordan@contoso.com", phone: "555-010-0100", token: "t" };

test("a valid lead is stored with a hashed IP and posted to Teams", async () => {
  const env = makeEnv();
  const calls = mockFetch();
  const res = await submitLead(leadReq(good), env);
  assert.equal(res.status, 200);
  const row = env.DB.raw.prepare("SELECT name, email, ip_key FROM leads").get();
  assert.equal(row.email, "jordan@contoso.com");
  assert.ok(!row.ip_key.includes("203.0.113.7"));
  assert.equal(calls.filter((c) => c.url.includes("teams")).length, 1);
});

test("leads are rejected for bad input, failed Turnstile and wrong hostname", async () => {
  mockFetch();
  assert.equal((await submitLead(leadReq({ ...good, email: "x@mailinator.com" }), makeEnv())).status, 400);
  assert.equal((await submitLead(leadReq({ ...good, name: "J" }), makeEnv())).status, 400);
  assert.equal((await submitLead(leadReq({ ...good, phone: "123" }), makeEnv())).status, 400);
  mockFetch({ turnstileOk: false });
  assert.equal((await submitLead(leadReq(good), makeEnv())).status, 403);
  mockFetch({ hostname: "attacker.example" });
  assert.equal((await submitLead(leadReq(good), makeEnv())).status, 403);
});

test("honeypot submissions get a fake success and are not stored", async () => {
  const env = makeEnv();
  mockFetch();
  const res = await submitLead(leadReq({ ...good, website: "spam" }), env);
  assert.equal(res.status, 200);
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM leads").get().n, 0);
});

test("more than three leads per IP per hour are rate limited", async () => {
  const env = makeEnv();
  mockFetch();
  for (let i = 0; i < 3; i++) assert.equal((await submitLead(leadReq({ ...good, email: `p${i}@contoso.com` }), env)).status, 200);
  assert.equal((await submitLead(leadReq({ ...good, email: "p9@contoso.com" }), env)).status, 429);
  assert.equal((await submitLead(leadReq({ ...good, email: "other@contoso.com" }, "198.51.100.2"), env)).status, 200);
});

test("stats require a valid Access JWT from an allowlisted user", async () => {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const jwk = { ...(await crypto.subtle.exportKey("jwk", publicKey)), kid: "k1" };
  const env = makeEnv({ ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com", ACCESS_AUD: "aud123", STATS_ALLOWLIST: "alex@example.com" });
  const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
  const sign = async (payload) => {
    const h = b64u(JSON.stringify({ alg: "RS256", kid: "k1" }));
    const p = b64u(JSON.stringify(payload));
    const s = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(`${h}.${p}`));
    return `${h}.${p}.${b64u(new Uint8Array(s))}`;
  };
  const certs = async () => new Response(JSON.stringify({ keys: [jwk] }));
  const base = { aud: ["aud123"], iss: "https://team.cloudflareaccess.com", exp: Math.floor(Date.now() / 1000) + 600 };
  const withJwt = (t) => req("https://example.com/stats", { headers: { "cf-access-jwt-assertion": t } });

  assert.equal(await verifyAccessJwt(withJwt(await sign({ ...base, email: "alex@example.com" })), env, certs), "alex@example.com");
  assert.equal(await verifyAccessJwt(withJwt(await sign({ ...base, email: "eve@example.com" })), env, certs), null);
  assert.equal(await verifyAccessJwt(withJwt(await sign({ ...base, email: "alex@example.com", aud: ["other"] })), env, certs), null);
  assert.equal(await verifyAccessJwt(withJwt(await sign({ ...base, email: "alex@example.com", exp: 1 })), env, certs), null);
  const forged = (await sign({ ...base, email: "alex@example.com" })).replace(/\.[^.]+$/, ".AAAA");
  assert.equal(await verifyAccessJwt(withJwt(forged), env, certs), null);
  assert.equal(await verifyAccessJwt(req("https://example.com/stats"), env, certs), null);
});

test("router: /lead rejects GET, /stats without Access is forbidden, other paths serve assets", async () => {
  const env = makeEnv();
  mockFetch();
  assert.equal((await worker.fetch(req("https://example.com/lead"), env, {})).status, 405);
  assert.equal((await worker.fetch(req("https://example.com/stats"), env, {})).status, 403);
  assert.equal(await (await worker.fetch(req("https://example.com/"), env, {})).text(), "asset");
});
