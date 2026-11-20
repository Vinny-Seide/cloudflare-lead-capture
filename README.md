# cloudflare-lead-capture

A Cloudflare Worker that adds lead capture and tap analytics to digital business cards. No servers to run: the Worker, a D1 database and static files cover all of it, and it fits in Cloudflare's free plan at small-business volume.

## What it does

- **Tap analytics.** Every time someone opens a card (`/card/<id>`) or saves the contact (`/card/<id>.vcf`), the Worker logs it to D1: the source (`?src=nfc`, `?src=qr`, a referral or a direct visit), the device type and the city. Bots, link previews and browser prefetches are skipped. Logging runs after the page is sent, so it never slows a visit down or breaks the page if it fails.
- **Lead capture.** A "share your info" form on the card posts to `/lead`. The Worker checks a Cloudflare Turnstile token, validates the fields, rejects throwaway email domains, catches bots with a honeypot field, and limits each IP to three leads an hour. The lead goes into D1 and an alert goes to a Teams channel.
- **Teams alerts.** New leads and first-time card opens post an Adaptive Card to Teams through a Teams Workflows webhook. Refreshes within 10 minutes are stored but don't alert again.
- **Stats endpoint.** `/stats` returns opens, saves, sources, cities and lead counts as JSON. It sits behind Cloudflare Access, and the Worker also verifies the Access JWT itself (signature, audience, issuer, expiry and an email allowlist), so it stays closed even if the Access policy is ever removed.

## Privacy

Client IP addresses are never stored. The rate limit uses a salted SHA-256 hash of the IP. City and region come from Cloudflare's request metadata, not from the browser.

## Layout

```
src/worker.js          the Worker
schema.sql             D1 tables and indexes
wrangler.toml          bindings and settings (placeholders, no real IDs)
public/card/alex.html  sample card page with the lead form
public/card/alex.vcf   sample contact file
test/                  tests that run the Worker against a real SQLite database
```

## Setup

1. Create the database and apply the schema:
   ```bash
   npx wrangler d1 create lead-capture
   npx wrangler d1 execute lead-capture --remote --file=schema.sql
   ```
   Put the returned `database_id` in `wrangler.toml`.
2. Create a Turnstile widget for your hostname. Put the site key in the card page and set the secret:
   ```bash
   npx wrangler secret put TURNSTILE_SECRET
   ```
3. In Teams, add the **Workflows** app to the channel and use the "Post to a channel when a webhook request is received" template. Set the URL it gives you:
   ```bash
   npx wrangler secret put TEAMS_WEBHOOK_URL
   ```
4. Set a random salt for IP hashing:
   ```bash
   openssl rand -hex 32 | npx wrangler secret put IP_HASH_SALT
   ```
5. In Cloudflare Zero Trust, create an Access application for `/stats`. Copy its AUD tag and your team domain into `wrangler.toml`, along with the emails allowed to view stats.
6. Set `CARDS` to your card ids and deploy:
   ```bash
   npm install
   npx wrangler deploy
   ```

## Tests

```bash
npm test
```

The tests use Node's built-in SQLite to run the real SQL from `schema.sql`. They cover bot filtering, duplicate alerts, input validation, Turnstile failures and hostname checks, the honeypot, the per-IP rate limit, IP hashing, and Access JWT checks (valid, wrong user, wrong audience, expired, forged signature, missing token). Requires Node 22.13 or later.

## License

MIT
