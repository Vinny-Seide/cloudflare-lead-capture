-- D1 schema. Apply with:
--   npx wrangler d1 execute <database-name> --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS taps (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL,          -- ISO 8601, UTC
  card    TEXT NOT NULL,          -- card id from the CARDS variable
  event   TEXT NOT NULL,          -- 'view' or 'save'
  src     TEXT NOT NULL,          -- ?src= value (nfc, qr, email...) or direct / site / referral
  device  TEXT NOT NULL,          -- ios, android, desktop, other
  country TEXT,
  region  TEXT,
  city    TEXT
);
CREATE INDEX IF NOT EXISTS idx_taps_ts ON taps (ts);
CREATE INDEX IF NOT EXISTS idx_taps_card_ts ON taps (card, ts);

CREATE TABLE IF NOT EXISTS leads (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL,
  card    TEXT NOT NULL,
  src     TEXT NOT NULL,
  name    TEXT NOT NULL,
  email   TEXT NOT NULL,
  phone   TEXT,
  company TEXT,
  note    TEXT,
  city    TEXT,
  region  TEXT,
  ip_key  TEXT NOT NULL           -- salted SHA-256 of the client IP, for rate limiting only
);
CREATE INDEX IF NOT EXISTS idx_leads_ip_ts ON leads (ip_key, ts);
