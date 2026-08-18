-- Manager Key Pro — schema v0.1
-- Design: manager-key-pro-design.md (v4.0). Findings that shaped this file:
--   * usage_records.upstream_account holds UsageRecord.AuthID, which CPA formats as
--     "provider:kind:id" (e.g. "claude:apikey:fd74e9378020"), so no separate type column.
--   * One client request can produce several usage records (CPA retries other credentials),
--     hence client_request_id + attempt_no + billed.
--   * Wallet belongs to a user; quota belongs to a key, exactly one at a time.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- Users own the wallet. Sign in with Telegram or username+password; no email anywhere.
CREATE TABLE IF NOT EXISTS users (
    id                 TEXT PRIMARY KEY,
    username           TEXT NOT NULL UNIQUE,
    password_hash      TEXT,                                  -- argon2id; NULL = Telegram only
    telegram_id        TEXT UNIQUE,                           -- NULL = password only
    role               TEXT NOT NULL DEFAULT 'user',          -- user | admin
    status             TEXT NOT NULL DEFAULT 'active',        -- active | pending | disabled | banned
    balance            INTEGER NOT NULL DEFAULT 0,            -- micro-credit; 1 USD = 1 credit
    wallet_mode        TEXT NOT NULL DEFAULT 'prepaid',       -- prepaid | postpaid
    credit_limit       INTEGER NOT NULL DEFAULT 0,            -- postpaid floor, micro-credit
    referral_code      TEXT NOT NULL UNIQUE,
    referred_by        TEXT REFERENCES users(id),
    failed_logins      INTEGER NOT NULL DEFAULT 0,
    locked_until       INTEGER,
    created_at         INTEGER NOT NULL,
    last_login_at      INTEGER,
    CHECK (role IN ('user','admin')),
    CHECK (status IN ('active','pending','disabled','banned')),
    CHECK (wallet_mode IN ('prepaid','postpaid')),
    CHECK (id <> referred_by)                                 -- nobody refers themselves
);
CREATE INDEX IF NOT EXISTS idx_users_upline ON users(referred_by);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,                             -- sha256 of the cookie value
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip          TEXT,
    user_agent  TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

-- Admin-authored catalogue. Buying one applies its quota onto a fresh or existing key.
CREATE TABLE IF NOT EXISTS packages (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    description    TEXT,
    quota_kind     TEXT NOT NULL,                             -- credit | token | request | unlimited
    quota_scope    TEXT NOT NULL,                             -- lifetime | hour | day | week | month
    quota_amount   INTEGER NOT NULL,
    duration_days  INTEGER NOT NULL DEFAULT -1,               -- -1 = no time limit
    price_credit   INTEGER NOT NULL,                          -- micro-credit
    allowed_models TEXT NOT NULL DEFAULT '[]',
    rpm            INTEGER NOT NULL DEFAULT 60,
    visible        INTEGER NOT NULL DEFAULT 1,                -- 0 = hidden from portal, still assignable
    created_at     INTEGER NOT NULL,
    CHECK (quota_kind IN ('credit','token','request','unlimited')),
    CHECK (quota_scope IN ('lifetime','hour','day','week','month')),
    CHECK (quota_amount >= 0),
    CHECK (price_credit >= 0)
);

-- Keys carry exactly one quota state. Stored twice: hash to authenticate, cipher to re-reveal.
CREATE TABLE IF NOT EXISTS keys (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash           TEXT NOT NULL UNIQUE,                  -- sha256(plaintext)
    key_cipher         BLOB NOT NULL,                         -- AES-256-GCM ciphertext
    key_nonce          BLOB NOT NULL,
    prefix             TEXT NOT NULL,                         -- first chars, for display only
    name               TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active',        -- active|disabled|banned|expired|exhausted
    quota_kind         TEXT NOT NULL DEFAULT 'credit',
    quota_scope        TEXT NOT NULL DEFAULT 'lifetime',
    quota_amount       INTEGER NOT NULL DEFAULT 0,
    quota_used         INTEGER NOT NULL DEFAULT 0,
    period_start       INTEGER,
    period_end         INTEGER,
    expires_at         INTEGER NOT NULL DEFAULT -1,           -- -1 = never
    overflow_to_wallet INTEGER NOT NULL DEFAULT 0,            -- user-controlled switch
    package_id         TEXT REFERENCES packages(id),
    allowed_models     TEXT NOT NULL DEFAULT '[]',
    allowed_providers  TEXT NOT NULL DEFAULT '[]',
    ip_allowlist       TEXT NOT NULL DEFAULT '[]',
    rpm                INTEGER NOT NULL DEFAULT 60,
    log_mode           TEXT,                                  -- NULL = follow global setting
    pricing_overrides  TEXT,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    last_used_at       INTEGER,
    CHECK (status IN ('active','disabled','banned','expired','exhausted')),
    CHECK (quota_kind IN ('credit','token','request','unlimited')),
    CHECK (quota_scope IN ('lifetime','hour','day','week','month')),
    CHECK (quota_amount >= 0),
    CHECK (quota_used >= 0),
    CHECK (log_mode IS NULL OR log_mode IN ('full','standard','error_only'))
);
CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(user_id, status);
CREATE INDEX IF NOT EXISTS idx_keys_hash ON keys(key_hash);

-- Every quota change leaves a trace: assign, switch kind, renew, period reset, expiry.
CREATE TABLE IF NOT EXISTS key_quota_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id      TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    action      TEXT NOT NULL,                                -- assign|switch|renew|reset|expire
    before_json TEXT,
    after_json  TEXT,
    actor       TEXT NOT NULL,                                -- admin:<id> | user:<id> | system
    created_at  INTEGER NOT NULL,
    CHECK (action IN ('assign','switch','renew','reset','expire'))
);
CREATE INDEX IF NOT EXISTS idx_quota_history_key ON key_quota_history(key_id, created_at);

CREATE TABLE IF NOT EXISTS orders (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id),
    package_id   TEXT NOT NULL REFERENCES packages(id),
    key_id       TEXT REFERENCES keys(id),                    -- key created, or key renewed
    kind         TEXT NOT NULL,                               -- new_key | renew
    price_credit INTEGER NOT NULL,
    status       TEXT NOT NULL,                               -- paid | failed | refunded
    created_at   INTEGER NOT NULL,
    CHECK (kind IN ('new_key','renew')),
    CHECK (status IN ('paid','failed','refunded'))
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at);

-- Wallet ledger: every movement, independently auditable.
CREATE TABLE IF NOT EXISTS credit_ledger (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT NOT NULL REFERENCES users(id),
    key_id        TEXT,                                       -- key that caused it, when relevant
    delta         INTEGER NOT NULL,                           -- micro-credit, signed
    reason        TEXT NOT NULL,
    ref_id        TEXT,                                       -- usage id | order id | tx id
    channel       TEXT,                                       -- dashboard|telegram|portal|system
    balance_after INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    CHECK (reason IN ('recharge','usage','purchase','renew','refund','overflow','referral_bonus','adjust','hold'))
);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON credit_ledger(user_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_tx ON credit_ledger(ref_id)
    WHERE channel = 'telegram' AND ref_id IS NOT NULL;        -- webhook idempotency

CREATE TABLE IF NOT EXISTS referral_earnings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      TEXT NOT NULL REFERENCES users(id),          -- receives the reward
    from_user_id TEXT NOT NULL REFERENCES users(id),          -- downline that generated it
    tier         INTEGER NOT NULL,                            -- 1 = direct
    mode         TEXT NOT NULL,                               -- percent | fixed
    base_amount  INTEGER,                                     -- recharge amount when percent
    reward       INTEGER NOT NULL,
    ref_id       TEXT,
    created_at   INTEGER NOT NULL,
    CHECK (mode IN ('percent','fixed')),
    CHECK (tier >= 1)
);
CREATE INDEX IF NOT EXISTS idx_ref_earn_user ON referral_earnings(user_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ref_earn_fixed_once
    ON referral_earnings(user_id, from_user_id) WHERE mode = 'fixed';

-- Open holds. Persisted so a crash between hold and settle can be reconciled at boot.
CREATE TABLE IF NOT EXISTS reservations (
    reservation_id TEXT PRIMARY KEY,                          -- host RequestID
    key_id         TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id),
    model          TEXT NOT NULL,
    hold           INTEGER NOT NULL,                          -- micro-credit held
    source         TEXT NOT NULL,                             -- key_quota | wallet
    status         TEXT NOT NULL DEFAULT 'open',              -- open | settled | released
    created_at     INTEGER NOT NULL,
    CHECK (source IN ('key_quota','wallet')),
    CHECK (status IN ('open','settled','released'))
);
CREATE INDEX IF NOT EXISTS idx_reservations_open ON reservations(status, created_at);

CREATE TABLE IF NOT EXISTS usage_records (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id              TEXT NOT NULL,
    user_id             TEXT NOT NULL,
    provider            TEXT,
    model               TEXT,
    requested_name      TEXT,                                 -- UsageRecord.Alias: what the client asked for
    upstream_account    TEXT,                                 -- UsageRecord.AuthID, "provider:kind:id"
    input_tokens        INTEGER NOT NULL DEFAULT 0,
    output_tokens       INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens    INTEGER NOT NULL DEFAULT 0,
    cached_tokens       INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens   INTEGER NOT NULL DEFAULT 0,
    cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
    cost                INTEGER NOT NULL DEFAULT 0,           -- micro-credit charged
    source              TEXT,                                 -- key_quota | wallet | NULL when unbilled
    billed              INTEGER NOT NULL DEFAULT 1,           -- 0 = failed attempt with no tokens
    client_request_id   TEXT,                                 -- groups retries of one client request
    attempt_no          INTEGER NOT NULL DEFAULT 1,
    status              TEXT NOT NULL,                        -- ok|failed|canceled|rejected
    failure_status_code INTEGER,
    ttft_ms             INTEGER,
    latency_ms          INTEGER,
    created_at          INTEGER NOT NULL,
    CHECK (source IS NULL OR source IN ('key_quota','wallet')),
    CHECK (status IN ('ok','failed','canceled','rejected'))
);
CREATE INDEX IF NOT EXISTS idx_usage_key_time ON usage_records(key_id, created_at);
CREATE INDEX IF NOT EXISTS idx_usage_user_time ON usage_records(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_usage_client_req ON usage_records(client_request_id);

-- Detailed logs. Only mode=full stores customer content, and only briefly.
CREATE TABLE IF NOT EXISTS request_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    usage_id        INTEGER,
    key_id          TEXT,
    user_id         TEXT,
    mode            TEXT NOT NULL,                            -- full | standard | error_only
    request_context TEXT,                                     -- full only, secrets redacted
    response_body   TEXT,                                     -- full only
    error_code      TEXT,
    upstream_status INTEGER,
    upstream_body   TEXT,                                     -- redacted
    provider        TEXT,
    attempt         INTEGER,
    fallback_from   TEXT,
    purge_after     INTEGER,                                  -- TTL for mode=full rows
    created_at      INTEGER NOT NULL,
    CHECK (mode IN ('full','standard','error_only'))
);
CREATE INDEX IF NOT EXISTS idx_reqlog_purge ON request_logs(purge_after);
CREATE INDEX IF NOT EXISTS idx_reqlog_key ON request_logs(key_id, created_at);

CREATE TABLE IF NOT EXISTS pricing (
    model                 TEXT PRIMARY KEY,
    input_per_mtok        REAL NOT NULL DEFAULT 0,
    output_per_mtok       REAL NOT NULL DEFAULT 0,
    reasoning_per_mtok    REAL NOT NULL DEFAULT 0,
    cache_read_per_mtok   REAL NOT NULL DEFAULT 0,
    cache_write_per_mtok  REAL NOT NULL DEFAULT 0,
    per_call_credit       REAL,                                -- non-NULL = charge per call
    hold_multiplier       REAL NOT NULL DEFAULT 1.5,
    updated_at            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT,
    key_id     TEXT,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,                                 -- key.reveal, quota.switch, log.mode…
    detail     TEXT NOT NULL,                                 -- JSON, secrets redacted
    ip         TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_key ON audit_log(key_id, created_at);

-- Runtime-adjustable settings (fx, referral mode, log mode, backup).
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Single-row table tracking the applied schema version.
CREATE TABLE IF NOT EXISTS schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT INTO schema_meta (id, version) VALUES (1, 1)
    ON CONFLICT(id) DO NOTHING;
