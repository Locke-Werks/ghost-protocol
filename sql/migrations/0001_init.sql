-- Ghost Protocol: the auth plumbing and the request trail.
--
-- Nothing this server retrieves is stored. Page text, screenshots and DOM never
-- reach the database; a capture lives in memory for the length of one tool call
-- and is gone. What persists is who may sign in, which clients have registered,
-- the short-lived grants between them, and a line per request saying where the
-- relay was pointed.

CREATE SCHEMA IF NOT EXISTS ghost;

-- Login credentials for the built-in authorization page. One row per principal;
-- `ghost_cli passwd` writes them. password_phc is a PHC-format scrypt string, so
-- the parameters travel with the hash and can be raised later without a flag day.
CREATE TABLE IF NOT EXISTS ghost.principal_credentials (
    principal    TEXT PRIMARY KEY,
    password_phc TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dynamically registered OAuth clients (RFC 7591). claude.ai and ChatGPT
-- self-register when the connector is added. Rows are cheap and prunable;
-- redirect_uris are stored exactly as registered and matched exactly at
-- authorize time, registration having already enforced https and the
-- redirect-host allowlist.
CREATE TABLE IF NOT EXISTS ghost.oauth_clients (
    client_id           TEXT PRIMARY KEY,
    client_secret_hash  TEXT,               -- sha256 hex; NULL = public client, PKCE only
    token_endpoint_auth TEXT NOT NULL DEFAULT 'none'
        CHECK (token_endpoint_auth IN ('none','client_secret_post','client_secret_basic')),
    client_name         TEXT,
    redirect_uris       JSONB NOT NULL,     -- array of exact-match https URIs
    scope               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ
);

-- Single-use authorization codes. Row lifetime is minutes. A code presented
-- twice is a replay: the exchange revokes every refresh-token family that code
-- minted and refuses.
CREATE TABLE IF NOT EXISTS ghost.oauth_codes (
    code_hash      TEXT PRIMARY KEY,        -- sha256 hex; the plaintext is never stored
    client_id      TEXT NOT NULL REFERENCES ghost.oauth_clients(client_id) ON DELETE CASCADE,
    principal      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,           -- must match the exchange's redirect_uri
    code_challenge TEXT NOT NULL,           -- PKCE S256 challenge
    resource       TEXT,                    -- RFC 8707 binding when the client sent one
    scope          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ              -- set atomically by the single-use claim
);
CREATE INDEX IF NOT EXISTS oauth_codes_expires_idx ON ghost.oauth_codes (expires_at);

-- Rotating refresh tokens. Each rotation inserts a successor sharing the
-- family_id and stamps rotated_at on its predecessor. Presenting a token whose
-- rotated_at is already set is the theft signal from RFC 9700 and revokes the
-- whole family.
CREATE TABLE IF NOT EXISTS ghost.oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,            -- sha256 hex; the plaintext is shown once
    family_id  UUID NOT NULL,
    client_id  TEXT NOT NULL REFERENCES ghost.oauth_clients(client_id) ON DELETE CASCADE,
    principal  TEXT NOT NULL,
    scope      TEXT,
    resource   TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,                 -- successor issued; reuse after this is theft
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS oauth_refresh_family_idx ON ghost.oauth_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_principal_idx ON ghost.oauth_refresh_tokens (principal);

-- Where the relay was pointed, and what came back. The URL and the counts, not
-- the content: this is an operational trail, not an archive of the web.
CREATE TABLE IF NOT EXISTS ghost.request_log (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    principal          TEXT NOT NULL,
    tool               TEXT NOT NULL,
    url                TEXT NOT NULL,
    final_url          TEXT,
    status             INTEGER,
    ok                 BOOLEAN NOT NULL,
    injection_findings INTEGER NOT NULL DEFAULT 0,
    hidden_elements    INTEGER NOT NULL DEFAULT 0,
    bytes              INTEGER,
    detail             TEXT
);
CREATE INDEX IF NOT EXISTS request_log_at_idx ON ghost.request_log (at DESC);
CREATE INDEX IF NOT EXISTS request_log_principal_idx ON ghost.request_log (principal, at DESC);

-- Auth events worth keeping separately from the request trail: logins, client
-- registrations, refresh-token reuse.
CREATE TABLE IF NOT EXISTS ghost.audit (
    id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    action    TEXT NOT NULL,
    principal TEXT,
    details   JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS audit_at_idx ON ghost.audit (at DESC);
