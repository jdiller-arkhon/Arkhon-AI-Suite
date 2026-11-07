-- Customer portal: people at a customer company who sign in to see their own licenses,
-- computers and downloads. Separate from Arkhon staff (admins) on purpose.

CREATE TABLE portal_users (
    id              TEXT PRIMARY KEY,                -- pu-<random>
    customer_id     TEXT NOT NULL REFERENCES customers(id),
    email           TEXT NOT NULL UNIQUE,            -- one company per email address
    name            TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL CHECK (role IN ('owner','billing','viewer')),
    password_hash   TEXT,                            -- argon2id PHC string; NULL until the invite is accepted
    totp_secret     BYTEA,                           -- set once two-step sign-in is confirmed
    totp_pending    BYTEA,                           -- secret being enrolled, not yet confirmed
    status          TEXT NOT NULL CHECK (status IN ('invited','active','removed')),
    created_at      BIGINT NOT NULL
);
CREATE INDEX portal_users_customer ON portal_users (customer_id);

-- One-time links for invites and password resets. Only the hash is stored.
CREATE TABLE portal_invites (
    token_hash  BYTEA PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES portal_users(id),
    purpose     TEXT NOT NULL CHECK (purpose IN ('invite','reset')),
    expires_at  BIGINT NOT NULL,
    used_at     BIGINT
);

CREATE TABLE portal_sessions (
    token_hash  BYTEA PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES portal_users(id),
    expires_at  BIGINT NOT NULL
);
