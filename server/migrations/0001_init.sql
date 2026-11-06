-- Arkhon License Manager schema. Holds license and activation METADATA only:
-- no customer content ever reaches this database (N1).

CREATE TABLE customers (
    id          TEXT PRIMARY KEY,                    -- cust-<random>
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    created_at  BIGINT NOT NULL
);

CREATE TABLE licenses (
    id                  TEXT PRIMARY KEY,            -- lic-<random>
    customer_id         TEXT NOT NULL REFERENCES customers(id),
    key_hash            BYTEA NOT NULL UNIQUE,       -- SHA-256 of the activation key; the key itself is shown once
    plan                TEXT NOT NULL CHECK (plan IN ('starter','business','pro','trial')),
    seats               INTEGER NOT NULL CHECK (seats > 0),
    max_devices         INTEGER NOT NULL CHECK (max_devices > 0),
    workspaces          TEXT[] NOT NULL,
    engines             TEXT[] NOT NULL,
    packs               TEXT[] NOT NULL,
    allow_software_binding BOOLEAN NOT NULL,
    starts_at           BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL,
    update_window_end   BIGINT NOT NULL,
    offline_grace_days  INTEGER NOT NULL CHECK (offline_grace_days BETWEEN 1 AND 365),
    license_term_days   INTEGER NOT NULL CHECK (license_term_days BETWEEN 1 AND 400),
    status              TEXT NOT NULL CHECK (status IN ('active','suspended','revoked')),
    created_at          BIGINT NOT NULL
);

CREATE TABLE activations (
    id                  BIGSERIAL PRIMARY KEY,
    license_id          TEXT NOT NULL REFERENCES licenses(id),
    device_public_key   BYTEA NOT NULL,
    fingerprint         BYTEA NOT NULL,
    binding             TEXT NOT NULL CHECK (binding IN ('tpm','secure-enclave','software')),
    status              TEXT NOT NULL CHECK (status IN ('active','deactivated')),
    activated_at        BIGINT NOT NULL,
    last_checkin_at     BIGINT NOT NULL,
    deactivated_at      BIGINT
);
CREATE UNIQUE INDEX activations_one_active_per_device
    ON activations (license_id, device_public_key) WHERE status = 'active';

CREATE TABLE releases (
    id              TEXT PRIMARY KEY,                -- hex release id
    engine          TEXT NOT NULL,
    version         TEXT NOT NULL,
    released_at     BIGINT NOT NULL,
    manifest        BYTEA NOT NULL,                  -- signed manifest bytes
    cek_sealed      BYTEA NOT NULL,                  -- CEK encrypted under the server KEK
    created_at      BIGINT NOT NULL,
    UNIQUE (engine, version)
);

CREATE TABLE revocation_lists (
    version     BIGINT PRIMARY KEY,
    list        BYTEA NOT NULL,                      -- root-signed bytes
    uploaded_at BIGINT NOT NULL
);

CREATE TABLE admins (
    email           TEXT PRIMARY KEY,
    password_hash   TEXT NOT NULL,                   -- argon2id PHC string
    totp_secret     BYTEA NOT NULL,
    created_at      BIGINT NOT NULL
);

CREATE TABLE admin_sessions (
    token_hash  BYTEA PRIMARY KEY,
    email       TEXT NOT NULL REFERENCES admins(email),
    expires_at  BIGINT NOT NULL
);

CREATE TABLE audit_log (
    id      BIGSERIAL PRIMARY KEY,
    at      BIGINT NOT NULL,
    actor   TEXT NOT NULL,                           -- admin email, 'device', or 'system'
    action  TEXT NOT NULL,
    target  TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_target ON audit_log (target);

CREATE TABLE seen_renewal_requests (
    request_id  BYTEA PRIMARY KEY,
    seen_at     BIGINT NOT NULL
);
