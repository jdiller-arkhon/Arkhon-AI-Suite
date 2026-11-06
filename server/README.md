# arkhon-license-server (License Manager)

Issues and manages Arkhon licenses. Stores **license and activation metadata only**; customer content
never reaches it (N1). API: [`openapi.yaml`](openapi.yaml), also served at `/openapi.yaml`.

## Run locally
```bash
# Postgres (any 14+); then:
export DATABASE_URL=postgresql://arkhon@127.0.0.1:5433/arkhon_license
export ARKHON_ROOT_PUBLIC_KEY=<hex>            # arkhon-keygen root --out root.key   (OFFLINE)
export ARKHON_ISSUING_KEY_FILE=issuing.key     # arkhon-keygen issuing --root root.key --out issuing.key --cert issuing.cert --serial 1 --days 365
export ARKHON_ISSUING_CERT_FILE=issuing.cert
export ARKHON_CEK_KEK_FILE=cek-kek.hex          # openssl rand -hex 32 > cek-kek.hex
cargo run -p arkhon-license-server -- create-admin --email you@arkhonindustries.com --password '<14+ chars>'
cargo run -p arkhon-license-server -- serve      # 127.0.0.1:8443 by default
```
Then upload the first revocation list (`arkhon-keygen revoke --version 1 --serials ""`) through
`POST /admin/revocations`. Activation is refused until one exists, so a fresh server can't issue
licenses before it's fully set up. Production deployment: `deploy/docker-compose.yml`.

## What's enforced (each has an integration test against Postgres)
- **Activation:** the activation key is hashed (only the hash is stored). The license must be active and inside its validity window. Software binding is refused unless the license allows it. A device limit applies, serialized per license so concurrent requests can't exceed it. Re-activating the same computer is idempotent.
- **Device licenses** are short-lived (`license_term_days`, default 30) and renewed at check-in. Check-in tolerates one changed hardware component.
- **Suspend** (for example failed payment) blocks check-in with a plain message. **Revoke** is final.
- **Offline renewal:** a `RenewalRequest` file in, a `RenewalResponse` file out. Each request id works once.
- **Releases** are signed by the issuing key, and their CEKs are sealed at rest under the KEK (bound to the release id). Devices only get keys for releases inside their update window.
- **Revocation lists** must be root-signed and strictly newer than the current one.
- **Admins** sign in with password (argon2id) plus TOTP and get an 8-hour session. Every change is in the audit log.
- **Hardening:** a per-IP rate limit (60/min); SQL errors never reach clients.

## Tests
```bash
ARKHON_TEST_DATABASE_URL=postgresql://arkhon@127.0.0.1:5433/postgres cargo test -p arkhon-license-server
```
Each test creates its own database. CI runs them against a Postgres service.

## Production TODOs
- Run the issuing key in a KMS/HSM: implement `IssuingSigner` over it.
- Use a KMS data key for `CekVault`.
- Use a shared rate limiter at the edge when running several instances.
- Add passkeys when the admin portal arrives (Phase 9).
