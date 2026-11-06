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
- **Customer portal** (`/portal` page, `/portal/...` API; see below).

## Customer portal
A single static page at `/portal` (strict CSP, no external resources) on top of the `/portal/...` API.
People at a customer company sign in to see **their own company only**.

- **Accounts:** portal users belong to one customer, with a role: `owner` (can change things), `billing` (reads everything plus billing) or `viewer` (reads). Passwords are argon2id (12+ characters). Two-step sign-in (TOTP) is optional per person. Sessions last 2 hours, in `portal_sessions`, separate from admin sessions; an admin token doesn't work on `/portal` and vice versa.
- **Invites:** Arkhon staff invite a customer's first owner with `POST /admin/customers/{id}/portal-invite`; owners invite the rest from **Team**. Each invite or reset link (`/portal#accept=<token>`) works once, for 7 days, and only its hash is stored. **Email isn't wired yet:** links are returned in the API response and written to the server log (`portal invite link for …`). SMTP comes later.
- **Scoping:** every portal query filters by the signed-in person's customer. Another company's license, computer, person or renewal file answers **404**, exactly as if it didn't exist.
- **Owner-only actions (all audited as `portal:<email>`):** request a new activation key (rotates `key_hash`: the old key stops activating new computers, running computers are unaffected, the key is shown once), deactivate a computer (frees its slot), offline activation (upload a `RenewalRequest` file, download the `RenewalResponse`; the same single-use rule as `/v1/offline/renew`), and team invite/remove/reset. You can't remove yourself or the last owner.
- **Downloads:** releases each license may install (inside its update window), with file sizes and SHA-256.
- **Billing:** `GET /portal/invoices` returns a "Billing is being set up" placeholder. No payment provider is connected.
- **Free trial:** `POST /portal/trial` (public) creates the company, a 14-day `trial` license (plan preset, 2 computers, software binding allowed) and an owner invite, and returns the activation key once. Limited to 5 sign-ups per hour per IP, on top of the global limit.

## Tests
```bash
ARKHON_TEST_DATABASE_URL=postgresql://arkhon@127.0.0.1:5433/postgres cargo test -p arkhon-license-server
```
Each test creates its own database. CI runs them against a Postgres service.

## Production TODOs
- Run the issuing key in a KMS/HSM: implement `IssuingSigner` over it.
- Use a KMS data key for `CekVault`.
- Use a shared rate limiter at the edge when running several instances.
- Add passkeys for admins and portal users.
- Wire SMTP so invite, reset and trial links are emailed instead of shown and logged.
- Connect online billing to the `/portal/invoices` placeholder.
