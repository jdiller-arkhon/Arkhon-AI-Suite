# Arkhon operations runbook

For Arkhon staff who run the License Manager and support customers. Everything day-to-day happens
in the **Operator Console** (`/console` on the License Manager), and every action there is recorded
in the audit log. Commands below use `make`; run `make` on its own to see every target.

## 0. One-time setup
1. **Root key (offline).** On an air-gapped machine, run `make keys-root OUT=/secure/root.key`. Store the file offline, ideally with two copies in two places. Copy the printed **public** key: it is compiled into the runtime and set as `ARKHON_ROOT_PUBLIC_KEY`.
2. **Issuing key.** Still offline, run `make keys-issuing ROOT=/secure/root.key OUT=issuing.key CERT=issuing.cert SERIAL=1`. Move `issuing.key` and `issuing.cert` into the server's secret store. Never commit them.
3. **First revocation list.** Run `arkhon-keygen revoke --root /secure/root.key --version 1 --serials "" --out rl.bin`, then upload it (`POST /admin/revocations`). Activation stays off until a list exists.
4. **Release-key encryption key.** Run `openssl rand -hex 32 > cek-kek.hex` and put it in the secret store (a KMS in production).
5. **Deploy.** Use `deploy/docker-compose.yml`, behind a TLS reverse proxy.
6. **Operators.** For each person, run `make admin EMAIL=… PASSWORD='…'` and scan the printed link into their authenticator app.

## 1. Onboard a customer (about 2 minutes)
1. In the Console, go to **Customers → Add a customer**.
2. Go to **Licenses → Issue a license**. Pick the customer and plan. Seats, workspaces, engines and terms fill in from the plan; adjust seats or computers if needed. For trades customers, pick the *Trades & field services* pack. For an offline site, pick *90 days* of offline grace.
3. Copy the **activation key** shown. It's displayed once only, because Arkhon stores just a hash.
4. Send the key to the customer's owner. They paste it into Arkhon during setup.

**14-day trial:** use the *14-day trial* plan, which allows computers without a TPM.

## 2. Everyday support
| Customer says | Do this |
|---|---|
| "We got a new computer" | Licenses → open the license → **Free this slot** on the old computer, then they activate the new one. (They can also deactivate from inside the app.) |
| "It says all computers are in use" | Same as above, or raise **Computers** by issuing an updated license. |
| "It says our hardware changed too much" | More than one major part was replaced. Free the old slot, and they activate again. |
| "We're on a ship / an air-gapped site" | They export a renewal file from the app. You (or they, through the portal later) send it to `POST /v1/offline/renew` and return the response file. Each file works once. |
| "Can we add people?" | Seats are on the license. Issue the change, then they invite people in Company → People. |

## 3. Billing events
- **Payment failed:** open the license → **Pause**. Computers keep working until their current device license runs out (at most the license term, 30 days by default), and then they stop renewing, with a plain message.
- **Paid again:** **Resume**.
- **Renewal:** **Renew 1 year**, which extends both the end date and the update window.
- **Contract ended for cause:** **Revoke…** (click twice). This is final; issue a new license if they come back.

## 4. Releases
1. The packaging pipeline encrypts the engine and produces the file size, its SHA-256 and the release key.
2. Go to Console → **Releases**, fill those in and click **Publish**. The server signs the manifest and seals the key.
3. Customers inside their update window receive the release key at their next check-in. Customers outside it keep their current version.

## 5. Incidents
| Event | Response |
|---|---|
| **Issuing key exposed** | (1) Offline, issue a new issuing key with the next serial. (2) Sign a revocation list that revokes the old serial, with a higher version, and upload it. (3) Swap the server's key files and restart. Devices pick up the new list at their next check-in, and licenses signed by the old key stop verifying. |
| **Root key exposed** | Critical. Every runtime trusts it. Ship a runtime update with a new root public key. Re-issue every issuing key and license. Treat it as a security incident. |
| **License key leaked publicly** | Revoke that license and issue a new one to the customer. The old key then stops activating. |
| **Leaked engine found** | Use `tools/trace` (Phase 7) to identify the customer from its fingerprint. Then revoke the license and follow the EULA. |
| **Server compromised** | No customer content is on it. Rotate the issuing key (above), the release-key KEK and the database credentials. Review the audit log. |

## 6. Health checks
- **Console → Overview** flags licenses ending within 30 days, and computers not seen for 30 days (possibly offline or uninstalled).
- `GET /healthz` is for uptime monitoring.
- **Audit log:** filter by license or customer id to see exactly who did what.
