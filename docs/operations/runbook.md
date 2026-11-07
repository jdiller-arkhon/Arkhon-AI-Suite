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
| "We're on a ship / an air-gapped site" | They export a renewal file from the app, then upload it in the portal under **Offline activation** and take the reply file back. (You can also send it to `POST /v1/offline/renew` for them.) Each file works once. |
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

## 7. Customer portal
Customers manage their own account at **`/portal`** on the License Manager. They only ever see their own company.

**Give a customer access (first owner).** After creating the customer and license, call
`POST /admin/customers/{id}/portal-invite` with `{"email": "...", "role": "owner"}` (admin session).
The response has an `invite_link` (`/portal#accept=…`). **Email isn't set up yet**: send the full link
(`https://<license-server>/portal#accept=…`) to the customer yourself. It works once, for 7 days. The
link is also written to the server log (`portal invite link for …`), so treat those logs as sensitive.

**What customers can do there.**
| Page | Who | What |
|---|---|---|
| Overview | everyone | Plain-language status, people, computers in use, next renewal. |
| Licenses | everyone | Plan, dates, workspaces, engines. Owners can **Request a new activation key** (old key stops activating new computers; running computers keep working). The key is never shown again after that. |
| Computers | everyone (owners act) | **Deactivate** frees a slot, for example after replacing a computer. |
| Offline activation | owners | Upload a renewal file from an offline computer, download the reply. Each file works once. |
| Downloads | everyone | Engine versions their licenses include, with sizes and SHA-256. |
| Team | everyone (owners act) | Invite (owner / billing / viewer), remove, issue a password reset link, turn on two-step sign-in. |
| Billing | owners, billing | Placeholder: "Billing is being set up". No online payments yet. |

**Free trial.** `/portal#trial` lets anyone start a 14-day trial: it creates the customer, a trial license
(10 people, 2 computers, no TPM needed) and an owner account, and shows the activation key once.
Limited to 5 sign-ups per hour per IP. Trials appear in the Console like any other customer.

**Support.**
| Customer says | Do this |
|---|---|
| "My invite link doesn't work" | It expired (7 days) or was already used. Send a new one with the same `portal-invite` call (it replaces the old link), or an owner uses **Team → New invite link**. |
| "I forgot my password" | Another owner uses **Team → Password reset link**. If they're the only owner, call `portal-invite` again for their email (this resets their password and two-step sign-in, and ends their sessions). |
| "I lost my authenticator" | Call `portal-invite` again for their email. From Arkhon staff this clears their password and two-step sign-in and ends their sessions; they set a new password from the link. |
| "We lost our activation key" | An owner uses **Licenses → Request a new activation key**. Nothing stops working. |
| "Someone left the company" | An owner removes them under **Team**; their sessions end at once. |

**Audit.** Portal actions appear in the audit log with actor `portal:<email>` (sign-in, invites, new keys,
deactivations, offline renewals, team changes, trial sign-ups). Filter by the customer id or license id.
