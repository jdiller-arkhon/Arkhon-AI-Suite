# ADR-0005: Organizations, roles and administration

- Status: Accepted (owner direction, 2026-11-06) · Needs: N3, N9, N2, N10
- Implementation: `crates/arkhon-org` (permission core, 21 tests); admin screens in `suite/app/design/dashboard.html#people`

## Context
Customers range from 2 to 200 people. The owner asked for an organization and role model similar
to team plans in modern AI products: one company, owners and admins, invited members, seats, and
simple controls that a non-technical owner understands.

## Decision
**Structure:** Organization → People (one role each) → Teams (optional groups). Seats are bought on
the license (N10). Invited people hold a seat so a company can't over-invite; paused people free it.

**Built-in roles (every plan):**
| Role | In plain words | Key powers |
|---|---|---|
| Owner | Runs the account | Everything, including plan and billing. At least one is always required |
| Admin | Runs Arkhon day to day | People, roles, teams, company connections, automations, updates. No billing, can't touch owners |
| Manager | Leads a team | Approves their team's work, sees company time-saved reports, manages teams |
| Member | Uses Arkhon | The workspaces they're given. Default: Inbox, Knowledge, Docs |

**Custom roles (Business and Pro):** built from the same 12 plain-language permissions, for example
"Dispatcher" or "Bookkeeper". Billing is owner-only and can never go into a custom role.

**Workspace access** = role defaults ∪ team grants ∩ what the plan includes. Teams scale access
without making a role for every combination, e.g. "Front office" gets Desk + Growth.

**Safety rules (enforced and tested):**
1. Only owners create, change, pause or remove owners.
2. The last active owner can't be demoted, paused or removed. An unaccepted owner invite doesn't count.
3. Nobody can hand out a role or build a custom role with permissions they don't hold (no escalation).
4. Seat limits apply to invites and restores. Seat count changes are owner-only, never below seats in use.
5. Paused people have no permissions and no workspaces.
6. Every refusal returns a sentence an owner can act on, e.g. "All 10 seats are in use. Add seats or remove someone first."

**Where it runs:** the org model is stored locally in the suite and enforced by the engine. Seat
counts are mirrored to the License Manager as license metadata only (counts, roles and hashed
member IDs, never content), so N1 holds.

## Later (not in this ADR)
SSO/SCIM for larger customers (Phase 9 portal), domain capture, multi-site organizations,
and per-connection data scopes. The audit log already records every admin action (brief §4.2).
