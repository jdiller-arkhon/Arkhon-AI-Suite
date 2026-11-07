# ADR-0006: Connected apps — company and personal accounts

- Status: Accepted (owner direction, 2026-11-06) · Needs: N6, N3, N1, N9
- Implementation: `crates/arkhon-org/src/connections.rs` (12 tests); UI in `suite/app/design/dashboard.html#connections`

## Context
The owner wants many relevant apps to be connectable at the organization level. People under the
admins should also be able to connect accounts themselves, without every setup going through the owner.

## Decision
**Two kinds of connection**
- **Company account:** a shared account, such as the service mailbox, the books or the shared drive. It is shared with *Everyone*, chosen *roles*, or chosen *teams*.
- **Personal account:** a person's own work mailbox or calendar. Only that person can use it.

**A rule for each app, set by admins.** These are plain-language options in the App library.
| Rule | Admins | Everyone else |
|---|---|---|
| Off | — | — (existing connections pause, and resume if it's turned back on) |
| Admins only | connect anything | nothing |
| Everyone: own accounts | connect anything | their own account |
| Everyone: own + team accounts | connect anything | their own account, plus accounts shared with **teams they're on** |

Defaults follow what each app is like. Mail, calendars and personal drives default to "own accounts".
Accounting, CRM, payments and job systems default to "Admins only".

**What a connection may do:** *Read*, *Draft* (the default; a person approves before anything is sent
or changed, N9), or *Act*. Act is never allowed on personal accounts. On company accounts it
requires the automations permission.

**When people change:** if someone is paused, their personal connections pause too. If someone is
removed, their personal connections are disconnected. Company accounts they set up stay connected,
and admins can still manage them.

**Privacy (N1):** OAuth tokens are stored encrypted on the customer's machine by the connector
framework (Phase 5). Arkhon's servers never see tokens or content.

**App library, 20 apps:** Outlook, Gmail, Google Calendar, other email (IMAP), OneDrive/SharePoint,
Google Drive, local or network folder, Dropbox, QuickBooks Online, Xero, HubSpot, ServiceTitan,
Jobber, Housecall Pro, Stripe, Square, Microsoft Teams, Slack, Zoom, DocuSign.
- **Scheduled now:** the brief's N6 set. Mail, files and folders come in Phase 5. QuickBooks, Xero and HubSpot come in Phase 6.
- **Shown as "Coming soon":** everything else. Each needs its API terms, OAuth app-review requirements and rate limits verified and recorded in an ADR before it is committed (brief §2). This matters most for the field-service apps (ServiceTitan, Jobber, Housecall Pro), which fit the Trades launch pack.
- **Logos:** the UI uses neutral letter tiles, not vendor logos, until brand-use terms are checked.
