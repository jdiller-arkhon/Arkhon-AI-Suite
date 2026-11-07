# ADR-0003: Launch Industry Pack — Trades & field services

- Status: Accepted (owner decision, 2026-11-06) · Needs: N11, N5, N6

## Decision
The launch pack is **Trades & field services** (HVAC, plumbing, electrical, construction, general
contractors).

## Scope for Phase 6
- **Document schemas (Docs):** supplier bills/invoices, receipts, purchase orders, work orders, change orders, quotes/estimates, lien waivers, certificates of insurance, permits.
- **Workflows:** supplier bill → extract → match PO → QuickBooks/Xero draft bill (approval); inbound job request email → triage → quote draft; job complete → invoice draft + follow-up; expiring COI/permit reminders.
- **Templates and vocabulary:** quote and estimate language, scheduling and dispatch replies, warranty and service-call responses, and trade terminology (SEER, rough-in, punch list, T&M, retainage).
- **Eval set:** extraction field-F1 per document type and reply-draft rubrics, sourced from licensed datasets and design partners' real documents (with permission). Nothing authored by Claude.
- **Disclaimers:** no code-compliance, legal, tax or engineering advice; pricing drafts need human review.

## Consequences
- The Docs → QuickBooks Online/Xero path becomes launch-critical, so connectors are prioritized in Phase 6.
- Buyers are less technical, which raises the bar on N2 (zero-config onboarding) and on a mobile-photo receipt intake path.
- Discovery interviews should over-sample trades owners (≥ 6 of the first 12).
