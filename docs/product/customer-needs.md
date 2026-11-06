# Customer needs (N1–N11)

Every product, model and feature decision must trace to at least one need below. PR descriptions
and gate reports cite need IDs. **If a feature serves no need, it is cut.**

Target customer: small and mid-sized businesses, 2–200 employees, often with no in-house AI or IT
specialist.

| ID | Need | What it means for Arkhon | Primary proof point |
|----|------|--------------------------|---------------------|
| N1 | **Privacy and data control.** The #1 barrier to adoption: owners won't put customer, client or financial data into cloud AI. | All inference, retrieval and fine-tuning run on the customer's machine. Customer data never reaches Arkhon servers; license checks send license metadata only. Visible in-product and verifiable via a network-activity log. | Automated outbound-traffic capture test during a full workspace session; Privacy Center live connection log. |
| N2 | **No in-house AI expertise.** | One-click installer, automatic hardware detection and model selection, ready-made workflows instead of a blank chat box. Users never pick a model. | Install → first useful result in < 15 min with zero model choices. |
| N3 | **Too many tools.** The average AI-using small business juggles ~5 separate AI tools. | One suite, one install, one license, one admin panel replacing several subscriptions. | Workspace coverage map vs. the tools a customer replaces. |
| N4 | **Accuracy and trust.** | Answers grounded in the customer's data with citations, confidence flags, "not found in your data" over guessing, and human approval before anything is sent or changed. | Citation-accuracy and faithfulness evals; zero unapproved external actions in audit log. |
| N5 | **Unproven ROI.** | Built-in Value Dashboard: hours saved, drafts accepted, documents processed, estimated $ saved — measured locally from real usage. | Monthly ROI export; one-week trial shows measured time saved. |
| N6 | **Works inside existing tools.** | Connectors: M365/Outlook, Google Workspace/Gmail, IMAP/SMTP, local/SMB/OneDrive/Google Drive files, QuickBooks Online, Xero, HubSpot, calendars. | Connector integration tests; pilot customers use existing mailboxes and files unchanged. |
| N7 | **Communication is the biggest daily workload.** | The Inbox drafting experience is the flagship and must be excellent first. | Draft-acceptance rate; pairwise preference vs. base. |
| N8 | **Customer service and sales load.** | Support-reply and outreach drafting grounded in the company's policies, products and history. | Desk/Growth draft acceptance; grounded-answer faithfulness. |
| N9 | **Supervised automation, not autopilot.** | Workflows run up to a review queue; autonomy is opt-in per workflow; every action logged. | Review-queue gate on every external action; audit log completeness test. |
| N10 | **Predictable cost.** | Flat annual per-site + per-seat licensing; no usage meters. Runs on owned or recommended hardware. | No metering code paths; pricing page. |
| N11 | **Industry fit.** | Industry Packs: document schemas, templates, workflows, vocabulary and eval sets per vertical. | Pack eval set passes on base engines; pilot feedback. |

## Traceability

| Component | Needs |
|-----------|-------|
| Inbox workspace | N1, N4, N6, N7 |
| Desk workspace | N4, N8 |
| Docs workspace | N1, N4, N6, N11 |
| Knowledge workspace | N1, N4 |
| Meetings workspace | N1, N7 |
| Growth workspace | N3, N8 |
| Insights workspace | N5, N6 |
| Dev workspace (add-on) | — (revenue add-on; powers Arkhon AI) |
| Review queue + workflows | N9, N4 |
| Citations & confidence | N4 |
| Company Voice / Arkhon Tune | N7, N8 |
| Value Dashboard | N5 |
| Privacy Center | N1 |
| Onboarding wizard, model router, env detection | N2 |
| Licensing (flat, no metering) | N10 |
| Industry Packs | N11 |
| Connectors | N6, N3 |

> Source note: N1–N11 are taken from the founder brief (2026-11). The discovery kit in
> `docs/discovery/` is designed to validate or re-rank them with real owners before Phase 5 pilots.
> No third-party statistic is asserted here beyond what the brief states; figures such as "~5 tools"
> must be re-confirmed with a cited source before use in marketing.
