# DRAFT TEMPLATE FOR ATTORNEY REVIEW — NOT LEGAL ADVICE — DO NOT USE AS-IS

> This document is an engineering-prepared starting point. Arkhon's attorney must review it before it is
> used with any customer. Bracketed text like `[LICENSOR]` is a placeholder. Text marked **[OPTIONAL]**
> is for the attorney to keep or remove. No statute, regulation or case is cited as authority here.
> Where a law may apply, it appears only as a question in Section 22 (Open questions for the attorney).
> Technical claims in this template must stay consistent with [`docs/threat-model.md`](../threat-model.md).

---

# Arkhon Suite End User License Agreement

**Effective date:** `[DATE]`

This End User License Agreement (the "**Agreement**") is between `[LICENSOR LEGAL NAME]`, a
`[STATE/COUNTRY]` `[ENTITY TYPE]` with its principal office at `[ADDRESS]` ("**Arkhon**", "**we**"),
and the business that accepts this Agreement or signs an order for the Software (the "**Customer**",
"**you**"). By installing, activating or using the Software, you agree to this Agreement on behalf of
the Customer, and you confirm that you have authority to do so.

## 1. Definitions

- **"Software"** means Arkhon Suite, the Arkhon Runtime, the Engines, Industry Packs, connectors,
  documentation and any Updates we provide to you.
- **"Engines"** means the machine-learning models (including their weights, adapters and
  configuration) that we deliver with the Software, in any form, encrypted or not.
- **"Industry Pack"** means a set of templates, workflows, schemas, vocabulary and evaluation data for
  a particular industry.
- **"Order"** means the order form, online checkout or invoice that names your plan, Sites, Seats,
  Term and fees.
- **"Site"** means one physical business location `[ATTORNEY: confirm definition, e.g. one address]`
  named in the Order.
- **"Seat"** means one named person in your organization who is allowed to use the Software at a time.
- **"Machine"** means one computer on which the Software is activated.
- **"Customer Data"** means all content you or your users put into, connect to or create with the
  Software, including email, documents, files, prompts, outputs, indexes, recordings and adapters
  trained on your data.
- **"License Metadata"** means the data described in Section 10.2.
- **"Update"** means a new version, fix, Engine or Industry Pack that we make generally available to
  customers on your plan.
- **"Term"** means the license period in your Order.
- **"Update Window"** means the period during which you are entitled to receive Updates, as stated in
  Section 2.4.

## 2. License grant

2.1 **Grant.** Subject to this Agreement and payment of the fees, Arkhon grants you a limited,
non-exclusive, non-transferable (except under Section 9), non-sublicensable license during the Term
to install and use the Software in object-code form, for your internal business purposes only.

2.2 **Per-Site and per-Seat limits.** You may activate the Software on up to `[NUMBER]` Machines at
each Site named in your Order, and make it available to no more than the number of Seats in your
Order. A Seat may be reassigned to another person `[ATTORNEY: e.g. when someone leaves, but not to
share one Seat among several people]`.

2.3 **Term.** The license lasts for the Term in your Order (`[e.g. 12 months]`) and renews as stated
in the Order unless either party gives notice under Section 17. Licenses for Machines that operate
offline have a technical validity of `[90 days]` and must be renewed as described in Section 8; this
does not shorten your paid Term.

2.4 **Update Window.** While your license is active and fees are paid, you are entitled to Updates.
`[ATTORNEY: decide whether a perpetual-use option exists after the Term ends, and if so, that it
covers only versions released inside the Update Window.]`

2.5 **Users.** You may let your employees and contractors use the Software for your benefit. You are
responsible for their compliance with this Agreement.

2.6 **Reservation.** The Software is licensed, not sold. Arkhon and its licensors keep all rights not
expressly granted.

## 3. Restrictions

You will not, and will not permit anyone to:

a. copy, distribute, sell, rent, lease, lend, sublicense, host for third parties, or otherwise make
   the Software available to anyone other than your authorized users;

b. reverse engineer, decompile, disassemble or try to derive the source code, model weights or
   internal structure of the Software, except to the extent applicable law expressly permits this
   despite this restriction `[ATTORNEY: confirm carve-out language for the governing jurisdiction]`;

c. circumvent, disable, or interfere with any license check, activation, encryption, hardware
   binding, watermark, fingerprint or other technical protection in the Software;

d. extract, dump, copy, export or save any Engine weights or adapters from memory, from storage, from
   a graphics processor or from any other location, or use Engines outside the Arkhon Runtime;

e. use the Software or its outputs to develop, train, fine-tune, distill or improve any machine
   learning model that competes with the Software or the Engines;

f. remove or alter any proprietary notice, attribution or license file;

g. exceed the Sites, Machines or Seats in your Order;

h. use the Software in violation of law, or in violation of the third-party usage policies passed
   through in Section 12; or

i. **[OPTIONAL]** publish benchmark or performance test results about the Software without Arkhon's
   prior written consent. `[ATTORNEY: decide whether to keep this clause; consider enforceability and
   customer reaction.]`

## 4. Ownership of Customer Data and outputs

4.1 You own your Customer Data. Arkhon claims no rights in it.

4.2 As between you and Arkhon, you own the outputs the Software generates for you, subject to
Section 3(e) and the third-party terms in Section 12. `[ATTORNEY: confirm wording; consider that
outputs may not be protectable.]`

4.3 Adapters that the Software trains on your Customer Data on your Machine (for example, a
"Company Voice" adapter) are Customer Data. They work only with the Engines and only under a valid
license.

## 5. Fingerprinting, watermarking and tracing (disclosure)

5.1 Each copy of the Engines delivered to you carries a unique fingerprint (watermark) that
identifies your license. Arkhon may also embed identifiers in the Software.

5.2 The fingerprint does not contain or transmit Customer Data, and does not report your use of the
Software to Arkhon. It allows Arkhon to determine, from a copy of Engine weights or from output
produced by them, which license the copy came from.

5.3 If Arkhon finds Engine weights or derived models outside an authorized Arkhon Runtime, Arkhon may
use the fingerprint to identify the source license and may rely on that result in enforcing this
Agreement. `[ATTORNEY: consider evidentiary language; engineering notes that fingerprint robustness
is still being measured.]`

## 6. Audit

6.1 You will keep accurate records of the Machines, Sites and Seats on which you use the Software.

6.2 No more than once in any `[12]`-month period, on at least `[30]` days' written notice, Arkhon (or
an independent auditor bound by confidentiality) may verify your compliance during normal business
hours. **The audit is limited to license usage (Machines, Sites, Seats, activation records). It will
not include access to Customer Data.**

6.3 You may first satisfy an audit request by providing a usage report generated by the Software's
admin panel.

6.4 If an audit shows usage above your entitlement, you will pay the fees for the excess at the
then-current rates `[ATTORNEY: decide on audit-cost shifting threshold, e.g. above [5]% under-licensing]`.

## 7. Activation and hardware binding

7.1 The Software must be activated on each Machine. Activation creates a cryptographic key inside the
Machine's security chip (TPM) where available, and binds the license and Engines to that Machine.

7.2 Where a Machine has no usable security chip, the Software may use a software-based key, shown in
the license as "software binding". Arkhon may limit or refuse software binding on certain plans.

7.3 The Software checks that the system clock has not been set back. If it detects tampering, it may
pause until the clock is corrected or the license is re-validated.

7.4 Replacing or resetting the security chip, or major hardware changes, may require re-activation.

## 8. Offline use

8.1 For Machines that cannot connect to the internet, Arkhon issues licenses valid for `[90 days]`.

8.2 Renewal works by file exchange: the Software produces a request file; an authorized person
uploads it to the customer portal from any connected device; the portal returns a signed license
file to load on the Machine. The request file contains only License Metadata (Section 10.2).

8.3 If an offline license is not renewed before it expires, the Software stops running Engines until
it is renewed. Your Customer Data stays on the Machine and is not deleted.

## 9. Transfer

9.1 **Between your Machines.** You may move a license to a replacement Machine by deactivating the old
Machine in the admin panel or customer portal, then activating the new one. Where the old Machine is
lost or broken, contact support; Arkhon may permit `[NUMBER]` such transfers per `[PERIOD]` without
deactivation.

9.2 **To another business.** You may not assign or transfer this Agreement or any license to another
legal entity without Arkhon's prior written consent, except `[ATTORNEY: e.g. in a merger or sale of
substantially all assets, with notice]`.

## 10. Data and privacy

10.1 **Customer Data stays local.** The Software is designed so that all processing of Customer Data,
including inference, search and adapter training, happens on your Machines. Arkhon does not receive,
store or have access to Customer Data. Connectors you set up exchange Customer Data only between your
Machine and the third-party services you connect, under your own accounts.

10.2 **What Arkhon receives (License Metadata).** Arkhon receives only:
- the license key and license identifier;
- the public part of each Machine's activation key (never the private key);
- a hashed hardware fingerprint of each Machine;
- the binding type (security chip or software);
- Software and Engine version numbers;
- activation, renewal and deactivation dates and times;
- the number of Seats in use, the names and counts of roles, and hashed member identifiers (not names
  or email addresses);
- the IP address of the connection when the Software or portal contacts Arkhon `[ATTORNEY: confirm
  retention and whether to state it]`; and
- account and billing information you give us directly when you buy or manage your license
  (contact name, business name, billing email, address), with payments processed by our payment
  processor `[PAYMENT PROCESSOR]`. Arkhon does not store full card numbers.

Arkhon does not receive prompts, outputs, documents, email, files, recordings, indexes, adapters,
connector credentials or OAuth tokens.

10.3 **Use of License Metadata.** Arkhon uses License Metadata only to activate, validate and renew
licenses, enforce Seat and Machine limits, deliver Updates, prevent fraud, provide support and
invoice you. `[ATTORNEY: link to Privacy Policy; confirm controller/processor roles.]`

10.4 **Diagnostics.** Crash reports are off by default. If you turn them on, they exclude Customer
Data `[ENGINEERING: keep consistent with implementation before release]`.

10.5 **Your responsibilities.** You are responsible for the security of your Machines and networks,
including full-disk encryption, user accounts, backups, and lawful collection and use of personal
data you process with the Software. Arkhon recommends full-disk encryption on every Machine.

10.6 **Support access.** Arkhon support will not access your Machines or Customer Data unless you
start a support session and choose what to share.

## 11. Updates and update gating

11.1 Updates are available only to licenses that are active and paid up.

11.2 Some Updates may be required for continued security or license validation.
`[ATTORNEY: confirm whether mandatory updates are acceptable and how to describe them.]`

11.3 Arkhon may stop providing Updates for versions older than `[PERIOD]`.

## 12. Third-party components and model attributions

12.1 The Engines are fine-tuned from third-party open-weight base models licensed under the Apache
License 2.0 or the MIT License. The base models, their copyright holders and licenses are listed in
the `NOTICE` file, and full license texts are included in the `licenses/` folder of every release.

12.2 Where a base model's licensor publishes a usage policy (as identified in `NOTICE`), you agree to
comply with that policy when using the Engines derived from that base model. Those policies are
incorporated by reference. `[ATTORNEY: confirm pass-through mechanics and whether to reproduce the
policy text in the release.]`

12.3 Open-source components in the Software are licensed under their own licenses, listed in the
release's software bill of materials and `licenses/` folder. Nothing in this Agreement limits your
rights under those licenses.

12.4 Third-party services you connect (email, accounting, CRM, storage and similar) are governed by
your agreements with those providers. Arkhon is not responsible for them.

## 13. Industry Packs and AI outputs: no professional advice

13.1 **Drafts only.** Outputs of the Software, including outputs from Industry Packs, are drafts
generated by machine learning. They may be wrong, incomplete or out of date, even when they show
citations or confidence indicators.

13.2 **No professional advice.** The Software and Industry Packs do not provide legal, medical,
health, financial, tax, accounting, engineering, safety, insurance or other professional advice, and
are not a substitute for a qualified professional.

13.3 **Human review and your approvals.** The Software is designed so that a person reviews and
approves actions before they are sent or carried out. You are responsible for:
- reviewing every output before relying on it or sending it;
- every approval made by your users, and every action you configure to run without approval
  ("automation");
- choosing who in your organization may approve or automate actions; and
- compliance with laws and professional rules that apply to your business.

13.4 **Untrusted content.** Emails and documents from outside your business may contain text intended
to manipulate AI systems. Review drafts carefully, especially those that send information outside
your organization.

## 14. Fees

Fees, payment terms and taxes are as stated in your Order. Fees are flat per Site and per Seat and
are not based on usage. Late amounts may bear interest at `[RATE]` or the maximum permitted by law,
whichever is lower. Arkhon may suspend Updates for unpaid amounts more than `[30]` days overdue after
notice.

## 15. Warranty disclaimer

`[ATTORNEY: decide whether to offer a limited warranty, e.g. media/functionality for [30] days.]`

EXCEPT AS EXPRESSLY STATED IN THIS AGREEMENT, THE SOFTWARE, ENGINES, INDUSTRY PACKS AND ALL OUTPUTS
ARE PROVIDED "AS IS" AND "AS AVAILABLE". TO THE MAXIMUM EXTENT PERMITTED BY LAW, ARKHON AND ITS
LICENSORS DISCLAIM ALL WARRANTIES, EXPRESS, IMPLIED OR STATUTORY, INCLUDING WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, AND THAT THE
SOFTWARE WILL BE ERROR-FREE OR UNINTERRUPTED, OR THAT OUTPUTS WILL BE CORRECT.

## 16. Limitation of liability

16.1 TO THE MAXIMUM EXTENT PERMITTED BY LAW, NEITHER PARTY WILL BE LIABLE FOR ANY INDIRECT,
INCIDENTAL, SPECIAL, CONSEQUENTIAL OR PUNITIVE DAMAGES, OR FOR LOST PROFITS, REVENUE, DATA OR
GOODWILL, ARISING OUT OF THIS AGREEMENT, EVEN IF ADVISED OF THEIR POSSIBILITY.

16.2 TO THE MAXIMUM EXTENT PERMITTED BY LAW, EACH PARTY'S TOTAL LIABILITY ARISING OUT OF THIS
AGREEMENT WILL NOT EXCEED THE FEES PAID OR PAYABLE BY CUSTOMER IN THE `[12]` MONTHS BEFORE THE EVENT
GIVING RISE TO THE CLAIM `[or $[AMOUNT], whichever is greater]`.

16.3 **Exclusions.** Sections 16.1 and 16.2 do not limit `[ATTORNEY: e.g. Customer's breach of
Section 3, payment obligations, either party's indemnity obligations, or liability that cannot be
limited by law]`.

16.4 Because Customer Data never leaves your Machines, Arkhon is not responsible for loss of Customer
Data. You are responsible for backups.

## 17. Term and termination

17.1 This Agreement lasts for the Term and any renewals.

17.2 Either party may terminate this Agreement on written notice if the other party materially
breaches it and fails to cure within `[30]` days of notice. Arkhon may terminate immediately on
notice for a breach of Section 3.

17.3 On expiry or termination: your license ends; the Software will stop running Engines; you will
uninstall the Software and delete Engines; and, on request, certify this in writing. **Your Customer
Data remains on your Machines and stays yours.** The Software will let you export Customer Data it
stores in `[FORMATS]` for `[PERIOD]` after expiry.

17.4 Sections 1, 3, 4, 5, 6 (for `[12]` months), 10, 12, 13, 15, 16, 17.3, 17.4 and 18 to 21 survive.

## 18. Indemnity

`[ATTORNEY: decide on IP infringement indemnity by Arkhon (with carve-outs for base models, Customer
Data and modifications), and Customer indemnity for Customer Data and approved actions.]`

## 19. Export controls and sanctions

You will comply with all applicable export control and sanctions laws. You will not export, re-export
or transfer the Software or Engines to any country, entity or person prohibited by those laws, or use
them for any prohibited end use. You represent that you are not on any government restricted-party
list. `[ATTORNEY: see Section 22, question 9.]`

## 20. Governing law and disputes

This Agreement is governed by the laws of `[JURISDICTION]`, without regard to its conflict-of-laws
rules. The courts of `[VENUE]` have exclusive jurisdiction `[or: disputes are resolved by arbitration
under [RULES] in [SEAT]]`. The UN Convention on Contracts for the International Sale of Goods does not
apply `[ATTORNEY: confirm]`.

## 21. General

Entire agreement (this Agreement plus your Order; the Order controls for commercial terms);
amendments only in writing signed by both parties; no waiver by delay; severability; notices to
`[NOTICE ADDRESS]` and the email in your account; force majeure; independent contractors; no
third-party beneficiaries; `[ATTORNEY: government end-user clause if relevant]`.

---

## 22. Open questions for the attorney

1. **Form of acceptance.** Click-through at install, signed Order, or both? How should the Order and
   this Agreement interact?
2. **Reverse-engineering carve-outs.** What restrictions are enforceable in the target jurisdictions,
   and how to phrase interoperability exceptions?
3. **Model weights and outputs.** How to describe Arkhon's rights in fine-tuned weights built on
   Apache-2.0 / MIT base models; whether outputs are protectable; how Section 3(e) (no training of
   competing models) interacts with Section 4.2.
4. **Base-model usage policy pass-through** (Section 12.2). Mechanics, notice, and whether to bundle
   the policy text.
5. **Fingerprint disclosure** (Section 5). Adequacy of disclosure, privacy implications, and
   evidentiary use. Engineering notes robustness is not yet measured.
6. **Optional benchmarking clause** (Section 3(i)). Keep or drop?
7. **Audit** (Section 6). Frequency, notice, cost shifting, and keeping Customer Data out of scope.
8. **Professional-advice disclaimers** (Section 13). Sufficiency per Industry Pack. For a healthcare
   pack: whether **HIPAA** applies and whether a **Business Associate Agreement** is needed, noting
   Arkhon does not receive Customer Data. Similar review for legal, financial or accounting packs and
   relevant professional rules.
9. **Export controls.** Classification of the Software and Engines under the **U.S. Export
   Administration Regulations (EAR)** and any encryption-related requirements; sanctions screening at
   checkout.
10. **Privacy laws.** Whether License Metadata (including hashed identifiers and IP addresses) is
    personal data under **U.S. state privacy laws** and, if selling outside the U.S., laws such as the
    **GDPR / UK GDPR**; need for a privacy policy, a DPA, or controller/processor statements.
11. **AI-specific rules.** Whether any AI transparency or risk-management laws in target markets
    impose duties on Arkhon or customers.
12. **Consumer-law overlap.** Customers are businesses; confirm that sole proprietors are not treated
    as consumers in target jurisdictions.
13. **Automatic renewal.** Notice requirements for auto-renewing Terms.
14. **Liability cap and exclusions** (Section 16). Amount, super-cap for data or IP claims, and which
    breaches sit outside the cap.
15. **Warranty** (Section 15). Whether to offer a limited functional warranty.
16. **Indemnity** (Section 18). Scope, especially given third-party base models.
17. **Perpetual fallback** (Section 2.4). Whether customers keep using versions released in their
    Update Window after the Term ends.
18. **Mandatory updates and remote disablement** (Sections 8.3, 11.2, 17.3). Enforceability and
    required notices when the Software stops running Engines.
19. **Transfer rules** (Section 9). Limits on Machine transfers, and assignment on acquisition.
20. **Design-partner and pilot customers.** Whether a separate agreement
    (see `docs/discovery/design-partner-agreement-outline.md`) overrides parts of this Agreement.
