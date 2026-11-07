//! Example content for "Coastline Mechanical" (an HVAC contractor). Sample data only: the UI
//! labels it as an example company.

use arkhon_org::{MemberId, Workspace};

use crate::queue::{Confidence, ItemId, ItemKind, Proposal, Queue, Urgency};
use crate::src;
use crate::work::{
    ActionItem, Answer, Bar, CheckState, DocType, Document, Field, Insight, Meeting, NetEvent,
    Outreach, PrivacySettings, Quote, QuoteLine, SetupState, Thread, Ticket, WorkData,
};

pub(crate) struct Ids {
    pub owner: MemberId,
    pub admin: MemberId,
    pub dispatcher: MemberId,
    pub tech: MemberId,
    pub service: u64,
    pub books: u64,
    pub nas: u64,
    pub dana_mail: u64,
    pub tia_mail: u64,
}

const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;

fn find(q: &Queue, title: &str) -> Option<ItemId> {
    q.items.iter().find(|i| i.title == title).map(|i| i.id)
}

fn f(label: &str, value: &str) -> Field {
    Field {
        label: label.into(),
        value: value.into(),
    }
}

fn line(description: &str, qty: u32, dollars: u64) -> QuoteLine {
    QuoteLine {
        description: description.into(),
        qty,
        unit_cents: dollars * 100,
    }
}

fn bar(label: &str, value: u64) -> Bar {
    Bar {
        label: label.into(),
        value,
    }
}

fn answer(q: &str, a: Option<&str>, sources: &[(&str, &str)]) -> Answer {
    Answer {
        question: q.into(),
        answer: a.map(Into::into),
        sources: sources.iter().map(|(l, r)| src(l, r)).collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn propose(
    q: &mut Queue,
    at: u64,
    workspace: Workspace,
    kind: ItemKind,
    title: &str,
    summary: &str,
    draft: Option<&str>,
    question: Option<&str>,
    sources: &[(&str, &str)],
    confidence: Confidence,
    urgency: Urgency,
    assignee: MemberId,
    team: Option<&str>,
    connection: Option<u64>,
) -> ItemId {
    q.propose(
        Proposal {
            workspace,
            kind,
            title: title.into(),
            summary: summary.into(),
            draft: draft.map(Into::into),
            question: question.map(Into::into),
            sources: sources.iter().map(|(l, r)| src(l, r)).collect(),
            confidence,
            urgency,
            assignee,
            team: team.map(Into::into),
            connection,
        },
        at,
    )
}

/// Adds the workspace items to `q` and returns the records that point at them.
#[allow(clippy::too_many_lines)] // linear seed script
pub(crate) fn demo_work(today: u64, q: &mut Queue, ids: &Ids) -> WorkData {
    let fo = Some("Front office");
    let marisol = find(q, "Reply to Marisol Vega");
    let ferguson = find(q, "File a Ferguson bill for $2,418.36");
    let mitsubishi = find(q, "A customer asked about Mitsubishi units");
    let ortiz = find(q, "Send the Ortiz furnace quote");
    let harbor = find(q, "Confirm Harbor Dental's maintenance visit");
    let bayview = find(q, "Share notes from the Bayview Apartments walk-through");

    let lund_reply = propose(
        q,
        today - 5 * HOUR,
        Workspace::Inbox,
        ItemKind::DraftReply,
        "Reply to Greg Lund",
        "He's comparing a heat pump with a new furnace. Arkhon explained both and said Lena will send a quote.",
        Some("Hi Greg,\n\nGood question. A heat pump heats and cools with one system and costs less to run in our climate; a furnace costs less up front. For your 1,800 sq ft home we'd suggest a 3-ton heat pump. Lena will send you a written quote today.\n\nDana\nCoastline Mechanical"),
        None,
        &[("Price book 2026", r"file:\\office-nas\jobs\price-book-2026.pdf#p8"), ("Lund site visit notes", r"file:\\office-nas\jobs\4519\visit.docx")],
        Confidence::Medium,
        Urgency::Low,
        ids.owner,
        None,
        Some(ids.dana_mail),
    );
    let johnstone = propose(
        q,
        today - 2 * HOUR,
        Workspace::Inbox,
        ItemKind::DraftReply,
        "Reply to Johnstone Supply",
        "The evaporator coil for the Vega job is backordered. Arkhon asked for the earliest date and a substitute.",
        Some("Hi Rick,\n\nThanks for the heads-up. What's the earliest date you can get the coil? If a Goodman equivalent is in stock, please hold one for us and send the part number.\n\nTia"),
        None,
        &[("Purchase order 1192", r"file:\\office-nas\jobs\po\1192.pdf")],
        Confidence::High,
        Urgency::Normal,
        ids.tech,
        None,
        Some(ids.tia_mail),
    );
    let receipt = propose(
        q,
        today - 4 * HOUR,
        Workspace::Docs,
        ItemKind::FileBill,
        "File a Home Depot receipt for $186.40",
        "Fittings and copper for the Vega job, paid with the company card ending 4417.",
        None,
        None,
        &[(
            "Receipt photo from Tia",
            "mail:service@coastline.com/rcpt-1105",
        )],
        Confidence::High,
        Urgency::Normal,
        ids.admin,
        None,
        Some(ids.books),
    );
    let lund_quote = propose(
        q,
        today - 3 * HOUR,
        Workspace::Growth,
        ItemKind::SendQuote,
        "Send the Lund heat-pump quote",
        "3-ton heat pump with air handler, installed, from the 2026 price book: $13,095.",
        Some("Hi Greg,\n\nAs promised, here's your quote for a 3-ton heat pump with a new air handler, fully installed, for $13,095. It includes the permit, removal of the old furnace and our 10-year parts warranty. The quote is good for 30 days.\n\nLena\nCoastline Mechanical"),
        None,
        &[("Price book 2026", r"file:\\office-nas\jobs\price-book-2026.pdf#p8"), ("Warranty policy", r"file:\\office-nas\jobs\policies\warranty.docx")],
        Confidence::Medium,
        Urgency::Normal,
        ids.dispatcher,
        fo,
        Some(ids.service),
    );
    let tuneups = propose(
        q,
        today - 6 * HOUR,
        Workspace::Growth,
        ItemKind::DraftReply,
        "Send fall tune-up reminders",
        "A friendly reminder to 38 past customers whose furnace hasn't been checked this year.",
        Some("Hi {first name},\n\nCold mornings are on the way. It's been over a year since we checked your furnace, and a tune-up now helps avoid a no-heat call in January. Reply to this email or call (805) 555-0142 to book. Comfort Club members get it free.\n\nCoastline Mechanical"),
        None,
        &[("Customer list", "app:quickbooks/customers"), ("Comfort Club plan", r"file:\\office-nas\jobs\policies\comfort-club.pdf")],
        Confidence::High,
        Urgency::Low,
        ids.dispatcher,
        fo,
        Some(ids.service),
    );
    let weekend = propose(
        q,
        today - 90 * 60,
        Workspace::Desk,
        ItemKind::KnowledgeGap,
        "A customer asked about weekend rates",
        "Your price list doesn't mention weekends, so Arkhon didn't guess. Answer once and it will remember.",
        None,
        Some("Do we charge extra for weekend service calls?"),
        &[],
        Confidence::NotFound,
        Urgency::Normal,
        ids.dispatcher,
        fo,
        None,
    );
    let filters = propose(
        q,
        today - 50 * 60,
        Workspace::Desk,
        ItemKind::DraftReply,
        "Answer Tom Becker about filter changes",
        "He asked how often to change filters. Arkhon answered from your maintenance guide.",
        Some("Hi Tom,\n\nFor the 1-inch filter in your return, change it every 2 to 3 months, or every month if you have pets. Comfort Club members get filters at each tune-up.\n\nCoastline Mechanical"),
        None,
        &[("Homeowner maintenance guide", r"file:\\office-nas\jobs\policies\maintenance-guide.pdf#p1")],
        Confidence::High,
        Urgency::Normal,
        ids.dispatcher,
        fo,
        Some(ids.service),
    );

    let threads = vec![
        Thread {
            id: 1,
            customer: "Marisol Vega".into(),
            subject: "AC blowing warm air".into(),
            summary: "Her AC is blowing warm and she wants someone out today.".into(),
            message: "Hi, our AC has been blowing warm air since last night. Can someone come out today? We're home all afternoon. Thanks, Marisol".into(),
            urgency: Urgency::Urgent,
            at: today - HOUR,
            source: Some(ids.dana_mail),
            item: marisol,
        },
        Thread {
            id: 2,
            customer: "Greg Lund".into(),
            subject: "Heat pump or furnace?".into(),
            summary: "Comparing a heat pump with a furnace before winter.".into(),
            message: "Dana, thanks for coming by. Before we decide: is a heat pump worth it here, or should we just replace the furnace? -Greg".into(),
            urgency: Urgency::Low,
            at: today - 5 * HOUR,
            source: Some(ids.dana_mail),
            item: Some(lund_reply),
        },
        Thread {
            id: 3,
            customer: "Johnstone Supply".into(),
            subject: "Backorder: evaporator coil".into(),
            summary: "The coil for the Vega job is backordered about 10 days.".into(),
            message: "Tia, the coil on PO 1192 is backordered. Current estimate is 10 business days. Let me know how you'd like to proceed. -Rick".into(),
            urgency: Urgency::Normal,
            at: today - 2 * HOUR,
            source: Some(ids.tia_mail),
            item: Some(johnstone),
        },
    ];

    let tickets = vec![
        Ticket {
            id: 1,
            customer: "Priya Shah, Harbor Dental".into(),
            channel: "Email".into(),
            question: "Can we move Tuesday's maintenance visit to Thursday morning?".into(),
            at: today - 2 * HOUR,
            source: Some(ids.service),
            item: harbor,
        },
        Ticket {
            id: 2,
            customer: "Tom Becker".into(),
            channel: "Web form".into(),
            question: "How often should I change my furnace filter?".into(),
            at: today - 50 * 60,
            source: Some(ids.service),
            item: Some(filters),
        },
        Ticket {
            id: 3,
            customer: "Caller, (805) 555-0199".into(),
            channel: "Phone message".into(),
            question: "Do you charge extra to come out on a Saturday?".into(),
            at: today - 90 * 60,
            source: Some(ids.service),
            item: Some(weekend),
        },
        Ticket {
            id: 4,
            customer: "Alan Whitford".into(),
            channel: "Email".into(),
            question: "Do you service Mitsubishi mini-splits?".into(),
            at: today - 2 * HOUR,
            source: Some(ids.service),
            item: mitsubishi,
        },
    ];

    let documents = vec![
        Document {
            id: 1,
            doc_type: DocType::SupplierBill,
            title: "Ferguson invoice 88213".into(),
            from: "Ferguson Enterprises".into(),
            at: today - 3 * HOUR,
            fields: vec![
                f("Supplier", "Ferguson Enterprises"),
                f("Invoice number", "88213"),
                f("Invoice date", "Nov 4, 2026"),
                f("Due", "Dec 4, 2026 (net 30)"),
                f("Amount", "$2,418.36"),
                f("Purchase order", "PO-1187"),
                f("Job", "Harbor Dental, #4502"),
            ],
            check: CheckState::Ok,
            check_text: "Matches PO-1187".into(),
            note: "Every line and the total match the purchase order.".into(),
            source: Some(ids.service),
            item: ferguson,
        },
        Document {
            id: 2,
            doc_type: DocType::Receipt,
            title: "Home Depot receipt".into(),
            from: "Tia Alvarez (phone photo)".into(),
            at: today - 4 * HOUR,
            fields: vec![
                f("Store", "The Home Depot #6618"),
                f("Date", "Nov 5, 2026"),
                f("Amount", "$186.40"),
                f("Paid with", "Company card ending 4417"),
                f("Job", "Vega residence, #4471"),
            ],
            check: CheckState::Ok,
            check_text: "Matches card ending 4417".into(),
            note: "Arkhon matched the receipt to the Vega job from Tia's schedule.".into(),
            source: Some(ids.service),
            item: Some(receipt),
        },
        Document {
            id: 3,
            doc_type: DocType::LienWaiver,
            title: "Conditional lien waiver".into(),
            from: "Pacific Sheet Metal".into(),
            at: today - 7 * HOUR,
            fields: vec![
                f("Subcontractor", "Pacific Sheet Metal"),
                f("Job", "Harbor Dental, #4502"),
                f("Through", "Oct 31, 2026"),
                f("Amount", "$3,200.00"),
                f("Signed", "No"),
            ],
            check: CheckState::Missing,
            check_text: "Not signed yet".into(),
            note: "Saved to the Harbor Dental job folder. Get a signed copy before you pay them."
                .into(),
            source: Some(ids.nas),
            item: None,
        },
        Document {
            id: 4,
            doc_type: DocType::InsuranceCertificate,
            title: "Certificate of insurance".into(),
            from: "Pacific Sheet Metal".into(),
            at: today - DAY - 2 * HOUR,
            fields: vec![
                f("Insured", "Pacific Sheet Metal"),
                f("General liability", "$1,000,000 each occurrence"),
                f("Workers' comp", "Yes"),
                f("Expires", "Nov 30, 2026"),
            ],
            check: CheckState::Warn,
            check_text: "Expires in 24 days".into(),
            note: "Arkhon will remind you two weeks before it expires.".into(),
            source: Some(ids.nas),
            item: None,
        },
        Document {
            id: 5,
            doc_type: DocType::WorkOrder,
            title: "Work order WO-4471".into(),
            from: "Jobber".into(),
            at: today - 20 * HOUR,
            fields: vec![
                f("Customer", "Marisol Vega"),
                f("Job", "#4471, AC not cooling"),
                f("Technician", "Tia Alvarez"),
                f("Scheduled", "Nov 6, 2026, 1\u{2013}3 pm"),
            ],
            check: CheckState::Ok,
            check_text: "Linked to job #4471".into(),
            note: "Saved with the job.".into(),
            source: Some(ids.nas),
            item: None,
        },
        Document {
            id: 6,
            doc_type: DocType::ChangeOrder,
            title: "Change order CO-12".into(),
            from: "Bayview Apartments".into(),
            at: today - 2 * DAY,
            fields: vec![
                f("Job", "Bayview Apartments, #4488"),
                f("Change", "Add condensate lines in six units"),
                f("Amount", "+$2,940.00"),
                f("Customer signature", "Missing"),
            ],
            check: CheckState::Missing,
            check_text: "Customer signature missing".into(),
            note: "Don't start the extra work until the property manager signs.".into(),
            source: Some(ids.nas),
            item: None,
        },
        Document {
            id: 7,
            doc_type: DocType::Permit,
            title: "Mechanical permit M-26-1043".into(),
            from: "City of Ventura".into(),
            at: today - 3 * DAY,
            fields: vec![
                f("Address", "418 Seaward Ave"),
                f("Work", "Replace furnace and add AC"),
                f("Status", "Approved"),
                f("Inspection", "Nov 12, 2026"),
            ],
            check: CheckState::Ok,
            check_text: "Approved".into(),
            note: "The inspection is on the shared calendar.".into(),
            source: Some(ids.nas),
            item: None,
        },
    ];

    let warranty = (
        "Warranty policy",
        r"file:\\office-nas\jobs\policies\warranty.docx",
    );
    let prices = (
        "Price list 2026",
        r"file:\\office-nas\jobs\price-list-2026.pdf#p2",
    );
    let handbook = (
        "Employee handbook",
        r"file:\\office-nas\jobs\policies\handbook.pdf",
    );
    let answers = vec![
        answer("What is our warranty on new installs?", Some("10 years on parts and 2 years on labor for systems we install, as long as the customer keeps up yearly maintenance."), &[warranty]),
        answer("How much is a diagnostic visit?", Some("$129. It's waived if the customer goes ahead with the repair on the same visit."), &[prices]),
        answer("What's in the Comfort Club plan?", Some("Two tune-ups a year, 15% off repairs, priority scheduling and no overtime fees, for $19 a month."), &[("Comfort Club plan", r"file:\\office-nas\jobs\policies\comfort-club.pdf")]),
        answer("Who do we use for sheet metal work?", Some("Pacific Sheet Metal. Their insurance certificate expires on Nov 30, 2026."), &[("Vendor list", r"file:\\office-nas\jobs\vendors.xlsx"), ("Certificate of insurance", r"file:\\office-nas\jobs\coi\pacific.pdf")]),
        answer("Where are the job folders?", Some("On the office drive under Jobs, one folder per job number, like Jobs\\4471 for the Vega job."), &[handbook]),
        answer("What do I do if a customer isn't home?", Some("Wait 15 minutes, call the customer and the office, then leave a door tag. The office reschedules; there's no trip charge the first time."), &[handbook]),
        answer("How do I order parts?", Some("Text the part number and job number to the office. Lena orders from Ferguson or Johnstone and tells you when it's ready for pickup."), &[handbook]),
        answer("How do I log my hours?", None, &[]),
    ];
    let starter_questions = vec![
        "Where are the job folders?".into(),
        "What do I do if a customer isn't home?".into(),
        "How do I order parts?".into(),
        "How do I log my hours?".into(),
        "What is our warranty on new installs?".into(),
    ];

    let meetings = vec![
        Meeting {
            id: 1,
            title: "Bayview Apartments walk-through".into(),
            at: today - DAY + HOUR,
            minutes: 42,
            attendees: vec!["Tia Alvarez".into(), "Max Okafor".into(), "Rosa Medina (Bayview)".into()],
            summary: "Walked all twelve units. Six have cracked or clogged condensate lines; the rest are fine. Rosa wants the work done before the holidays.".into(),
            decisions: vec![
                "Replace condensate lines in units 2B, 2C, 3A, 3D, 4A and 4C.".into(),
                "Do the work in two visits so tenants are only out of AC for one afternoon.".into(),
            ],
            actions: vec![
                ActionItem { who: "Max Okafor".into(), what: "Send Rosa the quote and change order".into(), due: "Monday".into() },
                ActionItem { who: "Tia Alvarez".into(), what: "Order PVC and fittings for six units".into(), due: "Tuesday".into() },
                ActionItem { who: "Rosa Medina".into(), what: "Give tenants 48 hours' notice".into(), due: "Before the first visit".into() },
            ],
            team: Some("Field techs".into()),
            item: bayview,
        },
        Meeting {
            id: 2,
            title: "Monday dispatch huddle".into(),
            at: today - 4 * DAY,
            minutes: 15,
            attendees: vec!["Dana Ruiz".into(), "Lena Cho".into(), "Max Okafor".into(), "Tia Alvarez".into(), "Sam Brooks".into()],
            summary: "Busy week ahead with the first cold snap. Two installs, 23 service calls booked.".into(),
            decisions: vec!["Sam takes all no-heat calls on Wednesday and Thursday.".into()],
            actions: vec![
                ActionItem { who: "Lena Cho".into(), what: "Move non-urgent tune-ups to next week".into(), due: "Today".into() },
            ],
            team: None,
            item: None,
        },
    ];

    let quotes = vec![
        Quote {
            id: 1,
            customer: "Greg Lund".into(),
            title: "3-ton heat pump, installed".into(),
            lines: vec![
                line("Carrier 3-ton heat pump, 17 SEER2", 1, 8_950),
                line("Variable-speed air handler", 1, 2_400),
                line("Line set, pad and disconnect", 1, 640),
                line("40-amp electrical circuit", 1, 480),
                line("Permit and inspection", 1, 275),
                line("Remove and recycle old furnace", 1, 350),
            ],
            price_book: "Price book 2026".into(),
            valid_days: 30,
            item: Some(lund_quote),
        },
        Quote {
            id: 2,
            customer: "Luis Ortiz".into(),
            title: "Replacement furnace, installed".into(),
            lines: vec![
                line("96% gas furnace, 80,000 BTU", 1, 4_980),
                line("Installation labor", 1, 1_050),
                line("Venting kit", 1, 245),
                line("Permit", 1, 175),
            ],
            price_book: "Price list 2026".into(),
            valid_days: 30,
            item: ortiz,
        },
    ];
    let outreach = vec![Outreach {
        id: 1,
        audience: "Past customers due for a fall tune-up".into(),
        recipients: 38,
        item: Some(tuneups),
    }];

    let qb = ("QuickBooks invoices", "app:quickbooks/invoices");
    let insights = vec![
        Insight {
            id: 1,
            question: "Who hasn't paid yet?".into(),
            answer: "Three customers owe you $6,912.40. Harbor Dental is the largest at $4,180, now 41 days late.".into(),
            unit: "money".into(),
            bars: vec![bar("Harbor Dental", 418_000), bar("Bayview Apartments", 192_240), bar("Luis Ortiz", 81_000)],
            assumptions: vec![
                "Counts invoices more than 30 days past their due date.".into(),
                "Partial payments are already subtracted.".into(),
            ],
            sources: vec![src(qb.0, qb.1)],
        },
        Insight {
            id: 2,
            question: "What brought in the most money in October?".into(),
            answer: "October brought in $116,670. New installs were the biggest share, about 53%.".into(),
            unit: "money".into(),
            bars: vec![
                bar("New installs", 6_140_000),
                bar("Repairs", 2_835_000),
                bar("Commercial service", 1_780_000),
                bar("Maintenance plans", 912_000),
            ],
            assumptions: vec![
                "Uses every invoice dated October 1\u{2013}31, paid or not.".into(),
                "Job type comes from the item on each invoice.".into(),
                "Sales tax is left out.".into(),
            ],
            sources: vec![src(qb.0, qb.1)],
        },
        Insight {
            id: 3,
            question: "How many jobs did we finish each week?".into(),
            answer: "41 jobs last week, the busiest week in a month.".into(),
            unit: "count".into(),
            bars: vec![bar("Oct 12", 31), bar("Oct 19", 36), bar("Oct 26", 29), bar("Nov 2", 41)],
            assumptions: vec!["A job counts when its work order is marked complete in Jobber.".into()],
            sources: vec![src("Jobber work orders", "app:jobber/work-orders")],
        },
    ];

    let net = |ago: u64, service: &str, address: &str, purpose: &str| NetEvent {
        at: today - ago,
        service: service.into(),
        address: address.into(),
        purpose: purpose.into(),
        sent_customer_data: false,
    };
    let network = vec![
        net(
            26 * HOUR,
            "Arkhon license",
            "license.arkhonindustries.com",
            "Confirmed your license is active. Only the license number was sent.",
        ),
        net(
            2 * HOUR,
            "Arkhon updates",
            "updates.arkhonindustries.com",
            "Checked for an update to the Trades pack. Nothing about your company was sent.",
        ),
        net(
            HOUR,
            "Google Calendar",
            "www.googleapis.com",
            "Read Dana's calendar for today's open slots.",
        ),
        net(
            35 * 60,
            "Gmail",
            "gmail.googleapis.com",
            "Checked tia@coastline.com for new email.",
        ),
        net(
            20 * 60,
            "QuickBooks",
            "quickbooks.api.intuit.com",
            "Read open bills and unpaid invoices.",
        ),
        net(
            5 * 60,
            "Microsoft Outlook",
            "outlook.office365.com",
            "Checked service@coastline.com for new email.",
        ),
    ];

    WorkData {
        threads,
        tickets,
        documents,
        answers,
        starter_questions,
        meetings,
        quotes,
        outreach,
        insights,
        network,
        privacy: PrivacySettings::default(),
        setup: SetupState {
            industry_pack: Some("trades".into()),
            files_read: 12_480,
            files_total: 14_200,
        },
    }
}
