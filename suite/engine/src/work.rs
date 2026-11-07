//! Workspace content (Inbox, Desk, Docs, Knowledge, Meetings, Growth, Insights), the Privacy
//! Center and first-run setup.
//!
//! Records here are what the workflows read and prepared. Anything that would leave the computer
//! or change another system is a review-queue item ([`crate::queue`]) linked by `item`, so every
//! Send / File / Answer button runs the existing approval commands and rules.
//!
//! Who sees what:
//! * a workspace page is only built for people who can use that workspace (role + teams + plan);
//! * a record read from a connected account is only shown to people who can use that account,
//!   plus admins for company accounts (personal mailboxes stay personal).

use arkhon_org::connections::Kind;
use arkhon_org::{MemberId, Permission, Workspace};
use serde::{Deserialize, Serialize};

use crate::queue::{ItemId, Source, Urgency};
use crate::{ItemView, Suite};

/// Everything the workspaces hold for one company.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkData {
    /// Email threads waiting for a reply.
    #[serde(default)]
    pub threads: Vec<Thread>,
    /// Customer questions (Desk).
    #[serde(default)]
    pub tickets: Vec<Ticket>,
    /// Documents Arkhon read (Docs).
    #[serde(default)]
    pub documents: Vec<Document>,
    /// Example answers for "Ask the company".
    #[serde(default)]
    pub answers: Vec<Answer>,
    /// New-hire starter questions.
    #[serde(default)]
    pub starter_questions: Vec<String>,
    /// Meetings written up.
    #[serde(default)]
    pub meetings: Vec<Meeting>,
    /// Quotes prepared from the price book.
    #[serde(default)]
    pub quotes: Vec<Quote>,
    /// Marketing and follow-up drafts.
    #[serde(default)]
    pub outreach: Vec<Outreach>,
    /// Plain-English answers about the numbers.
    #[serde(default)]
    pub insights: Vec<Insight>,
    /// Every connection Arkhon made to another computer, oldest first.
    #[serde(default)]
    pub network: Vec<NetEvent>,
    /// Privacy settings.
    #[serde(default)]
    pub privacy: PrivacySettings,
    /// First-run setup.
    #[serde(default)]
    pub setup: SetupState,
}

/// An email thread that needs a reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    /// Id.
    pub id: u64,
    /// Customer or sender.
    pub customer: String,
    /// Subject line.
    pub subject: String,
    /// What they want, in one sentence.
    pub summary: String,
    /// The customer's last message.
    pub message: String,
    /// How soon.
    pub urgency: Urgency,
    /// Received (Unix seconds).
    pub at: u64,
    /// Account it arrived in.
    pub source: Option<u64>,
    /// The drafted reply waiting for approval.
    pub item: Option<ItemId>,
}

/// A customer question (Desk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    /// Id.
    pub id: u64,
    /// Customer.
    pub customer: String,
    /// Where it came from ("Email", "Web form", "Phone message").
    pub channel: String,
    /// The question.
    pub question: String,
    /// Received.
    pub at: u64,
    /// Account it arrived in.
    pub source: Option<u64>,
    /// Suggested answer, or a "not found" question to answer once.
    pub item: Option<ItemId>,
}

/// Document types from the Trades & field services pack (ADR-0003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DocType {
    /// Supplier bill or invoice.
    SupplierBill,
    /// Receipt.
    Receipt,
    /// Purchase order.
    PurchaseOrder,
    /// Work order.
    WorkOrder,
    /// Change order.
    ChangeOrder,
    /// Quote or estimate.
    Quote,
    /// Lien waiver.
    LienWaiver,
    /// Certificate of insurance.
    InsuranceCertificate,
    /// Permit.
    Permit,
}

impl DocType {
    /// Plain label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            DocType::SupplierBill => "Supplier bill",
            DocType::Receipt => "Receipt",
            DocType::PurchaseOrder => "Purchase order",
            DocType::WorkOrder => "Work order",
            DocType::ChangeOrder => "Change order",
            DocType::Quote => "Quote",
            DocType::LienWaiver => "Lien waiver",
            DocType::InsuranceCertificate => "Insurance certificate",
            DocType::Permit => "Permit",
        }
    }
}

/// One extracted field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// Label.
    pub label: String,
    /// Value as read.
    pub value: String,
}

/// Result of checking a document against the company's records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckState {
    /// Everything matches.
    Ok,
    /// Something needs a look.
    Warn,
    /// A required piece is missing.
    Missing,
}

/// A document Arkhon read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    /// Id.
    pub id: u64,
    /// Type.
    pub doc_type: DocType,
    /// Short title.
    pub title: String,
    /// Who sent it.
    pub from: String,
    /// Received.
    pub at: u64,
    /// Extracted fields.
    pub fields: Vec<Field>,
    /// Check result.
    pub check: CheckState,
    /// Check in words, e.g. "Matches PO-1187".
    pub check_text: String,
    /// What Arkhon did or suggests, when there's no approval.
    pub note: String,
    /// Account it arrived in.
    pub source: Option<u64>,
    /// The "File to `QuickBooks`" approval.
    pub item: Option<ItemId>,
}

/// An answer to a question about the company.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    /// Question.
    pub question: String,
    /// Answer, `None` when the files don't say.
    pub answer: Option<String>,
    /// Where it came from.
    pub sources: Vec<Source>,
}

/// A follow-up task from a meeting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionItem {
    /// Who.
    pub who: String,
    /// What.
    pub what: String,
    /// By when, in words.
    pub due: String,
}

/// A meeting Arkhon wrote up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meeting {
    /// Id.
    pub id: u64,
    /// Title.
    pub title: String,
    /// When it happened.
    pub at: u64,
    /// Length in minutes.
    pub minutes: u32,
    /// Who was there.
    pub attendees: Vec<String>,
    /// Summary.
    pub summary: String,
    /// Decisions.
    pub decisions: Vec<String>,
    /// Action items.
    pub actions: Vec<ActionItem>,
    /// Team it belongs to (visibility).
    pub team: Option<String>,
    /// Follow-up email waiting for approval.
    pub item: Option<ItemId>,
}

/// A quote line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteLine {
    /// Description.
    pub description: String,
    /// Quantity.
    pub qty: u32,
    /// Unit price in cents.
    pub unit_cents: u64,
}

/// A quote prepared from the price book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    /// Id.
    pub id: u64,
    /// Customer.
    pub customer: String,
    /// Title.
    pub title: String,
    /// Lines.
    pub lines: Vec<QuoteLine>,
    /// Price book used.
    pub price_book: String,
    /// Good for (days).
    pub valid_days: u32,
    /// Approval to send it.
    pub item: Option<ItemId>,
}

/// A marketing or follow-up draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outreach {
    /// Id.
    pub id: u64,
    /// Who it goes to, in words.
    pub audience: String,
    /// How many people.
    pub recipients: u32,
    /// Approval to send it.
    pub item: Option<ItemId>,
}

/// One bar of an insight chart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bar {
    /// Label.
    pub label: String,
    /// Value (cents for money, otherwise a count).
    pub value: u64,
}

/// A plain-English answer about the numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Insight {
    /// Id.
    pub id: u64,
    /// Question.
    pub question: String,
    /// Answer in one or two sentences.
    pub answer: String,
    /// `money` (cents) or `count`.
    pub unit: String,
    /// Bars, drawn to scale from zero.
    pub bars: Vec<Bar>,
    /// What the answer assumes.
    pub assumptions: Vec<String>,
    /// Where the numbers came from.
    pub sources: Vec<Source>,
}

/// One connection Arkhon made to another computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEvent {
    /// When.
    pub at: u64,
    /// Service, e.g. "Microsoft Outlook".
    pub service: String,
    /// Address contacted.
    pub address: String,
    /// Why, in words.
    pub purpose: String,
    /// Whether customer information was sent.
    pub sent_customer_data: bool,
}

/// Privacy settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySettings {
    /// Days to keep finished work and history; 0 keeps it until deleted.
    pub retention_days: u32,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        PrivacySettings {
            retention_days: 365,
        }
    }
}

/// Retention choices offered in the Privacy Center.
pub const RETENTION_CHOICES: [u32; 4] = [30, 90, 365, 0];

/// First-run setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupState {
    /// Chosen industry pack key.
    pub industry_pack: Option<String>,
    /// Files read so far.
    pub files_read: u32,
    /// Files found.
    pub files_total: u32,
}

impl Default for SetupState {
    fn default() -> Self {
        SetupState {
            industry_pack: Some("trades".into()),
            files_read: 0,
            files_total: 0,
        }
    }
}

/// Industry packs: (key, name, description, available).
pub const PACKS: [(&str, &str, &str, bool); 4] = [
    (
        "trades",
        "Trades & field services",
        "HVAC, plumbing, electrical and contractors: supplier bills, work orders, lien waivers, quotes.",
        true,
    ),
    (
        "professional",
        "Professional services",
        "Accountants, agencies and consultants.",
        false,
    ),
    (
        "health",
        "Clinics & dental",
        "Front desk, scheduling and insurance paperwork.",
        false,
    ),
    (
        "general",
        "General business",
        "Email, documents and answers for any small business.",
        true,
    ),
];

// ---------------------------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------------------------

/// Header navigation entry.
#[derive(Debug, Clone, Serialize)]
pub struct NavLink {
    /// Route key (`inbox`, `desk`, ...).
    pub key: String,
    /// Label.
    pub label: String,
}

/// Inbox page.
#[derive(Debug, Clone, Serialize)]
pub struct InboxView {
    /// Threads, urgent first.
    pub threads: Vec<ThreadView>,
    /// Threads still waiting.
    pub waiting: usize,
}

/// A thread row.
#[derive(Debug, Clone, Serialize)]
pub struct ThreadView {
    /// Id.
    pub id: u64,
    /// Customer.
    pub customer: String,
    /// Subject.
    pub subject: String,
    /// Summary.
    pub summary: String,
    /// Their message.
    pub message: String,
    /// Urgency.
    pub urgency: Urgency,
    /// "1 hour ago".
    pub received: String,
    /// Account it arrived in.
    pub account: Option<String>,
    /// Drafted reply.
    pub item: Option<ItemView>,
}

/// Desk page.
#[derive(Debug, Clone, Serialize)]
pub struct DeskView {
    /// Tickets.
    pub tickets: Vec<TicketView>,
    /// Questions Arkhon couldn't answer from the files.
    pub not_found: usize,
}

/// A ticket row.
#[derive(Debug, Clone, Serialize)]
pub struct TicketView {
    /// Id.
    pub id: u64,
    /// Customer.
    pub customer: String,
    /// Channel.
    pub channel: String,
    /// Question.
    pub question: String,
    /// "2 hours ago".
    pub received: String,
    /// Suggested answer or gap.
    pub item: Option<ItemView>,
}

/// Docs page.
#[derive(Debug, Clone, Serialize)]
pub struct DocsView {
    /// Documents, newest first.
    pub documents: Vec<DocumentView>,
    /// Waiting to be filed.
    pub to_file: usize,
    /// Types this pack reads.
    pub types: Vec<String>,
}

/// A document row.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentView {
    /// Id.
    pub id: u64,
    /// Type key.
    pub doc_type: DocType,
    /// Type label.
    pub type_label: String,
    /// Title.
    pub title: String,
    /// From.
    pub from: String,
    /// "3 hours ago".
    pub received: String,
    /// Fields.
    pub fields: Vec<Field>,
    /// Check.
    pub check: CheckState,
    /// Check in words.
    pub check_text: String,
    /// Note.
    pub note: String,
    /// Filing approval.
    pub item: Option<ItemView>,
}

/// Knowledge page.
#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeView {
    /// Example questions.
    pub examples: Vec<String>,
    /// Answers (examples plus what people taught Arkhon).
    pub answers: Vec<Answer>,
    /// New-hire starter questions.
    pub starter_questions: Vec<String>,
    /// Answers people gave once.
    pub remembered: usize,
}

/// Result of asking the company a question.
#[derive(Debug, Clone, Serialize)]
pub struct AskResult {
    /// The question.
    pub question: String,
    /// Whether an answer was found in the company's files.
    pub found: bool,
    /// The answer, or an honest "not found" sentence.
    pub answer: String,
    /// Citations.
    pub sources: Vec<Source>,
}

/// Meetings page.
#[derive(Debug, Clone, Serialize)]
pub struct MeetingsView {
    /// Meetings, newest first.
    pub meetings: Vec<MeetingView>,
}

/// A meeting.
#[derive(Debug, Clone, Serialize)]
pub struct MeetingView {
    /// Id.
    pub id: u64,
    /// Title.
    pub title: String,
    /// "Yesterday".
    pub when: String,
    /// Minutes.
    pub minutes: u32,
    /// Attendees.
    pub attendees: Vec<String>,
    /// Summary.
    pub summary: String,
    /// Decisions.
    pub decisions: Vec<String>,
    /// Actions.
    pub actions: Vec<ActionItem>,
    /// Follow-up email.
    pub item: Option<ItemView>,
}

/// Growth page.
#[derive(Debug, Clone, Serialize)]
pub struct GrowthView {
    /// Quotes.
    pub quotes: Vec<QuoteView>,
    /// Outreach drafts.
    pub outreach: Vec<OutreachView>,
}

/// A quote with totals.
#[derive(Debug, Clone, Serialize)]
pub struct QuoteView {
    /// Id.
    pub id: u64,
    /// Customer.
    pub customer: String,
    /// Title.
    pub title: String,
    /// Lines with totals.
    pub lines: Vec<QuoteLineView>,
    /// Total in cents.
    pub total_cents: u64,
    /// Price book.
    pub price_book: String,
    /// Valid for (days).
    pub valid_days: u32,
    /// Send approval.
    pub item: Option<ItemView>,
}

/// A quote line with its total.
#[derive(Debug, Clone, Serialize)]
pub struct QuoteLineView {
    /// Description.
    pub description: String,
    /// Qty.
    pub qty: u32,
    /// Unit price, cents.
    pub unit_cents: u64,
    /// Line total, cents.
    pub total_cents: u64,
}

/// An outreach draft.
#[derive(Debug, Clone, Serialize)]
pub struct OutreachView {
    /// Id.
    pub id: u64,
    /// Audience.
    pub audience: String,
    /// Recipients.
    pub recipients: u32,
    /// Send approval.
    pub item: Option<ItemView>,
}

/// Insights page.
#[derive(Debug, Clone, Serialize)]
pub struct InsightsView {
    /// Answers.
    pub insights: Vec<Insight>,
}

/// Privacy Center.
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyView {
    /// Where the data lives, in plain sentences.
    pub where_data_lives: Vec<String>,
    /// Connections made, newest first.
    pub network: Vec<NetEventView>,
    /// Connections that carried customer information.
    pub customer_data_sent: usize,
    /// Retention in days (0 = until deleted).
    pub retention_days: u32,
    /// Retention choices.
    pub retention_choices: Vec<u32>,
    /// Viewer may change retention and delete everything (admins).
    pub can_manage: bool,
    /// What "Delete all" removes, in words.
    pub delete_covers: Vec<String>,
}

/// A network event row.
#[derive(Debug, Clone, Serialize)]
pub struct NetEventView {
    /// Service.
    pub service: String,
    /// Address.
    pub address: String,
    /// Why.
    pub purpose: String,
    /// "9:02 AM" style time, or "Yesterday".
    pub when: String,
    /// Customer information sent.
    pub sent_customer_data: bool,
}

/// First-run setup.
#[derive(Debug, Clone, Serialize)]
pub struct SetupView {
    /// Computer check result.
    pub computer: ComputerCheck,
    /// Email connected (any mail account the viewer can use).
    pub email_connected: bool,
    /// Files connected (a folder or drive).
    pub files_connected: bool,
    /// Packs.
    pub packs: Vec<PackView>,
    /// Chosen pack.
    pub industry_pack: Option<String>,
    /// Files read.
    pub files_read: u32,
    /// Files found.
    pub files_total: u32,
    /// Viewer may choose the pack.
    pub can_choose_pack: bool,
}

/// Computer check.
#[derive(Debug, Clone, Serialize)]
pub struct ComputerCheck {
    /// Tier name.
    pub tier: String,
    /// In plain words.
    pub words: String,
    /// Individual checks.
    pub checks: Vec<String>,
}

/// An industry pack option.
#[derive(Debug, Clone, Serialize)]
pub struct PackView {
    /// Key.
    pub key: String,
    /// Name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Available now.
    pub available: bool,
}

/// Route key for a workspace.
#[must_use]
pub fn workspace_key(w: Workspace) -> &'static str {
    match w {
        Workspace::Inbox => "inbox",
        Workspace::Desk => "desk",
        Workspace::Docs => "docs",
        Workspace::Knowledge => "knowledge",
        Workspace::Meetings => "meetings",
        Workspace::Growth => "growth",
        Workspace::Insights => "insights",
        Workspace::Dev => "dev",
    }
}

/// "Just now", "40 min ago", "3 hours ago", "Yesterday", "4 days ago".
#[must_use]
pub fn ago(now: u64, at: u64) -> String {
    let s = now.saturating_sub(at);
    match s {
        0..=119 => "Just now".into(),
        120..=3_599 => format!("{} min ago", s / 60),
        3_600..=7_199 => "1 hour ago".into(),
        7_200..=86_399 => format!("{} hours ago", s / 3_600),
        86_400..=172_799 => "Yesterday".into(),
        _ => format!("{} days ago", s / 86_400),
    }
}

impl Suite {
    fn has_ws(&self, viewer: MemberId, w: Workspace) -> bool {
        self.state.org.workspaces_for(viewer).contains(&w)
    }

    /// Whether `viewer` may see a record read from connection `source`: anyone who can use it,
    /// plus admins for company accounts. Records without a source are company-wide.
    pub(crate) fn may_see_source(&self, viewer: MemberId, source: Option<u64>) -> bool {
        let Some(id) = source else { return true };
        let conns = &self.state.connections;
        let Some(c) = conns.get(id) else { return false };
        if conns
            .usable_by(&self.state.org, viewer)
            .iter()
            .any(|u| u.id == id)
        {
            return true;
        }
        matches!(c.kind, Kind::Company { .. })
            && self.state.org.can(viewer, Permission::ManageOrganization)
    }

    fn linked(&self, viewer: MemberId, item: Option<ItemId>) -> Option<ItemView> {
        item.and_then(|id| self.state.queue.get(id))
            .map(|i| self.item_view(viewer, i))
    }

    fn account_label(&self, id: Option<u64>) -> Option<String> {
        id.and_then(|c| self.state.connections.get(c))
            .map(|c| format!("{} ({})", c.app.name(), c.account))
    }

    /// Header navigation for the viewer's workspaces.
    pub(crate) fn nav(&self, viewer: MemberId) -> Vec<NavLink> {
        self.state
            .org
            .workspaces_for(viewer)
            .into_iter()
            .filter(|w| *w != Workspace::Dev)
            .map(|w| NavLink {
                key: workspace_key(w).into(),
                label: crate::workspace_label(w).into(),
            })
            .collect()
    }

    /// Inbox page, if the viewer has Email.
    #[must_use]
    pub fn inbox_view(&self, viewer: MemberId) -> Option<InboxView> {
        if !self.has_ws(viewer, Workspace::Inbox) {
            return None;
        }
        let now = self.today();
        let mut threads: Vec<&Thread> = self
            .state
            .work
            .threads
            .iter()
            .filter(|t| self.may_see_source(viewer, t.source))
            .collect();
        threads.sort_by_key(|t| (t.urgency, std::cmp::Reverse(t.at)));
        let threads: Vec<ThreadView> = threads
            .into_iter()
            .map(|t| ThreadView {
                id: t.id,
                customer: t.customer.clone(),
                subject: t.subject.clone(),
                summary: t.summary.clone(),
                message: t.message.clone(),
                urgency: t.urgency,
                received: ago(now, t.at),
                account: self.account_label(t.source),
                item: self.linked(viewer, t.item),
            })
            .collect();
        let waiting = threads
            .iter()
            .filter(|t| is_waiting(t.item.as_ref()))
            .count();
        Some(InboxView { threads, waiting })
    }

    /// Desk page, if the viewer has Customer replies.
    #[must_use]
    pub fn desk_view(&self, viewer: MemberId) -> Option<DeskView> {
        if !self.has_ws(viewer, Workspace::Desk) {
            return None;
        }
        let now = self.today();
        let tickets: Vec<TicketView> = self
            .state
            .work
            .tickets
            .iter()
            .filter(|t| self.may_see_source(viewer, t.source))
            .map(|t| TicketView {
                id: t.id,
                customer: t.customer.clone(),
                channel: t.channel.clone(),
                question: t.question.clone(),
                received: ago(now, t.at),
                item: self.linked(viewer, t.item),
            })
            .collect();
        let not_found = tickets
            .iter()
            .filter(|t| {
                t.item.as_ref().is_some_and(|i| {
                    i.kind == crate::ItemKind::KnowledgeGap
                        && i.status == crate::ItemStatus::Waiting
                })
            })
            .count();
        Some(DeskView { tickets, not_found })
    }

    /// Docs page, if the viewer has Documents.
    #[must_use]
    pub fn docs_view(&self, viewer: MemberId) -> Option<DocsView> {
        if !self.has_ws(viewer, Workspace::Docs) {
            return None;
        }
        let now = self.today();
        let mut docs: Vec<&Document> = self
            .state
            .work
            .documents
            .iter()
            .filter(|d| self.may_see_source(viewer, d.source))
            .collect();
        docs.sort_by_key(|d| std::cmp::Reverse(d.at));
        let documents: Vec<DocumentView> = docs
            .into_iter()
            .map(|d| DocumentView {
                id: d.id,
                doc_type: d.doc_type,
                type_label: d.doc_type.label().into(),
                title: d.title.clone(),
                from: d.from.clone(),
                received: ago(now, d.at),
                fields: d.fields.clone(),
                check: d.check,
                check_text: d.check_text.clone(),
                note: d.note.clone(),
                item: self.linked(viewer, d.item),
            })
            .collect();
        let to_file = documents
            .iter()
            .filter(|d| is_waiting(d.item.as_ref()))
            .count();
        Some(DocsView {
            documents,
            to_file,
            types: [
                DocType::SupplierBill,
                DocType::Receipt,
                DocType::PurchaseOrder,
                DocType::WorkOrder,
                DocType::ChangeOrder,
                DocType::Quote,
                DocType::LienWaiver,
                DocType::InsuranceCertificate,
                DocType::Permit,
            ]
            .iter()
            .map(|t| t.label().to_owned())
            .collect(),
        })
    }

    /// Knowledge page, if the viewer has Company answers.
    #[must_use]
    pub fn knowledge_view(&self, viewer: MemberId) -> Option<KnowledgeView> {
        if !self.has_ws(viewer, Workspace::Knowledge) {
            return None;
        }
        let w = &self.state.work;
        let mut answers = w.answers.clone();
        for k in &self.state.queue.knowledge {
            answers.push(Answer {
                question: k.question.clone(),
                answer: Some(k.answer.clone()),
                sources: vec![Source {
                    label: format!("Answered by {}", self.name_of(k.answered_by)),
                    reference: format!("knowledge:{}", k.id),
                }],
            });
        }
        Some(KnowledgeView {
            examples: w.answers.iter().map(|a| a.question.clone()).collect(),
            answers,
            starter_questions: w.starter_questions.clone(),
            remembered: self.state.queue.knowledge.len(),
        })
    }

    /// Ask the company a question. Answers only from the company's own material; when nothing
    /// matches, says so instead of guessing (N4).
    ///
    /// # Errors
    /// Forbidden without the Company answers workspace; bad input for an empty question.
    pub fn ask(&self, viewer: MemberId, question: &str) -> Result<AskResult, crate::Refusal> {
        let Some(k) = self.knowledge_view(viewer) else {
            return Err(crate::forbid(
                "Company answers isn't part of your role. Ask an admin to add it.",
            ));
        };
        let q = question.trim();
        if q.is_empty() {
            return Err(crate::bad("Type a question first."));
        }
        let best = k
            .answers
            .iter()
            .map(|a| (overlap(q, &a.question), a))
            .filter(|(score, _)| *score >= 0.5)
            .max_by(|a, b| a.0.total_cmp(&b.0));
        Ok(match best {
            Some((_, a)) if a.answer.is_some() => AskResult {
                question: q.to_owned(),
                found: true,
                answer: a.answer.clone().unwrap_or_default(),
                sources: a.sources.clone(),
            },
            _ => AskResult {
                question: q.to_owned(),
                found: false,
                answer: "Your files don't say, so Arkhon didn't guess. An admin can answer it \
                         once and Arkhon will remember."
                    .into(),
                sources: Vec::new(),
            },
        })
    }

    /// Meetings page.
    #[must_use]
    pub fn meetings_view(&self, viewer: MemberId) -> Option<MeetingsView> {
        if !self.has_ws(viewer, Workspace::Meetings) {
            return None;
        }
        let org = &self.state.org;
        let now = self.today();
        let admin = org.can(viewer, Permission::ManageOrganization);
        let mut ms: Vec<&Meeting> = self
            .state
            .work
            .meetings
            .iter()
            .filter(|m| {
                admin
                    || m.team
                        .as_deref()
                        .is_none_or(|t| org.team(t).is_some_and(|t| t.members.contains(&viewer)))
            })
            .collect();
        ms.sort_by_key(|m| std::cmp::Reverse(m.at));
        Some(MeetingsView {
            meetings: ms
                .into_iter()
                .map(|m| MeetingView {
                    id: m.id,
                    title: m.title.clone(),
                    when: ago(now, m.at),
                    minutes: m.minutes,
                    attendees: m.attendees.clone(),
                    summary: m.summary.clone(),
                    decisions: m.decisions.clone(),
                    actions: m.actions.clone(),
                    item: self.linked(viewer, m.item),
                })
                .collect(),
        })
    }

    /// Growth page.
    #[must_use]
    pub fn growth_view(&self, viewer: MemberId) -> Option<GrowthView> {
        if !self.has_ws(viewer, Workspace::Growth) {
            return None;
        }
        let w = &self.state.work;
        Some(GrowthView {
            quotes: w
                .quotes
                .iter()
                .map(|q| {
                    let lines: Vec<QuoteLineView> = q
                        .lines
                        .iter()
                        .map(|l| QuoteLineView {
                            description: l.description.clone(),
                            qty: l.qty,
                            unit_cents: l.unit_cents,
                            total_cents: l.unit_cents * u64::from(l.qty),
                        })
                        .collect();
                    QuoteView {
                        id: q.id,
                        customer: q.customer.clone(),
                        title: q.title.clone(),
                        total_cents: lines.iter().map(|l| l.total_cents).sum(),
                        lines,
                        price_book: q.price_book.clone(),
                        valid_days: q.valid_days,
                        item: self.linked(viewer, q.item),
                    }
                })
                .collect(),
            outreach: w
                .outreach
                .iter()
                .map(|o| OutreachView {
                    id: o.id,
                    audience: o.audience.clone(),
                    recipients: o.recipients,
                    item: self.linked(viewer, o.item),
                })
                .collect(),
        })
    }

    /// Insights page.
    #[must_use]
    pub fn insights_view(&self, viewer: MemberId) -> Option<InsightsView> {
        if !self.has_ws(viewer, Workspace::Insights) {
            return None;
        }
        Some(InsightsView {
            insights: self.state.work.insights.clone(),
        })
    }

    /// Privacy Center (everyone can see it; only admins change it).
    #[must_use]
    pub fn privacy_view(&self, viewer: MemberId) -> PrivacyView {
        let w = &self.state.work;
        let now = self.today();
        let computer = "this computer";
        PrivacyView {
            where_data_lives: vec![
                format!("Your email, files and answers are read and stored on {computer}, in one encrypted folder."),
                "Arkhon's AI runs on this computer too. Your customers' information is never sent to an AI company.".into(),
                "Sign-ins to your apps are kept in an encrypted vault that only this computer can open.".into(),
                "Arkhon only connects to the apps you connected, to read new items and to send what you approved.".into(),
            ],
            network: w
                .network
                .iter()
                .rev()
                .map(|e| NetEventView {
                    service: e.service.clone(),
                    address: e.address.clone(),
                    purpose: e.purpose.clone(),
                    when: ago(now, e.at),
                    sent_customer_data: e.sent_customer_data,
                })
                .collect(),
            customer_data_sent: w.network.iter().filter(|e| e.sent_customer_data).count(),
            retention_days: w.privacy.retention_days,
            retention_choices: RETENTION_CHOICES.to_vec(),
            can_manage: self.state.org.can(viewer, Permission::ManageOrganization),
            delete_covers: vec![
                "Everything Arkhon read and learned from your email and files".into(),
                "Drafts, answers, documents, meeting notes and quotes".into(),
                "Every connection and saved sign-in".into(),
                "Time-saved history and the connection list on this page".into(),
            ],
        }
    }

    /// First-run setup.
    #[must_use]
    pub fn setup_view(&self, viewer: MemberId) -> SetupView {
        use arkhon_org::connections::App;
        let usable = self.state.connections.usable_by(&self.state.org, viewer);
        let mail = [App::Outlook, App::Gmail, App::OtherEmail];
        let files = [
            App::LocalFolder,
            App::GoogleDrive,
            App::OneDrive,
            App::Dropbox,
        ];
        let s = &self.state.work.setup;
        SetupView {
            computer: ComputerCheck {
                tier: "Standard".into(),
                words: "This computer can run Arkhon well. Most answers take a few seconds.".into(),
                checks: vec![
                    "Enough memory for Arkhon's AI".into(),
                    "Enough free space for your files".into(),
                    "Security chip found, so sign-ins can be locked to this computer".into(),
                ],
            },
            email_connected: usable.iter().any(|c| mail.contains(&c.app)),
            files_connected: usable.iter().any(|c| files.contains(&c.app)),
            packs: PACKS
                .iter()
                .map(|(k, n, d, a)| PackView {
                    key: (*k).into(),
                    name: (*n).into(),
                    description: (*d).into(),
                    available: *a,
                })
                .collect(),
            industry_pack: s.industry_pack.clone(),
            files_read: s.files_read,
            files_total: s.files_total,
            can_choose_pack: self.state.org.can(viewer, Permission::ManageUpdates),
        }
    }
}

fn is_waiting(i: Option<&ItemView>) -> bool {
    i.is_some_and(|i| i.status == crate::ItemStatus::Waiting)
}

fn words(s: &str) -> Vec<String> {
    const SKIP: [&str; 14] = [
        "the", "a", "an", "do", "we", "our", "is", "are", "what", "how", "of", "to", "for", "you",
    ];
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 1 && !SKIP.contains(w))
        .map(str::to_owned)
        .collect()
}

/// Share of the stored question's meaningful words that appear in the asked question.
fn overlap(asked: &str, stored: &str) -> f64 {
    let a = words(asked);
    let s = words(stored);
    if s.is_empty() {
        return 0.0;
    }
    let hits = s.iter().filter(|w| a.contains(w)).count();
    #[allow(clippy::cast_precision_loss)] // tiny counts
    let r = hits as f64 / s.len() as f64;
    r
}
