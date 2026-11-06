//! Review queue (N9, N4): work Arkhon prepared that waits for a person.
//!
//! Nothing external happens without an approval. Workflows *propose* items; people approve,
//! edit-and-approve, dismiss or answer them through [`crate::Command`]s. The rules for who may
//! decide live in [`crate::Suite`] next to the other commands.

use arkhon_org::{MemberId, Workspace};
use serde::{Deserialize, Serialize};

/// Identifier of a queue item.
pub type ItemId = u64;

/// What the item would do once approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    /// Send a drafted email reply.
    DraftReply,
    /// File a bill or receipt into the accounting system.
    FileBill,
    /// Send a quote to a customer.
    SendQuote,
    /// Share meeting notes with attendees.
    MeetingNotes,
    /// Arkhon couldn't find an answer in the company's files; a person answers once.
    KnowledgeGap,
}

impl ItemKind {
    /// Label for the primary button.
    #[must_use]
    pub fn verb(self) -> &'static str {
        match self {
            ItemKind::DraftReply | ItemKind::SendQuote | ItemKind::MeetingNotes => "Send",
            ItemKind::FileBill => "File it",
            ItemKind::KnowledgeGap => "Answer",
        }
    }

    /// Word shown after it's done.
    #[must_use]
    pub fn done_word(self) -> &'static str {
        match self {
            ItemKind::DraftReply | ItemKind::SendQuote | ItemKind::MeetingNotes => "Sent",
            ItemKind::FileBill => "Filed",
            ItemKind::KnowledgeGap => "Answered",
        }
    }
}

/// How sure Arkhon is, shown so people know how closely to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Backed by clear sources.
    High,
    /// Mostly backed; worth a look.
    Medium,
    /// Weak support; read carefully.
    Low,
    /// No answer found; Arkhon did not guess.
    NotFound,
}

impl Confidence {
    /// Plain-language label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Confidence::High => "Sure",
            Confidence::Medium => "Check this",
            Confidence::Low => "Read carefully",
            Confidence::NotFound => "Not sure",
        }
    }
}

/// How soon it should be handled. Ordered: `Urgent` sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Urgency {
    /// Today, a customer is waiting.
    Urgent,
    /// Normal.
    Normal,
    /// Whenever.
    Low,
}

/// Where the item is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemStatus {
    /// Waiting for a person.
    Waiting,
    /// Approved as prepared.
    Approved,
    /// Approved after a person changed the text.
    Edited,
    /// Dismissed; nothing happened.
    Dismissed,
}

/// A citation: where a fact came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// Human label, e.g. "Price list 2026".
    pub label: String,
    /// Reference into the local index, e.g. `file:\\office-nas\jobs\price-list.pdf#p3`, or
    /// `knowledge:3` for an answer someone gave earlier.
    pub reference: String,
}

/// One item in the review queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewItem {
    /// Id.
    pub id: ItemId,
    /// Workspace that proposed it.
    pub workspace: Workspace,
    /// Kind.
    pub kind: ItemKind,
    /// Short title.
    pub title: String,
    /// Plain-language summary of what Arkhon prepared and why.
    pub summary: String,
    /// The prepared text (email body, quote cover note...), if any.
    pub draft: Option<String>,
    /// For knowledge gaps: the question to answer once.
    pub question: Option<String>,
    /// Citations.
    pub sources: Vec<Source>,
    /// How sure Arkhon is.
    pub confidence: Confidence,
    /// How soon.
    pub urgency: Urgency,
    /// When it was proposed (Unix seconds).
    pub created_at: u64,
    /// The person it's for.
    pub assignee: MemberId,
    /// Team whose approvers may also decide it.
    pub team: Option<String>,
    /// Connection it would act through (none for knowledge gaps).
    pub connection: Option<u64>,
    /// Status.
    pub status: ItemStatus,
    /// Who decided it.
    pub decided_by: Option<MemberId>,
    /// When.
    pub decided_at: Option<u64>,
    /// Text that was approved (the draft, the edited text, or the answer).
    pub final_text: Option<String>,
}

/// A new item proposed by a workflow (no id, status or decision yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Workspace.
    pub workspace: Workspace,
    /// Kind.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Summary.
    pub summary: String,
    /// Draft text.
    pub draft: Option<String>,
    /// Question (knowledge gaps).
    pub question: Option<String>,
    /// Citations.
    pub sources: Vec<Source>,
    /// Confidence.
    pub confidence: Confidence,
    /// Urgency.
    pub urgency: Urgency,
    /// For whom.
    pub assignee: MemberId,
    /// Team.
    pub team: Option<String>,
    /// Connection it would act through.
    pub connection: Option<u64>,
}

/// A remembered answer ("answer once, Arkhon remembers").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeEntry {
    /// Id (cited as `knowledge:<id>`).
    pub id: u64,
    /// The question.
    pub question: String,
    /// The answer a person gave.
    pub answer: String,
    /// Who answered.
    pub answered_by: MemberId,
    /// When.
    pub at: u64,
}

/// The review queue and the small local knowledge store it feeds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queue {
    /// Items, oldest first.
    pub items: Vec<ReviewItem>,
    /// Remembered answers.
    pub knowledge: Vec<KnowledgeEntry>,
    next_item: ItemId,
    next_answer: u64,
}

impl Queue {
    /// Add a proposed item. Returns its id.
    pub fn propose(&mut self, p: Proposal, now: u64) -> ItemId {
        self.next_item += 1;
        let id = self.next_item;
        self.items.push(ReviewItem {
            id,
            workspace: p.workspace,
            kind: p.kind,
            title: p.title,
            summary: p.summary,
            draft: p.draft,
            question: p.question,
            sources: p.sources,
            confidence: p.confidence,
            urgency: p.urgency,
            created_at: now,
            assignee: p.assignee,
            team: p.team,
            connection: p.connection,
            status: ItemStatus::Waiting,
            decided_by: None,
            decided_at: None,
            final_text: None,
        });
        id
    }

    /// Item by id.
    #[must_use]
    pub fn get(&self, id: ItemId) -> Option<&ReviewItem> {
        self.items.iter().find(|i| i.id == id)
    }

    pub(crate) fn get_mut(&mut self, id: ItemId) -> Option<&mut ReviewItem> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    pub(crate) fn remember(&mut self, question: &str, answer: &str, by: MemberId, at: u64) -> u64 {
        self.next_answer += 1;
        let id = self.next_answer;
        self.knowledge.push(KnowledgeEntry {
            id,
            question: question.to_owned(),
            answer: answer.to_owned(),
            answered_by: by,
            at,
        });
        id
    }

    /// Find a remembered answer whose question matches (case and spacing ignored).
    #[must_use]
    pub fn lookup(&self, question: &str) -> Option<&KnowledgeEntry> {
        let norm = |s: &str| {
            s.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase()
        };
        let q = norm(question);
        self.knowledge.iter().rev().find(|k| norm(&k.question) == q)
    }
}
