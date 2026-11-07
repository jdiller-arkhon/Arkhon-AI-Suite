//! Value metrics (N5): time given back, measured only from real approvals.
//!
//! Every approved queue item records a [`ValueEvent`]. Minutes saved are not stored on the
//! event: they are computed from the company's current per-kind assumptions
//! ([`ValueSettings`]), which an admin can adjust, so the numbers always match what the report
//! says it assumed. Nothing is estimated from activity that didn't happen.
//!
//! Days are calendar days in UTC.

use std::collections::BTreeMap;

use arkhon_org::MemberId;
use serde::{Deserialize, Serialize};

use crate::queue::ItemId;

/// Seconds in a day.
pub const DAY: u64 = 86_400;

/// What kind of work was saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueKind {
    /// A drafted email, reply or quote was approved (as is or edited).
    DraftAccepted,
    /// A bill, receipt or document was filed.
    DocumentFiled,
    /// Meeting notes were approved.
    MeetingSummarized,
    /// A remembered answer was used again in approved work.
    AnswerReused,
}

impl ValueKind {
    /// Every kind.
    pub const ALL: [ValueKind; 4] = [
        ValueKind::DraftAccepted,
        ValueKind::DocumentFiled,
        ValueKind::MeetingSummarized,
        ValueKind::AnswerReused,
    ];

    /// Plain-language label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ValueKind::DraftAccepted => "Emails and quotes written for you",
            ValueKind::DocumentFiled => "Bills and documents filed",
            ValueKind::MeetingSummarized => "Meetings written up",
            ValueKind::AnswerReused => "Saved answers reused",
        }
    }

    /// Default minutes saved per event.
    #[must_use]
    pub fn default_minutes(self) -> u32 {
        match self {
            ValueKind::DraftAccepted => 4,
            ValueKind::DocumentFiled => 3,
            ValueKind::MeetingSummarized => 20,
            ValueKind::AnswerReused => 5,
        }
    }
}

/// One measured saving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueEvent {
    /// When (Unix seconds).
    pub at: u64,
    /// Kind.
    pub kind: ValueKind,
    /// Whose work it was (the item's assignee).
    pub member: MemberId,
    /// Approved queue item it came from. `None` only in the example company's sample history.
    pub item: Option<ItemId>,
}

/// Company assumptions for turning events into time and money.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueSettings {
    /// Minutes saved per event, per kind.
    pub minutes: BTreeMap<ValueKind, u32>,
    /// Loaded hourly cost of staff time, in cents.
    pub hourly_rate_cents: u32,
}

impl Default for ValueSettings {
    fn default() -> Self {
        ValueSettings {
            minutes: ValueKind::ALL
                .iter()
                .map(|k| (*k, k.default_minutes()))
                .collect(),
            hourly_rate_cents: 5_800,
        }
    }
}

impl ValueSettings {
    /// Minutes for one event of `kind`.
    #[must_use]
    pub fn minutes_for(&self, kind: ValueKind) -> u32 {
        self.minutes
            .get(&kind)
            .copied()
            .unwrap_or_else(|| kind.default_minutes())
    }

    /// Dollars (whole, rounded) for `minutes`.
    #[must_use]
    pub fn dollars(&self, minutes: u64) -> u64 {
        (minutes * u64::from(self.hourly_rate_cents) + 3_000) / 6_000
    }
}

/// Counts per kind plus total minutes.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Totals {
    /// Approved drafts (emails, quotes).
    pub drafts: u32,
    /// Documents filed.
    pub documents: u32,
    /// Meetings written up.
    pub meetings: u32,
    /// Saved answers reused.
    pub answers: u32,
    /// Minutes saved.
    pub minutes: u64,
    /// Hours saved, one decimal.
    pub hours: f64,
    /// Value of that time, whole dollars.
    pub dollars: u64,
}

impl Totals {
    pub(crate) fn add(&mut self, kind: ValueKind, minutes: u32) {
        match kind {
            ValueKind::DraftAccepted => self.drafts += 1,
            ValueKind::DocumentFiled => self.documents += 1,
            ValueKind::MeetingSummarized => self.meetings += 1,
            ValueKind::AnswerReused => self.answers += 1,
        }
        self.minutes += u64::from(minutes);
    }

    pub(crate) fn finish(&mut self, s: &ValueSettings) {
        self.hours = hours(self.minutes);
        self.dollars = s.dollars(self.minutes);
    }
}

/// Minutes as hours with one decimal.
#[must_use]
#[allow(clippy::cast_precision_loss)] // minute counts are far below 2^52
pub fn hours(minutes: u64) -> f64 {
    ((minutes * 10 + 30) / 60) as f64 / 10.0
}

/// Days since the epoch for a Unix time.
#[must_use]
pub fn day_number(t: u64) -> u64 {
    t / DAY
}

/// `(year, month, day)` for a day number (proleptic Gregorian, UTC).
#[must_use]
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)] // bounded calendar arithmetic
pub fn civil(day: u64) -> (i64, u32, u32) {
    // Howard Hinnant's days-from-civil inverse.
    let z = day as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Day number for a calendar date.
#[must_use]
#[allow(clippy::cast_sign_loss)] // dates before 1970 clamp to 0 below
pub fn days_from_civil(y: i64, m: u32, d: u32) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468).max(0) as u64
}

/// `YYYY-MM-DD`.
#[must_use]
pub fn iso_date(day: u64) -> String {
    let (y, m, d) = civil(day);
    format!("{y:04}-{m:02}-{d:02}")
}

/// One-letter weekday (`M`..`S`). Day 0 (1970-01-01) was a Thursday.
#[must_use]
pub fn weekday_letter(day: u64) -> &'static str {
    ["T", "F", "S", "S", "M", "T", "W"][usize::try_from(day % 7).unwrap_or(0)]
}

/// Full weekday name.
#[must_use]
pub fn weekday_name(day: u64) -> &'static str {
    [
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
    ][usize::try_from(day % 7).unwrap_or(0)]
}

/// Time saved on one day.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DayValue {
    /// `YYYY-MM-DD`.
    pub date: String,
    /// One-letter weekday for the chart.
    pub label: String,
    /// Full weekday name (for screen readers).
    pub weekday: String,
    /// Minutes saved.
    pub minutes: u64,
    /// Hours saved, one decimal.
    pub hours: f64,
}

/// "This week" on Home: the last 7 days ending today, plus 14 days of daily values
/// (`days[0..7]` is the week before, `days[7..14]` this week).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WeekView {
    /// `"company"` when the viewer sees company reports, `"you"` otherwise.
    pub scope: String,
    /// Hours saved in the last 7 days, one decimal.
    pub hours: f64,
    /// Value of that time, whole dollars.
    pub dollars: u64,
    /// Hourly rate used, whole dollars.
    pub hourly_rate: u32,
    /// Counts and minutes for the last 7 days.
    pub totals: Totals,
    /// Hours for the 7 days before that (for comparison).
    pub previous_hours: f64,
    /// Last 14 days, oldest first.
    pub days: Vec<DayValue>,
    /// `true` when this is the example company's sample history.
    pub example: bool,
}

/// One assumption line in the monthly report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Assumption {
    /// Kind key.
    pub kind: ValueKind,
    /// Label.
    pub label: String,
    /// Minutes saved per item.
    pub minutes_each: u32,
}

/// One person's line in the monthly report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PersonValue {
    /// Name.
    pub name: String,
    /// Their totals.
    pub totals: Totals,
}

/// Monthly value report, ready to export as JSON.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonthlyReport {
    /// Company.
    pub company: String,
    /// `YYYY-MM`.
    pub month: String,
    /// `"company"` or `"you"` (see [`WeekView::scope`]).
    pub scope: String,
    /// Person the report is limited to, when `scope == "you"`.
    pub person: Option<String>,
    /// Hourly rate used, whole dollars.
    pub hourly_rate: u32,
    /// The assumptions used for every number below.
    pub assumptions: Vec<Assumption>,
    /// Totals for the month.
    pub totals: Totals,
    /// Per person (company scope only).
    pub by_person: Vec<PersonValue>,
    /// Every day of the month.
    pub days: Vec<DayValue>,
    /// How the numbers were measured, in words.
    pub method: String,
    /// `true` for the example company's sample history.
    pub example: bool,
}
