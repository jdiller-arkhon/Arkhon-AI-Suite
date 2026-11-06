//! Arkhon Suite engine.
//!
//! One command surface over the organization model (`arkhon-org`): people, roles, teams and
//! connected apps. Every command:
//!
//! 1. runs the permission rules in `arkhon-org` (the only place rules live),
//! 2. records an entry in the activity log, including refusals (brief §4.2 audit log),
//! 3. is persisted by [`Store`] with an atomic write.
//!
//! The desktop app (Tauri, Phase 5) and the local dev server both call [`Suite::execute`];
//! neither re-implements rules. Views ([`Suite::view`]) are shaped for the screens and carry
//! the viewer's capabilities so the UI can hide what a person can't do.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub mod connector;
mod demo_work;
pub mod queue;
pub mod value;
pub mod vault;
pub mod work;

use arkhon_org::connections::{
    Access, App, AppPolicy, Audience, Availability, ConnError, ConnStatus, Connection, Connections,
    Kind,
};
use arkhon_org::{
    MemberId, MemberStatus, OrgError, Organization, Permission, Plan, Role, RoleId, Workspace,
};
use serde::{Deserialize, Serialize};

pub use connector::SendApproval;
pub use queue::{
    Confidence, ItemId, ItemKind, ItemStatus, Proposal, Queue, ReviewItem, Source, Urgency,
};
pub use value::{MonthlyReport, Totals, ValueEvent, ValueKind, ValueSettings, WeekView};
pub use vault::{Credential, MailLogin, Secret, TokenVault};
pub use work::{AskResult, WorkData};

use value::{day_number, DayValue, DAY};

/// Clock abstraction so tests are deterministic.
pub trait Clock: Send {
    /// Seconds since the Unix epoch.
    fn now(&self) -> u64;
}

/// Wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// One line of the activity log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEntry {
    /// When (Unix seconds).
    pub at: u64,
    /// Who did it (display name, kept even if the person is later removed).
    pub actor: String,
    /// What they tried, in plain words.
    pub action: String,
    /// `None` when it worked; the refusal sentence otherwise.
    pub refused: Option<String>,
}

/// Everything persisted for one organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// People, roles, teams.
    pub org: Organization,
    /// Connected apps.
    pub connections: Connections,
    /// Activity log, oldest first.
    pub activity: Vec<ActivityEntry>,
    /// Review queue and remembered answers.
    #[serde(default)]
    pub queue: Queue,
    /// Measured savings, oldest first.
    #[serde(default)]
    pub value: Vec<ValueEvent>,
    /// Minutes-saved assumptions and hourly rate.
    #[serde(default)]
    pub value_settings: ValueSettings,
    /// Example company only: pins "today" (Unix seconds) so the sample week stays put. Real
    /// companies leave this empty and use the clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example_today: Option<u64>,
    /// Workspace content, privacy settings and setup progress.
    #[serde(default)]
    pub work: WorkData,
}

/// Who a connection is for, as chosen in the Connect sheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ConnectFor {
    /// The viewer's own account.
    Me,
    /// Shared with one team.
    Team {
        /// Team name.
        team: String,
    },
    /// Shared with everyone.
    Everyone,
}

/// A request from the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum Command {
    /// Invite someone.
    Invite {
        /// Email.
        email: String,
        /// Role name.
        role: String,
    },
    /// Change a role.
    SetRole {
        /// Person.
        member: MemberId,
        /// Role name.
        role: String,
    },
    /// Pause access.
    Suspend {
        /// Person.
        member: MemberId,
    },
    /// Restore access.
    Restore {
        /// Person.
        member: MemberId,
    },
    /// Remove from the company.
    Remove {
        /// Person.
        member: MemberId,
    },
    /// Accept an invitation (on the invitee's first sign-in).
    AcceptInvite {
        /// Person.
        member: MemberId,
    },
    /// Change seat count.
    SetSeats {
        /// New count.
        seats: u32,
    },
    /// Change who may connect an app.
    SetAppPolicy {
        /// App.
        app: App,
        /// Rule.
        policy: AppPolicy,
    },
    /// Connect an account. New connections are always `Draft`: Arkhon asks before acting.
    Connect {
        /// App.
        app: App,
        /// Account label (email, company file name, folder path).
        account: String,
        /// Who it's for.
        #[serde(rename = "for")]
        for_: ConnectFor,
        /// Mailbox sign-in, for "Other email (IMAP)" only. Goes straight to the encrypted
        /// vault; never stored in state, logged or echoed back.
        #[serde(default, skip_serializing)]
        credentials: Option<MailLogin>,
    },
    /// Disconnect.
    Disconnect {
        /// Connection id.
        id: u64,
    },
    /// Sign in again after a connection expired.
    Reconnect {
        /// Connection id.
        id: u64,
    },
    /// Approve a queue item as Arkhon prepared it.
    Approve {
        /// Queue item.
        item: ItemId,
    },
    /// Change the prepared text, then approve.
    EditAndApprove {
        /// Queue item.
        item: ItemId,
        /// The text to use instead.
        text: String,
    },
    /// Dismiss a queue item; nothing happens.
    Dismiss {
        /// Queue item.
        item: ItemId,
    },
    /// Answer a question Arkhon couldn't; it remembers the answer.
    AnswerOnce {
        /// Queue item (a knowledge gap).
        item: ItemId,
        /// The answer.
        answer: String,
    },
    /// Change how many minutes one kind of work is assumed to save (admins).
    SetMinutesSaved {
        /// Kind of work.
        kind: ValueKind,
        /// Minutes per item.
        minutes: u32,
    },
    /// Change the hourly cost used for the dollar value (admins).
    SetHourlyRate {
        /// Whole dollars per hour.
        dollars: u32,
    },
    /// How long finished work and history are kept, in days; 0 keeps it until deleted (admins).
    SetRetention {
        /// Days (30, 90, 365 or 0).
        days: u32,
    },
    /// Erase everything Arkhon read, prepared and learned, and every connection (admins).
    /// People and roles are kept so the company can still sign in.
    DeleteAllData {
        /// The company name, typed to confirm.
        confirm: String,
    },
    /// Choose the industry pack (people who may install packs).
    SetIndustryPack {
        /// Pack key, e.g. `trades`.
        pack: String,
    },
}

/// A refused or failed command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    /// Plain-language sentence for the screen.
    pub message: String,
    /// `true` when the refusal is a permission decision (HTTP 403), `false` for bad input (400).
    pub forbidden: bool,
}

impl From<OrgError> for Refusal {
    fn from(e: OrgError) -> Self {
        let forbidden = matches!(
            e,
            OrgError::NotAllowed(_)
                | OrgError::OwnerOnly
                | OrgError::WouldEscalate(_)
                | OrgError::ActorInactive
                | OrgError::OwnerOnlyPermission(_)
        );
        Refusal {
            message: e.to_string(),
            forbidden,
        }
    }
}

impl From<ConnError> for Refusal {
    fn from(e: ConnError) -> Self {
        let forbidden = matches!(
            e,
            ConnError::AppOff(_)
                | ConnError::AdminsOnly(_)
                | ConnError::OwnAccountsOnly(_)
                | ConnError::NotYourTeam(_)
                | ConnError::NotAllowed
                | ConnError::NeedsAutomationRights
                | ConnError::PersonalCannotAct
                | ConnError::Inactive
        );
        Refusal {
            message: e.to_string(),
            forbidden,
        }
    }
}

fn bad(message: impl Into<String>) -> Refusal {
    Refusal {
        message: message.into(),
        forbidden: false,
    }
}

fn forbid(message: impl Into<String>) -> Refusal {
    Refusal {
        message: message.into(),
        forbidden: true,
    }
}

enum Decision {
    Approve,
    Edit(String),
    Dismiss,
    Answer(String),
}

/// The suite: state, a clock and (optionally) the sign-in vault.
pub struct Suite {
    state: State,
    clock: Box<dyn Clock>,
    vault: Option<TokenVault>,
}

impl std::fmt::Debug for Suite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Suite")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Suite {
    /// Wrap existing state.
    #[must_use]
    pub fn new(state: State, clock: Box<dyn Clock>) -> Self {
        Suite {
            state,
            clock,
            vault: None,
        }
    }

    /// Attach the encrypted sign-in vault (needed to connect "Other email").
    #[must_use]
    pub fn with_vault(mut self, vault: TokenVault) -> Self {
        self.vault = Some(vault);
        self
    }

    /// The sign-in vault, if attached.
    #[must_use]
    pub fn vault(&self) -> Option<&TokenVault> {
        self.vault.as_ref()
    }

    /// "Now" for value metrics and the review queue: the clock, or the example company's pinned
    /// day.
    #[must_use]
    pub fn today(&self) -> u64 {
        self.state.example_today.unwrap_or_else(|| self.clock.now())
    }

    /// Persistable state.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Run a command as `actor`. Every attempt is logged.
    ///
    /// # Errors
    /// A [`Refusal`] with a sentence to show.
    pub fn execute(&mut self, actor: MemberId, cmd: Command) -> Result<String, Refusal> {
        let actor_name = self.name_of(actor);
        let action = self.describe(&cmd);
        let result = self.apply(actor, cmd);
        if result.is_ok() {
            self.state.connections.sync_people(&self.state.org);
        }
        self.state.activity.push(ActivityEntry {
            at: self.clock.now(),
            actor: actor_name,
            action,
            refused: result.as_ref().err().map(|r| r.message.clone()),
        });
        result
    }

    #[allow(clippy::too_many_lines)] // one arm per command; splitting hides the mapping
    fn apply(&mut self, actor: MemberId, cmd: Command) -> Result<String, Refusal> {
        let State {
            org, connections, ..
        } = &mut self.state;
        match cmd {
            Command::Invite { email, role } => {
                let role = parse_role(org, &role)?;
                let name = name_from_email(&email);
                org.invite(actor, &name, &email, role)?;
                Ok(format!(
                    "Invite sent to {}. It holds a seat until they join.",
                    email.trim().to_lowercase()
                ))
            }
            Command::SetRole { member, role } => {
                let role = parse_role(org, &role)?;
                org.set_role(actor, member, role.clone())?;
                let n = org
                    .member(member)
                    .map(|m| m.name.clone())
                    .unwrap_or_default();
                Ok(format!("{n} is now {} {role}.", article(&role.to_string())))
            }
            Command::Suspend { member } => {
                org.suspend(actor, member)?;
                Ok(format!(
                    "Paused {}. Their seat is free.",
                    display(org, member)
                ))
            }
            Command::Restore { member } => {
                org.restore(actor, member)?;
                Ok(format!("{} can use Arkhon again.", display(org, member)))
            }
            Command::Remove { member } => {
                let n = display(org, member);
                org.remove(actor, member)?;
                Ok(format!("Removed {n} from the company."))
            }
            Command::AcceptInvite { member } => {
                org.accept_invite(member)?;
                Ok(format!("{} joined.", display(org, member)))
            }
            Command::SetSeats { seats } => {
                org.set_seats(actor, seats)?;
                Ok(format!("You now have {seats} seats."))
            }
            Command::SetAppPolicy { app, policy } => {
                connections.set_policy(org, actor, app, policy)?;
                Ok(if policy == AppPolicy::Off {
                    format!("{} is turned off. Its connections are paused.", app.name())
                } else {
                    format!("{}: {}.", app.name(), policy.label())
                })
            }
            Command::Connect {
                app,
                account,
                for_,
                credentials,
            } => {
                if account.trim().is_empty() {
                    return Err(Refusal {
                        message: "Enter the account to connect, like an email address.".into(),
                        forbidden: false,
                    });
                }
                if app.availability() == Availability::Planned {
                    return Err(Refusal {
                        message: format!("{} is coming soon.", app.name()),
                        forbidden: false,
                    });
                }
                let credential = match (app, credentials) {
                    (App::OtherEmail, Some(login)) => {
                        if login.imap_host.trim().is_empty()
                            || login.smtp_host.trim().is_empty()
                            || login.username.trim().is_empty()
                            || login.password.is_blank()
                        {
                            return Err(bad(
                                "Enter the mail servers, your sign-in name and password.",
                            ));
                        }
                        Some(Credential::Mail(login))
                    }
                    (App::OtherEmail, None) => {
                        return Err(bad(
                            "Enter the mail servers, your sign-in name and password.",
                        ))
                    }
                    (_, Some(_)) => {
                        return Err(bad(format!(
                            "{} signs in on its own page, not with a password here.",
                            app.name()
                        )))
                    }
                    (_, None) => None,
                };
                if credential.is_some() && self.vault.is_none() {
                    return Err(bad(
                        "Arkhon can't store passwords safely on this computer yet, so nothing was connected.",
                    ));
                }
                let before = connections.clone();
                let id = match for_ {
                    ConnectFor::Me => {
                        connections.connect_personal(org, actor, app, &account, Access::Draft)?
                    }
                    ConnectFor::Team { team } => connections.connect_company(
                        org,
                        actor,
                        app,
                        &account,
                        Audience::Teams([team].into()),
                        Access::Draft,
                    )?,
                    ConnectFor::Everyone => connections.connect_company(
                        org,
                        actor,
                        app,
                        &account,
                        Audience::Everyone,
                        Access::Draft,
                    )?,
                };
                if let (Some(cred), Some(vault)) = (credential, self.vault.as_ref()) {
                    if let Err(e) = vault.put(id, &cred) {
                        *connections = before;
                        return Err(bad(format!("{e} Nothing was connected.")));
                    }
                }
                Ok(format!(
                    "{} is connected. Arkhon will start reading it in the background.",
                    app.name()
                ))
            }
            Command::Disconnect { id } => {
                let label = connections
                    .get(id)
                    .map(|c| format!("{} ({})", c.app.name(), c.account))
                    .unwrap_or_default();
                connections.disconnect(org, actor, id)?;
                if let Some(vault) = &self.vault {
                    if vault.remove(id).is_err() {
                        return Ok(format!(
                            "Disconnected {label}. Its saved sign-in couldn't be erased; reconnecting will replace it."
                        ));
                    }
                }
                Ok(format!("Disconnected {label}."))
            }
            Command::Reconnect { id } => {
                // The connector framework re-runs sign-in (Phase 5). Here: only the owner of the
                // connection or an admin may trigger it, and it must currently need sign-in.
                let c = connections.get(id).ok_or(ConnError::UnknownConnection)?;
                let mine = match c.kind {
                    Kind::Personal { owner } => owner == actor,
                    Kind::Company { .. } => c.connected_by == actor,
                };
                if !(mine || org.can(actor, Permission::ManageConnections)) {
                    return Err(ConnError::NotAllowed.into());
                }
                let name = c.app.name();
                connections.mark_signed_in(id)?;
                Ok(format!("{name} is connected again."))
            }
            Command::Approve { item } => self.decide(actor, item, Decision::Approve),
            Command::EditAndApprove { item, text } => {
                self.decide(actor, item, Decision::Edit(text))
            }
            Command::Dismiss { item } => self.decide(actor, item, Decision::Dismiss),
            Command::AnswerOnce { item, answer } => {
                self.decide(actor, item, Decision::Answer(answer))
            }
            Command::SetMinutesSaved { kind, minutes } => {
                self.require(actor, Permission::ManageOrganization)?;
                if !(1..=240).contains(&minutes) {
                    return Err(bad("Use a number of minutes between 1 and 240."));
                }
                self.state.value_settings.minutes.insert(kind, minutes);
                Ok(format!(
                    "{}: now counted as {minutes} minutes each.",
                    kind.label()
                ))
            }
            Command::SetHourlyRate { dollars } => {
                self.require(actor, Permission::ManageOrganization)?;
                if !(1..=1_000).contains(&dollars) {
                    return Err(bad("Use an hourly cost between $1 and $1,000."));
                }
                self.state.value_settings.hourly_rate_cents = dollars * 100;
                Ok(format!("Time saved is now valued at ${dollars} an hour."))
            }
            Command::SetRetention { days } => {
                self.require(actor, Permission::ManageOrganization)?;
                if !work::RETENTION_CHOICES.contains(&days) {
                    return Err(bad("Pick 30 days, 90 days, 1 year or until you delete it."));
                }
                self.state.work.privacy.retention_days = days;
                Ok(if days == 0 {
                    "Arkhon will keep finished work until you delete it.".to_owned()
                } else {
                    format!(
                        "Arkhon will keep finished work for {}.",
                        retention_words(days)
                    )
                })
            }
            Command::DeleteAllData { confirm } => {
                self.require(actor, Permission::ManageOrganization)?;
                let name = self.state.org.name.clone();
                if !confirm.trim().eq_ignore_ascii_case(name.trim()) {
                    return Err(bad(format!(
                        "Type the company name, {name}, to confirm. Nothing was deleted."
                    )));
                }
                Ok(self.delete_all())
            }
            Command::SetIndustryPack { pack } => {
                self.require(actor, Permission::ManageUpdates)?;
                let Some((key, label, _, available)) =
                    work::PACKS.iter().find(|p| p.0 == pack.trim())
                else {
                    return Err(bad("That industry pack doesn't exist."));
                };
                if !available {
                    return Err(bad(format!("{label} is coming soon.")));
                }
                self.state.work.setup.industry_pack = Some((*key).to_owned());
                Ok(format!("Arkhon will use the {label} pack."))
            }
        }
    }

    /// Erase everything except people, roles, teams and settings.
    fn delete_all(&mut self) -> String {
        let ids: Vec<u64> = self.state.connections.all().map(|c| c.id).collect();
        let mut kept = 0;
        if let Some(vault) = &self.vault {
            kept = ids.iter().filter(|id| vault.remove(**id).is_err()).count();
        }
        self.state.connections = Connections::new();
        self.state.queue = Queue::default();
        self.state.value.clear();
        self.state.activity.clear();
        let w = &mut self.state.work;
        *w = WorkData {
            privacy: w.privacy.clone(),
            setup: work::SetupState {
                industry_pack: w.setup.industry_pack.clone(),
                files_read: 0,
                files_total: 0,
            },
            ..WorkData::default()
        };
        if kept > 0 {
            format!(
                "Deleted all Arkhon data. {kept} saved sign-in(s) couldn't be erased; delete the vault file to finish."
            )
        } else {
            "Deleted all Arkhon data on this computer. People and roles were kept so you can still sign in."
                .to_owned()
        }
    }

    fn require(&self, actor: MemberId, p: Permission) -> Result<(), Refusal> {
        if self.state.org.can(actor, p) {
            Ok(())
        } else if self.is_active(actor) {
            Err(OrgError::NotAllowed(p).into())
        } else {
            Err(OrgError::ActorInactive.into())
        }
    }

    fn is_active(&self, id: MemberId) -> bool {
        self.state
            .org
            .member(id)
            .is_some_and(|m| m.status == MemberStatus::Active)
    }

    /// Whether `actor` may decide `item`: its assignee, an approver on its team, or an admin.
    fn may_decide(&self, actor: MemberId, item: &ReviewItem) -> Result<(), Refusal> {
        let org = &self.state.org;
        if !self.is_active(actor) {
            return Err(OrgError::ActorInactive.into());
        }
        if item.assignee == actor || org.can(actor, Permission::ManageOrganization) {
            return Ok(());
        }
        if self.team_approver(actor, item) {
            return Ok(());
        }
        let who = self.name_of(item.assignee);
        Err(forbid(match &item.team {
            Some(t) => format!(
                "This is waiting for {who}. Only they, an approver on {t}, or an admin can decide it."
            ),
            None => format!("This is waiting for {who}. Only they or an admin can decide it."),
        }))
    }

    fn team_approver(&self, actor: MemberId, item: &ReviewItem) -> bool {
        let org = &self.state.org;
        item.team.as_deref().is_some_and(|t| {
            org.can(actor, Permission::ApproveForTeam)
                && org.team(t).is_some_and(|t| t.members.contains(&actor))
        })
    }

    /// Whether `actor` may let `item` go out through its connection.
    fn connection_ok(&self, actor: MemberId, item: &ReviewItem) -> Result<(), Refusal> {
        let Some(id) = item.connection else {
            return Ok(());
        };
        let conns = &self.state.connections;
        let c: &Connection = conns.get(id).ok_or_else(|| {
            bad("The account this would go through is no longer connected, so it can't be sent.")
        })?;
        let label = format!("{} ({})", c.app.name(), c.account);
        if c.status != ConnStatus::Active {
            return Err(bad(format!(
                "{label} needs attention before anything can go out through it."
            )));
        }
        if !conns
            .usable_by(&self.state.org, actor)
            .iter()
            .any(|u| u.id == id)
        {
            return Err(forbid(format!(
                "This would go out through {label}, which you can't use. Ask someone who can to approve it."
            )));
        }
        if c.access == Access::Read {
            return Err(forbid(format!(
                "{label} is connected read-only, so Arkhon can't send or change anything through it."
            )));
        }
        Ok(())
    }

    fn decide(&mut self, actor: MemberId, id: ItemId, d: Decision) -> Result<String, Refusal> {
        let item = self
            .state
            .queue
            .get(id)
            .cloned()
            .ok_or_else(|| bad("That item is no longer waiting."))?;
        if item.status != ItemStatus::Waiting {
            return Err(bad("Someone already handled this one."));
        }
        let gap = item.kind == ItemKind::KnowledgeGap;
        match &d {
            Decision::Answer(_) if !gap => {
                return Err(bad(
                    "This one doesn't ask a question. Approve or dismiss it.",
                ))
            }
            Decision::Approve | Decision::Edit(_) if gap => {
                return Err(bad(
                    "Arkhon didn't find an answer to this. Answer it once instead.",
                ))
            }
            Decision::Edit(t) | Decision::Answer(t) if t.trim().is_empty() => {
                return Err(bad("Write the text first."))
            }
            Decision::Edit(_) if item.draft.is_none() => {
                return Err(bad("There's no text to edit on this one."))
            }
            _ => {}
        }
        self.may_decide(actor, &item)?;
        if !matches!(d, Decision::Dismiss) {
            self.connection_ok(actor, &item)?;
        }
        let now = self.today();
        let (status, text, msg) = match d {
            Decision::Approve => (
                ItemStatus::Approved,
                item.draft.clone(),
                format!("{}: {}.", item.kind.done_word(), item.title),
            ),
            Decision::Edit(t) => (
                ItemStatus::Edited,
                Some(t.trim().to_owned()),
                format!(
                    "{} with your changes: {}.",
                    item.kind.done_word(),
                    item.title
                ),
            ),
            Decision::Dismiss => (
                ItemStatus::Dismissed,
                None,
                format!("Dismissed: {}. Nothing was sent.", item.title),
            ),
            Decision::Answer(a) => {
                let q = item.question.clone().unwrap_or_else(|| item.title.clone());
                self.state.queue.remember(&q, a.trim(), actor, now);
                (
                    ItemStatus::Approved,
                    Some(a.trim().to_owned()),
                    "Thanks. Arkhon will use your answer from now on.".to_owned(),
                )
            }
        };
        if let Some(it) = self.state.queue.get_mut(id) {
            it.status = status;
            it.final_text = text;
            it.decided_by = Some(actor);
            it.decided_at = Some(now);
        }
        if matches!(status, ItemStatus::Approved | ItemStatus::Edited) {
            let kind = match item.kind {
                ItemKind::DraftReply | ItemKind::SendQuote => Some(ValueKind::DraftAccepted),
                ItemKind::FileBill => Some(ValueKind::DocumentFiled),
                ItemKind::MeetingNotes => Some(ValueKind::MeetingSummarized),
                ItemKind::KnowledgeGap => None, // answering costs time; reuse saves it later
            };
            let reused = item
                .sources
                .iter()
                .filter(|s| s.reference.starts_with("knowledge:"))
                .count();
            for k in kind
                .into_iter()
                .chain(std::iter::repeat_n(ValueKind::AnswerReused, reused))
            {
                self.state.value.push(ValueEvent {
                    at: now,
                    kind: k,
                    member: item.assignee,
                    item: Some(id),
                });
            }
        }
        Ok(msg)
    }

    /// Add work a workflow prepared to the review queue. Logged as done by Arkhon.
    ///
    /// # Errors
    /// Bad input when the person, team or connection doesn't exist.
    pub fn propose(&mut self, p: Proposal) -> Result<ItemId, Refusal> {
        if self.state.org.member(p.assignee).is_none() {
            return Err(bad("That person isn't in the company."));
        }
        if let Some(t) = &p.team {
            if self.state.org.team(t).is_none() {
                return Err(ConnError::UnknownTeam(t.clone()).into());
            }
        }
        if let Some(c) = p.connection {
            if self.state.connections.get(c).is_none() {
                return Err(ConnError::UnknownConnection.into());
            }
        }
        let action = format!(
            "Prepared \u{201c}{}\u{201d} for {}",
            p.title,
            self.name_of(p.assignee)
        );
        let now = self.today();
        let id = self.state.queue.propose(p, now);
        self.state.activity.push(ActivityEntry {
            at: self.clock.now(),
            actor: "Arkhon".into(),
            action,
            refused: None,
        });
        Ok(id)
    }

    /// Permission for a connector to send an approved item (see [`connector`]).
    ///
    /// # Errors
    /// When the item doesn't exist, isn't approved, or doesn't go out through a connection.
    pub fn approval_for_send(&self, item: ItemId) -> Result<SendApproval, Refusal> {
        let it = self
            .state
            .queue
            .get(item)
            .ok_or_else(|| bad("That item doesn't exist."))?;
        if !matches!(it.status, ItemStatus::Approved | ItemStatus::Edited) {
            return Err(forbid(
                "Nothing is sent until someone approves it in Needs you.",
            ));
        }
        let (Some(connection), Some(text)) = (it.connection, it.final_text.clone()) else {
            return Err(bad("This item doesn't send anything."));
        };
        Ok(SendApproval {
            item,
            connection,
            text,
        })
    }

    fn name_of(&self, id: MemberId) -> String {
        self.state
            .org
            .member(id)
            .map_or_else(|| "Unknown person".into(), |m| m.name.clone())
    }

    fn describe(&self, cmd: &Command) -> String {
        let who = |id: &MemberId| self.name_of(*id);
        match cmd {
            Command::Invite { email, role } => format!("Invite {email} as {role}"),
            Command::SetRole { member, role } => format!("Change {}'s role to {role}", who(member)),
            Command::Suspend { member } => format!("Pause {}", who(member)),
            Command::Restore { member } => format!("Restore {}", who(member)),
            Command::Remove { member } => format!("Remove {}", who(member)),
            Command::AcceptInvite { member } => format!("{} accepted their invite", who(member)),
            Command::SetSeats { seats } => format!("Change seats to {seats}"),
            Command::SetAppPolicy { app, policy } => {
                format!("Set {} to \"{}\"", app.name(), policy.label())
            }
            Command::Connect {
                app, account, for_, ..
            } => {
                let f = match for_ {
                    ConnectFor::Me => "themselves".to_owned(),
                    ConnectFor::Team { team } => team.clone(),
                    ConnectFor::Everyone => "everyone".to_owned(),
                };
                format!("Connect {} ({account}) for {f}", app.name())
            }
            Command::Disconnect { id } => format!("Disconnect {}", self.conn_label(*id)),
            Command::Reconnect { id } => format!("Reconnect {}", self.conn_label(*id)),
            Command::Approve { item } => format!("Approve {}", self.item_label(*item)),
            Command::EditAndApprove { item, .. } => {
                format!("Edit and approve {}", self.item_label(*item))
            }
            Command::Dismiss { item } => format!("Dismiss {}", self.item_label(*item)),
            Command::AnswerOnce { item, .. } => format!("Answer {}", self.item_label(*item)),
            Command::SetMinutesSaved { kind, minutes } => {
                format!("Count \"{}\" as {minutes} minutes each", kind.label())
            }
            Command::SetHourlyRate { dollars } => format!("Value time at ${dollars} an hour"),
            Command::SetRetention { days } => format!(
                "Keep finished work {}",
                if *days == 0 {
                    "until deleted".to_owned()
                } else {
                    format!("for {}", retention_words(*days))
                }
            ),
            Command::DeleteAllData { .. } => "Delete all Arkhon data".to_owned(),
            Command::SetIndustryPack { pack } => format!("Choose the \"{pack}\" industry pack"),
        }
    }

    fn item_label(&self, id: ItemId) -> String {
        self.state.queue.get(id).map_or_else(
            || "an item".into(),
            |i| format!("\u{201c}{}\u{201d}", i.title),
        )
    }

    fn conn_label(&self, id: u64) -> String {
        self.state
            .connections
            .get(id)
            .map_or_else(|| "a connection".into(), |c| c.app.name().to_owned())
    }

    /// Everything a screen needs, shaped for `viewer`.
    #[must_use]
    #[allow(clippy::too_many_lines)] // assembles one screen snapshot
    pub fn view(&self, viewer: MemberId) -> View {
        let org = &self.state.org;
        let can = |p| org.can(viewer, p);
        let viewer_m = org.member(viewer);
        let mut roles: Vec<RoleView> = [
            RoleId::Owner,
            RoleId::Admin,
            RoleId::Manager,
            RoleId::Member,
        ]
        .iter()
        .filter_map(Role::builtin)
        .chain(org.custom_roles())
        .map(|r| RoleView::from_role(&r, org))
        .collect();
        roles.sort_by_key(|r| r.custom);
        let teams = org
            .teams()
            .map(|t| TeamView {
                name: t.name.clone(),
                members: t
                    .members
                    .iter()
                    .filter_map(|m| org.member(*m))
                    .map(|m| m.name.clone())
                    .collect(),
                workspaces: t
                    .workspaces
                    .iter()
                    .map(|w| workspace_label(*w).to_owned())
                    .collect(),
                is_member: t.members.contains(&viewer),
            })
            .collect();
        let people = org
            .members()
            .map(|m| PersonView {
                id: m.id,
                name: m.name.clone(),
                email: m.email.clone(),
                role: m.role.to_string(),
                status: m.status,
            })
            .collect();
        let conns = &self.state.connections;
        let manage_conns = can(Permission::ManageConnections);
        let connections = conns
            .all()
            .filter(|c| match c.kind {
                Kind::Personal { owner } => owner == viewer || manage_conns,
                Kind::Company { .. } => true,
            })
            .map(|c| ConnectionView {
                id: c.id,
                app: c.app,
                app_name: c.app.name().to_owned(),
                account: c.account.clone(),
                mine: matches!(c.kind, Kind::Personal { owner } if owner == viewer),
                personal: matches!(c.kind, Kind::Personal { .. }),
                shared_with: match &c.kind {
                    Kind::Personal { owner } => {
                        format!("Only {}", self.name_of(*owner))
                    }
                    Kind::Company { audience } => audience_label(audience),
                },
                connected_by: self.name_of(c.connected_by),
                status: c.status,
                can_disconnect: manage_conns
                    || match c.kind {
                        Kind::Personal { owner } => owner == viewer,
                        Kind::Company { .. } => c.connected_by == viewer,
                    },
            })
            .collect();
        let apps = App::ALL
            .iter()
            .map(|a| {
                let policy = conns.policy(*a);
                AppView {
                    app: *a,
                    name: a.name().to_owned(),
                    category: a.category().label().to_owned(),
                    policy,
                    available: a.availability() != Availability::Planned,
                    connected: conns.all().filter(|c| c.app == *a).count(),
                    can_connect_me: policy != AppPolicy::Off
                        && (manage_conns || policy != AppPolicy::AdminsOnly),
                    can_connect_team: policy != AppPolicy::Off
                        && (manage_conns || policy == AppPolicy::TeamAccounts),
                    can_connect_everyone: policy != AppPolicy::Off && manage_conns,
                }
            })
            .collect();
        View {
            company: org.name.clone(),
            plan: match org.plan() {
                Plan::Starter => "Starter",
                Plan::Business => "Business",
                Plan::Pro => "Pro",
            }
            .to_owned(),
            seats: org.seats(),
            seats_used: org.seats_used(),
            viewer: viewer_m.map(|m| PersonView {
                id: m.id,
                name: m.name.clone(),
                email: m.email.clone(),
                role: m.role.to_string(),
                status: m.status,
            }),
            can: Capabilities {
                manage_people: can(Permission::ManageMembers),
                assign_roles: can(Permission::AssignRoles),
                manage_billing: can(Permission::ManageBilling),
                manage_connections: manage_conns,
                view_activity: can(Permission::ViewActivityHistory),
            },
            people,
            roles,
            teams,
            connections,
            apps,
            workspaces: org
                .workspaces_for(viewer)
                .into_iter()
                .map(|w| workspace_label(w).to_owned())
                .collect(),
            needs_you: self.needs_you(viewer),
            this_week: self.this_week(viewer),
            nav: self.nav(viewer),
            inbox: self.inbox_view(viewer),
            desk: self.desk_view(viewer),
            docs: self.docs_view(viewer),
            knowledge: self.knowledge_view(viewer),
            meetings: self.meetings_view(viewer),
            growth: self.growth_view(viewer),
            insights: self.insights_view(viewer),
            privacy: self.privacy_view(viewer),
            setup: self.setup_view(viewer),
            example: self.state.example_today.is_some(),
        }
    }

    /// Waiting items for `viewer`: assigned to them, or on a team they approve for. Urgent
    /// first, then oldest. At most three are listed; `total` counts all.
    #[must_use]
    pub fn needs_you(&self, viewer: MemberId) -> NeedsYouView {
        if !self.is_active(viewer) {
            return NeedsYouView {
                total: 0,
                items: Vec::new(),
            };
        }
        let mut mine: Vec<&ReviewItem> = self
            .state
            .queue
            .items
            .iter()
            .filter(|i| i.status == ItemStatus::Waiting)
            .filter(|i| i.assignee == viewer || self.team_approver(viewer, i))
            .collect();
        mine.sort_by_key(|i| (i.urgency, i.created_at, i.id));
        NeedsYouView {
            total: mine.len(),
            items: mine
                .into_iter()
                .take(3)
                .map(|i| self.item_view(viewer, i))
                .collect(),
        }
    }

    pub(crate) fn item_view(&self, viewer: MemberId, i: &ReviewItem) -> ItemView {
        let blocked = self
            .may_decide(viewer, i)
            .and_then(|()| self.connection_ok(viewer, i))
            .err()
            .map(|r| r.message);
        ItemView {
            id: i.id,
            kind: i.kind,
            workspace: workspace_label(i.workspace).to_owned(),
            title: i.title.clone(),
            summary: i.summary.clone(),
            draft: i.draft.clone(),
            question: i.question.clone(),
            sources: i.sources.clone(),
            confidence: i.confidence,
            confidence_label: i.confidence.label().to_owned(),
            urgency: i.urgency,
            created_at: i.created_at,
            assignee: self.name_of(i.assignee),
            team: i.team.clone(),
            connection: i.connection.and_then(|c| {
                self.state
                    .connections
                    .get(c)
                    .map(|c| format!("{} ({})", c.app.name(), c.account))
            }),
            action: i.kind.verb().to_owned(),
            done_word: i.kind.done_word().to_owned(),
            can_approve: i.status == ItemStatus::Waiting && blocked.is_none(),
            blocked: blocked.filter(|_| i.status == ItemStatus::Waiting),
            status: i.status,
            final_text: i.final_text.clone(),
        }
    }

    /// Events the viewer may see: everyone's with company reports, otherwise their own.
    fn visible_value(&self, viewer: MemberId) -> (bool, Vec<&ValueEvent>) {
        let company = self.state.org.can(viewer, Permission::ViewCompanyReports);
        let active = self.is_active(viewer);
        (
            company,
            self.state
                .value
                .iter()
                .filter(|e| active && (company || e.member == viewer))
                .collect(),
        )
    }

    fn day_values(&self, events: &[&ValueEvent], first: u64, last: u64) -> Vec<DayValue> {
        let s = &self.state.value_settings;
        (first..=last)
            .map(|d| {
                let minutes: u64 = events
                    .iter()
                    .filter(|e| day_number(e.at) == d)
                    .map(|e| u64::from(s.minutes_for(e.kind)))
                    .sum();
                DayValue {
                    date: value::iso_date(d),
                    label: value::weekday_letter(d).to_owned(),
                    weekday: value::weekday_name(d).to_owned(),
                    minutes,
                    hours: value::hours(minutes),
                }
            })
            .collect()
    }

    fn totals(&self, events: &[&ValueEvent], first: u64, last: u64) -> Totals {
        let s = &self.state.value_settings;
        let mut t = Totals::default();
        for e in events {
            let d = day_number(e.at);
            if (first..=last).contains(&d) {
                t.add(e.kind, s.minutes_for(e.kind));
            }
        }
        t.finish(s);
        t
    }

    /// Home's "This week": the last 7 days ending today, measured from approvals only.
    #[must_use]
    pub fn this_week(&self, viewer: MemberId) -> WeekView {
        let (company, events) = self.visible_value(viewer);
        let today = day_number(self.today());
        let first = today.saturating_sub(13);
        let days = self.day_values(&events, first, today);
        let totals = self.totals(&events, today.saturating_sub(6), today);
        let prev: u64 = days.iter().take(7).map(|d| d.minutes).sum();
        WeekView {
            scope: if company { "company" } else { "you" }.to_owned(),
            hours: totals.hours,
            dollars: totals.dollars,
            hourly_rate: self.state.value_settings.hourly_rate_cents / 100,
            totals,
            previous_hours: value::hours(prev),
            days,
            example: self.state.example_today.is_some(),
        }
    }

    /// Monthly value report as data (the UI exports it as JSON).
    ///
    /// # Errors
    /// Bad input for an impossible month; forbidden for people without access.
    pub fn monthly_report(
        &self,
        viewer: MemberId,
        year: i64,
        month: u32,
    ) -> Result<MonthlyReport, Refusal> {
        if !(1..=12).contains(&month) || !(1970..=9999).contains(&year) {
            return Err(bad("Pick a month like 2026-11."));
        }
        if !self.is_active(viewer) {
            return Err(OrgError::ActorInactive.into());
        }
        let (company, events) = self.visible_value(viewer);
        let first = value::days_from_civil(year, month, 1);
        let (ny, nm) = if month == 12 {
            (year + 1, 1)
        } else {
            (year, month + 1)
        };
        let last = value::days_from_civil(ny, nm, 1) - 1;
        let s = &self.state.value_settings;
        let mut by_person: Vec<value::PersonValue> = Vec::new();
        if company {
            let mut ids: Vec<MemberId> = events.iter().map(|e| e.member).collect();
            ids.sort_unstable();
            ids.dedup();
            for id in ids {
                let theirs: Vec<&ValueEvent> =
                    events.iter().copied().filter(|e| e.member == id).collect();
                let totals = self.totals(&theirs, first, last);
                if totals.minutes > 0 {
                    by_person.push(value::PersonValue {
                        name: self.name_of(id),
                        totals,
                    });
                }
            }
            by_person.sort_by_key(|p| std::cmp::Reverse(p.totals.minutes));
        }
        Ok(MonthlyReport {
            company: self.state.org.name.clone(),
            month: format!("{year:04}-{month:02}"),
            scope: if company { "company" } else { "you" }.to_owned(),
            person: (!company).then(|| self.name_of(viewer)),
            hourly_rate: s.hourly_rate_cents / 100,
            assumptions: ValueKind::ALL
                .iter()
                .map(|k| value::Assumption {
                    kind: *k,
                    label: k.label().to_owned(),
                    minutes_each: s.minutes_for(*k),
                })
                .collect(),
            totals: self.totals(&events, first, last),
            by_person,
            days: self.day_values(&events, first, last),
            method:
                "Counted only from work a person approved in Arkhon. Each approved item counts \
                     the minutes listed under assumptions; your admin can change them."
                    .to_owned(),
            example: self.state.example_today.is_some(),
        })
    }

    /// The activity log, newest first, if the viewer may see it.
    ///
    /// # Errors
    /// A forbidden [`Refusal`] without the activity permission.
    pub fn activity(&self, viewer: MemberId) -> Result<Vec<ActivityEntry>, Refusal> {
        if !self.state.org.can(viewer, Permission::ViewActivityHistory) {
            return Err(OrgError::NotAllowed(Permission::ViewActivityHistory).into());
        }
        Ok(self.state.activity.iter().rev().cloned().collect())
    }
}

/// Screen-shaped snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct View {
    /// Company name.
    pub company: String,
    /// Plan label.
    pub plan: String,
    /// Seats bought.
    pub seats: u32,
    /// Seats in use.
    pub seats_used: u32,
    /// The person viewing.
    pub viewer: Option<PersonView>,
    /// What the viewer may do.
    pub can: Capabilities,
    /// Everyone.
    pub people: Vec<PersonView>,
    /// Roles with plain-language lists.
    pub roles: Vec<RoleView>,
    /// Teams.
    pub teams: Vec<TeamView>,
    /// Connections the viewer can see.
    pub connections: Vec<ConnectionView>,
    /// App library.
    pub apps: Vec<AppView>,
    /// Workspaces the viewer can open.
    pub workspaces: Vec<String>,
    /// Home: work waiting for the viewer.
    pub needs_you: NeedsYouView,
    /// Home: time given back in the last 7 days.
    pub this_week: WeekView,
    /// Header links to the viewer's workspaces.
    pub nav: Vec<work::NavLink>,
    /// Email page (absent without the workspace).
    pub inbox: Option<work::InboxView>,
    /// Customer replies page.
    pub desk: Option<work::DeskView>,
    /// Documents page.
    pub docs: Option<work::DocsView>,
    /// Company answers page.
    pub knowledge: Option<work::KnowledgeView>,
    /// Meeting notes page.
    pub meetings: Option<work::MeetingsView>,
    /// Quotes & marketing page.
    pub growth: Option<work::GrowthView>,
    /// Reports page.
    pub insights: Option<work::InsightsView>,
    /// Privacy Center.
    pub privacy: work::PrivacyView,
    /// First-run setup.
    pub setup: work::SetupView,
    /// Example company (sample data).
    pub example: bool,
}

/// Home's "Needs you".
#[derive(Debug, Clone, Serialize)]
pub struct NeedsYouView {
    /// Everything waiting for the viewer.
    pub total: usize,
    /// Up to three, urgent first.
    pub items: Vec<ItemView>,
}

/// A queue item as shown on Home.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_field_names)]
pub struct ItemView {
    /// Id (send with approve/dismiss commands).
    pub id: ItemId,
    /// Kind.
    pub kind: ItemKind,
    /// Workspace label.
    pub workspace: String,
    /// Title.
    pub title: String,
    /// Summary.
    pub summary: String,
    /// Prepared text.
    pub draft: Option<String>,
    /// Question (knowledge gaps).
    pub question: Option<String>,
    /// Citations.
    pub sources: Vec<Source>,
    /// Confidence key.
    pub confidence: Confidence,
    /// Confidence in words.
    pub confidence_label: String,
    /// Urgency.
    pub urgency: Urgency,
    /// When proposed.
    pub created_at: u64,
    /// Who it's for.
    pub assignee: String,
    /// Team.
    pub team: Option<String>,
    /// Account it would go out through, in words.
    pub connection: Option<String>,
    /// Primary button label.
    pub action: String,
    /// Word shown once done.
    pub done_word: String,
    /// Whether the viewer can approve it right now.
    pub can_approve: bool,
    /// Why not, in words.
    pub blocked: Option<String>,
    /// Waiting, approved, edited or dismissed.
    pub status: ItemStatus,
    /// What was sent or filed, once decided.
    pub final_text: Option<String>,
}

/// What the viewer may do (drives which controls are shown).
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)] // independent UI flags
pub struct Capabilities {
    /// Invite, pause, remove.
    pub manage_people: bool,
    /// Change roles.
    pub assign_roles: bool,
    /// Seats and plan.
    pub manage_billing: bool,
    /// App rules and company accounts.
    pub manage_connections: bool,
    /// Activity history.
    pub view_activity: bool,
}

/// A person.
#[derive(Debug, Clone, Serialize)]
pub struct PersonView {
    /// Id.
    pub id: MemberId,
    /// Name.
    pub name: String,
    /// Email.
    pub email: String,
    /// Role name.
    pub role: String,
    /// Status.
    pub status: MemberStatus,
}

/// A role card.
#[derive(Debug, Clone, Serialize)]
pub struct RoleView {
    /// Name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Plain-language permissions held.
    pub can: Vec<String>,
    /// Workspaces included.
    pub workspaces: Vec<String>,
    /// People holding it.
    pub people: usize,
    /// Custom role.
    pub custom: bool,
}

impl RoleView {
    fn from_role(r: &Role, org: &Organization) -> Self {
        let custom = matches!(r.id, RoleId::Custom(_));
        RoleView {
            name: r.id.to_string(),
            description: match &r.id {
                RoleId::Owner => "Runs the account, including plan and billing.",
                RoleId::Admin => "Runs Arkhon day to day for the company.",
                RoleId::Manager => "Leads a team and signs off on their work.",
                RoleId::Member => "Uses Arkhon for their own work.",
                RoleId::Custom(_) => "A role your company created.",
            }
            .to_owned(),
            can: r.permissions.iter().map(|p| p.label().to_owned()).collect(),
            workspaces: r
                .workspaces
                .iter()
                .map(|w| workspace_label(*w).to_owned())
                .collect(),
            people: org.members().filter(|m| m.role == r.id).count(),
            custom,
        }
    }
}

/// A team card.
#[derive(Debug, Clone, Serialize)]
pub struct TeamView {
    /// Name.
    pub name: String,
    /// Member names.
    pub members: Vec<String>,
    /// Extra workspaces.
    pub workspaces: Vec<String>,
    /// Whether the viewer is on it.
    pub is_member: bool,
}

/// A connection row.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionView {
    /// Id.
    pub id: u64,
    /// App key.
    pub app: App,
    /// App display name.
    pub app_name: String,
    /// Account label.
    pub account: String,
    /// The viewer's own account.
    pub mine: bool,
    /// Personal (vs company).
    pub personal: bool,
    /// Who can use it, in words.
    pub shared_with: String,
    /// Who connected it.
    pub connected_by: String,
    /// Health.
    pub status: ConnStatus,
    /// Whether the viewer may disconnect it.
    pub can_disconnect: bool,
}

/// An app tile.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)] // independent UI flags
pub struct AppView {
    /// Key.
    pub app: App,
    /// Name.
    pub name: String,
    /// Category label.
    pub category: String,
    /// Rule.
    pub policy: AppPolicy,
    /// Built (vs coming soon).
    pub available: bool,
    /// Number of connections.
    pub connected: usize,
    /// Viewer may connect their own account.
    pub can_connect_me: bool,
    /// Viewer may connect a team account.
    pub can_connect_team: bool,
    /// Viewer may connect a company-wide account.
    pub can_connect_everyone: bool,
}

fn audience_label(a: &Audience) -> String {
    match a {
        Audience::Everyone => "Everyone".into(),
        Audience::Roles(r) => {
            let names: Vec<String> = r.iter().map(|x| format!("{x}s")).collect();
            join_words(&names)
        }
        Audience::Teams(t) => join_words(&t.iter().cloned().collect::<Vec<_>>()),
    }
}

fn join_words(v: &[String]) -> String {
    match v {
        [] => String::new(),
        [a] => a.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn retention_words(days: u32) -> String {
    match days {
        365 => "1 year".to_owned(),
        d => format!("{d} days"),
    }
}

fn workspace_label(w: Workspace) -> &'static str {
    match w {
        Workspace::Inbox => "Email",
        Workspace::Desk => "Customer replies",
        Workspace::Docs => "Documents",
        Workspace::Knowledge => "Company answers",
        Workspace::Meetings => "Meeting notes",
        Workspace::Growth => "Quotes & marketing",
        Workspace::Insights => "Reports",
        Workspace::Dev => "Coding & IT",
    }
}

fn parse_role(org: &Organization, name: &str) -> Result<RoleId, Refusal> {
    let id = RoleId::from(name.trim().to_owned());
    if org.role(&id).is_some() {
        Ok(id)
    } else {
        Err(OrgError::UnknownRole.into())
    }
}

fn display(org: &Organization, id: MemberId) -> String {
    org.member(id)
        .map_or_else(|| "that person".into(), |m| m.name.clone())
}

fn article(word: &str) -> &'static str {
    if word.starts_with(['A', 'E', 'I', 'O', 'U']) {
        "an"
    } else {
        "a"
    }
}

fn name_from_email(email: &str) -> String {
    email
        .trim()
        .split('@')
        .next()
        .unwrap_or_default()
        .split(['.', '_', '-'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------------------------

/// JSON file store with atomic replace (write temp, fsync, rename).
#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    /// Store at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Store { path: path.into() }
    }

    /// Path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load, or `None` if the file doesn't exist yet.
    ///
    /// # Errors
    /// I/O or corrupt-file errors.
    pub fn load(&self) -> std::io::Result<Option<State>> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Save atomically.
    ///
    /// # Errors
    /// I/O errors.
    pub fn save(&self, state: &State) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }
}

// ---------------------------------------------------------------------------------------------
// Example company
// ---------------------------------------------------------------------------------------------

/// Ids of the people in the example company, for tests and the dev server's "View as".
#[derive(Debug, Clone, Copy)]
pub struct DemoIds {
    /// Owner.
    pub owner: MemberId,
    /// Admin.
    pub admin: MemberId,
    /// Manager.
    pub manager: MemberId,
    /// Custom-role dispatcher on Front office.
    pub dispatcher: MemberId,
    /// Member on Field techs.
    pub tech: MemberId,
}

/// Build the "Coastline Mechanical" example company used by the prototype. Clearly sample data.
///
/// # Panics
/// Never in practice: the seed only performs operations the rules allow.
#[must_use]
#[allow(clippy::too_many_lines)] // linear seed script
pub fn demo_state() -> (State, DemoIds) {
    let (mut org, owner) = Organization::create(
        "Coastline Mechanical",
        Plan::Business,
        10,
        "Dana Ruiz",
        "dana@coastline.com",
    )
    .expect("seed");
    let dispatcher_role = org
        .create_role(
            owner,
            "Dispatcher",
            [Permission::ApproveForTeam].into(),
            [
                Workspace::Inbox,
                Workspace::Desk,
                Workspace::Knowledge,
                Workspace::Growth,
            ]
            .into(),
        )
        .expect("seed");
    let mut add = |name: &str, email: &str, role: RoleId, accept: bool| {
        let id = org.invite(owner, name, email, role).expect("seed");
        if accept {
            org.accept_invite(id).expect("seed");
        }
        id
    };
    let admin = add("Ari Patel", "ari@coastline.com", RoleId::Admin, true);
    let manager = add("Max Okafor", "max@coastline.com", RoleId::Manager, true);
    let dispatcher = add("Lena Cho", "lena@coastline.com", dispatcher_role, true);
    let tech = add("Tia Alvarez", "tia@coastline.com", RoleId::Member, true);
    let sam = add("Sam Brooks", "sam@coastline.com", RoleId::Member, true);
    let rae = add("Rae Kim", "rae@coastline.com", RoleId::Member, false);
    let jon = add("Jon Weiss", "jon@coastline.com", RoleId::Member, true);
    let pat = add("Pat Doyle", "pat@coastline.com", RoleId::Member, true);
    org.suspend(owner, pat).expect("seed");

    org.upsert_team(
        owner,
        "Front office",
        [Workspace::Desk, Workspace::Growth].into(),
    )
    .expect("seed");
    for m in [admin, dispatcher, rae] {
        org.add_to_team(owner, "Front office", m).expect("seed");
    }
    org.upsert_team(
        owner,
        "Field techs",
        [Workspace::Meetings, Workspace::Docs].into(),
    )
    .expect("seed");
    for m in [manager, tech, sam, jon] {
        org.add_to_team(owner, "Field techs", m).expect("seed");
    }

    let mut c = Connections::new();
    c.set_policy(&org, owner, App::Jobber, AppPolicy::TeamAccounts)
        .expect("seed");
    let team = |t: &str| Audience::Teams(BTreeSet::from([t.to_owned()]));
    let service = c
        .connect_company(
            &org,
            admin,
            App::Outlook,
            "service@coastline.com",
            team("Front office"),
            Access::Draft,
        )
        .expect("seed");
    let books = c
        .connect_company(
            &org,
            owner,
            App::QuickBooks,
            "Coastline Mechanical books",
            Audience::Roles([RoleId::Owner, RoleId::Admin].into()),
            Access::Draft,
        )
        .expect("seed");
    let nas = c
        .connect_company(
            &org,
            admin,
            App::LocalFolder,
            r"\\office-nas\jobs",
            Audience::Everyone,
            Access::Read,
        )
        .expect("seed");
    let drive = c
        .connect_company(
            &org,
            admin,
            App::GoogleDrive,
            "price books & manuals",
            Audience::Everyone,
            Access::Read,
        )
        .expect("seed");
    c.mark_needs_sign_in(drive).expect("seed");
    let dana_mail = c
        .connect_personal(
            &org,
            owner,
            App::Outlook,
            "dana@coastline.com",
            Access::Draft,
        )
        .expect("seed");
    c.connect_personal(
        &org,
        owner,
        App::GoogleCalendar,
        "dana@coastline.com",
        Access::Read,
    )
    .expect("seed");
    let tia_mail = c
        .connect_personal(&org, tech, App::Gmail, "tia@coastline.com", Access::Draft)
        .expect("seed");

    let today = demo_today();
    let mut queue = demo_queue(
        today,
        &DemoQueueIds {
            owner,
            dispatcher,
            tech,
            service,
            books,
            dana_mail,
            tia_mail,
        },
    );
    let work = demo_work::demo_work(
        today,
        &mut queue,
        &demo_work::Ids {
            owner,
            admin,
            dispatcher,
            tech,
            service,
            books,
            nas,
            dana_mail,
            tia_mail,
        },
    );
    let value = demo_value(today, &[owner, admin, dispatcher, tech, sam, jon, manager]);

    (
        State {
            org,
            connections: c,
            activity: Vec::new(),
            queue,
            value,
            value_settings: ValueSettings::default(),
            example_today: Some(today),
            work,
        },
        DemoIds {
            owner,
            admin,
            manager,
            dispatcher,
            tech,
        },
    )
}

/// The example company's pinned "today": Friday 6 November 2026, 9:00 UTC.
#[must_use]
pub fn demo_today() -> u64 {
    value::days_from_civil(2026, 11, 6) * DAY + 9 * 3_600
}

struct DemoQueueIds {
    owner: MemberId,
    dispatcher: MemberId,
    tech: MemberId,
    service: u64,
    books: u64,
    dana_mail: u64,
    tia_mail: u64,
}

fn src(label: &str, reference: &str) -> Source {
    Source {
        label: label.into(),
        reference: reference.into(),
    }
}

/// Example review queue (sample data).
#[allow(clippy::too_many_lines)] // linear seed script
fn demo_queue(today: u64, ids: &DemoQueueIds) -> Queue {
    let mut q = Queue::default();
    let hour = 3_600;
    q.propose(
        Proposal {
            workspace: Workspace::Inbox,
            kind: ItemKind::DraftReply,
            title: "Reply to Marisol Vega".into(),
            summary:
                "Her AC is blowing warm. Arkhon offered today's 1\u{2013}3 pm slot and confirmed \
                      her unit is under warranty."
                    .into(),
            draft: Some(
                "Hi Marisol,\n\nSorry to hear the AC is blowing warm. We can come out today \
                 between 1 and 3 pm. Your unit was installed in May 2024, so the visit and any \
                 covered parts are under warranty.\n\nDana\nCoastline Mechanical"
                    .into(),
            ),
            question: None,
            sources: vec![
                src(
                    "Price list 2026",
                    r"file:\\office-nas\jobs\price-list-2026.pdf#p2",
                ),
                src(
                    "Job #4471, Vega residence",
                    r"file:\\office-nas\jobs\4471\invoice.pdf",
                ),
                src(
                    "Warranty policy",
                    r"file:\\office-nas\jobs\policies\warranty.docx",
                ),
            ],
            confidence: Confidence::High,
            urgency: Urgency::Urgent,
            assignee: ids.owner,
            team: None,
            connection: Some(ids.dana_mail),
        },
        today - hour,
    );
    q.propose(
        Proposal {
            workspace: Workspace::Docs,
            kind: ItemKind::FileBill,
            title: "File a Ferguson bill for $2,418.36".into(),
            summary: "It matches purchase order 1187 exactly and belongs to the Harbor Dental job."
                .into(),
            draft: None,
            question: None,
            sources: vec![
                src("Ferguson invoice 88213", "mail:service@coastline.com/88213"),
                src("Purchase order 1187", r"file:\\office-nas\jobs\po\1187.pdf"),
            ],
            confidence: Confidence::High,
            urgency: Urgency::Normal,
            assignee: ids.owner,
            team: None,
            connection: Some(ids.books),
        },
        today - 3 * hour,
    );
    q.propose(
        Proposal {
            workspace: Workspace::Knowledge,
            kind: ItemKind::KnowledgeGap,
            title: "A customer asked about Mitsubishi units".into(),
            summary: "Your files don't say whether you service them, so Arkhon didn't guess. \
                      Answer once and it will remember."
                .into(),
            draft: None,
            question: Some("Do we service Mitsubishi mini-split units?".into()),
            sources: Vec::new(),
            confidence: Confidence::NotFound,
            urgency: Urgency::Normal,
            assignee: ids.owner,
            team: None,
            connection: None,
        },
        today - 2 * hour,
    );
    q.propose(
        Proposal {
            workspace: Workspace::Growth,
            kind: ItemKind::SendQuote,
            title: "Send the Ortiz furnace quote".into(),
            summary: "Replacement furnace, $6,450 installed, using this year's price list.".into(),
            draft: Some(
                "Hi Mr. Ortiz,\n\nAttached is the quote we discussed: a new 96% furnace, \
                 installed, for $6,450. It's good for 30 days.\n\nDana"
                    .into(),
            ),
            question: None,
            sources: vec![src(
                "Price list 2026",
                r"file:\\office-nas\jobs\price-list-2026.pdf#p5",
            )],
            confidence: Confidence::Medium,
            urgency: Urgency::Low,
            assignee: ids.owner,
            team: None,
            connection: Some(ids.dana_mail),
        },
        today - 20 * hour,
    );
    q.propose(
        Proposal {
            workspace: Workspace::Desk,
            kind: ItemKind::DraftReply,
            title: "Confirm Harbor Dental's maintenance visit".into(),
            summary:
                "They asked to move Tuesday's visit to Thursday morning; Thursday 8 am is open."
                    .into(),
            draft: Some(
                "Hi Priya,\n\nThursday at 8 am works. We'll see you then.\n\nCoastline Mechanical"
                    .into(),
            ),
            question: None,
            sources: vec![src("Dispatch calendar", "calendar:service@coastline.com")],
            confidence: Confidence::High,
            urgency: Urgency::Normal,
            assignee: ids.dispatcher,
            team: Some("Front office".into()),
            connection: Some(ids.service),
        },
        today - 2 * hour,
    );
    q.propose(
        Proposal {
            workspace: Workspace::Meetings,
            kind: ItemKind::MeetingNotes,
            title: "Share notes from the Bayview Apartments walk-through".into(),
            summary: "Six units need new condensate lines; Arkhon listed parts and next steps."
                .into(),
            draft: Some(
                "Notes from Thursday's walk-through at Bayview Apartments:\n- Units 2B, 2C, 3A, \
                 3D, 4A and 4C need new condensate lines.\n- Parts list attached.\n- Next: quote \
                 to the property manager by Monday."
                    .into(),
            ),
            question: None,
            sources: vec![src("Walk-through recording", "meeting:2026-11-05-bayview")],
            confidence: Confidence::Medium,
            urgency: Urgency::Normal,
            assignee: ids.tech,
            team: Some("Field techs".into()),
            connection: Some(ids.tia_mail),
        },
        today - 16 * hour,
    );
    q
}

/// Example history: two weeks of approved work (sample data, marked `item: None`).
fn demo_value(today: u64, people: &[MemberId]) -> Vec<ValueEvent> {
    // Per day, oldest first: (drafts, documents, meetings, answers reused).
    const DAYS: [(u32, u32, u32, u32); 14] = [
        (6, 4, 0, 0),
        (4, 2, 0, 1),
        (14, 9, 1, 2),
        (18, 12, 1, 3),
        (20, 14, 2, 2),
        (17, 11, 1, 3),
        (15, 8, 1, 2),
        (5, 3, 0, 1),
        (3, 2, 0, 0),
        (17, 11, 1, 3),
        (21, 14, 2, 4),
        (31, 16, 3, 5),
        (24, 13, 2, 4),
        (19, 10, 1, 3),
    ];
    let start = day_number(today) - 13;
    let mut out = Vec::new();
    let mut who = 0usize;
    for (i, (drafts, docs, meetings, answers)) in (0u64..).zip(DAYS) {
        let day = (start + i) * DAY;
        let kinds = [
            (ValueKind::DraftAccepted, drafts),
            (ValueKind::DocumentFiled, docs),
            (ValueKind::MeetingSummarized, meetings),
            (ValueKind::AnswerReused, answers),
        ];
        let mut minute = 8 * 60;
        for (kind, n) in kinds {
            for _ in 0..n {
                out.push(ValueEvent {
                    at: day + minute * 60,
                    kind,
                    member: people[who % people.len()],
                    item: None,
                });
                who += 1;
                minute += 7;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_pages;
#[cfg(test)]
mod tests_work;
