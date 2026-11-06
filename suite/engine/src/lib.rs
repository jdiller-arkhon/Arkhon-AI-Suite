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

use arkhon_org::connections::{
    Access, App, AppPolicy, Audience, Availability, ConnError, ConnStatus, Connections, Kind,
};
use arkhon_org::{
    MemberId, MemberStatus, OrgError, Organization, Permission, Plan, Role, RoleId, Workspace,
};
use serde::{Deserialize, Serialize};

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

/// The suite: state plus a clock.
pub struct Suite {
    state: State,
    clock: Box<dyn Clock>,
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
        Suite { state, clock }
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
            Command::Connect { app, account, for_ } => {
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
                match for_ {
                    ConnectFor::Me => {
                        connections.connect_personal(org, actor, app, &account, Access::Draft)?;
                    }
                    ConnectFor::Team { team } => {
                        connections.connect_company(
                            org,
                            actor,
                            app,
                            &account,
                            Audience::Teams([team].into()),
                            Access::Draft,
                        )?;
                    }
                    ConnectFor::Everyone => {
                        connections.connect_company(
                            org,
                            actor,
                            app,
                            &account,
                            Audience::Everyone,
                            Access::Draft,
                        )?;
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
        }
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
            Command::Connect { app, account, for_ } => {
                let f = match for_ {
                    ConnectFor::Me => "themselves".to_owned(),
                    ConnectFor::Team { team } => team.clone(),
                    ConnectFor::Everyone => "everyone".to_owned(),
                };
                format!("Connect {} ({account}) for {f}", app.name())
            }
            Command::Disconnect { id } => format!("Disconnect {}", self.conn_label(*id)),
            Command::Reconnect { id } => format!("Reconnect {}", self.conn_label(*id)),
        }
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
        }
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
    c.connect_company(
        &org,
        admin,
        App::Outlook,
        "service@coastline.com",
        team("Front office"),
        Access::Draft,
    )
    .expect("seed");
    c.connect_company(
        &org,
        owner,
        App::QuickBooks,
        "Coastline Mechanical books",
        Audience::Roles([RoleId::Owner, RoleId::Admin].into()),
        Access::Draft,
    )
    .expect("seed");
    c.connect_company(
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
    c.connect_personal(
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
    c.connect_personal(&org, tech, App::Gmail, "tia@coastline.com", Access::Draft)
        .expect("seed");

    (
        State {
            org,
            connections: c,
            activity: Vec::new(),
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

#[cfg(test)]
mod tests;
