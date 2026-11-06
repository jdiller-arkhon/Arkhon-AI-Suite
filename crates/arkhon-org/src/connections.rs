//! Connected apps: which outside accounts Arkhon may read from, and who may use them.
//!
//! Two kinds of connection (ADR-0006):
//!
//! * **Company** connections: a shared account (the `service@` mailbox, `QuickBooks`, the shared
//!   drive) shared with everyone, some roles, or some teams.
//! * **Personal** connections: a person's own work account (their mailbox, their calendar),
//!   used only by them.
//!
//! An admin sets an [`AppPolicy`] for every app, which decides who may connect it:
//! admins only, or also staff connecting their own work accounts, or also staff connecting
//! accounts shared with **their own** teams. This lets owners delegate setup without giving away
//! admin rights.
//!
//! What a connection may *do* is capped by [`Access`]. Every write that leaves the company still
//! goes through the review queue (N9). `Act` (writing without a person approving each item) is
//! only for company connections and needs the automation permission.
//!
//! Tokens themselves are stored encrypted on the customer's machine by the connector framework
//! (Phase 5). This module only decides *who may* (N1: nothing here leaves the machine).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{MemberId, MemberStatus, Organization, Permission, RoleId};

/// What kind of tool an app is. Used to group the app library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// Mail and calendars.
    EmailCalendar,
    /// Files and documents.
    Files,
    /// Bookkeeping.
    Accounting,
    /// Customers and sales.
    CustomersSales,
    /// Scheduling, dispatch and jobs.
    FieldService,
    /// Payments.
    Payments,
    /// Chat and meetings.
    ChatMeetings,
    /// E-signature.
    Signatures,
}

impl Category {
    /// Plain-language label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Category::EmailCalendar => "Email & calendar",
            Category::Files => "Files",
            Category::Accounting => "Accounting",
            Category::CustomersSales => "Customers & sales",
            Category::FieldService => "Jobs & scheduling",
            Category::Payments => "Payments",
            Category::ChatMeetings => "Chat & meetings",
            Category::Signatures => "Signatures",
        }
    }
}

/// An app Arkhon can connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum App {
    /// Outlook mail and calendar (Microsoft 365).
    Outlook,
    /// `OneDrive` / `SharePoint` files (Microsoft 365).
    OneDrive,
    /// Microsoft Teams chat and meetings.
    MicrosoftTeams,
    /// Gmail.
    Gmail,
    /// Google Calendar.
    GoogleCalendar,
    /// Google Drive.
    GoogleDrive,
    /// Any IMAP/SMTP mailbox.
    OtherEmail,
    /// A folder on this computer or a network share.
    LocalFolder,
    /// Dropbox.
    Dropbox,
    /// `QuickBooks` Online.
    QuickBooks,
    /// Xero.
    Xero,
    /// `HubSpot` CRM.
    HubSpot,
    /// `ServiceTitan`.
    ServiceTitan,
    /// Jobber.
    Jobber,
    /// Housecall Pro.
    HousecallPro,
    /// Stripe.
    Stripe,
    /// Square.
    Square,
    /// Slack.
    Slack,
    /// Zoom.
    Zoom,
    /// `DocuSign`.
    DocuSign,
}

/// Delivery status of an integration in the product roadmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Availability {
    /// Built in Phase 5 (suite foundation).
    Phase5,
    /// Built in Phase 6 (remaining workspaces).
    Phase6,
    /// On the roadmap; API terms must be verified before committing (brief §2).
    Planned,
}

impl App {
    /// Every app in the library.
    pub const ALL: [App; 20] = [
        App::Outlook,
        App::OneDrive,
        App::MicrosoftTeams,
        App::Gmail,
        App::GoogleCalendar,
        App::GoogleDrive,
        App::OtherEmail,
        App::LocalFolder,
        App::Dropbox,
        App::QuickBooks,
        App::Xero,
        App::HubSpot,
        App::ServiceTitan,
        App::Jobber,
        App::HousecallPro,
        App::Stripe,
        App::Square,
        App::Slack,
        App::Zoom,
        App::DocuSign,
    ];

    /// Display name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            App::Outlook => "Outlook",
            App::OneDrive => "OneDrive & SharePoint",
            App::MicrosoftTeams => "Microsoft Teams",
            App::Gmail => "Gmail",
            App::GoogleCalendar => "Google Calendar",
            App::GoogleDrive => "Google Drive",
            App::OtherEmail => "Other email (IMAP)",
            App::LocalFolder => "Folder or network drive",
            App::Dropbox => "Dropbox",
            App::QuickBooks => "QuickBooks Online",
            App::Xero => "Xero",
            App::HubSpot => "HubSpot",
            App::ServiceTitan => "ServiceTitan",
            App::Jobber => "Jobber",
            App::HousecallPro => "Housecall Pro",
            App::Stripe => "Stripe",
            App::Square => "Square",
            App::Slack => "Slack",
            App::Zoom => "Zoom",
            App::DocuSign => "DocuSign",
        }
    }

    /// Library grouping.
    #[must_use]
    pub fn category(self) -> Category {
        use App::{
            DocuSign, Dropbox, Gmail, GoogleCalendar, GoogleDrive, HousecallPro, HubSpot, Jobber,
            LocalFolder, MicrosoftTeams, OneDrive, OtherEmail, Outlook, QuickBooks, ServiceTitan,
            Slack, Square, Stripe, Xero, Zoom,
        };
        match self {
            Outlook | Gmail | GoogleCalendar | OtherEmail => Category::EmailCalendar,
            OneDrive | GoogleDrive | LocalFolder | Dropbox => Category::Files,
            QuickBooks | Xero => Category::Accounting,
            HubSpot => Category::CustomersSales,
            ServiceTitan | Jobber | HousecallPro => Category::FieldService,
            Stripe | Square => Category::Payments,
            MicrosoftTeams | Slack | Zoom => Category::ChatMeetings,
            DocuSign => Category::Signatures,
        }
    }

    /// Roadmap status (brief §4: N6 connector list is Phase 5/6; the rest is planned).
    #[must_use]
    pub fn availability(self) -> Availability {
        use App::{
            Gmail, GoogleCalendar, GoogleDrive, HubSpot, LocalFolder, OneDrive, OtherEmail,
            Outlook, QuickBooks, Xero,
        };
        match self {
            Outlook | OneDrive | Gmail | GoogleCalendar | GoogleDrive | OtherEmail
            | LocalFolder => Availability::Phase5,
            QuickBooks | Xero | HubSpot => Availability::Phase6,
            _ => Availability::Planned,
        }
    }

    /// Whether the account is naturally one-per-person (a mailbox) rather than one-per-company
    /// (the books). Drives the default policy.
    #[must_use]
    pub fn is_personal_by_nature(self) -> bool {
        matches!(
            self,
            App::Outlook
                | App::Gmail
                | App::GoogleCalendar
                | App::OtherEmail
                | App::OneDrive
                | App::GoogleDrive
        )
    }

    /// Default policy for a new organization: personal-by-nature apps let people connect their
    /// own work accounts; everything else stays with admins.
    #[must_use]
    pub fn default_policy(self) -> AppPolicy {
        if self.is_personal_by_nature() {
            AppPolicy::OwnAccounts
        } else {
            AppPolicy::AdminsOnly
        }
    }
}

/// Who may connect an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppPolicy {
    /// Nobody may connect it. Existing connections are paused.
    Off,
    /// Only people who can manage connections (Owner, Admin, or a custom role with it).
    AdminsOnly,
    /// Admins, plus anyone may connect **their own** work account.
    OwnAccounts,
    /// As above, plus anyone may connect an account shared with **teams they belong to**
    /// (e.g. a dispatcher connects the team's scheduling app).
    TeamAccounts,
}

impl AppPolicy {
    /// Plain-language label for the admin screen.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AppPolicy::Off => "Off",
            AppPolicy::AdminsOnly => "Admins only",
            AppPolicy::OwnAccounts => "Everyone can connect their own account",
            AppPolicy::TeamAccounts => "Everyone, and team accounts too",
        }
    }
}

/// What Arkhon may do through a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    /// Read only (search, answer questions, learn the company voice).
    Read,
    /// Read, and prepare drafts that a person approves before anything is sent or changed.
    Draft,
    /// Act without a per-item approval. Only for company connections used by automations an
    /// admin turned on.
    Act,
}

/// Who can use a company connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// Everyone in the organization.
    Everyone,
    /// People with any of these roles.
    Roles(BTreeSet<RoleId>),
    /// People on any of these teams.
    Teams(BTreeSet<String>),
}

/// Owner of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Shared company account.
    Company {
        /// Who may use it.
        audience: Audience,
    },
    /// A person's own work account.
    Personal {
        /// The person.
        owner: MemberId,
    },
}

/// Health of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnStatus {
    /// Working.
    Active,
    /// Paused because the app was turned off or its owner was paused.
    Paused,
    /// Sign-in expired; someone must reconnect.
    NeedsSignIn,
}

/// Identifier.
pub type ConnectionId = u64;

/// A connected account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Identifier.
    pub id: ConnectionId,
    /// App.
    pub app: App,
    /// Account label shown to people, e.g. `service@coastline.com`.
    pub account: String,
    /// Company or personal.
    pub kind: Kind,
    /// Capability cap.
    pub access: Access,
    /// Who connected it.
    pub connected_by: MemberId,
    /// Health.
    pub status: ConnStatus,
}

/// Why a connection request was refused. Messages are for the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnError {
    /// The app is turned off for this company.
    AppOff(App),
    /// Only admins may connect this app.
    AdminsOnly(App),
    /// The person may connect their own account but not a shared one.
    OwnAccountsOnly(App),
    /// A shared account must be shared only with teams the person is on.
    NotYourTeam(String),
    /// Changing app rules or others' connections needs the connections permission.
    NotAllowed,
    /// Personal connections can't act without approval.
    PersonalCannotAct,
    /// Acting without approval needs the automations permission.
    NeedsAutomationRights,
    /// The account is already connected.
    AlreadyConnected,
    /// Unknown connection.
    UnknownConnection,
    /// The person is not active in the organization.
    Inactive,
    /// Team doesn't exist.
    UnknownTeam(String),
    /// Audience is empty.
    EmptyAudience,
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnError::AppOff(a) => write!(f, "{} is turned off for your company.", a.name()),
            ConnError::AdminsOnly(a) => {
                write!(
                    f,
                    "Only admins can connect {}. Ask an admin to set it up.",
                    a.name()
                )
            }
            ConnError::OwnAccountsOnly(a) => write!(
                f,
                "You can connect your own {} account. Shared accounts are set up by an admin.",
                a.name()
            ),
            ConnError::NotYourTeam(t) => {
                write!(
                    f,
                    "You can only share with teams you're on. You're not on {t}."
                )
            }
            ConnError::NotAllowed => f.write_str("Only admins can change this."),
            ConnError::PersonalCannotAct => {
                f.write_str("Personal accounts always ask before sending or changing anything.")
            }
            ConnError::NeedsAutomationRights => f.write_str(
                "Letting Arkhon act without asking needs permission to turn on automations.",
            ),
            ConnError::AlreadyConnected => f.write_str("That account is already connected."),
            ConnError::UnknownConnection => f.write_str("That connection no longer exists."),
            ConnError::Inactive => f.write_str("Your access is paused."),
            ConnError::UnknownTeam(t) => write!(f, "There's no team called {t}."),
            ConnError::EmptyAudience => f.write_str("Choose who can use this account."),
        }
    }
}

impl std::error::Error for ConnError {}

/// Result alias.
pub type ConnResult<T> = Result<T, ConnError>;

/// All connections and app rules for one organization.
#[derive(Debug, Clone, Default)]
pub struct Connections {
    policies: BTreeMap<App, AppPolicy>,
    items: BTreeMap<ConnectionId, Connection>,
    next_id: ConnectionId,
}

impl Connections {
    /// New registry using each app's default policy.
    #[must_use]
    pub fn new() -> Self {
        Connections {
            policies: BTreeMap::new(),
            items: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// The policy for an app.
    #[must_use]
    pub fn policy(&self, app: App) -> AppPolicy {
        self.policies
            .get(&app)
            .copied()
            .unwrap_or_else(|| app.default_policy())
    }

    /// A connection by id.
    #[must_use]
    pub fn get(&self, id: ConnectionId) -> Option<&Connection> {
        self.items.get(&id)
    }

    /// All connections.
    pub fn all(&self) -> impl Iterator<Item = &Connection> {
        self.items.values()
    }

    /// Change who may connect an app. Turning an app off pauses its connections; turning it back
    /// on resumes them (people don't have to sign in again).
    ///
    /// # Errors
    /// [`ConnError::NotAllowed`] without the connections permission.
    pub fn set_policy(
        &mut self,
        org: &Organization,
        actor: MemberId,
        app: App,
        policy: AppPolicy,
    ) -> ConnResult<()> {
        if !org.can(actor, Permission::ManageConnections) {
            return Err(ConnError::NotAllowed);
        }
        self.policies.insert(app, policy);
        for c in self.items.values_mut().filter(|c| c.app == app) {
            match (policy, c.status) {
                (AppPolicy::Off, ConnStatus::Active) => c.status = ConnStatus::Paused,
                (p, ConnStatus::Paused) if p != AppPolicy::Off => {
                    let owner_active = match c.kind {
                        Kind::Personal { owner } => is_active(org, owner),
                        Kind::Company { .. } => true,
                    };
                    if owner_active {
                        c.status = ConnStatus::Active;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Connect a person's own work account.
    ///
    /// # Errors
    /// Policy, access and duplicate errors.
    pub fn connect_personal(
        &mut self,
        org: &Organization,
        actor: MemberId,
        app: App,
        account: &str,
        access: Access,
    ) -> ConnResult<ConnectionId> {
        if !is_active(org, actor) {
            return Err(ConnError::Inactive);
        }
        if access == Access::Act {
            return Err(ConnError::PersonalCannotAct);
        }
        let admin = org.can(actor, Permission::ManageConnections);
        match self.policy(app) {
            AppPolicy::Off => return Err(ConnError::AppOff(app)),
            AppPolicy::AdminsOnly if !admin => return Err(ConnError::AdminsOnly(app)),
            _ => {}
        }
        self.insert(app, account, Kind::Personal { owner: actor }, access, actor)
    }

    /// Connect a shared company account.
    ///
    /// Admins may share with anyone. Under [`AppPolicy::TeamAccounts`], other people may share
    /// with teams they are on.
    ///
    /// # Errors
    /// Policy, audience, access and duplicate errors.
    pub fn connect_company(
        &mut self,
        org: &Organization,
        actor: MemberId,
        app: App,
        account: &str,
        audience: Audience,
        access: Access,
    ) -> ConnResult<ConnectionId> {
        if !is_active(org, actor) {
            return Err(ConnError::Inactive);
        }
        validate_audience(org, &audience)?;
        let admin = org.can(actor, Permission::ManageConnections);
        match self.policy(app) {
            AppPolicy::Off => return Err(ConnError::AppOff(app)),
            AppPolicy::AdminsOnly if !admin => return Err(ConnError::AdminsOnly(app)),
            AppPolicy::OwnAccounts if !admin => return Err(ConnError::OwnAccountsOnly(app)),
            AppPolicy::TeamAccounts if !admin => match &audience {
                Audience::Teams(teams) => {
                    if let Some(t) = teams.iter().find(|t| !on_team(org, actor, t)) {
                        return Err(ConnError::NotYourTeam(t.clone()));
                    }
                }
                _ => return Err(ConnError::NotYourTeam("everyone".into())),
            },
            _ => {}
        }
        if access == Access::Act && !org.can(actor, Permission::ManageAutomations) {
            return Err(ConnError::NeedsAutomationRights);
        }
        self.insert(app, account, Kind::Company { audience }, access, actor)
    }

    /// Disconnect. Personal connections: their owner or an admin. Company connections: an admin,
    /// or the person who connected it (team accounts).
    ///
    /// # Errors
    /// [`ConnError::NotAllowed`] or [`ConnError::UnknownConnection`].
    pub fn disconnect(
        &mut self,
        org: &Organization,
        actor: MemberId,
        id: ConnectionId,
    ) -> ConnResult<()> {
        let c = self.items.get(&id).ok_or(ConnError::UnknownConnection)?;
        let admin = org.can(actor, Permission::ManageConnections);
        let mine = match c.kind {
            Kind::Personal { owner } => owner == actor,
            Kind::Company { .. } => c.connected_by == actor,
        };
        if !(admin || (mine && is_active(org, actor))) {
            return Err(ConnError::NotAllowed);
        }
        self.items.remove(&id);
        Ok(())
    }

    /// Connections a person may use right now: their own personal ones plus company ones whose
    /// audience includes them. Paused people get nothing.
    #[must_use]
    pub fn usable_by(&self, org: &Organization, member: MemberId) -> Vec<&Connection> {
        if !is_active(org, member) {
            return Vec::new();
        }
        let role = org.member(member).map(|m| m.role.clone());
        self.items
            .values()
            .filter(|c| c.status == ConnStatus::Active)
            .filter(|c| match &c.kind {
                Kind::Personal { owner } => *owner == member,
                Kind::Company { audience } => match audience {
                    Audience::Everyone => true,
                    Audience::Roles(r) => role.as_ref().is_some_and(|x| r.contains(x)),
                    Audience::Teams(t) => t.iter().any(|t| on_team(org, member, t)),
                },
            })
            .collect()
    }

    /// Bring connections in line with the organization after people change: removed people's
    /// personal accounts are disconnected, paused people's are paused, restored people's resume.
    /// Returns the ids that were disconnected.
    pub fn sync_people(&mut self, org: &Organization) -> Vec<ConnectionId> {
        let gone: Vec<ConnectionId> = self
            .items
            .values()
            .filter(|c| matches!(c.kind, Kind::Personal { owner } if org.member(owner).is_none()))
            .map(|c| c.id)
            .collect();
        for id in &gone {
            self.items.remove(id);
        }
        let policies = self.policies.clone();
        for c in self.items.values_mut() {
            if let Kind::Personal { owner } = c.kind {
                let app_on = policies
                    .get(&c.app)
                    .copied()
                    .unwrap_or_else(|| c.app.default_policy())
                    != AppPolicy::Off;
                match (is_active(org, owner), c.status) {
                    (false, ConnStatus::Active) => c.status = ConnStatus::Paused,
                    (true, ConnStatus::Paused) if app_on => c.status = ConnStatus::Active,
                    _ => {}
                }
            }
        }
        gone
    }

    /// Mark a connection as needing sign-in (e.g. the provider revoked the token).
    ///
    /// # Errors
    /// [`ConnError::UnknownConnection`].
    pub fn mark_needs_sign_in(&mut self, id: ConnectionId) -> ConnResult<()> {
        self.items
            .get_mut(&id)
            .ok_or(ConnError::UnknownConnection)?
            .status = ConnStatus::NeedsSignIn;
        Ok(())
    }

    fn insert(
        &mut self,
        app: App,
        account: &str,
        kind: Kind,
        access: Access,
        by: MemberId,
    ) -> ConnResult<ConnectionId> {
        let account = account.trim().to_lowercase();
        let dup = self.items.values().any(|c| {
            c.app == app
                && c.account == account
                && match (&c.kind, &kind) {
                    (Kind::Personal { owner: a }, Kind::Personal { owner: b }) => a == b,
                    (Kind::Company { .. }, Kind::Company { .. }) => true,
                    _ => false,
                }
        });
        if dup {
            return Err(ConnError::AlreadyConnected);
        }
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        self.items.insert(
            id,
            Connection {
                id,
                app,
                account,
                kind,
                access,
                connected_by: by,
                status: ConnStatus::Active,
            },
        );
        Ok(id)
    }
}

fn is_active(org: &Organization, m: MemberId) -> bool {
    org.member(m)
        .is_some_and(|m| m.status == MemberStatus::Active)
}

fn on_team(org: &Organization, m: MemberId, team: &str) -> bool {
    org.team(team).is_some_and(|t| t.members.contains(&m))
}

fn validate_audience(org: &Organization, a: &Audience) -> ConnResult<()> {
    match a {
        Audience::Everyone => Ok(()),
        Audience::Roles(r) => {
            if r.is_empty() {
                Err(ConnError::EmptyAudience)
            } else {
                Ok(())
            }
        }
        Audience::Teams(t) if t.is_empty() => Err(ConnError::EmptyAudience),
        Audience::Teams(t) => match t.iter().find(|t| org.team(t).is_none()) {
            Some(missing) => Err(ConnError::UnknownTeam(missing.clone())),
            None => Ok(()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Plan;

    struct Fx {
        org: Organization,
        owner: MemberId,
        admin: MemberId,
        disp: MemberId,
        tech: MemberId,
    }

    fn fx() -> Fx {
        let (mut org, owner) =
            Organization::create("Coastline", Plan::Business, 10, "Dana", "dana@co.com").unwrap();
        let mut add = |n: &str, r: RoleId| {
            let id = org.invite(owner, n, &format!("{n}@co.com"), r).unwrap();
            org.accept_invite(id).unwrap();
            id
        };
        let admin = add("ari", RoleId::Admin);
        let disp = add("lena", RoleId::Member);
        let tech = add("tia", RoleId::Member);
        org.upsert_team(owner, "Front office", BTreeSet::new())
            .unwrap();
        org.add_to_team(owner, "Front office", disp).unwrap();
        org.upsert_team(owner, "Field", BTreeSet::new()).unwrap();
        org.add_to_team(owner, "Field", tech).unwrap();
        Fx {
            org,
            owner,
            admin,
            disp,
            tech,
        }
    }

    fn teams(t: &[&str]) -> Audience {
        Audience::Teams(t.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn defaults_match_the_nature_of_each_app() {
        let c = Connections::new();
        assert_eq!(c.policy(App::Outlook), AppPolicy::OwnAccounts);
        assert_eq!(c.policy(App::QuickBooks), AppPolicy::AdminsOnly);
        assert_eq!(App::ALL.len(), 20);
        for a in App::ALL {
            assert!(!a.name().is_empty() && !a.category().label().is_empty());
        }
        assert_eq!(App::QuickBooks.availability(), Availability::Phase6);
        assert_eq!(App::Jobber.availability(), Availability::Planned);
    }

    #[test]
    fn staff_connect_their_own_mailbox_but_not_the_books() {
        let f = fx();
        let mut c = Connections::new();
        c.connect_personal(&f.org, f.tech, App::Outlook, "tia@co.com", Access::Draft)
            .unwrap();
        assert_eq!(
            c.connect_personal(&f.org, f.tech, App::QuickBooks, "x", Access::Read)
                .unwrap_err(),
            ConnError::AdminsOnly(App::QuickBooks)
        );
        assert_eq!(
            c.connect_company(
                &f.org,
                f.tech,
                App::Outlook,
                "service@co.com",
                Audience::Everyone,
                Access::Draft
            )
            .unwrap_err(),
            ConnError::OwnAccountsOnly(App::Outlook)
        );
    }

    #[test]
    fn admins_share_company_accounts_with_anyone() {
        let f = fx();
        let mut c = Connections::new();
        let qb = c
            .connect_company(
                &f.org,
                f.admin,
                App::QuickBooks,
                "Coastline books",
                Audience::Roles([RoleId::Owner, RoleId::Admin].into()),
                Access::Draft,
            )
            .unwrap();
        assert!(c.usable_by(&f.org, f.owner).iter().any(|x| x.id == qb));
        assert!(c.usable_by(&f.org, f.tech).is_empty());
        let shared = c
            .connect_company(
                &f.org,
                f.admin,
                App::Outlook,
                "service@co.com",
                teams(&["Front office"]),
                Access::Draft,
            )
            .unwrap();
        assert!(c.usable_by(&f.org, f.disp).iter().any(|x| x.id == shared));
        assert!(!c.usable_by(&f.org, f.tech).iter().any(|x| x.id == shared));
    }

    #[test]
    fn team_accounts_policy_delegates_to_team_members_only_for_their_teams() {
        let f = fx();
        let mut c = Connections::new();
        c.set_policy(&f.org, f.admin, App::Jobber, AppPolicy::TeamAccounts)
            .unwrap();
        c.connect_company(
            &f.org,
            f.disp,
            App::Jobber,
            "dispatch@co.com",
            teams(&["Front office"]),
            Access::Draft,
        )
        .unwrap();
        assert_eq!(
            c.connect_company(
                &f.org,
                f.disp,
                App::Jobber,
                "field@co.com",
                teams(&["Field"]),
                Access::Draft
            )
            .unwrap_err(),
            ConnError::NotYourTeam("Field".into())
        );
        assert!(matches!(
            c.connect_company(
                &f.org,
                f.disp,
                App::Jobber,
                "all@co.com",
                Audience::Everyone,
                Access::Draft
            )
            .unwrap_err(),
            ConnError::NotYourTeam(_)
        ));
    }

    #[test]
    fn act_needs_automation_rights_and_is_never_personal() {
        let f = fx();
        let mut c = Connections::new();
        assert_eq!(
            c.connect_personal(&f.org, f.admin, App::Gmail, "ari@co.com", Access::Act)
                .unwrap_err(),
            ConnError::PersonalCannotAct
        );
        c.set_policy(&f.org, f.owner, App::Jobber, AppPolicy::TeamAccounts)
            .unwrap();
        assert_eq!(
            c.connect_company(
                &f.org,
                f.disp,
                App::Jobber,
                "d@co.com",
                teams(&["Front office"]),
                Access::Act
            )
            .unwrap_err(),
            ConnError::NeedsAutomationRights
        );
        c.connect_company(
            &f.org,
            f.admin,
            App::QuickBooks,
            "books",
            Audience::Everyone,
            Access::Act,
        )
        .unwrap();
    }

    #[test]
    fn only_admins_change_rules() {
        let f = fx();
        let mut c = Connections::new();
        assert_eq!(
            c.set_policy(&f.org, f.tech, App::Gmail, AppPolicy::Off)
                .unwrap_err(),
            ConnError::NotAllowed
        );
    }

    #[test]
    fn turning_an_app_off_pauses_and_on_resumes() {
        let f = fx();
        let mut c = Connections::new();
        let id = c
            .connect_personal(&f.org, f.tech, App::Gmail, "tia@co.com", Access::Read)
            .unwrap();
        c.set_policy(&f.org, f.admin, App::Gmail, AppPolicy::Off)
            .unwrap();
        assert_eq!(c.get(id).unwrap().status, ConnStatus::Paused);
        assert!(c.usable_by(&f.org, f.tech).is_empty());
        assert_eq!(
            c.connect_personal(&f.org, f.tech, App::Gmail, "other@co.com", Access::Read)
                .unwrap_err(),
            ConnError::AppOff(App::Gmail)
        );
        c.set_policy(&f.org, f.admin, App::Gmail, AppPolicy::OwnAccounts)
            .unwrap();
        assert_eq!(c.get(id).unwrap().status, ConnStatus::Active);
    }

    #[test]
    fn people_changes_flow_through() {
        let mut f = fx();
        let mut c = Connections::new();
        let t = c
            .connect_personal(&f.org, f.tech, App::Gmail, "tia@co.com", Access::Read)
            .unwrap();
        let d = c
            .connect_personal(&f.org, f.disp, App::Gmail, "lena@co.com", Access::Read)
            .unwrap();
        f.org.suspend(f.owner, f.tech).unwrap();
        assert!(c.sync_people(&f.org).is_empty());
        assert_eq!(c.get(t).unwrap().status, ConnStatus::Paused);
        assert!(c.usable_by(&f.org, f.tech).is_empty());
        f.org.restore(f.owner, f.tech).unwrap();
        c.sync_people(&f.org);
        assert_eq!(c.get(t).unwrap().status, ConnStatus::Active);
        f.org.remove(f.owner, f.disp).unwrap();
        assert_eq!(c.sync_people(&f.org), vec![d]);
        assert!(c.get(d).is_none());
    }

    #[test]
    fn disconnect_rules() {
        let f = fx();
        let mut c = Connections::new();
        let t = c
            .connect_personal(&f.org, f.tech, App::Gmail, "tia@co.com", Access::Read)
            .unwrap();
        assert_eq!(
            c.disconnect(&f.org, f.disp, t).unwrap_err(),
            ConnError::NotAllowed
        );
        c.disconnect(&f.org, f.admin, t).unwrap();
        assert_eq!(
            c.disconnect(&f.org, f.admin, t).unwrap_err(),
            ConnError::UnknownConnection
        );
        let mine = c
            .connect_personal(&f.org, f.tech, App::Gmail, "tia@co.com", Access::Read)
            .unwrap();
        c.disconnect(&f.org, f.tech, mine).unwrap();
    }

    #[test]
    fn duplicates_and_bad_audiences_rejected() {
        let f = fx();
        let mut c = Connections::new();
        c.connect_personal(&f.org, f.tech, App::Gmail, "Tia@co.com ", Access::Read)
            .unwrap();
        assert_eq!(
            c.connect_personal(&f.org, f.tech, App::Gmail, "tia@co.com", Access::Read)
                .unwrap_err(),
            ConnError::AlreadyConnected
        );
        assert_eq!(
            c.connect_company(
                &f.org,
                f.admin,
                App::Xero,
                "b",
                Audience::Teams(BTreeSet::new()),
                Access::Read
            )
            .unwrap_err(),
            ConnError::EmptyAudience
        );
        assert_eq!(
            c.connect_company(
                &f.org,
                f.admin,
                App::Xero,
                "b",
                teams(&["Ghosts"]),
                Access::Read
            )
            .unwrap_err(),
            ConnError::UnknownTeam("Ghosts".into())
        );
    }

    #[test]
    fn needs_sign_in_removes_from_use() {
        let f = fx();
        let mut c = Connections::new();
        let id = c
            .connect_personal(&f.org, f.tech, App::Gmail, "tia@co.com", Access::Read)
            .unwrap();
        c.mark_needs_sign_in(id).unwrap();
        assert!(c.usable_by(&f.org, f.tech).is_empty());
    }

    #[test]
    fn errors_are_plain_language() {
        assert!(ConnError::AdminsOnly(App::QuickBooks)
            .to_string()
            .contains("Ask an admin"));
        assert!(ConnError::PersonalCannotAct
            .to_string()
            .contains("always ask"));
    }
}
