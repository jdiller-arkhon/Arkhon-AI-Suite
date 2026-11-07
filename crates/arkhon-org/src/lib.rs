//! Organizations, members, teams, roles and permission checks for Arkhon Suite.
//!
//! Model (see `docs/decisions/0005-organizations-and-roles.md`):
//!
//! * An [`Organization`] buys a plan with a number of seats.
//! * Each [`Member`] has exactly one [`Role`] and may belong to any number of [`Team`]s.
//! * Built-in roles are **Owner**, **Admin**, **Manager** and **Member**. Larger plans can add
//!   custom roles assembled from the same [`Permission`]s.
//! * Access to workspaces (Inbox, Docs, ...) is granted per role and widened per team.
//!
//! Every mutating operation goes through [`Organization`] methods that enforce the invariants:
//! an org always has an active Owner, nobody can grant a permission they don't hold, admins
//! can't act on owners, and seat limits hold. All checks are local; no customer content is
//! involved (N1).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub mod connections;

// ---------------------------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------------------------

/// A single capability. Kept deliberately coarse so owners can reason about it in plain words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Permission {
    /// See and change the plan, seats and invoices.
    ManageBilling,
    /// Change organization name, data-retention and privacy settings.
    ManageOrganization,
    /// Invite, suspend and remove people.
    ManageMembers,
    /// Change which role a person has.
    AssignRoles,
    /// Create and edit custom roles.
    ManageRoles,
    /// Create teams and change who is in them.
    ManageTeams,
    /// Connect company-wide accounts (shared mailbox, accounting, shared drives).
    ManageConnections,
    /// Turn on automations that act for the whole company.
    ManageAutomations,
    /// Approve items in teammates' review queues (e.g. a manager approving a quote).
    ApproveForTeam,
    /// See company-wide time-saved and value reports.
    ViewCompanyReports,
    /// See the activity history of everyone in the organization.
    ViewActivityHistory,
    /// Install industry packs, updates and model upgrades.
    ManageUpdates,
}

impl Permission {
    /// Every permission, in display order.
    pub const ALL: [Permission; 12] = [
        Permission::ManageBilling,
        Permission::ManageOrganization,
        Permission::ManageMembers,
        Permission::AssignRoles,
        Permission::ManageRoles,
        Permission::ManageTeams,
        Permission::ManageConnections,
        Permission::ManageAutomations,
        Permission::ApproveForTeam,
        Permission::ViewCompanyReports,
        Permission::ViewActivityHistory,
        Permission::ManageUpdates,
    ];

    /// Permissions only an Owner may hold; custom roles can never include them.
    pub const OWNER_ONLY: [Permission; 1] = [Permission::ManageBilling];

    /// Plain-language label shown in the admin screen.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Permission::ManageBilling => "Manage plan and billing",
            Permission::ManageOrganization => "Change company settings",
            Permission::ManageMembers => "Invite and remove people",
            Permission::AssignRoles => "Change people's roles",
            Permission::ManageRoles => "Create custom roles",
            Permission::ManageTeams => "Manage teams",
            Permission::ManageConnections => "Connect company accounts",
            Permission::ManageAutomations => "Turn on company automations",
            Permission::ApproveForTeam => "Approve work for their team",
            Permission::ViewCompanyReports => "See company time-saved reports",
            Permission::ViewActivityHistory => "See everyone's activity history",
            Permission::ManageUpdates => "Install updates and industry packs",
        }
    }
}

/// A set of permissions.
pub type Permissions = BTreeSet<Permission>;

// ---------------------------------------------------------------------------------------------
// Workspaces
// ---------------------------------------------------------------------------------------------

/// A product workspace a person can be given access to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Workspace {
    /// Email triage and drafting.
    Inbox,
    /// Customer support replies.
    Desk,
    /// Document intake and filing.
    Docs,
    /// Ask-the-company answers.
    Knowledge,
    /// Meeting notes.
    Meetings,
    /// Marketing, quotes and outreach.
    Growth,
    /// Reports and numbers.
    Insights,
    /// Coding and IT add-on.
    Dev,
}

impl Workspace {
    /// Every workspace.
    pub const ALL: [Workspace; 8] = [
        Workspace::Inbox,
        Workspace::Desk,
        Workspace::Docs,
        Workspace::Knowledge,
        Workspace::Meetings,
        Workspace::Growth,
        Workspace::Insights,
        Workspace::Dev,
    ];
}

// ---------------------------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------------------------

/// Commercial plan (brief section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Plan {
    /// Inbox + Knowledge + Docs.
    Starter,
    /// Adds Desk, Meetings, Growth, Insights; teams and custom roles.
    Business,
    /// Adds Tune and priority updates.
    Pro,
}

impl Plan {
    /// Workspaces included in the plan (Dev is a separately licensed add-on).
    #[must_use]
    pub fn workspaces(self) -> BTreeSet<Workspace> {
        use Workspace::{Desk, Docs, Growth, Inbox, Insights, Knowledge, Meetings};
        match self {
            Plan::Starter => [Inbox, Knowledge, Docs].into(),
            Plan::Business | Plan::Pro => {
                [Inbox, Knowledge, Docs, Desk, Meetings, Growth, Insights].into()
            }
        }
    }

    /// Whether custom roles are available (small teams use the four built-in roles).
    #[must_use]
    pub fn custom_roles(self) -> bool {
        !matches!(self, Plan::Starter)
    }
}

// ---------------------------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------------------------

/// Identifier of a role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "String", from = "String")
)]
pub enum RoleId {
    /// Full control, including billing and ownership. At least one is always required.
    Owner,
    /// Runs the organization day to day; cannot touch billing or owners.
    Admin,
    /// Leads a team: approves their work and sees company reports.
    Manager,
    /// Uses the workspaces they are given.
    Member,
    /// An organization-defined role.
    Custom(String),
}

impl From<RoleId> for String {
    fn from(r: RoleId) -> String {
        r.to_string()
    }
}

impl From<String> for RoleId {
    fn from(s: String) -> RoleId {
        match s.as_str() {
            "Owner" => RoleId::Owner,
            "Admin" => RoleId::Admin,
            "Manager" => RoleId::Manager,
            "Member" => RoleId::Member,
            _ => RoleId::Custom(s),
        }
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleId::Owner => f.write_str("Owner"),
            RoleId::Admin => f.write_str("Admin"),
            RoleId::Manager => f.write_str("Manager"),
            RoleId::Member => f.write_str("Member"),
            RoleId::Custom(name) => f.write_str(name),
        }
    }
}

/// A role: a name, a permission set and default workspace access.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Role {
    /// Identifier.
    pub id: RoleId,
    /// Permissions granted.
    pub permissions: Permissions,
    /// Workspaces every holder of this role can use (intersected with the plan).
    pub workspaces: BTreeSet<Workspace>,
}

impl Role {
    /// The built-in role for `id`. Returns `None` for custom roles.
    #[must_use]
    pub fn builtin(id: &RoleId) -> Option<Role> {
        use Permission as P;
        let everything: BTreeSet<Workspace> = Workspace::ALL.into();
        let (permissions, workspaces): (Permissions, BTreeSet<Workspace>) = match id {
            RoleId::Owner => (Permission::ALL.into(), everything),
            RoleId::Admin => (
                Permission::ALL
                    .into_iter()
                    .filter(|p| !Permission::OWNER_ONLY.contains(p))
                    .collect(),
                everything,
            ),
            RoleId::Manager => (
                [P::ApproveForTeam, P::ViewCompanyReports, P::ManageTeams].into(),
                everything,
            ),
            RoleId::Member => (
                BTreeSet::new(),
                [Workspace::Inbox, Workspace::Knowledge, Workspace::Docs].into(),
            ),
            RoleId::Custom(_) => return None,
        };
        Some(Role {
            id: id.clone(),
            permissions,
            workspaces,
        })
    }

    fn has(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }
}

// ---------------------------------------------------------------------------------------------
// Members and teams
// ---------------------------------------------------------------------------------------------

/// Stable member identifier (local user id).
pub type MemberId = u64;

/// Whether a person currently uses a seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum MemberStatus {
    /// Invitation sent, not yet accepted. Holds a seat so invites can't oversell.
    Invited,
    /// Active user.
    Active,
    /// Access paused; frees the seat.
    Suspended,
}

/// A person in the organization.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Member {
    /// Identifier.
    pub id: MemberId,
    /// Display name.
    pub name: String,
    /// Email (lower-cased).
    pub email: String,
    /// Role.
    pub role: RoleId,
    /// Status.
    pub status: MemberStatus,
}

impl Member {
    fn holds_seat(&self) -> bool {
        matches!(self.status, MemberStatus::Invited | MemberStatus::Active)
    }
}

/// A group of people sharing extra workspace access and an approver (e.g. "Field techs").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Team {
    /// Display name.
    pub name: String,
    /// Members.
    pub members: BTreeSet<MemberId>,
    /// Extra workspaces granted to everyone on the team.
    pub workspaces: BTreeSet<Workspace>,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Why an operation was refused. Messages are written for the admin screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgError {
    /// The acting person lacks a permission.
    NotAllowed(Permission),
    /// Only an Owner may do this.
    OwnerOnly,
    /// The change would leave the organization without an active Owner.
    LastOwner,
    /// No seats left on the plan.
    NoSeatsLeft {
        /// Seats on the plan.
        seats: u32,
    },
    /// A role or custom role can't grant something the actor does not have.
    WouldEscalate(Permission),
    /// The plan doesn't include custom roles.
    PlanLacksCustomRoles,
    /// A custom role tried to include an owner-only permission.
    OwnerOnlyPermission(Permission),
    /// Name clashes with an existing role.
    RoleExists,
    /// Role is still assigned to people.
    RoleInUse,
    /// Unknown role.
    UnknownRole,
    /// Unknown member.
    UnknownMember,
    /// Unknown team.
    UnknownTeam,
    /// Email already belongs to someone in the organization.
    AlreadyMember,
    /// Email is not a valid address.
    InvalidEmail,
    /// The acting person is not active.
    ActorInactive,
}

impl fmt::Display for OrgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrgError::NotAllowed(p) => {
                write!(
                    f,
                    "Your role doesn't allow this. Ask an admin for \"{}\".",
                    p.label()
                )
            }
            OrgError::OwnerOnly => f.write_str("Only an owner can do this."),
            OrgError::LastOwner => f.write_str(
                "Your company needs at least one owner. Make someone else an owner first.",
            ),
            OrgError::NoSeatsLeft { seats } => write!(
                f,
                "All {seats} seats are in use. Add seats or remove someone first."
            ),
            OrgError::WouldEscalate(p) => write!(
                f,
                "You can't give \"{}\" because your own role doesn't include it.",
                p.label()
            ),
            OrgError::PlanLacksCustomRoles => {
                f.write_str("Custom roles are available on the Business and Pro plans.")
            }
            OrgError::OwnerOnlyPermission(p) => {
                write!(f, "\"{}\" can only belong to owners.", p.label())
            }
            OrgError::RoleExists => f.write_str("A role with that name already exists."),
            OrgError::RoleInUse => {
                f.write_str("People still have this role. Move them to another role first.")
            }
            OrgError::UnknownRole => f.write_str("That role no longer exists."),
            OrgError::UnknownMember => f.write_str("That person is no longer in the company."),
            OrgError::UnknownTeam => f.write_str("That team no longer exists."),
            OrgError::AlreadyMember => f.write_str("That email is already in your company."),
            OrgError::InvalidEmail => f.write_str("Enter a valid email address."),
            OrgError::ActorInactive => f.write_str("Your access is paused."),
        }
    }
}

impl std::error::Error for OrgError {}

/// Result alias.
pub type OrgResult<T> = Result<T, OrgError>;

// ---------------------------------------------------------------------------------------------
// Organization
// ---------------------------------------------------------------------------------------------

/// An organization and everything needed to make permission decisions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Organization {
    /// Display name.
    pub name: String,
    plan: Plan,
    seats: u32,
    members: BTreeMap<MemberId, Member>,
    custom_roles: BTreeMap<String, Role>,
    teams: BTreeMap<String, Team>,
    next_id: MemberId,
}

impl Organization {
    /// Create an organization whose first person is its Owner.
    ///
    /// # Errors
    /// [`OrgError::InvalidEmail`] for a malformed address; [`OrgError::NoSeatsLeft`] if `seats`
    /// is zero.
    pub fn create(
        name: &str,
        plan: Plan,
        seats: u32,
        owner_name: &str,
        owner_email: &str,
    ) -> OrgResult<(Organization, MemberId)> {
        if seats == 0 {
            return Err(OrgError::NoSeatsLeft { seats });
        }
        let email = normalize_email(owner_email)?;
        let mut org = Organization {
            name: name.to_owned(),
            plan,
            seats,
            members: BTreeMap::new(),
            custom_roles: BTreeMap::new(),
            teams: BTreeMap::new(),
            next_id: 1,
        };
        let id = org.insert(owner_name, email, RoleId::Owner, MemberStatus::Active);
        Ok((org, id))
    }

    // ----- queries ----------------------------------------------------------------------------

    /// Plan.
    #[must_use]
    pub fn plan(&self) -> Plan {
        self.plan
    }

    /// Seats purchased.
    #[must_use]
    pub fn seats(&self) -> u32 {
        self.seats
    }

    /// Seats held by invited or active people.
    #[must_use]
    pub fn seats_used(&self) -> u32 {
        u32::try_from(self.members.values().filter(|m| m.holds_seat()).count()).unwrap_or(u32::MAX)
    }

    /// A member by id.
    #[must_use]
    pub fn member(&self, id: MemberId) -> Option<&Member> {
        self.members.get(&id)
    }

    /// All members.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.values()
    }

    /// Custom roles.
    pub fn custom_roles(&self) -> impl Iterator<Item = Role> + '_ {
        self.custom_roles.values().cloned()
    }

    /// All teams.
    pub fn teams(&self) -> impl Iterator<Item = &Team> {
        self.teams.values()
    }

    /// A team by name.
    #[must_use]
    pub fn team(&self, name: &str) -> Option<&Team> {
        self.teams.get(name)
    }

    /// Resolve a role (built-in or custom).
    #[must_use]
    pub fn role(&self, id: &RoleId) -> Option<Role> {
        match id {
            RoleId::Custom(name) => self.custom_roles.get(name).cloned(),
            other => Role::builtin(other),
        }
    }

    /// Whether `member` currently holds `permission`. Inactive people hold nothing.
    #[must_use]
    pub fn can(&self, member: MemberId, permission: Permission) -> bool {
        self.members
            .get(&member)
            .filter(|m| m.status == MemberStatus::Active)
            .and_then(|m| self.role(&m.role))
            .is_some_and(|r| r.has(permission))
    }

    /// Workspaces a person can open: (role defaults ∪ team grants) ∩ plan. Dev requires an
    /// explicit grant and is never implied by the plan alone.
    #[must_use]
    pub fn workspaces_for(&self, member: MemberId) -> BTreeSet<Workspace> {
        let Some(m) = self
            .members
            .get(&member)
            .filter(|m| m.status == MemberStatus::Active)
        else {
            return BTreeSet::new();
        };
        let mut granted = self.role(&m.role).map(|r| r.workspaces).unwrap_or_default();
        for team in self.teams.values().filter(|t| t.members.contains(&member)) {
            granted.extend(team.workspaces.iter().copied());
        }
        let mut allowed = self.plan.workspaces();
        allowed.insert(Workspace::Dev); // Dev is gated by its own add-on license, checked elsewhere.
        granted.intersection(&allowed).copied().collect()
    }

    // ----- mutations --------------------------------------------------------------------------

    /// Invite someone with a role.
    ///
    /// # Errors
    /// Permission, escalation, seat and validation errors.
    pub fn invite(
        &mut self,
        actor: MemberId,
        name: &str,
        email: &str,
        role: RoleId,
    ) -> OrgResult<MemberId> {
        self.require(actor, Permission::ManageMembers)?;
        let email = normalize_email(email)?;
        if self.members.values().any(|m| m.email == email) {
            return Err(OrgError::AlreadyMember);
        }
        self.check_can_hand_out(actor, &role)?;
        self.require_free_seat()?;
        Ok(self.insert(name, email, role, MemberStatus::Invited))
    }

    /// Mark an invitation accepted.
    ///
    /// # Errors
    /// [`OrgError::UnknownMember`].
    pub fn accept_invite(&mut self, member: MemberId) -> OrgResult<()> {
        let m = self
            .members
            .get_mut(&member)
            .ok_or(OrgError::UnknownMember)?;
        if m.status == MemberStatus::Invited {
            m.status = MemberStatus::Active;
        }
        Ok(())
    }

    /// Change someone's role.
    ///
    /// # Errors
    /// Permission, owner-protection, escalation and last-owner errors.
    pub fn set_role(&mut self, actor: MemberId, target: MemberId, role: RoleId) -> OrgResult<()> {
        self.require(actor, Permission::AssignRoles)?;
        let current = self
            .members
            .get(&target)
            .ok_or(OrgError::UnknownMember)?
            .role
            .clone();
        self.protect_owner(actor, &current)?;
        self.check_can_hand_out(actor, &role)?;
        if current == RoleId::Owner && role != RoleId::Owner {
            self.require_another_owner(target)?;
        }
        self.members
            .get_mut(&target)
            .ok_or(OrgError::UnknownMember)?
            .role = role;
        Ok(())
    }

    /// Pause someone's access (frees their seat).
    ///
    /// # Errors
    /// Permission, owner-protection and last-owner errors.
    pub fn suspend(&mut self, actor: MemberId, target: MemberId) -> OrgResult<()> {
        self.require(actor, Permission::ManageMembers)?;
        let role = self
            .members
            .get(&target)
            .ok_or(OrgError::UnknownMember)?
            .role
            .clone();
        self.protect_owner(actor, &role)?;
        if role == RoleId::Owner {
            self.require_another_owner(target)?;
        }
        self.members
            .get_mut(&target)
            .ok_or(OrgError::UnknownMember)?
            .status = MemberStatus::Suspended;
        Ok(())
    }

    /// Restore a paused person (needs a free seat).
    ///
    /// # Errors
    /// Permission, owner-protection and seat errors.
    pub fn restore(&mut self, actor: MemberId, target: MemberId) -> OrgResult<()> {
        self.require(actor, Permission::ManageMembers)?;
        let m = self.members.get(&target).ok_or(OrgError::UnknownMember)?;
        if m.status != MemberStatus::Suspended {
            return Ok(());
        }
        let role = m.role.clone();
        self.protect_owner(actor, &role)?;
        self.require_free_seat()?;
        self.members
            .get_mut(&target)
            .ok_or(OrgError::UnknownMember)?
            .status = MemberStatus::Active;
        Ok(())
    }

    /// Remove someone from the organization.
    ///
    /// # Errors
    /// Permission, owner-protection and last-owner errors.
    pub fn remove(&mut self, actor: MemberId, target: MemberId) -> OrgResult<()> {
        self.require(actor, Permission::ManageMembers)?;
        let role = self
            .members
            .get(&target)
            .ok_or(OrgError::UnknownMember)?
            .role
            .clone();
        self.protect_owner(actor, &role)?;
        if role == RoleId::Owner {
            self.require_another_owner(target)?;
        }
        self.members.remove(&target);
        for t in self.teams.values_mut() {
            t.members.remove(&target);
        }
        Ok(())
    }

    /// Change the number of seats (owners only, because it changes the bill).
    ///
    /// # Errors
    /// [`OrgError::NotAllowed`] or [`OrgError::NoSeatsLeft`] if fewer than in use.
    pub fn set_seats(&mut self, actor: MemberId, seats: u32) -> OrgResult<()> {
        self.require(actor, Permission::ManageBilling)?;
        if seats < self.seats_used() || seats == 0 {
            return Err(OrgError::NoSeatsLeft { seats });
        }
        self.seats = seats;
        Ok(())
    }

    /// Create a custom role.
    ///
    /// # Errors
    /// Plan, permission, escalation, owner-only and name errors.
    pub fn create_role(
        &mut self,
        actor: MemberId,
        name: &str,
        permissions: Permissions,
        workspaces: BTreeSet<Workspace>,
    ) -> OrgResult<RoleId> {
        if !self.plan.custom_roles() {
            return Err(OrgError::PlanLacksCustomRoles);
        }
        self.require(actor, Permission::ManageRoles)?;
        let name = name.trim();
        let builtin = ["owner", "admin", "manager", "member"];
        if name.is_empty()
            || builtin.contains(&name.to_lowercase().as_str())
            || self.custom_roles.contains_key(name)
        {
            return Err(OrgError::RoleExists);
        }
        if let Some(p) = permissions
            .iter()
            .find(|p| Permission::OWNER_ONLY.contains(p))
        {
            return Err(OrgError::OwnerOnlyPermission(*p));
        }
        let actor_role = self.actor_role(actor)?;
        if let Some(p) = permissions.iter().find(|p| !actor_role.has(**p)) {
            return Err(OrgError::WouldEscalate(*p));
        }
        let id = RoleId::Custom(name.to_owned());
        self.custom_roles.insert(
            name.to_owned(),
            Role {
                id: id.clone(),
                permissions,
                workspaces,
            },
        );
        Ok(id)
    }

    /// Delete a custom role that nobody holds.
    ///
    /// # Errors
    /// Permission, unknown and in-use errors.
    pub fn delete_role(&mut self, actor: MemberId, name: &str) -> OrgResult<()> {
        self.require(actor, Permission::ManageRoles)?;
        if !self.custom_roles.contains_key(name) {
            return Err(OrgError::UnknownRole);
        }
        let id = RoleId::Custom(name.to_owned());
        if self.members.values().any(|m| m.role == id) {
            return Err(OrgError::RoleInUse);
        }
        self.custom_roles.remove(name);
        Ok(())
    }

    /// Create or replace a team's extra workspace access.
    ///
    /// # Errors
    /// Permission errors.
    pub fn upsert_team(
        &mut self,
        actor: MemberId,
        name: &str,
        workspaces: BTreeSet<Workspace>,
    ) -> OrgResult<()> {
        self.require(actor, Permission::ManageTeams)?;
        let team = self.teams.entry(name.to_owned()).or_insert_with(|| Team {
            name: name.to_owned(),
            ..Team::default()
        });
        team.workspaces = workspaces;
        Ok(())
    }

    /// Add a person to a team.
    ///
    /// # Errors
    /// Permission and unknown errors.
    pub fn add_to_team(&mut self, actor: MemberId, team: &str, member: MemberId) -> OrgResult<()> {
        self.require(actor, Permission::ManageTeams)?;
        if !self.members.contains_key(&member) {
            return Err(OrgError::UnknownMember);
        }
        self.teams
            .get_mut(team)
            .ok_or(OrgError::UnknownTeam)?
            .members
            .insert(member);
        Ok(())
    }

    // ----- internals --------------------------------------------------------------------------

    fn insert(
        &mut self,
        name: &str,
        email: String,
        role: RoleId,
        status: MemberStatus,
    ) -> MemberId {
        let id = self.next_id;
        self.next_id += 1;
        self.members.insert(
            id,
            Member {
                id,
                name: name.trim().to_owned(),
                email,
                role,
                status,
            },
        );
        id
    }

    fn actor_role(&self, actor: MemberId) -> OrgResult<Role> {
        let m = self.members.get(&actor).ok_or(OrgError::UnknownMember)?;
        if m.status != MemberStatus::Active {
            return Err(OrgError::ActorInactive);
        }
        self.role(&m.role).ok_or(OrgError::UnknownRole)
    }

    fn require(&self, actor: MemberId, p: Permission) -> OrgResult<()> {
        if self.actor_role(actor)?.has(p) {
            Ok(())
        } else {
            Err(OrgError::NotAllowed(p))
        }
    }

    fn is_owner(&self, actor: MemberId) -> bool {
        self.members
            .get(&actor)
            .is_some_and(|m| m.role == RoleId::Owner && m.status == MemberStatus::Active)
    }

    /// Non-owners can never act on an owner.
    fn protect_owner(&self, actor: MemberId, target_role: &RoleId) -> OrgResult<()> {
        if *target_role == RoleId::Owner && !self.is_owner(actor) {
            Err(OrgError::OwnerOnly)
        } else {
            Ok(())
        }
    }

    /// Only owners hand out Owner; nobody hands out a role stronger than their own.
    fn check_can_hand_out(&self, actor: MemberId, role: &RoleId) -> OrgResult<()> {
        if *role == RoleId::Owner {
            return if self.is_owner(actor) {
                Ok(())
            } else {
                Err(OrgError::OwnerOnly)
            };
        }
        let target = self.role(role).ok_or(OrgError::UnknownRole)?;
        let mine = self.actor_role(actor)?;
        match target.permissions.iter().find(|p| !mine.has(**p)) {
            Some(p) => Err(OrgError::WouldEscalate(*p)),
            None => Ok(()),
        }
    }

    fn require_another_owner(&self, leaving: MemberId) -> OrgResult<()> {
        let others = self.members.values().any(|m| {
            m.id != leaving && m.role == RoleId::Owner && m.status == MemberStatus::Active
        });
        if others {
            Ok(())
        } else {
            Err(OrgError::LastOwner)
        }
    }

    fn require_free_seat(&self) -> OrgResult<()> {
        if self.seats_used() < self.seats {
            Ok(())
        } else {
            Err(OrgError::NoSeatsLeft { seats: self.seats })
        }
    }
}

fn normalize_email(email: &str) -> OrgResult<String> {
    let e = email.trim().to_lowercase();
    let valid = e.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
    }) && !e.contains(char::is_whitespace)
        && e.matches('@').count() == 1;
    if valid {
        Ok(e)
    } else {
        Err(OrgError::InvalidEmail)
    }
}

#[cfg(test)]
mod tests;
