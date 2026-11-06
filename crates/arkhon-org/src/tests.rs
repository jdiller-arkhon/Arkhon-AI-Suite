use super::*;

fn org(plan: Plan, seats: u32) -> (Organization, MemberId) {
    Organization::create(
        "Coastline Mechanical",
        plan,
        seats,
        "Dana Ruiz",
        "Dana@Coastline.com",
    )
    .unwrap()
}

fn active(o: &mut Organization, actor: MemberId, name: &str, role: RoleId) -> MemberId {
    let id = o
        .invite(
            actor,
            name,
            &format!("{}@coastline.com", name.to_lowercase()),
            role,
        )
        .unwrap();
    o.accept_invite(id).unwrap();
    id
}

#[test]
fn creator_is_active_owner_with_everything() {
    let (o, owner) = org(Plan::Business, 10);
    let m = o.member(owner).unwrap();
    assert_eq!(m.role, RoleId::Owner);
    assert_eq!(m.email, "dana@coastline.com");
    for p in Permission::ALL {
        assert!(o.can(owner, p), "{p:?}");
    }
    assert_eq!(o.seats_used(), 1);
}

#[test]
fn zero_seats_and_bad_email_rejected() {
    assert!(Organization::create("x", Plan::Starter, 0, "a", "a@b.co").is_err());
    for bad in [
        "", "no-at", "@b.co", "a@b", "a@.co", "a@b.", "a b@c.co", "a@@b.co",
    ] {
        assert_eq!(
            Organization::create("x", Plan::Starter, 1, "a", bad).unwrap_err(),
            OrgError::InvalidEmail,
            "{bad}"
        );
    }
}

#[test]
fn builtin_role_permissions() {
    let admin = Role::builtin(&RoleId::Admin).unwrap();
    assert!(!admin.has(Permission::ManageBilling));
    assert!(admin.has(Permission::ManageMembers));
    let manager = Role::builtin(&RoleId::Manager).unwrap();
    assert!(manager.has(Permission::ApproveForTeam));
    assert!(!manager.has(Permission::ManageMembers));
    let member = Role::builtin(&RoleId::Member).unwrap();
    assert!(member.permissions.is_empty());
    assert!(Role::builtin(&RoleId::Custom("x".into())).is_none());
}

#[test]
fn invites_hold_seats_and_limit_is_enforced() {
    let (mut o, owner) = org(Plan::Starter, 2);
    o.invite(owner, "Ana", "ana@coastline.com", RoleId::Member)
        .unwrap();
    assert_eq!(o.seats_used(), 2);
    assert_eq!(
        o.invite(owner, "Bo", "bo@coastline.com", RoleId::Member)
            .unwrap_err(),
        OrgError::NoSeatsLeft { seats: 2 }
    );
}

#[test]
fn duplicate_email_rejected_case_insensitively() {
    let (mut o, owner) = org(Plan::Starter, 5);
    assert_eq!(
        o.invite(owner, "Dup", " DANA@coastline.com ", RoleId::Member)
            .unwrap_err(),
        OrgError::AlreadyMember
    );
}

#[test]
fn members_cannot_manage_people() {
    let (mut o, owner) = org(Plan::Business, 5);
    let m = active(&mut o, owner, "Ana", RoleId::Member);
    assert_eq!(
        o.invite(m, "Bo", "bo@coastline.com", RoleId::Member)
            .unwrap_err(),
        OrgError::NotAllowed(Permission::ManageMembers)
    );
}

#[test]
fn only_owners_create_or_touch_owners() {
    let (mut o, owner) = org(Plan::Business, 10);
    let admin = active(&mut o, owner, "Ari", RoleId::Admin);
    assert_eq!(
        o.invite(admin, "Ow", "ow@coastline.com", RoleId::Owner)
            .unwrap_err(),
        OrgError::OwnerOnly
    );
    assert_eq!(
        o.set_role(admin, owner, RoleId::Member).unwrap_err(),
        OrgError::OwnerOnly
    );
    assert_eq!(o.suspend(admin, owner).unwrap_err(), OrgError::OwnerOnly);
    assert_eq!(o.remove(admin, owner).unwrap_err(), OrgError::OwnerOnly);
    // An owner can make a second owner.
    let o2 = active(&mut o, owner, "Sam", RoleId::Owner);
    assert!(o.can(o2, Permission::ManageBilling));
}

#[test]
fn last_owner_is_protected() {
    let (mut o, owner) = org(Plan::Business, 10);
    assert_eq!(
        o.set_role(owner, owner, RoleId::Admin).unwrap_err(),
        OrgError::LastOwner
    );
    assert_eq!(o.suspend(owner, owner).unwrap_err(), OrgError::LastOwner);
    assert_eq!(o.remove(owner, owner).unwrap_err(), OrgError::LastOwner);
    let second = active(&mut o, owner, "Sam", RoleId::Owner);
    o.set_role(second, owner, RoleId::Admin).unwrap();
    assert_eq!(o.member(owner).unwrap().role, RoleId::Admin);
}

#[test]
fn invited_owner_does_not_count_as_safety_net() {
    let (mut o, owner) = org(Plan::Business, 10);
    o.invite(owner, "Sam", "sam@coastline.com", RoleId::Owner)
        .unwrap(); // not accepted
    assert_eq!(o.remove(owner, owner).unwrap_err(), OrgError::LastOwner);
}

#[test]
fn admins_cannot_escalate_via_custom_roles() {
    let (mut o, owner) = org(Plan::Business, 10);
    let admin = active(&mut o, owner, "Ari", RoleId::Admin);
    let err = o
        .create_role(
            admin,
            "Bookkeeper",
            [Permission::ManageBilling].into(),
            BTreeSet::new(),
        )
        .unwrap_err();
    assert_eq!(
        err,
        OrgError::OwnerOnlyPermission(Permission::ManageBilling)
    );
}

#[test]
fn custom_role_cannot_exceed_creator() {
    let (mut o, owner) = org(Plan::Business, 10);
    // Owner makes a role-manager that can only manage roles + teams.
    let rm = o
        .create_role(
            owner,
            "Role clerk",
            [Permission::ManageRoles].into(),
            BTreeSet::new(),
        )
        .unwrap();
    let clerk = active(&mut o, owner, "Cy", rm);
    let err = o
        .create_role(
            clerk,
            "Sneaky",
            [Permission::ManageMembers].into(),
            BTreeSet::new(),
        )
        .unwrap_err();
    assert_eq!(err, OrgError::WouldEscalate(Permission::ManageMembers));
}

#[test]
fn cannot_assign_role_stronger_than_own() {
    let (mut o, owner) = org(Plan::Business, 10);
    let assigner = o
        .create_role(
            owner,
            "Office lead",
            [Permission::AssignRoles, Permission::ManageMembers].into(),
            BTreeSet::new(),
        )
        .unwrap();
    let lead = active(&mut o, owner, "Lee", assigner);
    let tech = active(&mut o, owner, "Tia", RoleId::Member);
    assert!(matches!(
        o.set_role(lead, tech, RoleId::Admin).unwrap_err(),
        OrgError::WouldEscalate(_)
    ));
    // Manager has ApproveForTeam which the lead lacks.
    assert!(matches!(
        o.set_role(lead, tech, RoleId::Manager).unwrap_err(),
        OrgError::WouldEscalate(_)
    ));
    o.set_role(lead, tech, RoleId::Member).unwrap();
}

#[test]
fn custom_roles_need_business_plan_and_unique_names() {
    let (mut s, owner) = org(Plan::Starter, 5);
    assert_eq!(
        s.create_role(owner, "Dispatcher", BTreeSet::new(), BTreeSet::new())
            .unwrap_err(),
        OrgError::PlanLacksCustomRoles
    );
    let (mut b, owner) = org(Plan::Business, 5);
    b.create_role(owner, "Dispatcher", BTreeSet::new(), BTreeSet::new())
        .unwrap();
    for name in ["Dispatcher", "admin", "  ", "Owner"] {
        assert_eq!(
            b.create_role(owner, name, BTreeSet::new(), BTreeSet::new())
                .unwrap_err(),
            OrgError::RoleExists,
            "{name}"
        );
    }
}

#[test]
fn role_in_use_cannot_be_deleted() {
    let (mut o, owner) = org(Plan::Business, 5);
    let r = o
        .create_role(owner, "Dispatcher", BTreeSet::new(), BTreeSet::new())
        .unwrap();
    let p = active(&mut o, owner, "Dee", r);
    assert_eq!(
        o.delete_role(owner, "Dispatcher").unwrap_err(),
        OrgError::RoleInUse
    );
    o.set_role(owner, p, RoleId::Member).unwrap();
    o.delete_role(owner, "Dispatcher").unwrap();
    assert_eq!(
        o.delete_role(owner, "Dispatcher").unwrap_err(),
        OrgError::UnknownRole
    );
}

#[test]
fn suspension_frees_seat_and_removes_access() {
    let (mut o, owner) = org(Plan::Business, 2);
    let a = active(&mut o, owner, "Ana", RoleId::Admin);
    o.suspend(owner, a).unwrap();
    assert!(!o.can(a, Permission::ManageMembers));
    assert!(o.workspaces_for(a).is_empty());
    assert_eq!(o.seats_used(), 1);
    let b = o
        .invite(owner, "Bo", "bo@coastline.com", RoleId::Member)
        .unwrap();
    assert_eq!(
        o.restore(owner, a).unwrap_err(),
        OrgError::NoSeatsLeft { seats: 2 }
    );
    o.remove(owner, b).unwrap();
    o.restore(owner, a).unwrap();
    assert!(o.can(a, Permission::ManageMembers));
}

#[test]
fn suspended_actor_is_powerless() {
    let (mut o, owner) = org(Plan::Business, 5);
    let a = active(&mut o, owner, "Ana", RoleId::Admin);
    o.suspend(owner, a).unwrap();
    assert_eq!(
        o.invite(a, "Bo", "bo@coastline.com", RoleId::Member)
            .unwrap_err(),
        OrgError::ActorInactive
    );
}

#[test]
fn seats_change_is_owner_only_and_not_below_usage() {
    let (mut o, owner) = org(Plan::Business, 3);
    let admin = active(&mut o, owner, "Ari", RoleId::Admin);
    active(&mut o, owner, "Bo", RoleId::Member);
    assert_eq!(
        o.set_seats(admin, 10).unwrap_err(),
        OrgError::NotAllowed(Permission::ManageBilling)
    );
    assert!(o.set_seats(owner, 2).is_err());
    o.set_seats(owner, 25).unwrap();
    assert_eq!(o.seats(), 25);
}

#[test]
fn workspace_access_is_role_plus_team_within_plan() {
    let (mut o, owner) = org(Plan::Business, 10);
    let tech = active(&mut o, owner, "Tia", RoleId::Member);
    assert_eq!(
        o.workspaces_for(tech),
        [Workspace::Inbox, Workspace::Knowledge, Workspace::Docs].into()
    );
    o.upsert_team(
        owner,
        "Front office",
        [Workspace::Desk, Workspace::Growth].into(),
    )
    .unwrap();
    o.add_to_team(owner, "Front office", tech).unwrap();
    assert!(o.workspaces_for(tech).contains(&Workspace::Desk));

    // Starter plan never exposes Business workspaces even if a team grants them.
    let (mut s, so) = org(Plan::Starter, 10);
    let t = active(&mut s, so, "Tia", RoleId::Member);
    s.upsert_team(so, "Office", [Workspace::Desk].into())
        .unwrap();
    s.add_to_team(so, "Office", t).unwrap();
    assert!(!s.workspaces_for(t).contains(&Workspace::Desk));
}

#[test]
fn removal_cleans_team_membership() {
    let (mut o, owner) = org(Plan::Business, 10);
    let t = active(&mut o, owner, "Tia", RoleId::Member);
    o.upsert_team(owner, "Field", BTreeSet::new()).unwrap();
    o.add_to_team(owner, "Field", t).unwrap();
    o.remove(owner, t).unwrap();
    assert!(o.team("Field").unwrap().members.is_empty());
    assert_eq!(
        o.add_to_team(owner, "Nope", owner).unwrap_err(),
        OrgError::UnknownTeam
    );
}

#[test]
fn managers_run_teams_but_not_people() {
    let (mut o, owner) = org(Plan::Business, 10);
    let mgr = active(&mut o, owner, "Max", RoleId::Manager);
    o.upsert_team(mgr, "Install crew", [Workspace::Meetings].into())
        .unwrap();
    assert!(o.can(mgr, Permission::ApproveForTeam));
    assert!(o
        .invite(mgr, "Bo", "bo@coastline.com", RoleId::Member)
        .is_err());
}

#[test]
fn errors_read_as_plain_language() {
    let msg = OrgError::NotAllowed(Permission::ManageMembers).to_string();
    assert!(msg.contains("Invite and remove people"));
    assert!(OrgError::LastOwner
        .to_string()
        .contains("at least one owner"));
    for p in Permission::ALL {
        assert!(!p.label().is_empty());
    }
}
