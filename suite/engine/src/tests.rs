use super::*;

struct Fixed(u64);
impl Clock for Fixed {
    fn now(&self) -> u64 {
        self.0
    }
}

fn suite() -> (Suite, DemoIds) {
    let (state, ids) = demo_state();
    (Suite::new(state, Box::new(Fixed(1_700_000_000))), ids)
}

#[test]
fn demo_company_matches_the_prototype() {
    let (s, ids) = suite();
    let v = s.view(ids.owner);
    assert_eq!(v.company, "Coastline Mechanical");
    assert_eq!((v.seats_used, v.seats), (8, 10)); // 9 people, 1 paused
    assert_eq!(v.people.len(), 9);
    assert!(v
        .roles
        .iter()
        .any(|r| r.name == "Dispatcher" && r.custom && r.people == 1));
    assert_eq!(v.teams.len(), 2);
    assert!(v.can.manage_billing && v.can.manage_connections);
}

#[test]
fn every_command_is_logged_including_refusals() {
    let (mut s, ids) = suite();
    s.execute(
        ids.owner,
        Command::Invite {
            email: "new@coastline.com".into(),
            role: "Member".into(),
        },
    )
    .unwrap();
    let err = s
        .execute(
            ids.tech,
            Command::Invite {
                email: "x@coastline.com".into(),
                role: "Member".into(),
            },
        )
        .unwrap_err();
    assert!(err.forbidden);
    let log = s.activity(ids.owner).unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].actor, "Tia Alvarez");
    assert!(log[0]
        .refused
        .as_deref()
        .unwrap()
        .contains("Invite and remove people"));
    assert_eq!(log[1].action, "Invite new@coastline.com as Member");
    assert!(log[1].refused.is_none());
    assert_eq!(log[1].at, 1_700_000_000);
}

#[test]
fn activity_is_admin_only() {
    let (s, ids) = suite();
    assert!(s.activity(ids.admin).is_ok());
    assert!(s.activity(ids.tech).unwrap_err().forbidden);
}

#[test]
fn invite_derives_a_name_and_respects_seats() {
    let (mut s, ids) = suite();
    let msg = s
        .execute(
            ids.owner,
            Command::Invite {
                email: "jo.ann_lee@coastline.com".into(),
                role: "Member".into(),
            },
        )
        .unwrap();
    assert!(msg.contains("holds a seat"));
    assert!(s
        .view(ids.owner)
        .people
        .iter()
        .any(|p| p.name == "Jo Ann Lee"));
    s.execute(
        ids.owner,
        Command::Invite {
            email: "b@coastline.com".into(),
            role: "Member".into(),
        },
    )
    .unwrap();
    let full = s
        .execute(
            ids.owner,
            Command::Invite {
                email: "c@coastline.com".into(),
                role: "Member".into(),
            },
        )
        .unwrap_err();
    assert!(full.message.contains("All 10 seats"));
}

#[test]
fn unknown_role_is_bad_input_not_forbidden() {
    let (mut s, ids) = suite();
    let e = s
        .execute(
            ids.owner,
            Command::Invite {
                email: "a@coastline.com".into(),
                role: "Wizard".into(),
            },
        )
        .unwrap_err();
    assert!(!e.forbidden);
}

#[test]
fn role_changes_use_custom_roles_and_protect_last_owner() {
    let (mut s, ids) = suite();
    let m = s
        .execute(
            ids.owner,
            Command::SetRole {
                member: ids.tech,
                role: "Dispatcher".into(),
            },
        )
        .unwrap();
    assert_eq!(m, "Tia Alvarez is now a Dispatcher.");
    let e = s
        .execute(
            ids.owner,
            Command::SetRole {
                member: ids.owner,
                role: "Admin".into(),
            },
        )
        .unwrap_err();
    assert!(e.message.contains("at least one owner"));
    let e = s
        .execute(
            ids.admin,
            Command::SetRole {
                member: ids.owner,
                role: "Member".into(),
            },
        )
        .unwrap_err();
    assert!(e.forbidden);
}

#[test]
fn view_reflects_viewer_capabilities() {
    let (s, ids) = suite();
    let tech = s.view(ids.tech);
    assert!(!tech.can.manage_people && !tech.can.manage_connections);
    // Tech sees their own Gmail and company accounts, but not Dana's personal ones.
    assert!(tech
        .connections
        .iter()
        .any(|c| c.mine && c.app == App::Gmail));
    assert!(!tech.connections.iter().any(|c| c.personal && !c.mine));
    let qb = tech.apps.iter().find(|a| a.app == App::QuickBooks).unwrap();
    assert!(!qb.can_connect_me && !qb.can_connect_everyone);
    let outlook = tech.apps.iter().find(|a| a.app == App::Outlook).unwrap();
    assert!(outlook.can_connect_me && !outlook.can_connect_team);
    let jobber = s
        .view(ids.dispatcher)
        .apps
        .into_iter()
        .find(|a| a.app == App::Jobber)
        .unwrap();
    assert!(jobber.can_connect_team && !jobber.can_connect_everyone);
    assert!(!jobber.available);
    // Admin sees everyone's personal connections (to manage them) but cannot pay.
    let admin = s.view(ids.admin);
    assert!(admin.connections.iter().any(|c| c.personal && !c.mine));
    assert!(!admin.can.manage_billing);
}

#[test]
fn workspaces_combine_role_and_team() {
    let (s, ids) = suite();
    let w = s.view(ids.tech).workspaces;
    assert!(w.contains(&"Email".to_owned()) && w.contains(&"Meeting notes".to_owned()));
    assert!(!w.contains(&"Customer replies".to_owned()));
}

#[test]
fn connect_flows() {
    let (mut s, ids) = suite();
    s.execute(
        ids.tech,
        Command::Connect {
            app: App::Outlook,
            account: "tia@coastline.com".into(),
            for_: ConnectFor::Me,
            credentials: None,
        },
    )
    .unwrap();
    let e = s
        .execute(
            ids.tech,
            Command::Connect {
                app: App::QuickBooks,
                account: "x".into(),
                for_: ConnectFor::Me,
                credentials: None,
            },
        )
        .unwrap_err();
    assert!(e.forbidden && e.message.contains("Ask an admin"));
    let e = s
        .execute(
            ids.dispatcher,
            Command::Connect {
                app: App::Jobber,
                account: "d".into(),
                for_: ConnectFor::Team {
                    team: "Front office".into(),
                },
                credentials: None,
            },
        )
        .unwrap_err();
    assert!(e.message.contains("coming soon"));
    let e = s
        .execute(
            ids.tech,
            Command::Connect {
                app: App::Gmail,
                account: "  ".into(),
                for_: ConnectFor::Me,
                credentials: None,
            },
        )
        .unwrap_err();
    assert!(!e.forbidden);
    s.execute(
        ids.owner,
        Command::Connect {
            app: App::Xero,
            account: "Coastline".into(),
            for_: ConnectFor::Everyone,
            credentials: None,
        },
    )
    .unwrap();
}

#[test]
fn policy_off_pauses_and_disconnect_permissions() {
    let (mut s, ids) = suite();
    s.execute(
        ids.admin,
        Command::SetAppPolicy {
            app: App::Gmail,
            policy: AppPolicy::Off,
        },
    )
    .unwrap();
    let tia = s
        .view(ids.tech)
        .connections
        .into_iter()
        .find(|c| c.app == App::Gmail)
        .unwrap();
    assert_eq!(tia.status, ConnStatus::Paused);
    assert!(
        s.execute(
            ids.tech,
            Command::SetAppPolicy {
                app: App::Gmail,
                policy: AppPolicy::OwnAccounts
            }
        )
        .unwrap_err()
        .forbidden
    );
    let qb = s
        .view(ids.owner)
        .connections
        .into_iter()
        .find(|c| c.app == App::QuickBooks)
        .unwrap();
    assert!(
        s.execute(ids.tech, Command::Disconnect { id: qb.id })
            .unwrap_err()
            .forbidden
    );
    s.execute(ids.admin, Command::Disconnect { id: qb.id })
        .unwrap();
}

#[test]
fn reconnect_fixes_expired_sign_in() {
    let (mut s, ids) = suite();
    let drive = s
        .view(ids.owner)
        .connections
        .into_iter()
        .find(|c| c.app == App::GoogleDrive)
        .unwrap();
    assert_eq!(drive.status, ConnStatus::NeedsSignIn);
    assert!(
        s.execute(ids.tech, Command::Reconnect { id: drive.id })
            .unwrap_err()
            .forbidden
    );
    s.execute(ids.admin, Command::Reconnect { id: drive.id })
        .unwrap();
    let drive = s
        .view(ids.owner)
        .connections
        .into_iter()
        .find(|c| c.app == App::GoogleDrive)
        .unwrap();
    assert_eq!(drive.status, ConnStatus::Active);
}

#[test]
fn removing_someone_disconnects_their_personal_accounts() {
    let (mut s, ids) = suite();
    s.execute(ids.owner, Command::Remove { member: ids.tech })
        .unwrap();
    assert!(!s
        .view(ids.owner)
        .connections
        .iter()
        .any(|c| c.app == App::Gmail));
}

#[test]
fn commands_round_trip_as_json() {
    let c: Command = serde_json::from_str(
        r#"{"command":"connect","app":"quick-books","account":"x","for":{"type":"team","team":"Field techs"}}"#,
    )
    .unwrap();
    assert_eq!(
        c,
        Command::Connect {
            app: App::QuickBooks,
            account: "x".into(),
            for_: ConnectFor::Team {
                team: "Field techs".into()
            },
            credentials: None,
        }
    );
}

#[test]
fn store_saves_atomically_and_reloads() {
    let dir = std::env::temp_dir().join(format!("arkhon-store-{}", std::process::id()));
    let store = Store::new(dir.join("org.json"));
    assert!(store.load().unwrap().is_none());
    let (mut s, ids) = suite();
    s.execute(ids.owner, Command::SetSeats { seats: 15 })
        .unwrap();
    store.save(s.state()).unwrap();
    let back = store.load().unwrap().unwrap();
    assert_eq!(back.org.seats(), 15);
    assert_eq!(back.activity.len(), 1);
    assert!(!dir.join("org.json.tmp").exists());
    fs::write(store.path(), b"{not json").unwrap();
    assert_eq!(
        store.load().unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    fs::remove_dir_all(dir).ok();
}
