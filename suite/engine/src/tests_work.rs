//! Review queue, value metrics, vault and connector-gate tests.
#![allow(clippy::unused_async_trait_impl)] // mock connector futures are ready immediately

use super::*;
use crate::connector::{
    check_approval, Connector, ConnectorError, Cursor, Envelope, FetchedMessage,
};
use crate::vault::{StaticKeyProvider, VaultError, VaultKeyProvider as _};

struct Fixed(u64);
impl Clock for Fixed {
    fn now(&self) -> u64 {
        self.0
    }
}

const SECRET: &str = "hunter2-very-secret-pw";

fn suite() -> (Suite, DemoIds) {
    let (state, ids) = demo_state();
    (Suite::new(state, Box::new(Fixed(1_800_000_000))), ids)
}

fn vault_in(dir: &tempfile::TempDir, key: u8) -> TokenVault {
    TokenVault::new(
        dir.path().join("vault.json"),
        Box::new(StaticKeyProvider([key; 32])),
    )
}

fn item_titled(s: &Suite, title: &str) -> ItemId {
    s.state()
        .queue
        .items
        .iter()
        .find(|i| i.title.starts_with(title))
        .unwrap()
        .id
}

fn mail_login() -> MailLogin {
    MailLogin {
        imap_host: "imap.example.com".into(),
        imap_port: 993,
        smtp_host: "smtp.example.com".into(),
        smtp_port: 587,
        username: "dana@example.com".into(),
        password: Secret::new(SECRET),
    }
}

fn connect_other(credentials: Option<MailLogin>) -> Command {
    Command::Connect {
        app: App::OtherEmail,
        account: "dana@example.com".into(),
        for_: ConnectFor::Me,
        credentials,
    }
}

fn approve(item: ItemId) -> Command {
    Command::Approve { item }
}

// ---------------------------------------------------------------------------------------------
// Needs you
// ---------------------------------------------------------------------------------------------

#[test]
fn needs_you_shows_three_urgent_first_with_total() {
    let (s, ids) = suite();
    let n = s.view(ids.owner).needs_you;
    assert_eq!(n.total, 5);
    assert_eq!(n.items.len(), 3);
    assert_eq!(n.items[0].title, "Reply to Marisol Vega");
    assert_eq!(n.items[0].urgency, Urgency::Urgent);
    assert!(n.items.iter().all(|i| i.urgency != Urgency::Low));
    assert!(n.items[0].can_approve && n.items[0].blocked.is_none());
    assert_eq!(n.items[0].sources.len(), 3);
    assert_eq!(n.items[0].action, "Send");
    let gap = n
        .items
        .iter()
        .find(|i| i.kind == ItemKind::KnowledgeGap)
        .unwrap();
    assert_eq!(gap.confidence, Confidence::NotFound);
    assert_eq!(gap.confidence_label, "Not sure");
}

#[test]
fn team_items_show_for_the_teams_approvers_only() {
    let (s, ids) = suite();
    // Lena is the assignee of the five Front office items.
    assert_eq!(s.view(ids.dispatcher).needs_you.total, 5);
    // Max approves for Field techs, so he sees Tia's meeting notes, but can't send them
    // through Tia's personal Gmail.
    let max = s.view(ids.manager).needs_you;
    assert_eq!(max.total, 1);
    assert!(!max.items[0].can_approve);
    assert!(max.items[0]
        .blocked
        .as_deref()
        .unwrap()
        .contains("which you can't use"));
    // Ari (admin, on Front office) approves for that team too; Tia sees her own item.
    // Ari also has her own receipt to file; Tia has a supplier reply too.
    assert_eq!(s.view(ids.admin).needs_you.total, 6);
    assert_eq!(s.view(ids.tech).needs_you.total, 2);
    // Sam is on Field techs but can't approve for the team.
    let sam = s
        .state()
        .org
        .members()
        .find(|m| m.name == "Sam Brooks")
        .unwrap()
        .id;
    assert_eq!(s.view(sam).needs_you.total, 0);
}

// ---------------------------------------------------------------------------------------------
// Approval rules
// ---------------------------------------------------------------------------------------------

#[test]
fn assignee_approves_records_activity_and_value() {
    let (mut s, ids) = suite();
    let before = s.this_week(ids.owner);
    let id = item_titled(&s, "Reply to Marisol");
    let msg = s.execute(ids.owner, approve(id)).unwrap();
    assert_eq!(msg, "Sent: Reply to Marisol Vega.");
    let it = s.state().queue.get(id).unwrap();
    assert_eq!(it.status, ItemStatus::Approved);
    assert_eq!(it.decided_by, Some(ids.owner));
    assert_eq!(it.final_text, it.draft);
    let ev = s.state().value.last().unwrap();
    assert_eq!(
        (ev.kind, ev.item, ev.member),
        (ValueKind::DraftAccepted, Some(id), ids.owner)
    );
    let log = s.activity(ids.owner).unwrap();
    assert_eq!(
        log[0].action,
        "Approve \u{201c}Reply to Marisol Vega\u{201d}"
    );
    assert!(log[0].refused.is_none());
    let after = s.this_week(ids.owner);
    assert_eq!(after.totals.drafts, before.totals.drafts + 1);
    assert_eq!(after.totals.minutes, before.totals.minutes + 4);
    assert_eq!(s.view(ids.owner).needs_you.total, 4);
}

#[test]
fn others_cannot_approve_and_refusals_are_logged() {
    let (mut s, ids) = suite();
    let id = item_titled(&s, "Reply to Marisol");
    let e = s.execute(ids.tech, approve(id)).unwrap_err();
    assert!(e.forbidden);
    assert!(e.message.contains("waiting for Dana Ruiz"));
    let e = s
        .execute(ids.tech, Command::Dismiss { item: id })
        .unwrap_err();
    assert!(e.forbidden);
    assert_eq!(s.state().queue.get(id).unwrap().status, ItemStatus::Waiting);
    assert!(s.state().value.iter().all(|v| v.item.is_none()));
    let log = s.activity(ids.owner).unwrap();
    assert_eq!(log.len(), 2);
    assert!(log.iter().all(|l| l.refused.is_some()));
}

#[test]
fn approver_must_be_on_the_items_team() {
    let (mut s, ids) = suite();
    let id = item_titled(&s, "Confirm Harbor Dental");
    // Max has "Approve work for their team" but isn't on Front office.
    let e = s.execute(ids.manager, approve(id)).unwrap_err();
    assert!(e.forbidden);
    assert!(e.message.contains("an approver on Front office"));
    s.execute(ids.dispatcher, approve(id)).unwrap();
}

#[test]
fn team_approver_can_decide_when_they_can_use_the_connection() {
    let (mut s, ids) = suite();
    // A Field techs item going out through the shared folder... read-only, so use a new
    // company Outlook shared with Field techs.
    let conn = s
        .state
        .connections
        .connect_company(
            &s.state.org,
            ids.owner,
            App::Gmail,
            "field@coastline.com",
            Audience::Teams(["Field techs".to_owned()].into()),
            Access::Draft,
        )
        .unwrap();
    let id = s
        .propose(Proposal {
            workspace: Workspace::Inbox,
            kind: ItemKind::DraftReply,
            title: "Tell Sam's customer the part arrived".into(),
            summary: "s".into(),
            draft: Some("The part is in.".into()),
            question: None,
            sources: Vec::new(),
            confidence: Confidence::High,
            urgency: Urgency::Normal,
            assignee: ids.tech,
            team: Some("Field techs".into()),
            connection: Some(conn),
        })
        .unwrap();
    s.execute(ids.manager, approve(id)).unwrap();
    let ev = s.state().value.last().unwrap();
    assert_eq!(ev.member, ids.tech, "value is credited to the assignee");
}

#[test]
fn approving_through_a_connection_you_cannot_use_is_refused() {
    let (mut s, ids) = suite();
    // Admin may decide anything, but Dana's personal Outlook isn't theirs.
    let id = item_titled(&s, "Reply to Marisol");
    let e = s.execute(ids.admin, approve(id)).unwrap_err();
    assert!(e.forbidden);
    assert!(e.message.contains("Outlook (dana@coastline.com)"));
    // Dismissing doesn't send anything, so it's allowed.
    s.execute(ids.admin, Command::Dismiss { item: id }).unwrap();
    // Max can't send Tia's meeting notes through her Gmail; Tia can.
    let notes = item_titled(&s, "Share notes");
    assert!(
        s.execute(ids.manager, approve(notes))
            .unwrap_err()
            .forbidden
    );
    s.execute(ids.tech, approve(notes)).unwrap();
}

#[test]
fn read_only_connections_never_send() {
    let (mut s, ids) = suite();
    let folder = s
        .state()
        .connections
        .all()
        .find(|c| c.app == App::LocalFolder)
        .unwrap()
        .id;
    let id = s
        .propose(Proposal {
            workspace: Workspace::Docs,
            kind: ItemKind::FileBill,
            title: "File a receipt".into(),
            summary: "s".into(),
            draft: None,
            question: None,
            sources: Vec::new(),
            confidence: Confidence::High,
            urgency: Urgency::Normal,
            assignee: ids.owner,
            team: None,
            connection: Some(folder),
        })
        .unwrap();
    let e = s.execute(ids.owner, approve(id)).unwrap_err();
    assert!(e.forbidden);
    assert!(e.message.contains("read-only"));
}

#[test]
fn connection_needing_sign_in_blocks_approval() {
    let (mut s, ids) = suite();
    let id = item_titled(&s, "Reply to Marisol");
    let conn = s.state().queue.get(id).unwrap().connection.unwrap();
    s.state.connections.mark_needs_sign_in(conn).unwrap();
    let e = s.execute(ids.owner, approve(id)).unwrap_err();
    assert!(!e.forbidden);
    assert!(e.message.contains("needs attention"));
}

#[test]
fn paused_people_cannot_decide() {
    let (mut s, ids) = suite();
    let id = item_titled(&s, "Confirm Harbor Dental");
    s.execute(
        ids.owner,
        Command::Suspend {
            member: ids.dispatcher,
        },
    )
    .unwrap();
    assert!(
        s.execute(ids.dispatcher, approve(id))
            .unwrap_err()
            .forbidden
    );
    assert_eq!(s.view(ids.dispatcher).needs_you.total, 0);
}

#[test]
fn items_are_decided_once() {
    let (mut s, ids) = suite();
    let id = item_titled(&s, "File a Ferguson");
    assert_eq!(
        s.execute(ids.owner, approve(id)).unwrap(),
        "Filed: File a Ferguson bill for $2,418.36."
    );
    let e = s.execute(ids.owner, approve(id)).unwrap_err();
    assert!(e.message.contains("already handled"));
    assert!(s.execute(ids.owner, approve(9_999)).is_err());
    assert_eq!(
        s.state().value.last().unwrap().kind,
        ValueKind::DocumentFiled
    );
}

#[test]
fn edit_and_approve_uses_the_edited_text() {
    let (mut s, ids) = suite();
    let id = item_titled(&s, "Reply to Marisol");
    let e = s
        .execute(
            ids.owner,
            Command::EditAndApprove {
                item: id,
                text: "   ".into(),
            },
        )
        .unwrap_err();
    assert!(!e.forbidden);
    s.execute(
        ids.owner,
        Command::EditAndApprove {
            item: id,
            text: "Hi Marisol, see you at 2 pm.".into(),
        },
    )
    .unwrap();
    let it = s.state().queue.get(id).unwrap();
    assert_eq!(it.status, ItemStatus::Edited);
    let a = s.approval_for_send(id).unwrap();
    assert_eq!(a.text(), "Hi Marisol, see you at 2 pm.");
    // Bills have no text to edit.
    let bill = item_titled(&s, "File a Ferguson");
    assert!(s
        .execute(
            ids.owner,
            Command::EditAndApprove {
                item: bill,
                text: "x".into()
            }
        )
        .unwrap_err()
        .message
        .contains("no text to edit"));
}

#[test]
fn dismissing_records_no_value_and_cannot_be_sent() {
    let (mut s, ids) = suite();
    let n = s.state().value.len();
    let id = item_titled(&s, "Send the Ortiz");
    s.execute(ids.owner, Command::Dismiss { item: id }).unwrap();
    assert_eq!(s.state().value.len(), n);
    assert_eq!(
        s.state().queue.get(id).unwrap().status,
        ItemStatus::Dismissed
    );
    assert!(s.approval_for_send(id).unwrap_err().forbidden);
}

#[test]
fn answer_once_is_remembered_and_reuse_counts() {
    let (mut s, ids) = suite();
    let gap = item_titled(&s, "A customer asked");
    assert!(s
        .execute(ids.owner, approve(gap))
        .unwrap_err()
        .message
        .contains("Answer it once"));
    let bill = item_titled(&s, "File a Ferguson");
    assert!(s
        .execute(
            ids.owner,
            Command::AnswerOnce {
                item: bill,
                answer: "x".into()
            }
        )
        .is_err());
    let n = s.state().value.len();
    s.execute(
        ids.owner,
        Command::AnswerOnce {
            item: gap,
            answer: "Yes, all Mitsubishi mini-splits.".into(),
        },
    )
    .unwrap();
    assert_eq!(s.state().value.len(), n, "answering itself saves no time");
    let k = s
        .state()
        .queue
        .lookup("do we service   mitsubishi mini-split units?")
        .unwrap();
    assert_eq!(k.answer, "Yes, all Mitsubishi mini-splits.");
    let kid = k.id;
    let id = s
        .propose(Proposal {
            workspace: Workspace::Inbox,
            kind: ItemKind::DraftReply,
            title: "Reply about a Mitsubishi unit".into(),
            summary: "s".into(),
            draft: Some("Yes, we do.".into()),
            question: None,
            sources: vec![Source {
                label: "Your answer".into(),
                reference: format!("knowledge:{kid}"),
            }],
            confidence: Confidence::High,
            urgency: Urgency::Normal,
            assignee: ids.owner,
            team: None,
            connection: s.state().queue.get(1).unwrap().connection,
        })
        .unwrap();
    s.execute(ids.owner, approve(id)).unwrap();
    let kinds: Vec<_> = s.state().value[n..].iter().map(|v| v.kind).collect();
    assert_eq!(kinds, [ValueKind::DraftAccepted, ValueKind::AnswerReused]);
}

#[test]
fn proposals_are_validated_and_logged_as_arkhon() {
    let (mut s, ids) = suite();
    let mut p = Proposal {
        workspace: Workspace::Inbox,
        kind: ItemKind::DraftReply,
        title: "t".into(),
        summary: "s".into(),
        draft: None,
        question: None,
        sources: Vec::new(),
        confidence: Confidence::Low,
        urgency: Urgency::Low,
        assignee: 999,
        team: None,
        connection: None,
    };
    assert!(s.propose(p.clone()).is_err());
    p.assignee = ids.owner;
    p.team = Some("Nope".into());
    assert!(s.propose(p.clone()).is_err());
    p.team = None;
    p.connection = Some(999);
    assert!(s.propose(p.clone()).is_err());
    p.connection = None;
    s.propose(p).unwrap();
    assert_eq!(s.activity(ids.owner).unwrap()[0].actor, "Arkhon");
}

// ---------------------------------------------------------------------------------------------
// No approval, no send
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct MockMail {
    id: u64,
    sent: Vec<String>,
}

impl Connector for MockMail {
    fn connection_id(&self) -> u64 {
        self.id
    }
    async fn fetch_new(
        &mut self,
        since: Option<Cursor>,
    ) -> Result<(Vec<FetchedMessage>, Cursor), ConnectorError> {
        Ok((Vec::new(), since.unwrap_or_default()))
    }
    async fn send_approved(
        &mut self,
        approval: Option<&SendApproval>,
        _envelope: &Envelope,
    ) -> Result<(), ConnectorError> {
        let text = check_approval(approval, self.id)?;
        self.sent.push(text.to_owned());
        Ok(())
    }
}

fn ready<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => panic!("mock future should be ready"),
    }
}

#[test]
fn connectors_refuse_to_send_without_an_approval() {
    let (mut s, ids) = suite();
    let id = item_titled(&s, "Reply to Marisol");
    let conn = s.state().queue.get(id).unwrap().connection.unwrap();
    let mut mail = MockMail {
        id: conn,
        ..MockMail::default()
    };
    let env = Envelope {
        from: "dana@coastline.com".into(),
        to: vec!["marisol@example.com".into()],
        subject: "Re: AC".into(),
        in_reply_to: None,
    };
    assert_eq!(
        ready(mail.send_approved(None, &env)),
        Err(ConnectorError::NotApproved)
    );
    // Waiting items can't produce an approval.
    assert!(s.approval_for_send(id).unwrap_err().forbidden);
    s.execute(ids.owner, approve(id)).unwrap();
    let ok = s.approval_for_send(id).unwrap();
    let mut other = MockMail {
        id: conn + 100,
        ..MockMail::default()
    };
    assert_eq!(
        ready(other.send_approved(Some(&ok), &env)),
        Err(ConnectorError::WrongConnection)
    );
    ready(mail.send_approved(Some(&ok), &env)).unwrap();
    assert_eq!(mail.sent.len(), 1);
    assert!(mail.sent[0].starts_with("Hi Marisol"));
    assert_eq!(other.sent.len(), 0);
    // Knowledge gaps never send.
    let gap = item_titled(&s, "A customer asked");
    s.execute(
        ids.owner,
        Command::AnswerOnce {
            item: gap,
            answer: "No.".into(),
        },
    )
    .unwrap();
    assert!(!s.approval_for_send(gap).unwrap_err().forbidden);
}

// ---------------------------------------------------------------------------------------------
// Value metrics
// ---------------------------------------------------------------------------------------------

#[test]
fn this_week_is_pinned_for_the_example_and_has_14_days() {
    let (s, ids) = suite();
    let w = s.this_week(ids.owner);
    assert_eq!(w.scope, "company");
    assert!(w.example);
    assert_eq!(w.days.len(), 14);
    assert_eq!(w.days[13].date, "2026-11-06");
    assert_eq!(w.days[13].label, "F");
    assert_eq!(w.days[13].weekday, "Friday");
    assert_eq!(w.days[0].date, "2026-10-24");
    let week: u64 = w.days[7..].iter().map(|d| d.minutes).sum();
    assert_eq!(week, w.totals.minutes);
    assert!(w.hours > 10.0 && w.hours < 20.0, "{}", w.hours);
    assert_eq!(w.hourly_rate, 58);
    assert_eq!(w.dollars, (w.totals.minutes * 58 + 30) / 60);
    // Same view regardless of the wall clock.
    let (state, _) = demo_state();
    let other = Suite::new(state, Box::new(Fixed(5))).this_week(ids.owner);
    assert_eq!(other, w);
}

#[test]
fn people_without_company_reports_see_only_their_own_numbers() {
    let (s, ids) = suite();
    let all = s.this_week(ids.owner);
    let mine = s.this_week(ids.tech);
    assert_eq!(mine.scope, "you");
    assert!(mine.totals.minutes > 0 && mine.totals.minutes < all.totals.minutes);
    let expected: u64 = s
        .state()
        .value
        .iter()
        .filter(|e| e.member == ids.tech && day_number(e.at) + 6 >= day_number(s.today()))
        .map(|e| u64::from(s.state().value_settings.minutes_for(e.kind)))
        .sum();
    assert_eq!(mine.totals.minutes, expected);
    // Managers have company reports.
    assert_eq!(s.this_week(ids.manager).scope, "company");
    let r = s.monthly_report(ids.tech, 2026, 11).unwrap();
    assert_eq!(r.scope, "you");
    assert_eq!(r.person.as_deref(), Some("Tia Alvarez"));
    assert_eq!(r.by_person.len(), 0);
}

#[test]
fn only_admins_change_assumptions_and_numbers_follow() {
    let (mut s, ids) = suite();
    let cmd = Command::SetMinutesSaved {
        kind: ValueKind::DraftAccepted,
        minutes: 8,
    };
    assert!(s.execute(ids.manager, cmd.clone()).unwrap_err().forbidden);
    assert!(s
        .execute(ids.owner, Command::SetHourlyRate { dollars: 0 })
        .is_err());
    assert!(s
        .execute(
            ids.owner,
            Command::SetMinutesSaved {
                kind: ValueKind::DraftAccepted,
                minutes: 0
            }
        )
        .is_err());
    let before = s.this_week(ids.owner);
    s.execute(ids.admin, cmd).unwrap();
    let after = s.this_week(ids.owner);
    assert_eq!(
        after.totals.minutes,
        before.totals.minutes + 4 * u64::from(before.totals.drafts)
    );
    s.execute(ids.owner, Command::SetHourlyRate { dollars: 120 })
        .unwrap();
    let w = s.this_week(ids.owner);
    assert_eq!(w.hourly_rate, 120);
    assert_eq!(w.dollars, w.totals.minutes * 2);
    let r = s.monthly_report(ids.owner, 2026, 11).unwrap();
    assert_eq!(r.hourly_rate, 120);
    assert!(r
        .assumptions
        .iter()
        .any(|a| a.kind == ValueKind::DraftAccepted && a.minutes_each == 8));
}

#[test]
fn monthly_report_has_every_day_and_people() {
    let (s, ids) = suite();
    let r = s.monthly_report(ids.owner, 2026, 10).unwrap();
    assert_eq!(r.month, "2026-10");
    assert_eq!(r.days.len(), 31);
    assert_eq!(r.days[0].date, "2026-10-01");
    let by_days: u64 = r.days.iter().map(|d| d.minutes).sum();
    assert_eq!(by_days, r.totals.minutes);
    let by_people: u64 = r.by_person.iter().map(|p| p.totals.minutes).sum();
    assert_eq!(by_people, r.totals.minutes);
    assert!(r
        .by_person
        .windows(2)
        .all(|w| w[0].totals.minutes >= w[1].totals.minutes));
    assert_eq!(s.monthly_report(ids.owner, 2026, 2).unwrap().days.len(), 28);
    assert_eq!(s.monthly_report(ids.owner, 2028, 2).unwrap().days.len(), 29);
    assert!(s.monthly_report(ids.owner, 2026, 13).is_err());
    let json = serde_json::to_value(&r).unwrap();
    assert!(json["totals"]["hours"].is_number());
}

#[test]
fn real_companies_measure_nothing_until_work_is_approved() {
    let (mut state, ids) = demo_state();
    state.value.clear();
    state.example_today = None;
    let s = Suite::new(state, Box::new(Fixed(demo_today())));
    let w = s.this_week(ids.owner);
    assert!(!w.example);
    assert_eq!(w.totals.minutes, 0);
    assert!(w.days.iter().all(|d| d.minutes == 0));
}

#[test]
fn calendar_math() {
    assert_eq!(value::iso_date(0), "1970-01-01");
    assert_eq!(value::weekday_name(0), "Thursday");
    assert_eq!(value::days_from_civil(2000, 3, 1), 11_017);
    for d in [0, 59, 365, 11_016, 20_000, 30_000] {
        let (y, m, dd) = value::civil(d);
        assert_eq!(value::days_from_civil(y, m, dd), d);
    }
    assert_eq!(value::hours(0), 0.0);
    assert_eq!(value::hours(90), 1.5);
}

// ---------------------------------------------------------------------------------------------
// Vault and credentials
// ---------------------------------------------------------------------------------------------

#[test]
fn vault_round_trips_and_binds_entries_to_their_connection() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_in(&dir, 7);
    v.put(3, &Credential::Mail(mail_login())).unwrap();
    v.put(
        4,
        &Credential::OAuthRefreshToken {
            token: Secret::new("refresh-abc"),
        },
    )
    .unwrap();
    assert_eq!(v.get(3).unwrap(), Some(Credential::Mail(mail_login())));
    assert!(v.get(5).unwrap().is_none());
    let raw = std::fs::read_to_string(v.path()).unwrap();
    assert!(!raw.contains(SECRET) && !raw.contains("refresh-abc"));
    assert!(!raw.contains("imap.example.com"), "hosts are sealed too");
    // Wrong key.
    assert!(matches!(vault_in(&dir, 8).get(3), Err(VaultError::Corrupt)));
    // An entry moved onto another connection doesn't open.
    let mut file: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let e3 = file["entries"]["3"].clone();
    file["entries"]["4"] = e3;
    std::fs::write(v.path(), file.to_string()).unwrap();
    assert!(matches!(v.get(4), Err(VaultError::Corrupt)));
    v.remove(3).unwrap();
    assert!(!v.contains(3).unwrap());
}

#[test]
fn dev_key_file_is_created_once_and_reused() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault::DevFileKeyProvider::new(dir.path().join("k"));
    let a = p.vault_key().unwrap();
    let b = p.vault_key().unwrap();
    assert_eq!(*a, *b);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.path().join("k"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
    std::fs::write(dir.path().join("k"), b"short").unwrap();
    assert!(matches!(p.vault_key(), Err(VaultError::Key(_))));
}

#[test]
fn secrets_never_leak_into_state_views_activity_or_debug() {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = demo_state();
    let mut s = Suite::new(state, Box::new(Fixed(1))).with_vault(vault_in(&dir, 1));
    let cmd = connect_other(Some(mail_login()));
    assert!(!format!("{cmd:?}").contains(SECRET));
    assert!(!serde_json::to_string(&cmd).unwrap().contains(SECRET));
    let msg = s.execute(ids.owner, cmd).unwrap();
    assert!(!msg.contains(SECRET));
    let conn = s
        .state()
        .connections
        .all()
        .find(|c| c.app == App::OtherEmail)
        .unwrap()
        .id;
    // Stored in the vault...
    match s.vault().unwrap().get(conn).unwrap() {
        Some(Credential::Mail(m)) => assert_eq!(m.password.expose(), SECRET),
        other => panic!("{other:?}"),
    }
    // ...and nowhere else.
    let state_json = serde_json::to_string(s.state()).unwrap();
    assert!(!state_json.contains(SECRET));
    assert!(!state_json.contains("imap.example.com"));
    assert!(!serde_json::to_string(&s.view(ids.owner))
        .unwrap()
        .contains(SECRET));
    let log = serde_json::to_string(&s.activity(ids.owner).unwrap()).unwrap();
    assert!(!log.contains(SECRET));
    assert!(!format!("{s:?}").contains(SECRET));
    let store = Store::new(dir.path().join("org.json"));
    store.save(s.state()).unwrap();
    assert!(!std::fs::read_to_string(store.path())
        .unwrap()
        .contains(SECRET));
    // Disconnecting erases the sign-in.
    s.execute(ids.owner, Command::Disconnect { id: conn })
        .unwrap();
    assert!(s.vault().unwrap().get(conn).unwrap().is_none());
}

#[test]
fn credentials_arrive_as_json_and_are_dropped_on_output() {
    let c: Command = serde_json::from_str(&format!(
        r#"{{"command":"connect","app":"other-email","account":"a@b.c","for":{{"type":"me"}},
            "credentials":{{"imap_host":"i","smtp_host":"s","username":"u","password":"{SECRET}"}}}}"#
    ))
    .unwrap();
    let Command::Connect {
        credentials: Some(m),
        ..
    } = &c
    else {
        panic!()
    };
    assert_eq!((m.imap_port, m.smtp_port), (993, 587));
    assert_eq!(m.password.expose(), SECRET);
    assert!(!serde_json::to_string(&c).unwrap().contains(SECRET));
}

#[test]
fn other_email_needs_credentials_and_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, ids) = suite();
    // No vault attached: refuse and connect nothing.
    let e = s
        .execute(ids.owner, connect_other(Some(mail_login())))
        .unwrap_err();
    assert!(e.message.contains("can't store passwords"));
    assert!(s
        .state()
        .connections
        .all()
        .all(|c| c.app != App::OtherEmail));
    let (state, _) = demo_state();
    let mut s = Suite::new(state, Box::new(Fixed(1))).with_vault(vault_in(&dir, 2));
    assert!(s.execute(ids.owner, connect_other(None)).is_err());
    let mut blank = mail_login();
    blank.password = Secret::new(" ");
    assert!(s.execute(ids.owner, connect_other(Some(blank))).is_err());
    let e = s
        .execute(
            ids.owner,
            Command::Connect {
                app: App::Gmail,
                account: "x@y.z".into(),
                for_: ConnectFor::Me,
                credentials: Some(mail_login()),
            },
        )
        .unwrap_err();
    assert!(e.message.contains("signs in on its own page"));
    // A refused connect (policy) stores nothing in the vault.
    s.execute(
        ids.owner,
        Command::SetAppPolicy {
            app: App::OtherEmail,
            policy: AppPolicy::Off,
        },
    )
    .unwrap();
    assert!(
        s.execute(ids.owner, connect_other(Some(mail_login())))
            .unwrap_err()
            .forbidden
    );
    assert!(!dir.path().join("vault.json").exists());
}

#[test]
fn vault_failure_rolls_back_the_connection() {
    struct Locked;
    impl vault::VaultKeyProvider for Locked {
        fn vault_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, VaultError> {
            Err(VaultError::Key("no key store".into()))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = demo_state();
    let mut s = Suite::new(state, Box::new(Fixed(1)))
        .with_vault(TokenVault::new(dir.path().join("v"), Box::new(Locked)));
    let e = s
        .execute(ids.owner, connect_other(Some(mail_login())))
        .unwrap_err();
    assert!(e.message.contains("Nothing was connected"));
    assert!(s
        .state()
        .connections
        .all()
        .all(|c| c.app != App::OtherEmail));
}

#[test]
fn old_state_files_without_queue_still_load() {
    let (state, _) = demo_state();
    let mut v = serde_json::to_value(&state).unwrap();
    let o = v.as_object_mut().unwrap();
    for k in ["queue", "value", "value_settings", "example_today"] {
        o.remove(k);
    }
    let back: State = serde_json::from_value(v).unwrap();
    assert!(back.queue.items.is_empty() && back.example_today.is_none());
    assert_eq!(back.value_settings, ValueSettings::default());
}
