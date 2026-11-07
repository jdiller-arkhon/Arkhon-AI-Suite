//! Workspace pages, Ask, Privacy Center and setup.
#![allow(clippy::assert_is_empty)] // plain emptiness checks read best here

use super::*;
use crate::vault::StaticKeyProvider;

struct Fixed(u64);
impl Clock for Fixed {
    fn now(&self) -> u64 {
        self.0
    }
}

fn suite() -> (Suite, DemoIds) {
    let (state, ids) = demo_state();
    (Suite::new(state, Box::new(Fixed(1_800_000_000))), ids)
}

fn member(s: &Suite, name: &str) -> MemberId {
    s.state().org.members().find(|m| m.name == name).unwrap().id
}

fn keys(v: &View) -> Vec<String> {
    v.nav.iter().map(|n| n.key.clone()).collect()
}

#[test]
fn pages_follow_workspace_access() {
    let (s, ids) = suite();
    let owner = s.view(ids.owner);
    assert_eq!(
        keys(&owner),
        [
            "inbox",
            "desk",
            "docs",
            "knowledge",
            "meetings",
            "growth",
            "insights"
        ]
    );
    assert!(owner.inbox.is_some() && owner.desk.is_some() && owner.insights.is_some());

    // Tia: Member (Email, Documents, Company answers) + Field techs (Meeting notes, Documents).
    let tia = s.view(ids.tech);
    assert_eq!(keys(&tia), ["inbox", "docs", "knowledge", "meetings"]);
    assert!(tia.desk.is_none(), "a Member without Desk doesn't get Desk");
    assert!(tia.growth.is_none() && tia.insights.is_none());

    // Lena: Dispatcher role + Front office.
    let lena = s.view(ids.dispatcher);
    assert_eq!(keys(&lena), ["inbox", "desk", "knowledge", "growth"]);
    assert!(lena.docs.is_none() && lena.meetings.is_none());

    // Paused people see nothing.
    let pat = s.view(member(&s, "Pat Doyle"));
    assert!(pat.nav.is_empty() && pat.inbox.is_none() && pat.knowledge.is_none());
}

#[test]
fn personal_mail_stays_personal_in_inbox() {
    let (s, ids) = suite();
    let customers = |id| -> Vec<String> {
        s.inbox_view(id)
            .unwrap()
            .threads
            .into_iter()
            .map(|t| t.customer)
            .collect()
    };
    // Urgent first.
    assert_eq!(customers(ids.owner), ["Marisol Vega", "Greg Lund"]);
    assert_eq!(customers(ids.tech), ["Johnstone Supply"]);
    // An admin doesn't read the owner's personal mailbox.
    assert!(customers(ids.admin).is_empty());
    let inbox = s.inbox_view(ids.owner).unwrap();
    assert_eq!(inbox.waiting, 2);
    let first = inbox.threads[0].item.as_ref().unwrap();
    assert!(first.can_approve && first.draft.is_some());
    assert_eq!(first.sources.len(), 3);
}

#[test]
fn inbox_send_runs_the_approval_and_stays_listed_as_sent() {
    let (mut s, ids) = suite();
    let item = s.inbox_view(ids.owner).unwrap().threads[0]
        .item
        .as_ref()
        .unwrap()
        .id;
    s.execute(ids.owner, Command::Approve { item }).unwrap();
    let inbox = s.inbox_view(ids.owner).unwrap();
    assert_eq!(inbox.waiting, 1);
    let done = inbox.threads[0].item.as_ref().unwrap();
    assert_eq!(done.status, ItemStatus::Approved);
    assert!(!done.can_approve, "a decided item can't be approved again");
    assert_eq!(done.final_text, done.draft);
    assert_eq!(s.view(ids.owner).needs_you.total, 4);
}

#[test]
fn docs_show_fields_checks_and_file_through_the_queue() {
    let (mut s, ids) = suite();
    let docs = s.docs_view(ids.owner).unwrap();
    assert_eq!(docs.documents.len(), 7);
    assert_eq!(docs.to_file, 2);
    assert!(docs.types.contains(&"Lien waiver".to_owned()));
    let bill = docs
        .documents
        .iter()
        .find(|d| d.doc_type == work::DocType::SupplierBill)
        .unwrap();
    assert_eq!(bill.check_text, "Matches PO-1187");
    assert!(bill
        .fields
        .iter()
        .any(|f| f.label == "Amount" && f.value == "$2,418.36"));
    let id = bill.item.as_ref().unwrap().id;
    assert_eq!(bill.item.as_ref().unwrap().action, "File it");

    // Tia reads the shared job folder, but bills arrive in the Front office mailbox.
    let tia = s.docs_view(ids.tech).unwrap();
    assert_eq!(tia.documents.len(), 5);
    assert_eq!(tia.to_file, 0);

    // Lena has no Documents workspace, and isn't the assignee, so she can't file it.
    let r = s.execute(ids.dispatcher, Command::Approve { item: id });
    assert!(r.unwrap_err().forbidden);

    s.execute(ids.owner, Command::Approve { item: id }).unwrap();
    assert_eq!(s.docs_view(ids.owner).unwrap().to_file, 1);
}

#[test]
fn desk_not_found_cases_answer_once_and_are_remembered() {
    let (mut s, ids) = suite();
    let desk = s.desk_view(ids.dispatcher).unwrap();
    assert_eq!(desk.tickets.len(), 4);
    assert_eq!(desk.not_found, 2);
    let weekend = desk
        .tickets
        .iter()
        .find(|t| t.question.contains("Saturday"))
        .unwrap()
        .item
        .clone()
        .unwrap();
    assert_eq!(weekend.confidence, Confidence::NotFound);
    let q = weekend.question.clone().unwrap();
    assert!(!s.ask(ids.dispatcher, &q).unwrap().found);
    s.execute(
        ids.dispatcher,
        Command::AnswerOnce {
            item: weekend.id,
            answer: "Yes, Saturday calls are $95 extra. Comfort Club members pay no extra.".into(),
        },
    )
    .unwrap();
    assert_eq!(s.desk_view(ids.dispatcher).unwrap().not_found, 1);
    let a = s.ask(ids.dispatcher, &q).unwrap();
    assert!(a.found);
    assert!(a.answer.contains("$95"));
    assert!(a.sources[0].label.contains("Lena Cho"));
}

#[test]
fn ask_cites_sources_and_never_guesses() {
    let (s, ids) = suite();
    let a = s
        .ask(ids.tech, "what's the warranty on new installs")
        .unwrap();
    assert!(a.found);
    assert!(a.answer.contains("10 years"));
    assert_eq!(a.sources[0].label, "Warranty policy");
    let none = s.ask(ids.tech, "What is the wifi password?").unwrap();
    assert!(!none.found && none.sources.is_empty());
    assert!(none.answer.contains("didn't guess"));
    // A starter question the files don't cover is honest too.
    assert!(!s.ask(ids.tech, "How do I log my hours?").unwrap().found);
    assert!(!s.ask(ids.tech, "   ").unwrap_err().forbidden);
    let pat = member(&s, "Pat Doyle");
    assert!(s.ask(pat, "warranty").unwrap_err().forbidden);
    let k = s.knowledge_view(ids.tech).unwrap();
    assert!(k.starter_questions.len() >= 4);
}

#[test]
fn meetings_are_shown_to_their_team_and_admins() {
    let (mut s, ids) = suite();
    assert_eq!(s.meetings_view(ids.owner).unwrap().meetings.len(), 2);
    let sam = member(&s, "Sam Brooks");
    let m = s.meetings_view(sam).unwrap();
    assert_eq!(m.meetings.len(), 2);
    let bay = &m.meetings[0];
    assert_eq!(bay.actions.len(), 3);
    assert!(!bay.decisions.is_empty());
    // Sam can see the follow-up but can't send it for Tia.
    assert!(!bay.item.as_ref().unwrap().can_approve);
    // A manager who isn't on Field techs sees only the company-wide meeting.
    s.execute(
        ids.owner,
        Command::Invite {
            email: "kim.lee@coastline.com".into(),
            role: "Manager".into(),
        },
    )
    .unwrap();
    let kim = member(&s, "Kim Lee");
    s.execute(ids.owner, Command::AcceptInvite { member: kim })
        .unwrap();
    let mk = s.meetings_view(kim).unwrap();
    assert_eq!(mk.meetings.len(), 1);
    assert_eq!(mk.meetings[0].title, "Monday dispatch huddle");
}

#[test]
fn quotes_add_up_from_the_price_book() {
    let (s, ids) = suite();
    let g = s.growth_view(ids.dispatcher).unwrap();
    let lund = g.quotes.iter().find(|q| q.customer == "Greg Lund").unwrap();
    assert_eq!(lund.total_cents, 1_309_500);
    assert_eq!(
        lund.total_cents,
        lund.lines.iter().map(|l| l.total_cents).sum::<u64>()
    );
    assert!(lund.item.as_ref().unwrap().can_approve);
    let ortiz = g
        .quotes
        .iter()
        .find(|q| q.customer == "Luis Ortiz")
        .unwrap();
    assert_eq!(ortiz.total_cents, 645_000);
    assert_eq!(g.outreach[0].recipients, 38);
}

#[test]
fn insights_bars_match_their_answers() {
    let (s, ids) = suite();
    let i = s.insights_view(ids.owner).unwrap();
    let owed: u64 = i.insights[0].bars.iter().map(|b| b.value).sum();
    assert_eq!(owed, 691_240);
    assert!(i.insights[0].answer.contains("$6,912.40"));
    let oct: u64 = i.insights[1].bars.iter().map(|b| b.value).sum();
    assert_eq!(oct, 11_667_000);
    assert!(i.insights.iter().all(|x| !x.assumptions.is_empty()));
}

#[test]
fn retention_is_admin_only_and_validated() {
    let (mut s, ids) = suite();
    assert_eq!(s.privacy_view(ids.owner).retention_days, 365);
    assert!(!s.privacy_view(ids.tech).can_manage);
    let r = s.execute(ids.tech, Command::SetRetention { days: 30 });
    assert!(r.unwrap_err().forbidden);
    assert!(
        !s.execute(ids.admin, Command::SetRetention { days: 7 })
            .unwrap_err()
            .forbidden
    );
    s.execute(ids.admin, Command::SetRetention { days: 90 })
        .unwrap();
    assert_eq!(s.privacy_view(ids.tech).retention_days, 90);
}

#[test]
fn privacy_lists_every_connection_newest_first() {
    let (s, ids) = suite();
    let p = s.privacy_view(ids.tech);
    assert_eq!(p.network.len(), 6);
    assert_eq!(p.network[0].service, "Microsoft Outlook");
    assert_eq!(p.network[0].when, "5 min ago");
    assert_eq!(p.customer_data_sent, 0);
}

#[test]
fn delete_all_is_admin_only_and_needs_the_company_name() {
    let (mut s, ids) = suite();
    let before = s.state().queue.items.len();
    for who in [ids.tech, ids.dispatcher, ids.manager] {
        let r = s.execute(
            who,
            Command::DeleteAllData {
                confirm: "Coastline Mechanical".into(),
            },
        );
        assert!(r.unwrap_err().forbidden);
    }
    let wrong = s.execute(
        ids.owner,
        Command::DeleteAllData {
            confirm: "yes".into(),
        },
    );
    let wrong = wrong.unwrap_err();
    assert!(!wrong.forbidden && wrong.message.contains("Nothing was deleted"));
    assert_eq!(s.state().queue.items.len(), before);
    assert!(!s.state().work.threads.is_empty());
    // Refusals are in the activity log.
    assert_eq!(s.activity(ids.owner).unwrap().len(), 4);
}

#[test]
fn delete_all_clears_everything_but_people() {
    let dir = tempfile::tempdir().unwrap();
    let vault = TokenVault::new(
        dir.path().join("vault.json"),
        Box::new(StaticKeyProvider([3; 32])),
    );
    let (state, ids) = demo_state();
    let mut s = Suite::new(state, Box::new(Fixed(1))).with_vault(vault);
    s.execute(
        ids.owner,
        Command::Connect {
            app: App::OtherEmail,
            account: "dana@example.com".into(),
            for_: ConnectFor::Me,
            credentials: Some(MailLogin {
                imap_host: "imap.example.com".into(),
                imap_port: 993,
                smtp_host: "smtp.example.com".into(),
                smtp_port: 587,
                username: "dana@example.com".into(),
                password: Secret::new("pw-123456"),
            }),
        },
    )
    .unwrap();
    let mail_id = s
        .state()
        .connections
        .all()
        .find(|c| c.app == App::OtherEmail)
        .unwrap()
        .id;
    assert!(s.vault().unwrap().contains(mail_id).unwrap());
    s.execute(ids.admin, Command::SetRetention { days: 30 })
        .unwrap();
    let people = s.state().org.members().count();

    let msg = s
        .execute(
            ids.admin,
            Command::DeleteAllData {
                confirm: "  coastline mechanical ".into(),
            },
        )
        .unwrap();
    assert!(msg.starts_with("Deleted all Arkhon data"));
    let st = s.state();
    assert!(st.queue.items.is_empty() && st.queue.knowledge.is_empty());
    assert!(st.value.is_empty());
    assert_eq!(st.connections.all().count(), 0);
    assert!(st.work.threads.is_empty() && st.work.documents.is_empty());
    assert!(st.work.network.is_empty() && st.work.answers.is_empty());
    assert_eq!(st.work.privacy.retention_days, 30, "settings are kept");
    assert_eq!(st.org.members().count(), people, "people are kept");
    assert!(!s.vault().unwrap().contains(mail_id).unwrap());
    // Only the deletion itself remains in the log.
    let log = s.activity(ids.owner).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "Delete all Arkhon data");
    assert_eq!(log[0].actor, "Ari Patel");
    let v = s.view(ids.owner);
    assert_eq!(v.needs_you.total, 0);
    assert!(v.inbox.unwrap().threads.is_empty());
}

#[test]
fn setup_reports_progress_and_pack_choice_is_guarded() {
    let (mut s, ids) = suite();
    let v = s.setup_view(ids.owner);
    assert!(v.email_connected && v.files_connected);
    assert_eq!(v.industry_pack.as_deref(), Some("trades"));
    assert!(v.files_read < v.files_total);
    assert!(v.can_choose_pack && !s.setup_view(ids.tech).can_choose_pack);
    let pick = |p: &str| Command::SetIndustryPack { pack: p.into() };
    assert!(s.execute(ids.tech, pick("general")).unwrap_err().forbidden);
    assert!(!s.execute(ids.owner, pick("health")).unwrap_err().forbidden);
    assert!(!s.execute(ids.owner, pick("nope")).unwrap_err().forbidden);
    s.execute(ids.owner, pick("general")).unwrap();
    assert_eq!(
        s.setup_view(ids.tech).industry_pack.as_deref(),
        Some("general")
    );
    // Lena reads the Front office mailbox, so her email step is done; she has no files share
    // other than the job folder everyone gets.
    let lena = s.setup_view(ids.dispatcher);
    assert!(lena.email_connected && lena.files_connected);
}

#[test]
fn example_views_do_not_depend_on_the_clock() {
    let (a, ids) = demo_state();
    let (b, _) = demo_state();
    let one = Suite::new(a, Box::new(Fixed(1)));
    let two = Suite::new(b, Box::new(Fixed(1_900_000_000)));
    for id in [ids.owner, ids.tech, ids.dispatcher] {
        assert_eq!(
            serde_json::to_string(&one.view(id)).unwrap(),
            serde_json::to_string(&two.view(id)).unwrap()
        );
    }
}
