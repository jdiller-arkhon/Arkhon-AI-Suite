//! Tests against in-process fake IMAP and SMTP servers on 127.0.0.1. No real mail servers.

use super::*;
use arkhon_engine::{demo_state, Command, Secret, Suite, SystemClock};
use std::fmt::Write as _;
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;

const PASSWORD: &str = "app-password-123";

fn login(imap_port: u16, smtp_port: u16) -> MailLogin {
    MailLogin {
        imap_host: "127.0.0.1".into(),
        imap_port,
        smtp_host: "127.0.0.1".into(),
        smtp_port,
        username: "dana@coastline.com".into(),
        password: Secret::new(PASSWORD),
    }
}

fn message(n: u32) -> String {
    format!(
        "From: Customer {n} <c{n}@example.com>\r\nSubject: Question {n}\r\n\
         Message-ID: <m{n}@example.com>\r\n\r\nHello {n}\r\n"
    )
}

/// A scripted IMAP server: mailbox with UIDVALIDITY 42 and messages at the given UIDs.
async fn fake_imap(uids: Vec<u32>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            w.write_all(b"* OK fake IMAP ready\r\n").await.unwrap();
            while let Ok(Some(line)) = lines.next_line().await {
                log.lock().unwrap().push(line.clone());
                let (tag, rest) = line.split_once(' ').unwrap();
                let upper = rest.to_ascii_uppercase();
                let reply = if upper.starts_with("LOGIN") {
                    if rest.contains(PASSWORD) {
                        format!("{tag} OK LOGIN completed\r\n")
                    } else {
                        format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
                    }
                } else if upper.starts_with("SELECT") {
                    format!(
                        "* {} EXISTS\r\n* OK [UIDVALIDITY 42] UIDs valid\r\n* OK [UIDNEXT 99] next\r\n\
                         {tag} OK [READ-WRITE] SELECT completed\r\n",
                        uids.len()
                    )
                } else if upper.starts_with("UID SEARCH") {
                    // "UID n:*" always includes the highest UID, like real servers.
                    let from: u32 = upper
                        .rsplit("UID ")
                        .next()
                        .and_then(|r| r.split(':').next())
                        .and_then(|n| n.trim().parse().ok())
                        .unwrap_or(1);
                    let max = uids.iter().max().copied().unwrap_or(0);
                    let hits: Vec<String> = uids
                        .iter()
                        .filter(|u| **u >= from || **u == max)
                        .map(u32::to_string)
                        .collect();
                    format!(
                        "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
                        hits.join(" ")
                    )
                } else if upper.starts_with("UID FETCH") {
                    let set = rest.split(' ').nth(2).unwrap();
                    let mut out = String::new();
                    for (i, u) in set.split(',').enumerate() {
                        let u: u32 = u.parse().unwrap();
                        let m = message(u);
                        let _ = write!(
                            out,
                            "* {} FETCH (UID {u} BODY[] {{{}}}\r\n{m})\r\n",
                            i + 1,
                            m.len()
                        );
                    }
                    format!("{out}{tag} OK FETCH completed\r\n")
                } else if upper.starts_with("LOGOUT") {
                    format!("* BYE bye\r\n{tag} OK LOGOUT completed\r\n")
                } else {
                    format!("{tag} OK done\r\n")
                };
                w.write_all(reply.as_bytes()).await.unwrap();
            }
        }
    });
    (port, seen)
}

/// A minimal SMTP server that records each message's DATA.
async fn fake_smtp() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(Vec::new()));
    let store = got.clone();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            w.write_all(b"220 fake ESMTP\r\n").await.unwrap();
            let mut data: Option<String> = None;
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(d) = data.as_mut() {
                    if line == "." {
                        store.lock().unwrap().push(std::mem::take(d));
                        data = None;
                        w.write_all(b"250 queued\r\n").await.unwrap();
                    } else {
                        d.push_str(&line);
                        d.push('\n');
                    }
                    continue;
                }
                let up = line.to_ascii_uppercase();
                let reply: &[u8] = if up.starts_with("EHLO") || up.starts_with("HELO") {
                    b"250-fake\r\n250 8BITMIME\r\n"
                } else if up.starts_with("DATA") {
                    data = Some(String::new());
                    b"354 go ahead\r\n"
                } else if up.starts_with("QUIT") {
                    w.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                w.write_all(reply).await.unwrap();
            }
        }
    });
    (port, got)
}

/// The engine with Dana's Marisol reply approved; returns the suite, item and connection.
fn approved() -> (Suite, u64, u64) {
    let (state, ids) = demo_state();
    let mut s = Suite::new(state, Box::new(SystemClock));
    let item = s.view(ids.owner).needs_you.items[0].id;
    let conn = s.state().queue.get(item).unwrap().connection.unwrap();
    s.execute(ids.owner, Command::Approve { item }).unwrap();
    (s, item, conn)
}

fn envelope() -> Envelope {
    Envelope {
        from: "dana@coastline.com".into(),
        to: vec!["marisol@example.com".into()],
        subject: "Re: AC blowing warm".into(),
        in_reply_to: Some("<m5@example.com>".into()),
    }
}

#[tokio::test]
async fn fetches_new_mail_and_advances_the_cursor() {
    let (imap, log) = fake_imap(vec![5, 7]).await;
    let mut c = MailConnector::plaintext_for_tests(1, login(imap, 1));
    let (msgs, cur) = c.fetch_new(None).await.unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].uid, 5);
    assert_eq!(msgs[0].subject, "Question 5");
    assert_eq!(msgs[0].from, "Customer 5 <c5@example.com>");
    assert_eq!(msgs[1].message_id.as_deref(), Some("<m7@example.com>"));
    assert!(String::from_utf8_lossy(&msgs[1].raw).contains("Hello 7"));
    assert_eq!(
        cur,
        Cursor {
            validity: 42,
            last_uid: 7
        }
    );
    // Nothing new: the server still returns UID 7 for "8:*", which we drop.
    let (again, cur2) = c.fetch_new(Some(cur)).await.unwrap();
    assert!(again.is_empty(), "{again:?}");
    assert_eq!(cur2, cur);
    // Reading never marks mail as read.
    let cmds = log.lock().unwrap().join("\n");
    assert!(cmds.contains("BODY.PEEK[]"));
    assert!(!cmds.to_ascii_uppercase().contains("STORE"));
}

#[tokio::test]
async fn new_uidvalidity_starts_over() {
    let (imap, _) = fake_imap(vec![5, 7]).await;
    let mut c = MailConnector::plaintext_for_tests(1, login(imap, 1));
    let stale = Cursor {
        validity: 41,
        last_uid: 7,
    };
    let (msgs, cur) = c.fetch_new(Some(stale)).await.unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(cur.validity, 42);
}

#[tokio::test]
async fn wrong_password_is_a_sign_in_error() {
    let (imap, _) = fake_imap(vec![1]).await;
    let mut l = login(imap, 1);
    l.password = Secret::new("wrong");
    let mut c = MailConnector::plaintext_for_tests(1, l);
    assert_eq!(
        c.fetch_new(None).await.unwrap_err(),
        ConnectorError::SignInFailed
    );
}

#[tokio::test]
async fn nothing_is_sent_without_an_approval() {
    let (smtp, got) = fake_smtp().await;
    let (_, _, conn) = approved();
    let mut c = MailConnector::plaintext_for_tests(conn, login(1, smtp));
    assert_eq!(
        c.send_approved(None, &envelope()).await.unwrap_err(),
        ConnectorError::NotApproved
    );
    // Waiting items can't even produce an approval.
    let (state, ids) = demo_state();
    let s = Suite::new(state, Box::new(SystemClock));
    let waiting = s.view(ids.owner).needs_you.items[0].id;
    assert!(s.approval_for_send(waiting).unwrap_err().forbidden);
    assert_eq!(got.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn an_approval_for_another_account_is_refused() {
    let (smtp, got) = fake_smtp().await;
    let (s, item, conn) = approved();
    let a = s.approval_for_send(item).unwrap();
    let mut c = MailConnector::plaintext_for_tests(conn + 1, login(1, smtp));
    assert_eq!(
        c.send_approved(Some(&a), &envelope()).await.unwrap_err(),
        ConnectorError::WrongConnection
    );
    assert_eq!(got.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn approved_text_is_sent_exactly() {
    let (smtp, got) = fake_smtp().await;
    let (s, item, conn) = approved();
    let a = s.approval_for_send(item).unwrap();
    let mut c = MailConnector::plaintext_for_tests(conn, login(1, smtp));
    c.send_approved(Some(&a), &envelope()).await.unwrap();
    let sent = got.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].contains("Subject: Re: AC blowing warm"));
    assert!(sent[0].contains("In-Reply-To: <m5@example.com>"));
    assert!(sent[0].contains("To: marisol@example.com"));
    assert!(sent[0].contains("Hi Marisol"));
    assert!(sent[0].contains("under warranty"));
    assert!(!sent[0].contains(PASSWORD));
}

#[test]
fn bad_addresses_are_explained() {
    let (s, item, _) = approved();
    let a = s.approval_for_send(item).unwrap();
    let mut env = envelope();
    env.to = vec!["not an address".into()];
    assert!(matches!(
        build_message(&a, &env),
        Err(ConnectorError::Invalid(m)) if m.contains("isn't an email address")
    ));
    env.to.clear();
    assert!(build_message(&a, &env).is_err());
}

#[test]
fn debug_output_hides_the_password() {
    let c = MailConnector::new(1, login(1, 2));
    assert!(!format!("{c:?}").contains(PASSWORD));
}

#[test]
fn headers_are_read_case_insensitively_and_unfolded() {
    let raw = b"SUBJECT: Long\r\n  subject line\r\nFrom: a@b.c\r\n\r\nSubject: not me\r\n";
    assert_eq!(header(raw, "subject").as_deref(), Some("Long subject line"));
    assert_eq!(header(raw, "from").as_deref(), Some("a@b.c"));
    assert_eq!(header(raw, "to"), None);
}

#[test]
fn tls_setup_uses_the_bundled_root_store() {
    let _ = tls_connector();
}
