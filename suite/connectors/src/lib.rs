//! Connectors to the apps a company already uses.
//!
//! First: **Other email** over IMAP (reading) and SMTP (sending), for mailboxes that aren't
//! Microsoft 365 or Google. It implements [`arkhon_engine::connector::Connector`]:
//!
//! * reading new mail needs no approval (`BODY.PEEK[]`, so nothing is marked as read);
//! * sending refuses unless it is handed a [`SendApproval`] that the engine issued for an
//!   approved queue item on this same connection, and it sends exactly the approved text.
//!
//! Crates: [`async_imap`] (maintained by the Delta Chat project, used in production by their
//! mail clients) and [`lettre`] (the most widely used Rust SMTP client). TLS is rustls with the
//! Mozilla root store; IMAP uses implicit TLS (993), SMTP uses STARTTLS (587).
//!
//! Sign-ins come from the engine's encrypted [`arkhon_engine::TokenVault`]; this crate never
//! stores them.

use std::fmt::Debug;
use std::sync::Arc;

use arkhon_engine::connector::{
    check_approval, Connector, ConnectorError, Cursor, Envelope, FetchedMessage,
};
use arkhon_engine::{MailLogin, SendApproval};
use futures_util::TryStreamExt as _;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Most messages fetched in one go; older ones wait for the next fetch.
pub const MAX_FETCH: usize = 200;

/// How the connector talks to the servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    /// TLS (production).
    Tls,
    /// Unencrypted, loopback test servers only.
    #[cfg(test)]
    Plain,
}

/// IMAP/SMTP connector for one connected mailbox.
pub struct MailConnector {
    connection: u64,
    login: MailLogin,
    mailbox: String,
    wire: Wire,
}

impl Debug for MailConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailConnector")
            .field("connection", &self.connection)
            .field("imap_host", &self.login.imap_host)
            .field("smtp_host", &self.login.smtp_host)
            .field("mailbox", &self.mailbox)
            .finish_non_exhaustive()
    }
}

impl MailConnector {
    /// Connector for `connection`, signing in with `login` (from the vault). Reads `INBOX`.
    #[must_use]
    pub fn new(connection: u64, login: MailLogin) -> Self {
        MailConnector {
            connection,
            login,
            mailbox: "INBOX".into(),
            wire: Wire::Tls,
        }
    }

    #[cfg(test)]
    fn plaintext_for_tests(connection: u64, login: MailLogin) -> Self {
        MailConnector {
            wire: Wire::Plain,
            ..MailConnector::new(connection, login)
        }
    }

    async fn tcp(host: &str, port: u16) -> Result<TcpStream, ConnectorError> {
        TcpStream::connect((host, port))
            .await
            .map_err(|e| ConnectorError::Network(e.kind().to_string()))
    }
}

fn tls_connector() -> TlsConnector {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn imap_err(e: &async_imap::error::Error) -> ConnectorError {
    match e {
        async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_) => {
            ConnectorError::SignInFailed
        }
        other => ConnectorError::Network(other.to_string()),
    }
}

/// Fetch messages newer than `since` over an already-open stream (TLS in production).
///
/// # Errors
/// Sign-in or network errors.
pub async fn fetch_over<S>(
    stream: S,
    login: &MailLogin,
    mailbox: &str,
    since: Option<Cursor>,
) -> Result<(Vec<FetchedMessage>, Cursor), ConnectorError>
where
    S: AsyncRead + AsyncWrite + Unpin + Debug + Send,
{
    let mut client = async_imap::Client::new(stream);
    client
        .read_response()
        .await
        .map_err(|e| ConnectorError::Network(e.kind().to_string()))?
        .ok_or_else(|| ConnectorError::Network("no greeting".into()))?;
    let mut session = client
        .login(&login.username, login.password.expose())
        .await
        .map_err(|(e, _)| match e {
            async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_) => {
                ConnectorError::SignInFailed
            }
            other => ConnectorError::Network(other.to_string()),
        })?;
    let mb = session.select(mailbox).await.map_err(|e| imap_err(&e))?;
    let validity = mb.uid_validity.unwrap_or(0);
    // A new UIDVALIDITY means the server rebuilt the mailbox: start over.
    let last = since
        .filter(|c| c.validity == validity)
        .map_or(0, |c| c.last_uid);
    let mut uids: Vec<u32> = session
        .uid_search(format!("UID {}:*", last.saturating_add(1)))
        .await
        .map_err(|e| imap_err(&e))?
        .into_iter()
        .filter(|u| *u > last)
        .collect();
    uids.sort_unstable();
    uids.truncate(MAX_FETCH);
    let mut out = Vec::with_capacity(uids.len());
    if !uids.is_empty() {
        let set = uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let fetches: Vec<_> = session
            .uid_fetch(set, "(UID BODY.PEEK[])")
            .await
            .map_err(|e| imap_err(&e))?
            .try_collect()
            .await
            .map_err(|e| imap_err(&e))?;
        for f in fetches {
            let (Some(uid), Some(raw)) = (f.uid, f.body()) else {
                continue;
            };
            out.push(FetchedMessage {
                uid,
                message_id: header(raw, "message-id"),
                from: header(raw, "from").unwrap_or_default(),
                subject: header(raw, "subject").unwrap_or_default(),
                raw: raw.to_vec(),
            });
        }
        out.sort_by_key(|m| m.uid);
    }
    // Best effort: the server may already have closed the connection.
    let _ = session.logout().await;
    let next = Cursor {
        validity,
        last_uid: out.last().map_or(last, |m| m.uid.max(last)),
    };
    Ok((out, next))
}

/// First value of a header (unfolded), case-insensitive.
fn header(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    let mut found: Option<String> = None;
    for line in head.split("\r\n") {
        if let Some(v) = found.as_mut() {
            if line.starts_with([' ', '\t']) {
                v.push(' ');
                v.push_str(line.trim());
                continue;
            }
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                found = Some(v.trim().to_owned());
            }
        }
    }
    found
}

/// Build the outgoing message: exactly the approved text, to the envelope's recipients.
///
/// # Errors
/// [`ConnectorError::Invalid`] for bad addresses or no recipients.
pub fn build_message(approval: &SendApproval, env: &Envelope) -> Result<Message, ConnectorError> {
    let addr = |a: &str| {
        a.parse()
            .map_err(|_| ConnectorError::Invalid(format!("\"{a}\" isn't an email address")))
    };
    if env.to.is_empty() {
        return Err(ConnectorError::Invalid(
            "there's no one to send it to".into(),
        ));
    }
    let mut b = Message::builder()
        .from(addr(&env.from)?)
        .subject(env.subject.clone())
        .header(ContentType::TEXT_PLAIN);
    for to in &env.to {
        b = b.to(addr(to)?);
    }
    if let Some(r) = &env.in_reply_to {
        b = b.in_reply_to(r.clone()).references(r.clone());
    }
    b.body(approval.text().to_owned())
        .map_err(|e| ConnectorError::Invalid(e.to_string()))
}

fn smtp_err(e: &lettre::transport::smtp::Error) -> ConnectorError {
    if e.status().is_some_and(|c| c.to_string() == "535") {
        ConnectorError::SignInFailed
    } else {
        ConnectorError::Network(e.to_string())
    }
}

impl Connector for MailConnector {
    fn connection_id(&self) -> u64 {
        self.connection
    }

    async fn fetch_new(
        &mut self,
        since: Option<Cursor>,
    ) -> Result<(Vec<FetchedMessage>, Cursor), ConnectorError> {
        let tcp = Self::tcp(&self.login.imap_host, self.login.imap_port).await?;
        match self.wire {
            Wire::Tls => {
                let name = ServerName::try_from(self.login.imap_host.clone()).map_err(|_| {
                    ConnectorError::Invalid("the mail server name is invalid".into())
                })?;
                let tls = tls_connector()
                    .connect(name, tcp)
                    .await
                    .map_err(|e| ConnectorError::Network(e.kind().to_string()))?;
                fetch_over(tls, &self.login, &self.mailbox, since).await
            }
            #[cfg(test)]
            Wire::Plain => fetch_over(tcp, &self.login, &self.mailbox, since).await,
        }
    }

    async fn send_approved(
        &mut self,
        approval: Option<&SendApproval>,
        envelope: &Envelope,
    ) -> Result<(), ConnectorError> {
        // The gate comes first: no approval, no network traffic at all.
        check_approval(approval, self.connection)?;
        let Some(approval) = approval else {
            return Err(ConnectorError::NotApproved);
        };
        let message = build_message(approval, envelope)?;
        let host = self.login.smtp_host.as_str();
        let transport: AsyncSmtpTransport<Tokio1Executor> = match self.wire {
            Wire::Tls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| smtp_err(&e))?
                .port(self.login.smtp_port)
                .credentials(Credentials::new(
                    self.login.username.clone(),
                    self.login.password.expose().to_owned(),
                ))
                .build(),
            #[cfg(test)]
            Wire::Plain => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                .port(self.login.smtp_port)
                .build(),
        };
        transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|e| smtp_err(&e))
    }
}

#[cfg(test)]
mod tests;
