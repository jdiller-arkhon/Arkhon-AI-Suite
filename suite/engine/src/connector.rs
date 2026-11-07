//! Connector framework: how Arkhon reads from and (after approval) writes to connected apps.
//!
//! A [`Connector`] does two things:
//!
//! * **fetch** new messages since a [`Cursor`] (reading needs no approval: connections are at
//!   least `Read`), and
//! * **send** an approved draft. Sending takes a [`SendApproval`], which only
//!   [`crate::Suite::approval_for_send`] can create, and only for a queue item a person approved.
//!   Without it every connector refuses ([`ConnectorError::NotApproved`]). The approved text
//!   travels inside the approval, so what goes out is exactly what the person saw.
//!
//! Implementations live outside the engine (for example `arkhon-connectors` for IMAP/SMTP), so
//! the engine itself never opens a network connection.

use std::fmt;
use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::queue::ItemId;

/// Proof that a person approved a queue item, carrying the text they approved.
///
/// Fields are private and there is no public constructor: get one from
/// [`crate::Suite::approval_for_send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendApproval {
    pub(crate) item: ItemId,
    pub(crate) connection: u64,
    pub(crate) text: String,
}

impl SendApproval {
    /// The approved queue item.
    #[must_use]
    pub fn item(&self) -> ItemId {
        self.item
    }
    /// The connection it was approved to go through.
    #[must_use]
    pub fn connection(&self) -> u64 {
        self.connection
    }
    /// The approved text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Who an approved message goes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// From address (the connected mailbox).
    pub from: String,
    /// Recipients.
    pub to: Vec<String>,
    /// Subject.
    pub subject: String,
    /// `Message-ID` being replied to, if any.
    pub in_reply_to: Option<String>,
}

/// Where the last fetch stopped (IMAP: UIDVALIDITY + highest UID seen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Cursor {
    /// Mailbox generation; if it changes the mailbox was rebuilt and we start over.
    pub validity: u32,
    /// Highest UID already fetched.
    pub last_uid: u32,
}

/// A message read from a connected mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchedMessage {
    /// Server UID.
    pub uid: u32,
    /// `Message-ID` header.
    pub message_id: Option<String>,
    /// `From` header.
    pub from: String,
    /// `Subject` header.
    pub subject: String,
    /// Raw RFC 5322 message.
    pub raw: Vec<u8>,
}

/// Why a connector call failed. Messages are for the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    /// No approval was supplied.
    NotApproved,
    /// The approval is for a different connection.
    WrongConnection,
    /// Sign-in was rejected; the person must reconnect.
    SignInFailed,
    /// The server couldn't be reached or misbehaved.
    Network(String),
    /// Bad input (e.g. an invalid address).
    Invalid(String),
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorError::NotApproved => {
                f.write_str("Nothing is sent until someone approves it in Needs you.")
            }
            ConnectorError::WrongConnection => {
                f.write_str("That approval was for a different account, so nothing was sent.")
            }
            ConnectorError::SignInFailed => f.write_str(
                "The email server didn't accept the sign-in. Connect the account again.",
            ),
            ConnectorError::Network(why) => {
                write!(
                    f,
                    "Couldn't reach the email server ({why}). Try again soon."
                )
            }
            ConnectorError::Invalid(why) => write!(f, "That message couldn't be sent: {why}."),
        }
    }
}

impl std::error::Error for ConnectorError {}

/// A connected app Arkhon can read from and, with approval, write to.
pub trait Connector {
    /// The connection this connector serves.
    fn connection_id(&self) -> u64;

    /// Messages newer than `since` (all recent ones when `None`), and the cursor to use next.
    fn fetch_new(
        &mut self,
        since: Option<Cursor>,
    ) -> impl Future<Output = Result<(Vec<FetchedMessage>, Cursor), ConnectorError>> + Send;

    /// Send an approved draft. Must call [`check_approval`] first.
    fn send_approved(
        &mut self,
        approval: Option<&SendApproval>,
        envelope: &Envelope,
    ) -> impl Future<Output = Result<(), ConnectorError>> + Send;
}

/// The check every connector runs before sending: an approval must be present and must be for
/// this connection. Returns the approved text.
///
/// # Errors
/// [`ConnectorError::NotApproved`] or [`ConnectorError::WrongConnection`].
pub fn check_approval(
    approval: Option<&SendApproval>,
    connection: u64,
) -> Result<&str, ConnectorError> {
    let a = approval.ok_or(ConnectorError::NotApproved)?;
    if a.connection != connection {
        return Err(ConnectorError::WrongConnection);
    }
    Ok(&a.text)
}
